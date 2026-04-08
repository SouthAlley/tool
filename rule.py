import re
import sys
import os
import time
import ipaddress
import urllib.request
import urllib.error
import concurrent.futures
from collections import defaultdict
from pathlib import Path
from typing import Optional

# ──────────────────────────────────────────────
# 配置与预编译正则
# ──────────────────────────────────────────────

TIMEOUT = 30
USER_AGENT = 'Surge iOS/3374'
MAX_DOWNLOAD_WORKERS = 5

VALID_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "IP-CIDR", "IP-CIDR6",
    "USER-AGENT", "URL-REGEX", "PROCESS-NAME",
    "AND", "OR", "NOT",
}

ORDER_DICT = {
    "AND": 1, "OR": 2, "NOT": 3,
    "DOMAIN": 4, "DOMAIN-SUFFIX": 5, "DOMAIN-KEYWORD": 6, "DOMAIN-WILDCARD": 7,
    "IP-CIDR": 8, "IP-CIDR6": 9,
    "USER-AGENT": 10, "URL-REGEX": 11, "PROCESS-NAME": 12,
}

TYPE_ALIAS = {
    'HOST': 'DOMAIN', 'host': 'DOMAIN',
    'HOST-SUFFIX': 'DOMAIN-SUFFIX', 'host-suffix': 'DOMAIN-SUFFIX',
    'HOST-KEYWORD': 'DOMAIN-KEYWORD', 'host-keyword': 'DOMAIN-KEYWORD',
    'HOST-WILDCARD': 'DOMAIN-WILDCARD', 'host-wildcard': 'DOMAIN-WILDCARD',
    'IP6-CIDR': 'IP-CIDR6', 'ip6-cidr': 'IP-CIDR6',
    'ip-cidr': 'IP-CIDR', 'domain': 'DOMAIN',
    'domain-suffix': 'DOMAIN-SUFFIX', 'domain-keyword': 'DOMAIN-KEYWORD',
    'domain-wildcard': 'DOMAIN-WILDCARD',
    'user-agent': 'USER-AGENT', 'url-regex': 'URL-REGEX',
    'process-name': 'PROCESS-NAME',
}

RULE_RE = re.compile(r'^([A-Za-z0-9\-]+),(.+?)(?:,([^,]+))?$')
HOSTS_RE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)$')
DOMAIN_RE = re.compile(
    r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$',
    re.IGNORECASE,
)
SUFFIX_NO_RESOLVE_RE = re.compile(r',no-resolve\s*$', flags=re.IGNORECASE)
SUFFIX_POLICY_RE = re.compile(r',(DIRECT|REJECT|PROXY)\s*$', flags=re.IGNORECASE)


# ──────────────────────────────────────────────
# 1. 下载规则文件
# ──────────────────────────────────────────────

def download_rules(url: str, retries: int = 3) -> list[str]:
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': USER_AGENT, 'Accept-Language': 'en-us'},
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
                content = response.read().decode('utf-8', errors='ignore')
                return content.splitlines()
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2)
            else:
                print(f"[WARN] 下载失败 ({attempt+1}/{retries}): {url} -> {e}")
    return []


# ──────────────────────────────────────────────
# 2. 规则标准化
# ──────────────────────────────────────────────

def normalize_line(raw: str) -> Optional[str]:
    line = raw.strip()

    if not line or line.startswith(('#', ';', '!', '@', '[', '<')):
        return None

    # 统一 tab → 空格（兼容 hosts 文件）
    line = line.replace('\t', ' ')

    # Adblock: ||example.com^
    if line.startswith('||'):
        domain = line[2:].split('^')[0].strip()
        if '@' in domain or not domain:
            return None
        return f"DOMAIN-SUFFIX,{domain.lower()}"

    # hosts: 0.0.0.0 example.com
    m = HOSTS_RE.match(line)
    if m:
        domain = m.group(1)
        if domain in ('localhost', '0.0.0.0', '127.0.0.1', '::1'):
            return None
        return f"DOMAIN,{domain.lower()}"

    # 纯域名
    if DOMAIN_RE.match(line):
        return f"DOMAIN,{line.lower()}"

    # 删除 no-resolve / policy 后缀
    line = SUFFIX_NO_RESOLVE_RE.sub('', line)
    line = SUFFIX_POLICY_RE.sub('', line)

    m = RULE_RE.match(line)
    if not m:
        return None

    rtype, value = m.group(1), m.group(2).strip()

    # 类型别名统一（只对 rtype，不污染 value）
    rtype = TYPE_ALIAS.get(rtype, rtype)

    if rtype not in VALID_TYPES:
        return None

    # 复合规则原样返回
    if rtype in ('AND', 'OR', 'NOT'):
        return f"{rtype},{value}"

    # 域名规则
    if rtype in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD'):
        value = value.lower().lstrip('*.')
        if not value or ('*' in value and rtype != 'DOMAIN-WILDCARD'):
            return None
        if rtype != 'DOMAIN-WILDCARD' and not DOMAIN_RE.match(value):
            return None

    # IP 标准化
    if rtype in ('IP-CIDR', 'IP-CIDR6'):
        try:
            net = ipaddress.ip_network(value, strict=False)
            value = str(net)
        except ValueError:
            return None

    return f"{rtype},{value}"


# ──────────────────────────────────────────────
# 3. 域名 Trie 树与关键词去重
# ──────────────────────────────────────────────

class DomainTree:
    def __init__(self):
        self._trie = {}
        self._keywords: list[str] = []
        self._keyword_regex = None
        self._built = False

    def add_keyword(self, kw: str):
        if kw:
            self._keywords.append(kw)
            self._built = False

    def build_keyword_matcher(self):
        if self._keywords:
            escaped = [re.escape(kw) for kw in self._keywords]
            self._keyword_regex = re.compile('|'.join(escaped))
        self._built = True

    def covered_by_keyword(self, domain: str) -> bool:
        if not self._keywords:
            return False
        if not self._built:
            self.build_keyword_matcher()
        return self._keyword_regex.search(domain) is not None

    def _insert_suffix(self, domain: str) -> bool:
        labels = domain.split('.')[::-1]
        node = self._trie
        for label in labels:
            if '__end__' in node:
                return False
            if label not in node:
                node[label] = {}
            node = node[label]
        node.clear()
        node['__end__'] = True
        return True

    def _is_covered_by_suffix(self, domain: str) -> bool:
        labels = domain.split('.')[::-1]
        node = self._trie
        for label in labels:
            if '__end__' in node:
                return True
            if label not in node:
                return False
            node = node[label]
        return '__end__' in node

    def add(self, rtype: str, value: str) -> bool:
        if self.covered_by_keyword(value):
            return False
        if rtype == 'DOMAIN-SUFFIX':
            return self._insert_suffix(value)
        if rtype == 'DOMAIN':
            return not self._is_covered_by_suffix(value)
        return True


# ──────────────────────────────────────────────
# 4. IP CIDR 聚合
# ──────────────────────────────────────────────

def aggregate_cidrs(networks: list[str], version: int) -> list[str]:
    parsed = []
    for n in networks:
        try:
            net = ipaddress.ip_network(n, strict=False)
            if net.version == version:
                parsed.append(net)
        except ValueError:
            continue
    if not parsed:
        return []
    collapsed = list(ipaddress.collapse_addresses(parsed))
    prefix = "IP-CIDR" if version == 4 else "IP-CIDR6"
    return [f"{prefix},{net},no-resolve" for net in collapsed]


# ──────────────────────────────────────────────
# 5. 主处理函数
# ──────────────────────────────────────────────

def process_rule_directory(rule_dir: Path):
    rule_dir = Path(rule_dir).resolve()
    attach_dir = rule_dir / 'attach'

    rule_list_file = attach_dir / 'rule-list.ini'
    del_file = attach_dir / 'del.ini'
    add_file = attach_dir / 'add.ini'
    output_file = rule_dir / 'fin.txt'

    print("=" * 70)
    print(f"处理规则目录: {rule_dir.name}")
    print("=" * 70)

    if not rule_list_file.exists():
        print(f"[ERROR] 找不到 {rule_list_file}")
        return

    # ── 1. 读取 URL 列表（保序去重）──────────────
    urls = []
    seen_urls = set()
    with open(rule_list_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                url = line.split()[0]
                if url.startswith('http') and url not in seen_urls:
                    urls.append(url)
                    seen_urls.add(url)

    if not urls:
        print("[WARN] rule-list.ini 中没有有效 URL")
        return

    # ── 2. 并发下载 ───────────────────────────
    all_lines: list[str] = []

    def fetch(url):
        return url, download_rules(url)

    print(f"[INFO] 并发下载 {len(urls)} 个规则文件...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_DOWNLOAD_WORKERS) as executor:
        future_to_url = {executor.submit(fetch, u): u for u in urls}
        for i, future in enumerate(concurrent.futures.as_completed(future_to_url), 1):
            url, lines = future.result()
            print(f"[{i}/{len(urls)}] ✓ {len(lines)} 行 <- {url}")
            all_lines.extend(lines)

    # ── 3. 读取 add.ini ───────────────────────
    if add_file.exists():
        with open(add_file, 'r', encoding='utf-8', errors='ignore') as f:
            add_lines = f.read().splitlines()
        all_lines.extend(add_lines)
        print(f"\n[INFO] 加载手动规则: {add_file.name} ({len(add_lines)} 行)")

    # ── 4. 读取 del.ini ───────────────────────
    pre_tags: list[str] = []
    post_exact: set[str] = set()
    post_suffix: list[str] = []

    if del_file.exists():
        with open(del_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.upper().startswith('TAG:'):
                    pre_tags.append(line[4:].strip())
                elif ',' in line:
                    post_exact.add(line)
                else:
                    post_suffix.append(line)

    # ── 5. 标签预过滤 ─────────────────────────
    if pre_tags:
        original_count = len(all_lines)
        all_lines = [
            line for line in all_lines
            if not any(tag in line for tag in pre_tags)
        ]
        removed = original_count - len(all_lines)
        print(f"[INFO] 标签模式预过滤: 删除了 {removed} 条原始规则")

    # ── 6. 原始行去重后再标准化 ─────────────────
    unique_raw = set(all_lines)
    print(f"[INFO] 原始行去重: {len(all_lines)} -> {len(unique_raw)}")
    print(f"[INFO] 标准化 {len(unique_raw)} 行...")

    buckets: dict[str, list[str]] = defaultdict(list)
    compound_rules: list[str] = []

    for line in unique_raw:
        norm = normalize_line(line)
        if not norm:
            continue
        rtype = norm.split(',', 1)[0]
        if rtype in ('AND', 'OR', 'NOT'):
            compound_rules.append(norm)
        else:
            value = norm.split(',', 1)[1] if ',' in norm else ''
            if value:
                buckets[rtype].append(value)

    # ── 7. 域名去重 ───────────────────────────
    print("[INFO] 域名规则去重 (Trie & Regex 加速)...")
    tree = DomainTree()

    # 关键词
    kw_kept = []
    for val in sorted(set(buckets.get('DOMAIN-KEYWORD', []))):
        tree.add_keyword(val)
        kw_kept.append(f"DOMAIN-KEYWORD,{val}")
    tree.build_keyword_matcher()

    # 后缀（短的优先，确保父域先插入）
    suffix_kept = []
    for val in sorted(set(buckets.get('DOMAIN-SUFFIX', [])), key=len):
        if tree.add('DOMAIN-SUFFIX', val):
            suffix_kept.append(f"DOMAIN-SUFFIX,{val}")

    # 精确域名
    domain_kept = []
    for val in sorted(set(buckets.get('DOMAIN', []))):
        if tree.add('DOMAIN', val):
            domain_kept.append(f"DOMAIN,{val}")

    # 通配符域名（检查是否被 keyword/suffix 覆盖）
    wildcard_kept = []
    for val in sorted(set(buckets.get('DOMAIN-WILDCARD', []))):
        if not tree.covered_by_keyword(val) and not tree._is_covered_by_suffix(val):
            wildcard_kept.append(f"DOMAIN-WILDCARD,{val}")

    # ── 8. IP 聚合 ────────────────────────────
    print("[INFO] IP CIDR 聚合...")
    ip4_rules = aggregate_cidrs(list(set(buckets.get('IP-CIDR', []))), version=4)
    ip6_rules = aggregate_cidrs(list(set(buckets.get('IP-CIDR6', []))), version=6)

    # ── 9. 其他规则 ───────────────────────────
    SKIP_TYPES = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'IP-CIDR', 'IP-CIDR6'}
    other_kept = []
    for rtype in buckets:
        if rtype in SKIP_TYPES:
            continue
        for val in sorted(set(buckets[rtype])):
            other_kept.append(f"{rtype},{val}")

    compound_kept = sorted(set(compound_rules))

    # ── 10. 合并 ──────────────────────────────
    final_rules = (
        compound_kept
        + kw_kept
        + suffix_kept
        + domain_kept
        + wildcard_kept
        + ip4_rules
        + ip6_rules
        + other_kept
    )

    # ── 11. 后缀过滤 + 精确过滤 ─────────────────
    if post_exact or post_suffix:
        original_count = len(final_rules)
        suffix_tuple = tuple(post_suffix) if post_suffix else ()
        final_rules = [
            r for r in final_rules
            if r not in post_exact and (not suffix_tuple or not r.endswith(suffix_tuple))
        ]
        removed = original_count - len(final_rules)
        print(f"[INFO] 最终过滤: 删除了 {removed} 条")

    # ── 12. 过滤过短规则 ───────────────────────
    final_rules = [r for r in final_rules if len(r) > 5]

    # ── 13. 排序 ──────────────────────────────
    def sort_rules_key(rule_line: str):
        parts = rule_line.split(',', 1)
        rtype = parts[0]
        value = parts[1] if len(parts) > 1 else ""
        priority = ORDER_DICT.get(rtype, 999)
        is_tld = 0 if (rtype.startswith('DOMAIN') and '.' not in value) else 1
        return (priority, is_tld, rule_line)

    final_rules.sort(key=sort_rules_key)

    # ── 14. 写入 ──────────────────────────────
    total = len(final_rules)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# Total: {total} rules\n")
        f.write("# " + "=" * 66 + "\n")
        for r in final_rules:
            f.write(r + '\n')

    # ── 15. 统计 ──────────────────────────────
    rel_path = os.path.relpath(output_file)
    print("\n" + "=" * 70)
    print(f"✅ 处理完成: {rule_dir.name}")
    print("=" * 70)
    print(f"  输出文件        : {rel_path}")
    print(f"  总规则数        : {total}")
    print("=" * 70 + "\n")


# ──────────────────────────────────────────────
# 6. 命令行入口
# ──────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("示例: python rule.py rule/ad rule/proxy")
        sys.exit(1)

    for rule_dir in sys.argv[1:]:
        try:
            process_rule_directory(rule_dir)
        except Exception as e:
            print(f"\n[ERROR] 处理 {rule_dir} 失败:")
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
