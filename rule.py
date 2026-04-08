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
# ahocorasick 安全导入
# ──────────────────────────────────────────────
try:
    import ahocorasick
    HAS_AHOCORASICK = True
except ImportError:
    HAS_AHOCORASICK = False

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

# 域名合法性校验
DOMAIN_RE = re.compile(
    r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$',
    re.IGNORECASE,
)

# hosts 文件格式：匹配行首 IP，后续所有空白+主机名
HOSTS_RE = re.compile(
    r'^(?:0\.0\.0\.0|127\.0\.0\.1)((?:\s+\S+)+)$'
)

# 仅去掉 no-resolve
SUFFIX_NO_RESOLVE_RE = re.compile(r',no-resolve\s*$', flags=re.IGNORECASE)

# 复合规则专用正则（不裁剪第三段）
COMPOUND_RULE_RE = re.compile(r'^(AND|OR|NOT),(.+)$', re.IGNORECASE)

# 纯 IPv4 地址（四段数字，用于排除误识别）
IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


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

def _parse_rule_parts(line: str) -> Optional[tuple[str, str]]:
    """
    将 'TYPE,value[,policy][,no-resolve]' 按逗号拆分，
    返回 (rtype_raw, value) 或 None。
    使用直接拆分替代正则 policy 裁剪，避免含逗号 policy 时解析错误。
    """
    parts = line.split(',')
    if len(parts) < 2:
        return None
    rtype_raw = parts[0].strip()
    value = parts[1].strip()
    if not rtype_raw or not value:
        return None
    return rtype_raw, value


def normalize_line(raw: str) -> Optional[str]:
    """
    将一行原始文本标准化为 "TYPE,value" 格式。
    返回 None 表示该行应被丢弃。
    """
    line = raw.strip()

    if not line or line.startswith(('#', ';', '!', '@', '[', '<')):
        return None

    # tab → 空格（兼容 hosts 文件的 tab 分隔）
    line = line.replace('\t', ' ')

    # ── Adblock: ||example.com^ ──────────────
    if line.startswith('||'):
        domain = line[2:].split('^')[0].strip()
        if not domain or '@' in domain:
            return None
        domain = domain.lower()
        if not DOMAIN_RE.match(domain):
            return None
        return f"DOMAIN-SUFFIX,{domain}"

    # ── hosts 格式 ────────────────────────────
    # 支持同一行多个主机名：0.0.0.0 a.com b.com c.com
    m = HOSTS_RE.match(line)
    if m:
        # 取最后一个主机名（兼容单主机名行，也能处理多主机名行首个有效域名）
        # 实际 hosts 规范每行一个域名，多主机名时返回第一个非保留域名
        hostnames = m.group(1).split()
        for hostname in hostnames:
            hostname = hostname.lower()
            if hostname in ('localhost', '0.0.0.0', '127.0.0.1', '::1'):
                continue
            # 排除纯 IPv4
            if IPV4_RE.match(hostname):
                continue
            if not DOMAIN_RE.match(hostname):
                continue
            return f"DOMAIN,{hostname}"
        return None

    # ── 纯域名（无逗号、无空格）──────────────
    if ' ' not in line and ',' not in line and '/' not in line:
        candidate = line.lower()
        # 排除纯 IPv4 地址
        if not IPV4_RE.match(candidate) and DOMAIN_RE.match(candidate):
            return f"DOMAIN,{candidate}"

    # ── 复合规则（AND/OR/NOT）：原样保留，不裁剪 ──
    mc = COMPOUND_RULE_RE.match(line)
    if mc:
        rtype = mc.group(1).upper()
        return f"{rtype},{mc.group(2).strip()}"

    # ── 去掉 no-resolve 后缀 ──────────────────
    line = SUFFIX_NO_RESOLVE_RE.sub('', line)

    # ── 通用规则解析（直接拆分，不依赖正则裁剪 policy）──
    parsed = _parse_rule_parts(line)
    if not parsed:
        return None

    rtype_raw, value = parsed

    # 类型别名统一
    rtype = TYPE_ALIAS.get(rtype_raw, rtype_raw)

    if rtype not in VALID_TYPES:
        return None

    # 复合规则（保险兜底）
    if rtype in ('AND', 'OR', 'NOT'):
        return f"{rtype},{value}"

    # ── 域名规则 ──────────────────────────────
    if rtype in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD'):
        value = value.lower()

        if rtype == 'DOMAIN-WILDCARD':
            # 去掉开头所有多余的 *. 前缀，保留干净的域名部分
            value = re.sub(r'^[\*\.]+', '', value)
            if not value:
                return None
            # 通配符允许内部含 *，基础域名部分需合法
            base = value.replace('*', 'x')
            if not DOMAIN_RE.match(base):
                return None
        else:
            # 去掉开头 *. 前缀
            value = value.lstrip('*.')
            if not value:
                return None
            # 非通配符不允许含 *
            if '*' in value:
                return None
            if not DOMAIN_RE.match(value):
                return None

    # ── IP 标准化 ─────────────────────────────
    elif rtype in ('IP-CIDR', 'IP-CIDR6'):
        try:
            net = ipaddress.ip_network(value, strict=False)
            # 类型与实际 IP 版本一致性校验
            if rtype == 'IP-CIDR' and net.version != 4:
                return None
            if rtype == 'IP-CIDR6' and net.version != 6:
                return None
            value = str(net)
        except ValueError:
            return None

    return f"{rtype},{value}"


# ──────────────────────────────────────────────
# 3. 域名 Trie 树 + Aho-Corasick 关键词匹配
# ──────────────────────────────────────────────

class DomainTree:
    """
    域名规则去重：
      - DOMAIN-KEYWORD  → Aho-Corasick 自动机（或 re 回退）
                          关键词之间也做子串去重
      - DOMAIN-SUFFIX   → 反向标签 Trie（父域覆盖子域）
      - DOMAIN          → 被 suffix / keyword 覆盖时丢弃
      - DOMAIN-WILDCARD → 被 suffix / keyword 覆盖时丢弃
    """

    def __init__(self):
        self._trie: dict = {}
        self._keywords: list[str] = []
        self._automaton: Optional[object] = None
        self._keyword_regex: Optional[re.Pattern] = None
        self._built = False

    # ── 关键词批量去重（替代逐条 add_keyword，避免 O(n²)）────

    def finalize_keywords(self, raw_keywords: list[str]) -> list[str]:
        """
        一次性对所有关键词做子串去重。
        按长度升序排列，短词优先保留；长词若包含已保留的短词则丢弃。
        返回最终保留的关键词列表。
        """
        sorted_kws = sorted(set(raw_keywords), key=len)
        kept: list[str] = []
        for kw in sorted_kws:
            if not kw:
                continue
            # 若已有更短的词是当前词的子串，则丢弃当前词
            if any(existing in kw for existing in kept):
                continue
            kept.append(kw)
        self._keywords = kept
        self._built = False
        return kept

    def build_keyword_matcher(self):
        if not self._keywords:
            self._built = True
            return
        if HAS_AHOCORASICK:
            A = ahocorasick.Automaton()
            for idx, kw in enumerate(self._keywords):
                A.add_word(kw, (idx, kw))
            A.make_automaton()
            self._automaton = A
            self._keyword_regex = None
        else:
            escaped = [re.escape(kw) for kw in self._keywords]
            self._keyword_regex = re.compile('|'.join(escaped))
            self._automaton = None
        self._built = True

    def covered_by_keyword(self, domain: str) -> bool:
        if not self._keywords:
            return False
        if not self._built:
            self.build_keyword_matcher()
        if self._automaton is not None:
            for _ in self._automaton.iter(domain):
                return True
            return False
        if self._keyword_regex is not None:
            return self._keyword_regex.search(domain) is not None
        return False

    # ── 后缀 Trie ─────────────────────────────

    def _insert_suffix(self, domain: str) -> bool:
        """
        插入 DOMAIN-SUFFIX。
        - 已有更短父后缀覆盖 → False（丢弃）
        - 当前域名更短 → 清除子树并标记，返回 True
        """
        labels = domain.split('.')[::-1]
        node = self._trie
        for label in labels:
            if '__end__' in node:
                return False          # 父后缀已存在，当前更长的被覆盖
            if label not in node:
                node[label] = {}
            node = node[label]
        # 标记终止，清除所有更长的子后缀
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

    # ── 对外统一接口 ───────────────────────────

    def add(self, rtype: str, value: str) -> bool:
        """返回 True 表示保留，False 表示被去重。"""
        if self.covered_by_keyword(value):
            return False

        if rtype == 'DOMAIN-SUFFIX':
            return self._insert_suffix(value)

        if rtype in ('DOMAIN', 'DOMAIN-WILDCARD'):
            return not self._is_covered_by_suffix(value)

        return True


# ──────────────────────────────────────────────
# 4. IP CIDR 聚合
# ──────────────────────────────────────────────

def aggregate_cidrs(networks: list[str], version: int) -> list[str]:
    """
    聚合 IP CIDR 列表。
    normalize_line 已做版本校验，此处仅做最终聚合，避免重复解析开销。
    """
    parsed: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
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
# 5. del.ini 过滤辅助
# ──────────────────────────────────────────────

def _rule_value(rule: str) -> str:
    """从 'TYPE,value' 中提取 value 部分。"""
    parts = rule.split(',', 2)
    return parts[1] if len(parts) >= 2 else ''


def build_delete_filter(post_exact: set[str], post_suffix: list[str]):
    """
    预处理删除规则，返回一个高效的过滤函数。

    - post_exact  : 完整规则字符串集合，O(1) 查找
    - post_suffix : 值级域名后缀列表，预处理为 set 加速精确匹配，
                    后缀匹配仍需线性扫描但已减少精确命中的压力
    """
    post_suffix_set = set(post_suffix)

    def should_delete(rule: str) -> bool:
        # 精确匹配：O(1)
        if rule in post_exact:
            return True
        if not post_suffix_set and not post_suffix:
            return False
        val = _rule_value(rule)
        if not val:
            return False
        # 精确值匹配：O(1)
        if val in post_suffix_set:
            return True
        # 后缀匹配：O(n)，但精确命中已被上面过滤，减少到达此处的频率
        for s in post_suffix:
            if val.endswith('.' + s):
                return True
        return False

    return should_delete


# ──────────────────────────────────────────────
# 6. 主处理函数
# ──────────────────────────────────────────────

def process_rule_directory(rule_dir: Path):
    rule_dir = Path(rule_dir).resolve()
    attach_dir = rule_dir / 'attach'

    rule_list_file = attach_dir / 'rule-list.ini'
    del_file       = attach_dir / 'del.ini'
    add_file       = attach_dir / 'add.ini'
    output_file    = rule_dir   / 'fin.txt'

    print("=" * 70)
    print(f"处理规则目录: {rule_dir.name}")
    print("=" * 70)

    if not rule_list_file.exists():
        print(f"[ERROR] 找不到 {rule_list_file}")
        return

    # ── 1. 读取 URL 列表（保序去重）──────────────
    urls: list[str] = []
    seen_urls: set[str] = set()
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

    # ── 2. 并发下载（保持原始 URL 顺序合并）────────
    print(f"[INFO] 并发下载 {len(urls)} 个规则文件...")

    def fetch(url: str) -> tuple[str, list[str]]:
        return url, download_rules(url)

    results: dict[str, list[str]] = {}
    width = len(str(len(urls)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_DOWNLOAD_WORKERS) as executor:
        future_map = {executor.submit(fetch, u): u for u in urls}
        completed = 0
        for future in concurrent.futures.as_completed(future_map):
            url, lines = future.result()
            results[url] = lines
            completed += 1
            print(f"  [{completed:>{width}}/{len(urls)}] ✓ {len(lines):>6} 行 <- {url}")

    # 按原始顺序合并，确保结果可复现
    all_lines: list[str] = []
    for url in urls:
        all_lines.extend(results.get(url, []))

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
        before = len(all_lines)
        all_lines = [l for l in all_lines if not any(tag in l for tag in pre_tags)]
        print(f"[INFO] 标签预过滤: 删除了 {before - len(all_lines)} 条原始行")

    # ── 6. 原始行去重 + 标准化 ─────────────────
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
            parts = norm.split(',', 1)
            if len(parts) == 2 and parts[1]:
                buckets[rtype].append(parts[1])

    # ── 7. 域名去重 ───────────────────────────
    print(
        "[INFO] 域名规则去重 (Trie"
        + (" + Aho-Corasick" if HAS_AHOCORASICK else " + re")
        + ")..."
    )
    tree = DomainTree()

    # 7-a. 关键词：批量一次性子串去重，O(n log n) 替代 O(n²)
    raw_keywords = list(set(buckets.get('DOMAIN-KEYWORD', [])))
    kept_keywords = tree.finalize_keywords(raw_keywords)
    tree.build_keyword_matcher()
    kw_kept = [f"DOMAIN-KEYWORD,{kw}" for kw in kept_keywords]

    # 7-b. 后缀（短→长排序，父域先插入以覆盖子域）
    suffix_kept: list[str] = []
    for val in sorted(set(buckets.get('DOMAIN-SUFFIX', [])), key=len):
        if tree.add('DOMAIN-SUFFIX', val):
            suffix_kept.append(f"DOMAIN-SUFFIX,{val}")

    # 7-c. 精确域名
    domain_kept: list[str] = []
    for val in sorted(set(buckets.get('DOMAIN', []))):
        if tree.add('DOMAIN', val):
            domain_kept.append(f"DOMAIN,{val}")

    # 7-d. 通配符域名
    wildcard_kept: list[str] = []
    for val in sorted(set(buckets.get('DOMAIN-WILDCARD', []))):
        if tree.add('DOMAIN-WILDCARD', val):
            wildcard_kept.append(f"DOMAIN-WILDCARD,{val}")

    # ── 8. IP 聚合 ────────────────────────────
    print("[INFO] IP CIDR 聚合...")
    ip4_rules = aggregate_cidrs(list(set(buckets.get('IP-CIDR',  []))), version=4)
    ip6_rules = aggregate_cidrs(list(set(buckets.get('IP-CIDR6', []))), version=6)

    # ── 9. 其他规则 ───────────────────────────
    DOMAIN_TYPES = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
                    'IP-CIDR', 'IP-CIDR6'}
    other_kept: list[str] = []
    for rtype, vals in buckets.items():
        if rtype in DOMAIN_TYPES:
            continue
        for val in sorted(set(vals)):
            other_kept.append(f"{rtype},{val}")

    compound_kept = sorted(set(compound_rules))

    # ── 10. 合并 ──────────────────────────────
    final_rules: list[str] = (
        compound_kept
        + kw_kept
        + suffix_kept
        + domain_kept
        + wildcard_kept
        + ip4_rules
        + ip6_rules
        + other_kept
    )

    # ── 11. del.ini 过滤 ──────────────────────
    if post_exact or post_suffix:
        should_delete = build_delete_filter(post_exact, post_suffix)
        before = len(final_rules)
        final_rules = [r for r in final_rules if not should_delete(r)]
        print(f"[INFO] del.ini 过滤: 删除了 {before - len(final_rules)} 条")

    # ── 12. 过滤值为空的规则 ───────────────────
    # 用明确的空值判断替代 len(r) > 5 的模糊过滤
    final_rules = [
        r for r in final_rules
        if ',' in r and r.split(',', 1)[1].strip()
    ]

    # ── 13. 排序 ──────────────────────────────
    def sort_key(rule_line: str):
        parts = rule_line.split(',', 1)
        rtype = parts[0]
        value = parts[1] if len(parts) > 1 else ''
        priority = ORDER_DICT.get(rtype, 999)
        # TLD（无点）优先排在同类型最前面
        is_tld = 0 if (rtype.startswith('DOMAIN') and '.' not in value) else 1
        return (priority, is_tld, rule_line)

    final_rules.sort(key=sort_key)

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
    print(f"  输出文件  : {rel_path}")
    print(f"  总规则数  : {total}")
    print("=" * 70 + "\n")

# ──────────────────────────────────────────────
# 7. 命令行入口
# ──────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("用法: python rule.py <rule目录> [rule目录2 ...]")
        print("示例: python rule.py rule/ad rule/proxy")
        sys.exit(1)

    for rule_dir in sys.argv[1:]:
        try:
            process_rule_directory(rule_dir)
        except Exception:
            print(f"\n[ERROR] 处理 {rule_dir} 失败:")
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
