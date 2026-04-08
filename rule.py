#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rule_processor.py - 通用规则处理器
用法：python rule_processor.py <规则目录路径>
示例：python rule_processor.py rule/ad
"""

import re
import sys
import ipaddress
import urllib.request
import urllib.error
from collections import defaultdict
from pathlib import Path
from typing import Optional

# ──────────────────────────────────────────────
# 配置
# ──────────────────────────────────────────────

TIMEOUT = 30
USER_AGENT = 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15'

# ──────────────────────────────────────────────
# 1. 下载规则文件
# ──────────────────────────────────────────────

def download_rules(url: str) -> list[str]:
    """下载单个规则文件，返回行列表"""
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': USER_AGENT,
                'Accept-Language': 'en-us',
            }
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            content = response.read().decode('utf-8', errors='ignore')
            return content.splitlines()
    except Exception as e:
        print(f"[WARN] 下载失败: {url}")
        print(f"       错误: {e}")
        return []


# ──────────────────────────────────────────────
# 2. 规则标准化
# ──────────────────────────────────────────────

VALID_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD",
    "IP-CIDR", "IP-CIDR6",
    "USER-AGENT",
    "AND", "OR", "NOT",
}

RULE_RE = re.compile(r'^([A-Z0-9\-]+),(.+?)(?:,([^,]+))?$')

def normalize_line(raw: str) -> Optional[str]:
    """标准化单行规则"""
    line = raw.strip()

    # 过滤无效行
    if not line or line.startswith(('#', ';', '!', '@', '[', '<')):
        return None
    if '\t' in line:
        return None

    # Adblock 语法：||example.com^
    if line.startswith('||'):
        domain = line[2:].split('^')[0].strip()
        if '@' in domain or not domain:
            return None
        return f"DOMAIN-SUFFIX,{domain}"

    # hosts 格式：0.0.0.0 example.com
    m = re.match(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)$', line)
    if m:
        domain = m.group(1)
        if domain in ('localhost', '0.0.0.0', '127.0.0.1', '::1'):
            return None
        return f"DOMAIN,{domain}"

    # 纯域名（无前缀）
    if re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', line, re.IGNORECASE):
        return f"DOMAIN,{line.lower()}"

    # 统一别名
    line = (line
            .replace('host-suffix',    'DOMAIN-SUFFIX')
            .replace('host-keyword',   'DOMAIN-KEYWORD')
            .replace('host',           'DOMAIN')
            .replace('HOST-SUFFIX',    'DOMAIN-SUFFIX')
            .replace('HOST-KEYWORD',   'DOMAIN-KEYWORD')
            .replace('HOST',           'DOMAIN')
            .replace('ip6-cidr',       'IP-CIDR6')
            .replace('IP6-CIDR',       'IP-CIDR6')
            .replace('domain-suffix',  'DOMAIN-SUFFIX')
            .replace('domain-keyword', 'DOMAIN-KEYWORD')
            .replace('domain',         'DOMAIN')
            .replace('user-agent',     'USER-AGENT')
    )
    
    # 删除 no-resolve / policy 等后缀
    line = re.sub(r',no-resolve\s*$', '', line, flags=re.IGNORECASE)
    line = re.sub(r',(DIRECT|REJECT|PROXY)\s*$', '', line, flags=re.IGNORECASE)

    m = RULE_RE.match(line)
    if not m:
        return None

    rtype, value = m.group(1), m.group(2).strip()

    if rtype not in VALID_TYPES:
        return None

    # 复合规则原样返回
    if rtype in ('AND', 'OR', 'NOT'):
        return line

    # 域名规则处理
    if rtype in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'):
        value = value.lower()
        if not value or '*' in value:
            return None
        # 去掉开头的通配点
        value = value.lstrip('*.')
        # 验证域名合法性（基本检查）
        if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', value):
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
# 3. 域名 Trie 树去重
# ──────────────────────────────────────────────

class DomainTree:
    def __init__(self):
        self._trie = {}
        self._keywords = []

    def add_keyword(self, kw: str):
        self._keywords.append(kw)

    def _covered_by_keyword(self, domain: str) -> bool:
        return any(kw in domain for kw in self._keywords)

    def _insert_suffix(self, domain: str) -> bool:
        """插入 DOMAIN-SUFFIX，若父后缀已存在则返回 False"""
        labels = domain.split('.')[::-1]  # 反转：com.example.sub
        node = self._trie

        for label in labels:
            if '__end__' in node:
                # 父后缀已存在，当前规则冗余
                return False
            if label not in node:
                node[label] = {}
            node = node[label]

        # 标记终点并清除所有子节点（子域名都冗余）
        node.clear()
        node['__end__'] = True
        return True

    def _is_covered_by_suffix(self, domain: str) -> bool:
        """检查 domain 是否被已有 DOMAIN-SUFFIX 覆盖"""
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
        """尝试添加规则，返回是否被采纳"""
        # KEYWORD 优先级最高
        if self._covered_by_keyword(value):
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
    """聚合合并 CIDR"""
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
    """
    处理指定的规则目录
    
    目录结构：
      rule_dir/
        ├── attach/
        │   ├── rule-list.ini  (必需)
        │   ├── del.ini        (可选)
        │   └── add.ini        (可选)
        └── fin.txt            (输出)
    """
    
    rule_dir = Path(rule_dir).resolve()
    attach_dir = rule_dir / 'attach'
    
    rule_list_file = attach_dir / 'rule-list.ini'
    del_file = attach_dir / 'del.ini'
    add_file = attach_dir / 'add.ini'
    output_file = rule_dir / 'fin.txt'

    print("=" * 70)
    print(f"处理规则目录: {rule_dir.name}")
    print("=" * 70)

    # 检查必需文件
    if not rule_list_file.exists():
        print(f"[ERROR] 找不到 {rule_list_file}")
        return

    # ── 1. 读取 URL 列表 ──────────────────────
    urls = []
    with open(rule_list_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                url = line.split()[0]
                if url.startswith('http'):
                    urls.append(url)

    if not urls:
        print("[WARN] rule-list.ini 中没有有效 URL")
        return

    # ── 2. 下载所有规则 ───────────────────────
    all_lines = []
    for i, url in enumerate(urls, 1):
        print(f"[{i}/{len(urls)}] {url}")
        lines = download_rules(url)
        all_lines.extend(lines)
        print(f"          ✓ {len(lines)} 行")

    # ── 3. 读取 add.ini ───────────────────────
    if add_file.exists():
        with open(add_file, 'r', encoding='utf-8', errors='ignore') as f:
            all_lines.extend(f.readlines())
        print(f"\n[INFO] 加载手动规则: {add_file.name}")

    # ── 4. 标准化 ─────────────────────────────
    print(f"\n[INFO] 标准化 {len(all_lines)} 行...")
    buckets = defaultdict(list)
    compound_rules = []

    for line in all_lines:
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

    # ── 5. 域名去重 ───────────────────────────
    print("[INFO] 域名规则去重...")
    tree = DomainTree()

    # KEYWORD 优先（覆盖范围最大）
    kw_kept = []
    for val in sorted(set(buckets.get('DOMAIN-KEYWORD', []))):
        tree.add_keyword(val)
        kw_kept.append(f"DOMAIN-KEYWORD,{val}")

    # SUFFIX（建立 Trie）
    suffix_kept = []
    for val in sorted(set(buckets.get('DOMAIN-SUFFIX', []))):
        if tree._insert_suffix(val):
            suffix_kept.append(f"DOMAIN-SUFFIX,{val}")

    # DOMAIN（精确匹配）
    domain_kept = []
    for val in sorted(set(buckets.get('DOMAIN', []))):
        if tree.add('DOMAIN', val):
            domain_kept.append(f"DOMAIN,{val}")

    # ── 6. IP 聚合 ────────────────────────────
    print("[INFO] IP CIDR 聚合...")
    ip4_rules = aggregate_cidrs(
        list(set(buckets.get('IP-CIDR', []))), version=4
    )
    ip6_rules = aggregate_cidrs(
        list(set(buckets.get('IP-CIDR6', []))), version=6
    )

    # ── 7. 其他规则 ───────────────────────────
    other_kept = []
    for rtype in buckets:
        if rtype in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6'):
            continue
        for val in sorted(set(buckets[rtype])):
            other_kept.append(f"{rtype},{val}")

    # ── 8. 复合规则去重 ───────────────────────
    compound_kept = sorted(set(compound_rules))

    # ── 9. 合并所有规则 ───────────────────────
    final_rules = (
        kw_kept +
        suffix_kept +
        domain_kept +
        ip4_rules +
        ip6_rules +
        other_kept
    )

    # ── 10. 应用 del.ini 过滤 ─────────────────
    if del_file.exists():
        with open(del_file, 'r', encoding='utf-8', errors='ignore') as f:
            endings = {l.strip() for l in f if l.strip()}
        if endings:
            original_count = len(final_rules)
            final_rules = [
                r for r in final_rules
                if not any(r.endswith(e) for e in endings)
            ]
            removed = original_count - len(final_rules)
            print(f"[INFO] 应用删除规则: 过滤 {removed} 条")

    # ── 11. 过滤过短规则 ──────────────────────
    final_rules = [r for r in final_rules if len(r) > 5]

    # ── 12. 写入输出 ──────────────────────────
    total = len(final_rules) + len(compound_kept)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# Total: {total} rules\n")
        f.write(f"# Updated: {rule_dir.name}\n")
        f.write("# " + "=" * 66 + "\n")
        
        if compound_kept:
            f.write("\n# Compound Rules\n")
            for r in compound_kept:
                f.write(r + '\n')
        
        for r in final_rules:
            f.write(r + '\n')

    # ── 13. 输出统计 ──────────────────────────
    print("\n" + "=" * 70)
    print(f"✅ 处理完成: {rule_dir.name}")
    print("=" * 70)
    print(f"  输出文件        : {output_file.relative_to(Path.cwd())}")
    print(f"  总规则数        : {total}")
    print(f"    DOMAIN-KEYWORD : {len(kw_kept)}")
    print(f"    DOMAIN-SUFFIX  : {len(suffix_kept)}")
    print(f"    DOMAIN         : {len(domain_kept)}")
    print(f"    IP-CIDR        : {len(ip4_rules)}")
    print(f"    IP-CIDR6       : {len(ip6_rules)}")
    print(f"    OTHER          : {len(other_kept)}")
    print(f"    COMPOUND       : {len(compound_kept)}")
    print("=" * 70 + "\n")


# ──────────────────────────────────────────────
# 6. 命令行入口
# ──────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("用法: python rule_processor.py <规则目录1> [规则目录2] ...")
        print("示例: python rule_processor.py rule/ad rule/proxy")
        sys.exit(1)

    for rule_dir in sys.argv[1:]:
        try:
            process_rule_directory(rule_dir)
        except Exception as e:
            print(f"\n[ERROR] 处理 {rule_dir} 失败:")
            print(f"        {e}")
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    main()
