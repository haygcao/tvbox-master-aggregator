#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 独立脚本：策略导出器 (过程文件隔离读取 process/ 目录，根目录仅展示最终结果文件)
=============================================================================
重点更新：
  1. 过程文件统一隔离读取 process/ 目录，根目录仅输出 PassWall / AdGuard / Clash 最终规则文件；
  2. 彻底切掉 #, ?, &, %, &amp;, ; 等 URL 参数与锚点杂质 (绝对不留存 nxog.top?mm=328 或 qzz.io?format=2)；
  3. 彻底绝杀只有后缀没有前缀的垃圾域名 (如 .com) 以及包含 .mp4#, com#.mp4 的无面脏字符串；
  4. 0.1 秒纯内存格式化输出最终规则集。
=============================================================================
"""

import os
import re
import json

try:
    import tldextract
    TLD_EXTRACTOR = tldextract.TLDExtract(include_psl_private_domains=False)
except ImportError:
    TLD_EXTRACTOR = None

WORK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESS_DIR = os.path.join(WORK_DIR, "process")

INVALID_FILE_EXTENSIONS = [
    "json", "txt", "m3u8", "ts", "js", "css", "html", "htm", "png", "jpg", "jpeg", "webp", "php", "mp4", "mkv", "flv"
]

def to_punycode_domain(dom_str):
    if not dom_str or not isinstance(dom_str, str): return None
    try: return dom_str.encode("idna").decode("ascii")
    except Exception: return dom_str

def final_clean_before_write(dom):
    """写盘前最后一关：100% 剥离 #, ?, &, %, &amp;, 协议头与无面脏数据"""
    if not dom or not isinstance(dom, str): return None

    # 1. 彻底切掉 #, ?, &, %, &amp;, ; 等 URL 参数与锚点杂质
    clean = str(dom).replace('&amp;', '&').replace('\\/', '/').replace('\\', '').strip()
    clean = clean.split('#')[0].split('?')[0].split('&')[0].split(';')[0].split('%')[0].split('|')[0].split('$')[0].strip()

    # 2. 擦除协议头与双斜杠
    clean = re.sub(r'^https?://', '', clean, flags=re.I)
    clean = re.sub(r'^//', '', clean)

    # 3. 擦除所有残存的单斜杠 /、双斜杠 // 与反斜杠 \
    clean = clean.replace('/', '').replace('\\', '').strip()

    # 4. 剥离端口号与特殊符号
    clean = clean.split(":")[0].strip("@|*^ \t\r\n'\"").lower()

    # 5. 滤掉纯文件后缀、无前缀纯后缀 (如 .com) 与垃圾杂质
    if not clean or clean.startswith(".") or "." not in clean:
        return None

    parts = clean.split(".")
    if len(parts) < 2 or not parts[0] or not parts[-1]:
        return None

    tld = parts[-1].lower()
    prefix = parts[0].lower()

    if tld in INVALID_FILE_EXTENSIONS or prefix in INVALID_FILE_EXTENSIONS:
        return None

    return clean

def read_existing_historical_rules(file_path):
    existing = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("!") and not line.startswith("payload:"):
                        clean_item = re.sub(r'^(?:@@\|\||- DOMAIN-SUFFIX,|- IP-CIDR,)\s*', '', line).rstrip("^/32").strip()
                        final_item = final_clean_before_write(clean_item)
                        if final_item: existing.add(final_item)
        except Exception: pass
    return existing

def export_grouped_router_rules(work_dir, sites, grouped_cdn_domains, dynamic_image_domains=None, extracted_ips=None, release_page_domains=None, py_code_domains=None):
    print("  [Task 9: 策略导出器] 正在从 process/ 读取数据并执行写盘前最后一关 100% 擦除导出...", flush=True)

    sanitized_direct_path = os.path.join(PROCESS_DIR, "sanitized_candidate_domains.json")
    sanitized_proxy_path = os.path.join(PROCESS_DIR, "sanitized_proxy_domains.json")
    verified_direct_path = os.path.join(PROCESS_DIR, "verified_direct_domains.json")
    verified_proxy_path = os.path.join(PROCESS_DIR, "verified_proxy_domains.json")

    direct_domains = set()
    proxy_domains = set()

    for p in [sanitized_direct_path, verified_direct_path]:
        if os.path.exists(p):
            try: direct_domains.update(json.load(open(p)))
            except Exception: pass

    for p in [sanitized_proxy_path, verified_proxy_path]:
        if os.path.exists(p):
            try: proxy_domains.update(json.load(open(p)))
            except Exception: pass

    # 读取历史规则增量累加
    hist_direct_path = os.path.join(work_dir, "domains_direct.txt")
    historical_items = read_existing_historical_rules(hist_direct_path)

    # 读取 process/extracted_ip_addresses.json
    process_ip_path = os.path.join(PROCESS_DIR, "extracted_ip_addresses.json")
    if os.path.exists(process_ip_path):
        try:
            ips = json.load(open(process_ip_path))
            if isinstance(ips, list): extracted_ips = (extracted_ips or []) + ips
        except Exception: pass

    pure_ips = set(extracted_ips or [])
    for h in historical_items:
        if h.replace('.', '').isdigit(): pure_ips.add(h)
        else:
            final_h = final_clean_before_write(h)
            if final_h: direct_domains.add(final_h)

    def expand_and_final_clean(raw_list):
        expanded = set()
        for dom in (raw_list or []):
            final_dom = final_clean_before_write(dom)
            if final_dom:
                expanded.add(final_dom)
                puny = to_punycode_domain(final_dom)
                if puny:
                    final_puny = final_clean_before_write(puny)
                    if final_puny: expanded.add(final_puny)
        return sorted(list(expanded))

    sorted_direct_doms = expand_and_final_clean(direct_domains)
    sorted_proxy_doms = expand_and_final_clean(proxy_domains)
    sorted_ips = sorted(list(pure_ips))

    # 1. 导出 PassWall / SmartDNS 直连列表 (domains_direct.txt)
    with open(os.path.join(work_dir, "domains_direct.txt"), "w", encoding="utf-8") as f:
        f.write("# =========================================================\n")
        f.write("# TVBox 视频源、发布页镜像、海报 CDN、中文 Punycode 与纯IP 增量直连列表\n")
        f.write("# =========================================================\n\n")
        f.write("# ===== 分组: 01_通过 4 大 DNS 校验与 Task 8 强力清洗放行的国内直连域名 =====\n")
        for d in sorted_direct_doms:
            final_d = final_clean_before_write(d)
            if final_d: f.write(f"{final_d}\n")
        f.write("\n")
        if sorted_ips:
            f.write("# ===== 分组: 02_视频切片纯IPv4地址 =====\n")
            for ip in sorted_ips: f.write(f"{ip}\n")
            f.write("\n")

    # 2. 导出 AdGuard Home 放行白名单 (adguard_direct.txt)
    with open(os.path.join(work_dir, "adguard_direct.txt"), "w", encoding="utf-8") as f:
        f.write("! =========================================================\n")
        f.write("! OpenWrt AdGuard Home TVBox 视频源、发布页镜像、中文 Punycode 与纯IP 放行白名单\n")
        f.write("! =========================================================\n\n")
        f.write("! ===== 分组: 01_通过 4 大 DNS 校验与 Task 8 强力清洗放行的国内直连域名 =====\n")
        for d in sorted_direct_doms:
            final_d = final_clean_before_write(d)
            if final_d: f.write(f"@@||{final_d}^\n")
        f.write("\n")
        if sorted_ips:
            f.write("! ===== 分组: 02_视频切片纯IPv4地址 =====\n")
            for ip in sorted_ips: f.write(f"@@||{ip}^\n")
            f.write("\n")

    # 3. 导出 Clash 规则集 (clash_rules_direct.yaml)
    with open(os.path.join(work_dir, "clash_rules_direct.yaml"), "w", encoding="utf-8") as f:
        f.write("# =========================================================\n")
        f.write("# TVBox 视频源、发布页镜像、中文 Punycode 域名与纯 IP Clash 增量直连规则集\n")
        f.write("# =========================================================\n")
        f.write("payload:\n")
        f.write("  # ===== 分组: 01_通过 4 大 DNS 校验与 Task 8 强力清洗放行的国内直连域名 =====\n")
        for d in sorted_direct_doms:
            final_d = final_clean_before_write(d)
            if final_d: f.write(f"  - DOMAIN-SUFFIX,{final_d}\n")
        if sorted_ips:
            f.write("  # ===== 分组: 02_视频切片纯IPv4地址 =====\n")
            for ip in sorted_ips: f.write(f"  - IP-CIDR,{ip}/32\n")

    # 4. 导出强制代理规则列表
    with open(os.path.join(work_dir, "domains_proxy.txt"), "w", encoding="utf-8") as f:
        f.write("# TVBox 强制代理域名列表 (含国内被墙/被阻断节点)\n")
        for d in sorted_proxy_doms:
            final_d = final_clean_before_write(d)
            if final_d: f.write(f"{final_d}\n")

    with open(os.path.join(work_dir, "adguard_proxy.txt"), "w", encoding="utf-8") as f:
        f.write("! OpenWrt AdGuard Home 强制代理域名放行规则\n")
        for d in sorted_proxy_doms:
            final_d = final_clean_before_write(d)
            if final_d: f.write(f"@@||{final_d}^\n")

    with open(os.path.join(work_dir, "clash_rules_proxy.yaml"), "w", encoding="utf-8") as f:
        f.write("# TVBox 强制代理 Clash 规则集\npayload:\n")
        for d in sorted_proxy_doms:
            final_d = final_clean_before_write(d)
            if final_d: f.write(f"  - DOMAIN-SUFFIX,{final_d}\n")

    print(f"  ├─ 终极极速导出 PassWall 直连列表: domains_direct.txt ({len(sorted_direct_doms)}条纯净域名, {len(sorted_ips)}条IP)")
    print(f"  ├─ 终极极速导出 AdGuard Home 放行白名单: adguard_direct.txt")
    print(f"  └─ 终极极速导出 Clash 规则集: clash_rules_direct.yaml (过程文件隔离存放于 process/)")

def export_all_router_rules(work_dir, sites, deep_cdn_domains, dynamic_image_domains=None, extracted_ips=None, release_page_domains=None, py_code_domains=None):
    return export_grouped_router_rules(work_dir, sites, deep_cdn_domains, dynamic_image_domains, extracted_ips, release_page_domains, py_code_domains)

if __name__ == "__main__":
    pass
