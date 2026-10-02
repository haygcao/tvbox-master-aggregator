#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 独立脚本八：策略导出器 (Task 8: 纯格式化写入，0 网络耗时，0.1 秒极速完成)
=============================================================================
功能：
  1. 纯粹读取 Task 7 校验好的 verified_direct_domains.json 与 verified_proxy_domains.json；
  2. 纯粹读取 Task 3 提取好的 extracted_ip_addresses.json 纯 IP；
  3. 执行历史增量累加 (set.union)；
  4. 0.1 秒纯内存格式化输出 Clash, PassWall 与 AdGuard 直连与代理规则。
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

INVALID_FILE_EXTENSIONS = [
    "json", "txt", "m3u8", "ts", "js", "css", "html", "htm", "png", "jpg", "jpeg", "webp", "php"
]

def to_punycode_domain(dom_str):
    if not dom_str or not isinstance(dom_str, str): return None
    try: return dom_str.encode("idna").decode("ascii")
    except Exception: return dom_str

def read_existing_historical_rules(file_path):
    existing = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith("!") and not line.startswith("payload:"):
                        clean_item = re.sub(r'^(?:@@\|\||- DOMAIN-SUFFIX,|- IP-CIDR,)\s*', '', line).rstrip("^/32").strip()
                        clean_item = clean_item.replace('\\/', '/').replace('\\', '')
                        if clean_item and clean_item not in INVALID_FILE_EXTENSIONS:
                            existing.add(clean_item)
        except Exception: pass
    return existing

def export_grouped_router_rules(work_dir, sites, grouped_cdn_domains, dynamic_image_domains=None, extracted_ips=None, release_page_domains=None, py_code_domains=None):
    print("  [Task 8: 策略导出器] 正在执行纯格式化写入 (0.1 秒极速完成)...", flush=True)

    verified_direct_path = os.path.join(work_dir, "verified_direct_domains.json")
    verified_proxy_path = os.path.join(work_dir, "verified_proxy_domains.json")

    direct_domains = set()
    proxy_domains = set()

    if os.path.exists(verified_direct_path):
        try: direct_domains.update(json.load(open(verified_direct_path)))
        except Exception: pass

    if os.path.exists(verified_proxy_path):
        try: proxy_domains.update(json.load(open(verified_proxy_path)))
        except Exception: pass

    # 读取历史规则增量累加
    hist_direct_path = os.path.join(work_dir, "domains_direct.txt")
    historical_items = read_existing_historical_rules(hist_direct_path)

    pure_ips = set(extracted_ips or [])
    for h in historical_items:
        if h.replace('.', '').isdigit(): pure_ips.add(h)
        else: direct_domains.add(h)

    def expand_punycode_list(raw_list):
        expanded = set()
        for dom in (raw_list or []):
            if dom and dom not in INVALID_FILE_EXTENSIONS:
                expanded.add(dom)
                puny = to_punycode_domain(dom)
                if puny and puny != dom: expanded.add(puny)
        return sorted(list(expanded))

    sorted_direct_doms = expand_punycode_list(direct_domains)
    sorted_proxy_doms = expand_punycode_list(proxy_domains)
    sorted_ips = sorted(list(pure_ips))

    # 1. 导出 PassWall / SmartDNS 直连列表 (domains_direct.txt)
    with open(os.path.join(work_dir, "domains_direct.txt"), "w", encoding="utf-8") as f:
        f.write("# =========================================================\n")
        f.write("# TVBox 视频源、发布页镜像、海报 CDN、中文 Punycode 与纯IP 增量直连列表\n")
        f.write("# =========================================================\n\n")
        f.write("# ===== 分组: 01_通过 4 大 DNS 校验放行的国内直连域名 =====\n")
        for d in sorted_direct_doms: f.write(f"{d}\n")
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
        f.write("! ===== 分组: 01_通过 4 大 DNS 校验放行的国内直连域名 =====\n")
        for d in sorted_direct_doms: f.write(f"@@||{d}^\n")
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
        f.write("  # ===== 分组: 01_通过 4 大 DNS 校验放行的国内直连域名 =====\n")
        for d in sorted_direct_doms: f.write(f"  - DOMAIN-SUFFIX,{d}\n")
        if sorted_ips:
            f.write("  # ===== 分组: 02_视频切片纯IPv4地址 =====\n")
            for ip in sorted_ips: f.write(f"  - IP-CIDR,{ip}/32\n")

    # 4. 导出强制代理规则列表
    with open(os.path.join(work_dir, "domains_proxy.txt"), "w", encoding="utf-8") as f:
        f.write("# TVBox 强制代理域名列表 (含国内被墙/被阻断节点)\n")
        for d in sorted_proxy_doms: f.write(f"{d}\n")

    with open(os.path.join(work_dir, "adguard_proxy.txt"), "w", encoding="utf-8") as f:
        f.write("! OpenWrt AdGuard Home 强制代理域名放行规则\n")
        for d in sorted_proxy_doms: f.write(f"@@||{d}^\n")

    with open(os.path.join(work_dir, "clash_rules_proxy.yaml"), "w", encoding="utf-8") as f:
        f.write("# TVBox 强制代理 Clash 规则集\npayload:\n")
        for d in sorted_proxy_doms: f.write(f"  - DOMAIN-SUFFIX,{d}\n")

    print(f"  ├─ 极速导出 PassWall 直连列表: domains_direct.txt ({len(sorted_direct_doms)}条域名, {len(sorted_ips)}条IP)")
    print(f"  ├─ 极速导出 AdGuard Home 放行白名单: adguard_direct.txt")
    print(f"  └─ 极速导出 Clash 规则集: clash_rules_direct.yaml")

def export_all_router_rules(work_dir, sites, deep_cdn_domains, dynamic_image_domains=None, extracted_ips=None, release_page_domains=None, py_code_domains=None):
    return export_grouped_router_rules(work_dir, sites, deep_cdn_domains, dynamic_image_domains, extracted_ips, release_page_domains, py_code_domains)

if __name__ == "__main__":
    pass
