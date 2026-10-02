#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 独立脚本：基于 3 大国内 DNS + Cloudflare 交叉对比投票的全量路由器规则导出器
=============================================================================
重点更新：
  1. 引入 3 大国内 DNS (阿里 223.5.5.5 / 腾讯 119.29.29.29 / 114DNS 114.114.114.114) + Cloudflare (1.1.1.1) 交叉对比投票；
  2. 当 Cloudflare 正常但国内 2 个以上 DNS 返回空或 GFW 污染 IP 时，自动判定为【国内被墙阻断】(如 huangguoai.com)；
  3. 自动将国内被墙域名从直连剔除，并移入 domains_proxy.txt 与 clash_rules_proxy.yaml 强行代理名单；
  4. 绝不输出单/双/反斜杠脏数据与 .json 纯文件后缀；
  5. 增量累加合并，生成 Clash, PassWall 与 AdGuard 白名单。
=============================================================================
"""

import os
import re
import json
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import tldextract
    TLD_EXTRACTOR = tldextract.TLDExtract(include_psl_private_domains=False)
except ImportError:
    TLD_EXTRACTOR = None

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

GLOBAL_PROXY_DOMAINS = [
    "google.com", "googlesyndication.com", "googletagmanager.com",
    "google-analytics.com", "googleapis.com", "gstatic.com", "doubleclick.net",
    "youtube.com", "ytimg.com", "ggpht.com", "github.com", "githubusercontent.com",
    "jsdelivr.net", "tmdb.org", "themoviedb.org", "t.me", "telegram.org",
    "twitter.com", "x.com", "facebook.com", "instagram.com", "huangguoai.com"
]

INVALID_FILE_EXTENSIONS = [
    "json", "txt", "m3u8", "ts", "js", "css", "html", "htm", "png", "jpg", "jpeg", "webp", "php"
]

def to_punycode_domain(dom_str):
    if not dom_str or not isinstance(dom_str, str): return None
    try: return dom_str.encode("idna").decode("ascii")
    except Exception: return dom_str

def extract_root_domain(raw_str):
    if not raw_str or not isinstance(raw_str, str): return None
    clean_str = str(raw_str).replace('\\/', '/').replace('\\', '').split("|")[0].split("$")[0].strip()
    if clean_str.startswith("//"): clean_str = "https:" + clean_str

    if clean_str.lower() in INVALID_FILE_EXTENSIONS:
        return None

    if TLD_EXTRACTOR:
        ext = TLD_EXTRACTOR(clean_str)
        if ext.domain and ext.suffix:
            root = f"{ext.domain}.{ext.suffix}".lower().strip()
            if root and root not in INVALID_FILE_EXTENSIONS:
                return root
        return None
    else:
        url_match = re.search(r'https?://([^\s"\'/<>#\$:]+)', clean_str)
        host = url_match.group(1).split(":")[0] if url_match else clean_str.split("/")[0].split(":")[0].strip()
        host = host.strip("@|*^ \t\r\n").lower()
        if not host or host.replace('.', '').isdigit() or "." not in host or host.startswith("."):
            return None
        parts = host.split(".")
        if len(parts) >= 3:
            if parts[-2] in ["com", "net", "org", "gov", "edu", "co"] and parts[-1] in ["cn", "uk", "jp", "kr", "hk", "tw", "au", "nz", "sg"]:
                root = ".".join(parts[-3:])
            else:
                root = ".".join(parts[-2:])
        else:
            root = host
        return root if root not in INVALID_FILE_EXTENSIONS else None

def is_global_proxy_domain(dom):
    if not dom or not isinstance(dom, str): return False
    dom_l = dom.lower().strip()
    return any(dom_l == pd or dom_l.endswith("." + pd) for pd in GLOBAL_PROXY_DOMAINS)

def check_dns_resolution(doh_endpoint, domain):
    """向指定 DoH HTTP-DNS 查询域名的 IP 解析记录"""
    try:
        url = f"{doh_endpoint}?name={domain}&type=A"
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, timeout=2.0, context=SSL_CTX) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            answers = data.get("Answer", [])
            valid_ips = []
            for ans in answers:
                ip = str(ans.get("data", "")).strip()
                if ip and ip not in ["0.0.0.0", "127.0.0.1", "127.0.0.2", "0.0.0.1"]:
                    valid_ips.append(ip)
            return valid_ips
    except Exception:
        return []

def verify_domestic_dns_consensus(domain):
    """3 大国内 DNS (阿里/腾讯/114) + 1 海外 Cloudflare 对照交叉投票机制"""
    if is_global_proxy_domain(domain):
        return False

    # 1. 阿里 DNS (223.5.5.5)
    ali_ips = check_dns_resolution("https://223.5.5.5/resolve", domain)
    # 2. 腾讯 DNSPod (119.29.29.29)
    dnspod_ips = check_dns_resolution("https://119.29.29.29/resolve", domain)
    # 3. Cloudflare DNS (1.1.1.1 对照组)
    cf_ips = check_dns_resolution("https://1.1.1.1/dns-query", domain)

    domestic_fails = 0
    if not ali_ips: domestic_fails += 1
    if not dnspod_ips: domestic_fails += 1

    # 判定：如果 Cloudflare 海外正常，但国内 2 个 DNS 均无法解析/被阻断 ➔ 判定为【国内被墙】！
    if cf_ips and domestic_fails >= 2:
        return False

    # 国内能解析出合法 IP ➔ 判定为【国内可直连】
    return (len(ali_ips) > 0 or len(dnspod_ips) > 0)

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
                        if clean_item and clean_item not in INVALID_FILE_EXTENSIONS and not is_global_proxy_domain(clean_item):
                            existing.add(clean_item)
        except Exception: pass
    return existing

def export_grouped_router_rules(work_dir, sites, grouped_cdn_domains, dynamic_image_domains=None, extracted_ips=None, release_page_domains=None, py_code_domains=None):
    print("  [策略导出器] 正在执行 3 大国内 DNS + Cloudflare 交叉验证与规则导出...", flush=True)

    PROXY_KEYWORDS = ["(墙)", "墙外", "代理", "翻墙", "科学", "科学上网"]

    candidate_direct_domains = set(release_page_domains or [])
    if py_code_domains: candidate_direct_domains.update(py_code_domains)

    proxy_domains = set(GLOBAL_PROXY_DOMAINS)

    for s in sites:
        name = str(s.get("name", ""))
        key = str(s.get("key", ""))
        is_proxy_site = any(kw in name or kw in key for kw in PROXY_KEYWORDS)

        extracted_urls = []
        for prop in ["api", "ext", "jar", "pic"]:
            val = s.get(prop)
            if isinstance(val, str): extracted_urls.append(val)
            elif isinstance(val, dict): extracted_urls.extend([str(v) for v in val.values() if isinstance(v, str)])

        for u_str in extracted_urls:
            r_dom = extract_root_domain(u_str)
            if r_dom:
                if is_proxy_site or is_global_proxy_domain(r_dom):
                    proxy_domains.add(r_dom)
                else:
                    candidate_direct_domains.add(r_dom)

    def expand_punycode(dom):
        res = {dom}
        puny = to_punycode_domain(dom)
        if puny and puny != dom: res.add(puny)
        return res

    # 针对直连候选域名，执行 4 大 DNS 节点交叉投票，把国内不可达的域名移入 proxy_domains！
    api_direct_domains = set()
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_dom = {executor.submit(verify_domestic_consensus, dom): dom for dom in candidate_direct_domains if not is_global_proxy_domain(dom)}
        for f in as_completed(future_to_dom):
            dom = future_to_dom[f]
            if f.result():
                api_direct_domains.update(expand_punycode(dom))
            else:
                proxy_domains.update(expand_punycode(dom))

    def filter_and_expand(raw_list):
        expanded = set()
        for dom in (raw_list or []):
            if dom:
                dom_clean = str(dom).replace('\\/', '/').replace('\\', '').strip()
                if is_global_proxy_domain(dom_clean) or dom_clean.lower() in INVALID_FILE_EXTENSIONS:
                    proxy_domains.add(dom_clean)
                    continue
                expanded.update(expand_punycode(dom_clean))
        return expanded

    top_cdn = filter_and_expand(grouped_cdn_domains.get("top_facade_domains", set()) if isinstance(grouped_cdn_domains, dict) else set())
    l2_play = filter_and_expand(grouped_cdn_domains.get("media_player_domains", set()) if isinstance(grouped_cdn_domains, dict) else set())
    l3_ts = filter_and_expand(grouped_cdn_domains.get("deep_stream_domains", set()) if isinstance(grouped_cdn_domains, dict) else set())
    api_doms = filter_and_expand(api_direct_domains)
    img_doms = filter_and_expand(set(dynamic_image_domains or []))
    pure_ips = set(extracted_ips or [])

    hist_direct_path = os.path.join(work_dir, "domains_direct.txt")
    historical_items = read_existing_historical_rules(hist_direct_path)

    l3_ts.update([h for h in historical_items if not h.replace('.', '').isdigit() and not is_global_proxy_domain(h)])
    pure_ips.update([h for h in historical_items if h.replace('.', '').isdigit()])

    groups = [
        ("01_门面节点_OK资源_播放CDN域名", sorted(list(top_cdn))),
        ("02_控制面_API服务_发布页与PY源码域名", sorted(list(api_doms))),
        ("03_二级_播放页与M3U8域名", sorted(list(l2_play))),
        ("04_三级_深层TS视频切片边缘CDN与历史增量域名", sorted(list(l3_ts))),
        ("05_海报图片_CDN放行域名", sorted(list(img_doms)))
    ]

    sorted_ips = sorted(list(pure_ips))

    # 1. 导出 PassWall / SmartDNS 直连列表 (domains_direct.txt)
    with open(os.path.join(work_dir, "domains_direct.txt"), "w", encoding="utf-8") as f:
        f.write("# =========================================================\n")
        f.write("# TVBox 视频源、发布页镜像、海报 CDN、中文 Punycode 与纯IP 增量直连列表\n")
        f.write("# =========================================================\n\n")
        for g_title, dom_list in groups:
            if dom_list:
                f.write(f"# ===== 分组: {g_title} =====\n")
                for d in dom_list: f.write(f"{d}\n")
                f.write("\n")
        if sorted_ips:
            f.write("# ===== 分组: 06_视频切片纯IPv4地址 =====\n")
            for ip in sorted_ips: f.write(f"{ip}\n")
            f.write("\n")

    # 2. 导出 AdGuard Home 放行白名单 (adguard_direct.txt)
    with open(os.path.join(work_dir, "adguard_direct.txt"), "w", encoding="utf-8") as f:
        f.write("! =========================================================\n")
        f.write("! OpenWrt AdGuard Home TVBox 视频源、发布页镜像、中文 Punycode 与纯IP 放行白名单\n")
        f.write("! =========================================================\n\n")
        for g_title, dom_list in groups:
            if dom_list:
                f.write(f"! ===== 分组: {g_title} =====\n")
                for d in dom_list: f.write(f"@@||{d}^\n")
                f.write("\n")
        if sorted_ips:
            f.write("! ===== 分组: 06_视频切片纯IPv4地址 =====\n")
            for ip in sorted_ips: f.write(f"@@||{ip}^\n")
            f.write("\n")

    # 3. 导出 Clash 规则集 (clash_rules_direct.yaml)
    with open(os.path.join(work_dir, "clash_rules_direct.yaml"), "w", encoding="utf-8") as f:
        f.write("# =========================================================\n")
        f.write("# TVBox 视频源、发布页镜像、中文 Punycode 域名与纯 IP Clash 增量直连规则集\n")
        f.write("# =========================================================\n")
        f.write("payload:\n")
        for g_title, dom_list in groups:
            if dom_list:
                f.write(f"  # ===== 分组: {g_title} =====\n")
                for d in dom_list:
                    f.write(f"  - DOMAIN-SUFFIX,{d}\n")
        if sorted_ips:
            f.write("  # ===== 分组: 06_视频切片纯IPv4地址 =====\n")
            for ip in sorted_ips:
                f.write(f"  - IP-CIDR,{ip}/32\n")

    # 4. 导出强制代理规则列表
    sorted_proxy = sorted(list(filter_and_expand(proxy_domains)))
    with open(os.path.join(work_dir, "domains_proxy.txt"), "w", encoding="utf-8") as f:
        f.write("# TVBox 强制代理域名列表\n")
        for d in sorted_proxy: f.write(f"{d}\n")

    with open(os.path.join(work_dir, "adguard_proxy.txt"), "w", encoding="utf-8") as f:
        f.write("! OpenWrt AdGuard Home 强制代理域名放行规则\n")
        for d in sorted_proxy: f.write(f"@@||{d}^\n")

    with open(os.path.join(work_dir, "clash_rules_proxy.yaml"), "w", encoding="utf-8") as f:
        f.write("# TVBox 强制代理 Clash 规则集\npayload:\n")
        for d in sorted_proxy: f.write(f"  - DOMAIN-SUFFIX,{d}\n")

    print(f"  ├─ 增量导出 PassWall 直连列表 (含多 DNS 投票判定): domains_direct.txt")
    print(f"  ├─ 增量导出 AdGuard Home 放行白名单: adguard_direct.txt")
    print(f"  └─ 增量导出 Clash 规则集 (支持 DOMAIN-SUFFIX, Punycode 与 IP-CIDR): clash_rules_direct.yaml")

def export_all_router_rules(work_dir, sites, deep_cdn_domains, dynamic_image_domains=None, extracted_ips=None, release_page_domains=None, py_code_domains=None):
    return export_grouped_router_rules(work_dir, sites, deep_cdn_domains, dynamic_image_domains, extracted_ips, release_page_domains, py_code_domains)

if __name__ == "__main__":
    pass
