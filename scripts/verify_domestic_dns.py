#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 独立脚本七：3 大国内 DNS + Cloudflare 交叉投票 DNS 可达性校验器 (verify_domestic_dns.py)
=============================================================================
功能：
  1. 独立读取 Task 2~6 汇集的候选域名；
  2. 30 线程并发向 3 大国内 DNS (阿里 223.5.5.5 / 腾讯 119.29.29.29 / 114DNS 114.114.114.114) + Cloudflare (1.1.1.1) 发起交叉查询；
  3. 判定：Cloudflare 正常但国内 2 个以上 DNS 解析空/GWP 污染 IP ➔ 判定为【国内被墙阻断】(如 huangguoai.com)；
  4. 分别输出 verified_direct_domains.json 与 verified_proxy_domains.json。
=============================================================================
"""

import os
import re
import json
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

WORK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GLOBAL_PROXY_DOMAINS = [
    "google.com", "googlesyndication.com", "googletagmanager.com",
    "google-analytics.com", "googleapis.com", "gstatic.com", "doubleclick.net",
    "youtube.com", "ytimg.com", "ggpht.com", "github.com", "githubusercontent.com",
    "jsdelivr.net", "tmdb.org", "themoviedb.org", "t.me", "telegram.org",
    "twitter.com", "x.com", "facebook.com", "instagram.com", "huangguoai.com"
]

def is_global_proxy_domain(dom):
    if not dom or not isinstance(dom, str): return False
    dom_l = dom.lower().strip()
    return any(dom_l == pd or dom_l.endswith("." + pd) for pd in GLOBAL_PROXY_DOMAINS)

def check_dns_resolution(doh_endpoint, domain):
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

def verify_single_domain_consensus(domain):
    if is_global_proxy_domain(domain):
        return domain, False

    ali_res = check_dns_resolution("https://223.5.5.5/resolve", domain)
    dnspod_res = check_dns_resolution("https://119.29.29.29/resolve", domain)
    cf_res = check_dns_resolution("https://1.1.1.1/dns-query", domain)

    domestic_fails = sum([1 for r in [ali_res, dnspod_res] if not r])

    if cf_res and domestic_fails >= 2:
        return domain, False

    return domain, (len(ali_res) > 0 or len(dnspod_res) > 0)

def process_dns_verification():
    print("  [Task 7: DNS 独立校验器] 正在执行 3 大国内 DNS + Cloudflare 交叉投票校验...", flush=True)

    candidate_domains = set()

    for json_file in ["grouped_cdn_domains.json", "extracted_release_page_domains.json", "extracted_py_code_domains.json", "dynamic_image_domains.json"]:
        fpath = os.path.join(WORK_DIR, json_file)
        if os.path.exists(fpath):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        for k in ["top_facade_domains", "media_player_domains", "deep_stream_domains"]:
                            candidate_domains.update(data.get(k, []))
                    elif isinstance(data, list):
                        candidate_domains.update(data)
            except Exception: pass

    verified_direct = set()
    verified_proxy = set(GLOBAL_PROXY_DOMAINS)

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(verify_single_domain_consensus, dom) for dom in candidate_domains if dom]
        for f in as_completed(futures):
            dom, is_direct = f.result()
            if is_direct:
                verified_direct.add(dom)
            else:
                verified_proxy.add(dom)

    open(os.path.join(WORK_DIR, "verified_direct_domains.json"), "w", encoding="utf-8").write(json.dumps(sorted(list(verified_direct)), ensure_ascii=False, indent=2))
    open(os.path.join(WORK_DIR, "verified_proxy_domains.json"), "w", encoding="utf-8").write(json.dumps(sorted(list(verified_proxy)), ensure_ascii=False, indent=2))

    print(f"  └─ DNS 独立校验完成！通过校验直连: {len(verified_direct)}个, 判定被墙代理: {len(verified_proxy)}个", flush=True)

if __name__ == "__main__":
    process_dns_verification()
