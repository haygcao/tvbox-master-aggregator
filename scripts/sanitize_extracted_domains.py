#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 独立脚本：全量域名与数据强力净化清洗器 (sanitize_extracted_domains.py)
=============================================================================
重点清洗：
  1. 100% 强行擦除所有反斜杠 \\ (把 kissjav\\.li 强行净化为 kissjav.li, 把 djj88\\.sbs 净化为 djj88.sbs)；
  2. 100% 强行剔除纯文件后缀 (如 .json, .txt, .m3u8, .ts, .php, .js, .css)；
  3. 100% 强行剔除开头的点 .、引号、空格或格式损坏的字符串；
  4. 100% 强行隔离 t.me, google.com, github.com 等强制代理域名；
  5. 输出 sanitized_candidate_domains.json 供后续流程无瑕调用。
=============================================================================
"""

import os
import re
import json

WORK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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

def is_global_proxy_domain(dom):
    if not dom or not isinstance(dom, str): return False
    dom_l = dom.lower().strip()
    return any(dom_l == pd or dom_l.endswith("." + pd) for pd in GLOBAL_PROXY_DOMAINS)

def sanitize_domain_string(raw_dom):
    if not raw_dom or not isinstance(raw_dom, str):
        return None, False

    # 1. 强行擦除反斜杠 \\、单斜杠转义 \\/ 与空字符
    clean = str(raw_dom).replace('\\/', '/').replace('\\', '').split("|")[0].split("$")[0].strip()
    if clean.startswith("//"): clean = clean[2:]
    clean = clean.strip("@|*^ \t\r\n'\"").lower()

    # 2. 剔除开头的点与纯文件后缀
    if not clean or clean.startswith(".") or "." not in clean:
        return None, False

    if clean in INVALID_FILE_EXTENSIONS:
        return None, False

    # 提取真正的主域名部分
    parts = clean.split("/")[0].split(":")[0].strip()
    if parts.startswith("."): parts = parts[1:]

    if not parts or parts.replace('.', '').isdigit() or "." not in parts or parts in INVALID_FILE_EXTENSIONS:
        return None, False

    # 判定是否属于代理域名
    if is_global_proxy_domain(parts):
        return parts, True  # 属于代理

    return parts, False  # 属于直连候选

def process_data_sanitization():
    print("  [数据强力清洗器] 正在对 Task 2~6 汇集的所有原始域名执行 4 重强力净化...", flush=True)

    raw_candidates = set()

    for json_file in ["grouped_cdn_domains.json", "extracted_release_page_domains.json", "extracted_py_code_domains.json", "dynamic_image_domains.json"]:
        fpath = os.path.join(WORK_DIR, json_file)
        if os.path.exists(fpath):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        for k in ["top_facade_domains", "media_player_domains", "deep_stream_domains"]:
                            raw_candidates.update(data.get(k, []))
                    elif isinstance(data, list):
                        raw_candidates.update(data)
            except Exception: pass

    sanitized_direct_candidates = set()
    sanitized_proxy_candidates = set(GLOBAL_PROXY_DOMAINS)

    for raw_d in raw_candidates:
        clean_d, is_proxy = sanitize_domain_string(raw_d)
        if clean_d:
            if is_proxy:
                sanitized_proxy_candidates.add(clean_d)
            else:
                sanitized_direct_candidates.add(clean_d)
                puny = to_punycode_domain(clean_d)
                if puny: sanitized_direct_candidates.add(puny)

    sorted_direct = sorted(list(sanitized_direct_candidates))
    sorted_proxy = sorted(list(sanitized_proxy_candidates))

    open(os.path.join(WORK_DIR, "sanitized_candidate_domains.json"), "w", encoding="utf-8").write(json.dumps(sorted_direct, ensure_ascii=False, indent=2))
    open(os.path.join(WORK_DIR, "sanitized_proxy_domains.json"), "w", encoding="utf-8").write(json.dumps(sorted_proxy, ensure_ascii=False, indent=2))

    print(f"  └─ 强力清洗完成！净化出直连候选域名: {len(sorted_direct)}个, 隔离代理域名: {len(sorted_proxy)}个", flush=True)

if __name__ == "__main__":
    process_data_sanitization()
