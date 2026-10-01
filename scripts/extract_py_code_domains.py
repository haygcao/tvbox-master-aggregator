#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 独立脚本九：.py 爬虫源码内部域名静态提取器 (Extract PY Code Domains)
=============================================================================
功能：
  1. 专门读取 repos/ 磁盘目录下所有克隆仓库中的 .py 爬虫源码文本；
  2. 正则 0.001 秒提取源码内部硬编码的所有 http:// 与 https:// 域名；
  3. 支持 cyscyy.com, fengbao12.com, zyxpedu.com, kuhh4jo.com 等海报与切片域名提取；
  4. 支持中文域名 Punycode IDNA 编码转换；
  5. 输出 extracted_py_code_domains.json 供规则导出器注入直连放行白名单。
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

def to_punycode_domain(dom_str):
    if not dom_str or not isinstance(dom_str, str): return None
    try: return dom_str.encode("idna").decode("ascii")
    except Exception: return dom_str

def extract_root_domain(raw_str):
    if not raw_str or not isinstance(raw_str, str): return None
    clean_str = str(raw_str).replace('\\/', '/').replace('\\', '').split("|")[0].split("$")[0].strip()
    if clean_str.startswith("//"): clean_str = "https:" + clean_str

    if TLD_EXTRACTOR:
        ext = TLD_EXTRACTOR(clean_str)
        if ext.domain and ext.suffix:
            root = f"{ext.domain}.{ext.suffix}".lower().strip()
            if root and "github" not in root and "jsdelivr" not in root:
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
        return root if "github" not in root and "jsdelivr" not in root else None

def extract_all_py_code_domains():
    """专门从 repos/ 磁盘目录下所有 .py 源码中提取硬编码的真实主域名与图片 CDN 域名"""
    print("  [.py 源码域名提取器] 正在全量扫描 repos/ 下所有 .py 源码中的硬编码域名...", flush=True)
    extracted_domains = set()

    repos_dir = os.path.join(WORK_DIR, "repos")
    if os.path.exists(repos_dir):
        for root, _, files in os.walk(repos_dir):
            for fname in files:
                if fname.endswith(".py"):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            code_text = f.read()
                            code_urls = re.findall(r'(https?://[^\s"\'<>#\$\[\]\(\)]+)', code_text)
                            for u in code_urls:
                                r_dom = extract_root_domain(u)
                                if r_dom:
                                    extracted_domains.add(r_dom)
                                    puny = to_punycode_domain(r_dom)
                                    if puny: extracted_domains.add(puny)
                    except Exception: pass

    sorted_doms = sorted(list(extracted_domains))
    print(f"  └─ .py 源码域名提取完成！共捕获到 {len(sorted_doms)} 个内部硬编码的直连主域名与图源！", flush=True)
    return sorted_doms

if __name__ == "__main__":
    pass
