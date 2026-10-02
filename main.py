#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 TVBox 主任务入口管道 (Pipeline Orchestrator)
=============================================================================
按顺序串联 10 个独立的单职责 Python 任务脚本：
  01. scripts/merge_sources.py                     : 资源抓取与合并
  02. scripts/analyze_potential_duplicates.py       : 潜在重复资源日志分析
  03. scripts/resolve_deep_cdn.py                   : 多层级 Stage 5 物理播放域名探测 (专干域名)
  04. scripts/extract_ip_addresses.py              : 纯 IPv4 提取与 DNS 实时解析 (专干 IP)
  05. scripts/extract_image_domains.py            : 动态海报图片 CDN 域名扒取 (专干图片)
  06. scripts/extract_release_page_domains.py       : 通用发布页镜像与 Punycode 动态扒取 (专干发布页)
  07. scripts/extract_py_code_domains.py            : .py 爬虫源码内部域名静态提取 (专干 PY 源码)
  08. scripts/verify_domestic_dns.py               : 3 大国内 DNS + Cloudflare 交叉投票校验 (专干 DNS 校验)
  09. scripts/export_router_rules.py                : 路由器与 AdGuard 放行规则导出 (专干 0.1s 纯格式化导出)
  10. scripts/merge_iptv_split_18.py                : 美英学英语 IPTV 整合与 not_suitable/ 隔离
=============================================================================
"""

import sys
import os
import time

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))

from scripts import merge_sources as step1
from scripts import analyze_potential_duplicates as step2
from scripts import resolve_deep_cdn as step3
from scripts import extract_ip_addresses as step4
from scripts import extract_image_domains as step5
from scripts import extract_release_page_domains as step6
from scripts import extract_py_code_domains as step7
from scripts import verify_domestic_dns as step8
from scripts import export_router_rules as step9
from scripts import merge_iptv_split_18 as step10

def main():
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{ts}] ===== 开始 TVBox 模块化管道全量更新 =====")

    # 1. 运行独立任务一：合并资源
    sites = step1.merge_sources()

    # 2. 运行独立任务二：日志分析潜在重复
    work_dir = os.path.dirname(os.path.abspath(__file__))
    step2.analyze_potential_duplicates(work_dir, sites)

    # 3. 运行独立任务三：多层级深解析播放域名 (专干域名)
    grouped_cdn_domains = step3.resolve_deep_media_domains(sites, max_sites=len(sites))

    # 4. 运行独立任务四：纯 IPv4 提取与 DNS 实时反向解析 (专干 IP)
    extracted_ips = step4.extract_ip_addresses_and_dns(sites, grouped_cdn_domains)

    # 5. 运行独立任务五：动态海报图片 CDN 扒取 (专干图片)
    dynamic_image_domains = step5.extract_all_poster_image_domains(sites, max_sites=len(sites))

    # 6. 运行独立任务六：通用发布页与最新镜像动态扒取 (专干发布页)
    release_page_domains = step6.extract_all_release_page_domains()

    # 7. 运行独立任务七：.py 爬虫源码内部域名静态提取 (专干 PY 源码)
    py_code_domains = step7.extract_all_py_code_domains()

    # 8. 运行独立任务八：3 大国内 DNS + Cloudflare 交叉投票校验 (专干 DNS 校验)
    step8.process_dns_verification()

    # 9. 运行独立任务九：策略导出 (AdGuard / PassWall / Clash)
    step9.export_all_router_rules(work_dir, sites, grouped_cdn_domains, dynamic_image_domains, extracted_ips, release_page_domains, py_code_domains)

    # 10. 运行独立任务十：美英学英语 IPTV 整合与 not_suitable/ 隔离导出
    step10.process_iptv_and_split_18()

    print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] ===== TVBox 模块化管道更新全部成功完成! =====")

if __name__ == "__main__":
    main()
