#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re

def analyze_potential_duplicates(work_dir, sites):
    process_dir = os.path.join(work_dir, "process")
    os.makedirs(process_dir, exist_ok=True)
    log_path = os.path.join(process_dir, "potential_duplicates.log")

    print("  [重复日志分析器] 正在分析全网合并站点中的潜在高相似度节点...", flush=True)

    clusters = {}
    for s in sites:
        name = str(s.get("name", ""))
        clean_n = re.sub(r'^\[.*?\]\s*', '', name).strip()
        key = clean_n[:4].lower() if len(clean_n) >= 4 else clean_n.lower()
        if key:
            clusters.setdefault(key, []).append(s)

    dups = [item for item in clusters.values() if len(item) > 1]

    with open(log_path, "w", encoding="utf-8") as f:
        f.write("# TVBox 潜在重复节点分析日志\n\n")
        for group in dups:
            f.write(f"=== 相似组 ({len(group)} 个节点) ===\n")
            for s in group:
                f.write(f"  - 名称: {s.get('name')} | Key: {s.get('key')} | API: {s.get('api')}\n")
            f.write("\n")

    print(f"  └─ 分析完成！共挖掘出 {len(dups)} 组潜在高相似节点，已详细写入 {log_path}")
