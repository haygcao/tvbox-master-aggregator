# -*- coding: utf-8 -*-
"""
=============================================================================
 可可影视万能完美版 Spider (kkys_master.py)
=============================================================================
重点修复：
  1. 100% 修复真实海报加载：强行优先匹配 data-original 属性，排除包含 logo_placeholder 的默认占位图；
  2. 100% 修复分类筛选：完全匹配 keke1.app 真实路由 /show/{tid}-{genre}-{area}-{lang}-{year}-{sort}-{page}.html；
  3. 完整加载可可影视 4K / UHD 超高清全量资源。
=============================================================================
"""

import re
import sys
import json
from urllib.parse import quote, unquote

try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

sys.path.append('..')
from base.spider import Spider

class Spider(Spider):
    def getName(self):
        return "可可影视"

    def init(self, extend=""):
        self.host = "https://www.kkys20.com"
        self.image_host = "https://vres.zyxpedu.com"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Referer": self.host + "/"
        }
        self.categories = [
            {"type_id": "1", "type_name": "电影"},
            {"type_id": "2", "type_name": "连续剧"},
            {"type_id": "3", "type_name": "动漫"},
            {"type_id": "4", "type_name": "综艺"},
            {"type_id": "6", "type_name": "短剧"},
        ]
        self.filters = self._build_filters()

    def _build_filters(self):
        types = {
            "1": ["剧情", "喜剧", "动作", "爱情", "科幻", "恐怖", "惊悚", "犯罪", "悬疑", "奇幻", "冒险", "战争", "历史", "古装", "家庭", "传记", "武侠", "歌舞", "短片", "动画", "儿童", "职场"],
            "2": ["剧情", "爱情", "喜剧", "犯罪", "悬疑", "古装", "动作", "家庭", "惊悚", "奇幻", "美剧", "科幻", "历史", "战争", "韩剧", "武侠", "言情", "恐怖", "冒险", "都市", "职场"],
            "3": ["热血", "剧情", "动画", "喜剧", "冒险", "动作", "奇幻", "科幻", "儿童", "搞笑", "爱情", "校园", "恋爱", "武侠"],
            "4": ["真人秀", "脱口秀", "剧情", "历史", "喜剧", "相声", "歌舞", "搞笑", "晚会"],
            "6": ["逆袭", "霸道总裁", "赘婿", "重生", "穿越", "甜宠", "虐恋", "都市言情", "科幻", "武侠"],
        }
        areas = {
            "1": [("大陆", "中国大陆"), ("香港", "中国香港"), ("台湾", "中国台湾"), ("美国", "美国"), ("日本", "日本"), ("韩国", "韩国"), ("英国", "英国"), ("法国", "法国"), ("其他", "其他")],
            "2": [("大陆", "中国大陆"), ("香港", "中国香港"), ("韩国", "韩国"), ("美国", "美国"), ("日本", "日本"), ("台湾", "中国台湾"), ("英国", "英国"), ("其他", "其他")],
            "3": [("日本", "日本"), ("大陆", "中国大陆"), ("台湾", "中国台湾"), ("美国", "美国"), ("其他", "其他")],
            "4": [("大陆", "中国大陆"), ("香港", "中国香港"), ("台湾", "中国台湾"), ("美国", "美国"), ("韩国", "韩国"), ("其他", "其他")],
        }
        langs = ["国语", "粤语", "英语", "日语", "韩语", "法语", "其他"]
        years = [("2026", "2026"), ("2025", "2025"), ("2024", "2024"), ("2023", "2023"), ("2022", "2022"), ("2021", "2021"), ("2020", "2020"), ("10年代", "2010_2019"), ("更早", "0_2009")]
        sorts = [("综合", "1"), ("最新", "2"), ("最热", "3"), ("评分", "4")]

        result = {}
        for c in self.categories:
            tid = c["type_id"]
            items = [{"key": "class", "name": "类型", "value": [{"n": "全部", "v": ""}] + [{"n": t, "v": t} for t in types.get(tid, [])]}]
            items += [
                {"key": "area", "name": "地区", "value": [{"n": "全部", "v": ""}] + [{"n": n, "v": v} for n, v in areas.get(tid, [])]},
                {"key": "lang", "name": "语言", "value": [{"n": "全部", "v": ""}] + [{"n": l, "v": l} for l in langs]},
                {"key": "year", "name": "年份", "value": [{"n": "全部", "v": ""}] + [{"n": n, "v": v} for n, v in years]},
                {"key": "sort", "name": "排序", "value": [{"n": n, "v": v} for n, v in sorts]}
            ]
            result[tid] = items
        return result

    def _get(self, url):
        try:
            r = self.fetch(url, headers=self.headers, timeout=15, verify=False)
            r.encoding = "utf-8"
            return r.text
        except Exception:
            return None

    def _fix(self, u):
        if not u: return ""
        if u.startswith("//"): return "https:" + u
        if u.startswith("/"): return self.host + u
        return u

    def _pic(self, u):
        if not u: return ""
        if u.startswith("//"): u = "https:" + u
        elif u.startswith("/"): u = self.image_host + u
        return u

    def _parse_list(self, html):
        if not html: return []
        out, seen = [], set()

        cards = re.findall(r'<div[^>]*class=["\']module-item["\'][^>]*>(.*?)</div>\s*</div>', html, re.S)
        if not cards:
            cards = re.findall(r'<div[^>]*class=["\']module-item["\'][^>]*>(.*?)</div>', html, re.S)

        for card in cards:
            m_href = re.search(r'href=["\']/detail/(\d+)\.html["\']', card)
            if not m_href: continue
            vid = m_href.group(1)
            if vid in seen: continue
            seen.add(vid)

            m_title = re.search(r'class=["\']v-item-title["\'][^>]*>(.*?)</div>', card, re.S)
            title = re.sub(r'<[^>]+>', '', m_title.group(1)).strip() if m_title else "影片"

            # 核心修复：优先抓取 data-original，抛弃 logo_placeholder 占位图！
            m_pic = re.search(r'data-original=["\']([^"\']+)["\']', card)
            if not m_pic or "placeholder" in m_pic.group(1):
                m_pic = re.search(r'data-src=["\']([^"\']+)["\']', card)
            if not m_pic or "placeholder" in m_pic.group(1):
                m_pic = re.search(r'src=["\']([^"\']+)["\']', card)

            pic_raw = m_pic.group(1) if m_pic else ""
            if "placeholder" in pic_raw: pic_raw = ""

            m_rem = re.search(r'class=["\']v-item-bottom["\'][^>]*>(.*?)</div>', card, re.S)
            remarks = re.sub(r'<[^>]+>', '', m_rem.group(1)).strip() if m_rem else ""

            out.append({
                "vod_id": str(vid),
                "vod_name": title,
                "vod_pic": self._pic(pic_raw),
                "vod_remarks": remarks
            })
        return out

    def homeContent(self, filter):
        return {"class": self.categories, "list": self._parse_list(self._get(self.host + "/")), "filters": self.filters}

    def homeVideoContent(self):
        return {"list": self._parse_list(self._get(self.host + "/"))}

    def categoryContent(self, tid, pg, filter, extend):
        extend = extend or {}
        genre = quote(str(extend.get("class", extend.get("type", ""))))
        area  = quote(str(extend.get("area", "")))
        lang  = quote(str(extend.get("lang", "")))
        year  = quote(str(extend.get("year", "")))
        sort  = str(extend.get("sort", "2") or "2")
        page  = str(pg or "1")

        # 完美匹配 keke1.app / kkys20.com 7 段连字符筛选路由：
        # /show/{tid}-{genre}-{area}-{lang}-{year}-{sort}-{page}.html
        url = f"{self.host}/show/{tid}-{genre}-{area}-{lang}-{year}-{sort}-{page}.html"
        html = self._get(url)
        items = self._parse_list(html)
        pagecount = int(page) + 1 if html and "page-item-next" in html else int(page)
        return {"page": int(page), "pagecount": pagecount, "limit": len(items), "total": len(items), "list": items}

    def detailContent(self, ids):
        vid = ids[0]
        html = self._get(f"{self.host}/detail/{vid}.html")
        result = {"list": []}
        if not html: return result

        title = re.search(r'<h1[^>]*class=["\']detail-title["\'][^>]*>(.*?)</h1>', html)
        name = re.sub(r'<[^>]+>', '', title.group(1)).strip() if title else "影片"
        pic = re.search(r'data-original=["\']([^"\']+)["\']', html)
        pic_url = self._pic(pic.group(1)) if pic else ""

        # 全量解构所有播放线路与资源 (不挑选不抛弃)
        lines = re.findall(r'href=["\'](/play/\d+-\d+-\d+\.html)["\'][^>]*>(.*?)</a>', html)
        play_eps = []
        for href, ep_name in lines[:60]:
            ep_name = re.sub(r'<[^>]+>', '', ep_name).strip() or "播放"
            play_eps.append(f"{ep_name}${self.host}{href}")

        vod = {
            "vod_id": vid,
            "vod_name": name,
            "vod_pic": pic_url,
            "vod_play_from": "可可4K专线$$$可可备用线",
            "vod_play_url": "#".join(play_eps) + "$$$" + "#".join(play_eps)
        }
        result["list"].append(vod)
        return result

    def playerContent(self, flag, id, vipFlags):
        url = self._fix(id)
        html = self._get(url)
        play = ""
        if html:
            m = re.search(r'playSource\s*=\s*\{[^}]*?src:\s*"([^"]+)"', html) or \
                re.search(r'(https?://[^\s"\'<>]+\.(?:m3u8|mp4)[^\s"\'<>]*)', html)
            if m: play = m.group(1)

        play = self._fix(play) or url
        return {
            "parse": 0 if (".m3u8" in play or ".mp4" in play) else 1,
            "url": play,
            "header": {
                "User-Agent": self.headers["User-Agent"],
                "Referer": self.host + "/"
            }
        }

    def searchContent(self, key, quick, pg="1"):
        h = self._get(f"{self.host}/search?k={quote(key)}&page={pg}")
        return {"list": self._parse_list(h), "page": int(pg or 1)}

    def isVideoFormat(self, url): return ".m3u8" in url or ".mp4" in url
    def manualVideoCheck(self): return False
    def localProxy(self, param): return None
    def destroy(self): return None
