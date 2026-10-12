#!/usr/bin/env python3
"""
asset_organizer.py —— 资产与攻击面整理

用途：把 recon/enum 阶段的原始输出整理成结构化清单：
      - 子域去重、归一化
      - 从 HAR / JS 中提取端点与参数
      - 从 Swagger 提取接口清单
      - 按价值分档

依赖：标准库。HAR 与 JS 解析均用内置实现。

子命令：
  subs          整理子域列表（去重、归一化、提取根域）
  extract-endpoints   从 HAR / JS 目录提取端点
  extract-params      从 HAR / JS 目录提取参数
  swagger       从 Swagger/OpenAPI JSON 提取接口清单
  split         端点按价值分档

示例：
  python3 asset_organizer.py subs --input raw.txt --output subs.txt
  python3 asset_organizer.py extract-endpoints --input traffic.har --output ep.txt
  python3 asset_organizer.py extract-endpoints --js-dir enum/js --output ep-js.txt
  python3 asset_organizer.py swagger --input swagger.json --output api.md
"""

import argparse
import json
import os
import re
import sys
from collections import OrderedDict
from urllib.parse import urlparse


# ---------------------------------------------------------------- 工具

DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"""https?://[^\s'"<>)\\]+""", re.I)

SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2",
    ".ttf", ".eot", ".css", ".mp4", ".mp3", ".pdf", ".zip",
)

# 端点的价值分档关键词
S_TIER_HINTS = ("order", "pay", "refund", "transfer", "withdraw", "coupon", "balance",
                "admin", "role", "permission", "auth", "token", "user", "account", "member")
A_TIER_HINTS = ("upload", "download", "file", "export", "import", "url", "redirect",
                "callback", "webhook", "proxy", "fetch", "preview")


def die(msg, code=2):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(code)


def read_text(path):
    if not os.path.exists(path):
        die(f"文件不存在: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def norm_host(token):
    token = token.strip().lower()
    token = re.sub(r"^\*\.", "", token)
    token = token.rstrip(".")
    return token


def is_noise(host):
    if not host or "." not in host:
        return True
    if host.endswith(SKIP_SUFFIXES):
        return True
    # 明显非目标
    if host.endswith((".local", ".invalid", ".test", ".example")):
        return True
    return False


def write_lines(path, items):
    with open(path, "w", encoding="utf-8") as f:
        for x in items:
            f.write(str(x) + "\n")


# ---------------------------------------------------------------- subs

def cmd_subs(args):
    text = read_text(args.input)
    hosts = OrderedDict()
    for m in DOMAIN_RE.finditer(text):
        h = norm_host(m.group(1))
        if is_noise(h):
            continue
        hosts.setdefault(h, None)
    for m in IP_RE.finditer(text):
        hosts.setdefault(m.group(0), None)

    result = sorted(hosts.keys())
    if args.root:
        result = [h for h in result if h == args.root or h.endswith("." + args.root)]
    if args.output:
        write_lines(args.output, result)
        print(f"[OK] 写入 {len(result)} 条 → {args.output}")
    else:
        for h in result:
            print(h)
    return 0


# ---------------------------------------------------------------- 提取

def _iter_har_entries(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            die(f"HAR 解析失败: {e}")
    for entry in (data.get("log") or {}).get("entries") or []:
        req = entry.get("request") or {}
        url = req.get("url") or ""
        method = req.get("method") or "GET"
        if url:
            yield method, url, req


def _iter_har_responses(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            die(f"HAR 解析失败: {e}")
    for entry in (data.get("log") or {}).get("entries") or []:
        url = (entry.get("request") or {}).get("url") or ""
        content = ((entry.get("response") or {}).get("content") or {}).get("text") or ""
        if url and content:
            yield url, content


def _iter_js_files(js_dir):
    if not os.path.isdir(js_dir):
        die(f"目录不存在: {js_dir}")
    for root, _dirs, files in os.walk(js_dir):
        for fn in files:
            if fn.lower().endswith((".js", ".mjs", ".map", ".json", ".html", ".htm", ".txt")):
                p = os.path.join(root, fn)
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as f:
                        yield p, f.read()
                except OSError:
                    continue


JS_PATH_RE = re.compile(
    r"""["'`](/(?:api|v\d+|rest|graphql|admin|internal|manage|user|account|order|auth|oauth|open|public|web|service)[^"'`\s\\]{0,200})["'`]""",
    re.I,
)


def extract_endpoints_from_text(text, base_host=""):
    found = OrderedDict()
    for m in URL_RE.finditer(text):
        u = m.group(0).rstrip(".,;)'\"")
        try:
            pu = urlparse(u)
        except ValueError:
            continue
        if base_host and pu.netloc and base_host not in pu.netloc:
            continue
        key = f"{pu.netloc}{pu.path}" if pu.netloc else pu.path
        if pu.query:
            key += "?" + pu.query
        found.setdefault(key, None)
    for m in JS_PATH_RE.finditer(text):
        found.setdefault(m.group(1), None)
    return list(found.keys())


def cmd_extract_endpoints(args):
    endpoints = OrderedDict()
    base_host = args.host or ""

    if args.input:
        if args.input.lower().endswith(".har"):
            for _method, url, _req in _iter_har_entries(args.input):
                try:
                    pu = urlparse(url)
                except ValueError:
                    continue
                if base_host and base_host not in pu.netloc:
                    continue
                key = f"{pu.path}" + (f"?{pu.query}" if pu.query else "")
                endpoints.setdefault(key, None)
        else:
            text = read_text(args.input)
            for e in extract_endpoints_from_text(text, base_host):
                endpoints.setdefault(e, None)

    if args.js_dir:
        for _p, content in _iter_js_files(args.js_dir):
            for e in extract_endpoints_from_text(content, base_host):
                endpoints.setdefault(e, None)

    result = sorted(endpoints.keys())
    if args.output:
        write_lines(args.output, result)
        print(f"[OK] 提取 {len(result)} 个端点 → {args.output}")
    else:
        for e in result:
            print(e)
    return 0


PARAM_RE = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_\-\[\]]{0,40})=")
JSON_KEY_RE = re.compile(r"""["']([a-zA-Z_][a-zA-Z0-9_]{1,40})["']\s*:""")
FETCH_BODY_RE = re.compile(r"""["']([a-zA-Z_][a-zA-Z0-9_]{1,40})["']\s*:""")

SENSITIVE_PARAMS = {
    "id", "uid", "user_id", "userid", "account", "account_id", "owner_id", "member_id",
    "order_id", "orderid", "file", "filename", "path", "url", "uri", "redirect",
    "redirect_uri", "callback", "return_url", "next", "goto", "role", "is_admin",
    "isadmin", "admin", "type", "level", "amount", "price", "quantity", "status",
    "action", "op", "token", "key", "sign", "signature", "tenant", "org",
}


def cmd_extract_params(args):
    params = OrderedDict()

    def collect(text):
        for m in PARAM_RE.finditer(text):
            params.setdefault(m.group(1), None)

    if args.input:
        if args.input.lower().endswith(".har"):
            for _method, url, req in _iter_har_entries(args.input):
                for m in PARAM_RE.finditer(url):
                    params.setdefault(m.group(1), None)
                for q in (req.get("queryString") or []):
                    if q.get("name"):
                        params.setdefault(q["name"], None)
                pd = req.get("postData") or {}
                txt = pd.get("text") or ""
                if txt:
                    for m in JSON_KEY_RE.finditer(txt):
                        params.setdefault(m.group(1), None)
        else:
            collect(read_text(args.input))

    if args.js_dir:
        for _p, content in _iter_js_files(args.js_dir):
            collect(content)

    result = sorted(params.keys())
    sensitive = [p for p in result if p.lower() in SENSITIVE_PARAMS]

    if args.output:
        write_lines(args.output, result)
        print(f"[OK] 提取 {len(result)} 个参数 → {args.output}")
    else:
        for p in result:
            print(p)

    if sensitive:
        print(f"\n[!] 高关注参数（{len(sensitive)}）: {', '.join(sensitive)}")
    return 0


# ---------------------------------------------------------------- swagger

def cmd_swagger(args):
    data = json.loads(read_text(args.input))
    lines = ["# API 清单（来源：Swagger/OpenAPI）", ""]
    info = data.get("info") or {}
    if info.get("title"):
        lines.append(f"- 标题：{info.get('title')}")
    if info.get("version"):
        lines.append(f"- 版本：{info.get('version')}")
    lines.append("")

    servers = data.get("servers") or []
    if servers:
        lines.append("## Servers")
        for s in servers:
            lines.append(f"- `{s.get('url', '')}`")
        lines.append("")

    lines.append("## 接口")
    lines.append("")
    lines.append("| 方法 | 路径 | 摘要 | 参数 |")
    lines.append("|---|---|---|---|")

    paths = data.get("paths") or {}
    count = 0
    for path, ops in sorted(paths.items()):
        if not isinstance(ops, dict):
            continue
        for method, op in sorted(ops.items()):
            if method.lower() not in ("get", "post", "put", "delete", "patch", "head", "options"):
                continue
            if not isinstance(op, dict):
                continue
            summary = (op.get("summary") or op.get("operationId") or "").replace("|", "/")
            plist = []
            for p in (op.get("parameters") or []):
                if isinstance(p, dict) and p.get("name"):
                    plist.append(p["name"])
            if isinstance(op.get("requestBody"), dict):
                plist.append("body")
            lines.append(
                f"| {method.upper()} | `{path}` | {summary} | {', '.join(plist) or '-'} |"
            )
            count += 1

    text = "\n".join(lines) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[OK] 提取 {count} 个接口 → {args.output}")
    else:
        print(text)
    return 0


# ---------------------------------------------------------------- split

def cmd_split(args):
    endpoints = [l.strip() for l in read_text(args.input).splitlines() if l.strip()]
    s_tier, a_tier, b_tier, c_tier = [], [], [], []
    for e in endpoints:
        low = e.lower()
        if any(h in low for h in S_TIER_HINTS):
            s_tier.append(e)
        elif any(h in low for h in A_TIER_HINTS):
            a_tier.append(e)
        elif any(x in low for x in (".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff")):
            c_tier.append(e)
        else:
            b_tier.append(e)

    out_dir = args.output_dir or "."
    os.makedirs(out_dir, exist_ok=True)
    write_lines(os.path.join(out_dir, "endpoints-s-class.txt"), s_tier)
    write_lines(os.path.join(out_dir, "endpoints-a-class.txt"), a_tier)
    write_lines(os.path.join(out_dir, "endpoints-b-class.txt"), b_tier)
    write_lines(os.path.join(out_dir, "endpoints-c-class.txt"), c_tier)

    print(f"[OK] 分档完成 → {out_dir}")
    print(f"  S 级（越权/逻辑优先）: {len(s_tier)}")
    print(f"  A 级（上传/SSRF/穿越）: {len(a_tier)}")
    print(f"  B 级（XSS/注入）     : {len(b_tier)}")
    print(f"  C 级（静态资源）     : {len(c_tier)}")
    return 0


def main():
    p = argparse.ArgumentParser(
        prog="asset_organizer.py",
        description="资产与攻击面整理",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("subs", help="整理子域")
    s.add_argument("--input", required=True)
    s.add_argument("--output")
    s.add_argument("--root", help="只保留该根域下")

    e = sub.add_parser("extract-endpoints", help="提取端点")
    e.add_argument("--input", help="HAR 或文本")
    e.add_argument("--js-dir")
    e.add_argument("--host", help="限定主机关键字")
    e.add_argument("--output")

    pa = sub.add_parser("extract-params", help="提取参数")
    pa.add_argument("--input")
    pa.add_argument("--js-dir")
    pa.add_argument("--output")

    sw = sub.add_parser("swagger", help="Swagger 转清单")
    sw.add_argument("--input", required=True)
    sw.add_argument("--output")

    sp = sub.add_parser("split", help="端点分档")
    sp.add_argument("--input", required=True)
    sp.add_argument("--output-dir", default=".")

    args = p.parse_args()
    dispatch = {
        "subs": cmd_subs,
        "extract-endpoints": cmd_extract_endpoints,
        "extract-params": cmd_extract_params,
        "swagger": cmd_swagger,
        "split": cmd_split,
    }
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
