#!/usr/bin/env python3
"""
scope_guard.py —— 授权范围校验器

用途：在授权安全测试中，机器化校验目标是否在允许范围内，
      避免"手滑打到范围外"。UNKNOWN（范围未明确）一律按 DENY 处理。

依赖：PyYAML（sudo pip3 install pyyaml）
若未安装 PyYAML，会退化为简易 YAML 解析（仅支持本工具生成的格式）。

子命令：
  init     生成范围清单模板
  check    校验目标（单个 / 批量）
  explain  解释某个目标为何 ALLOW / DENY

示例：
  python3 scope_guard.py init --output scope.yaml
  python3 scope_guard.py check --scope scope.yaml --target api.example.com
  python3 scope_guard.py check --scope scope.yaml --targets targets.txt --json
  python3 scope_guard.py explain --scope scope.yaml --target a.b.example.com
"""

import argparse
import ipaddress
import json
import os
import re
import sys

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ---------------------------------------------------------------- 加载

def load_scope(path):
    """加载范围清单。优先 PyYAML。"""
    if not os.path.exists(path):
        die(f"范围文件不存在: {path}\n先运行: python3 scope_guard.py init --output {path}")
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if HAS_YAML:
        try:
            return yaml.safe_load(text) or {}
        except Exception as e:
            die(f"YAML 解析失败: {e}")
    return _mini_yaml(text)


def _mini_yaml(text):
    """极简 YAML 解析：只支持 init 生成的层级结构（dict/list/标量）。"""
    root = {}
    stack = [(-1, root)]
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if line.startswith("- "):
            val = _scalar(line[2:].strip())
            if isinstance(parent, list):
                parent.append(val)
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if val == "":
            # 可能是 dict 也可能是 list，先建 dict，遇到 "- " 再转
            child = {}
            if isinstance(parent, dict):
                parent[key] = child
            stack.append((indent, child))
        else:
            if isinstance(parent, dict):
                parent[key] = _scalar(val)
    # 把空 dict 转成 list（其下若有 "- " 项已被跳过，这里做兜底）
    return root


def _scalar(v):
    v = v.strip()
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return [_scalar(x) for x in inner.split(",")] if inner else []
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    return v


def die(msg, code=2):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------- 匹配

def _norm_host(host):
    """归一化主机名：取 host[:port]、小写、去尾点。"""
    host = host.strip()
    if not host:
        return ""
    if host.startswith(("http://", "https://")):
        host = re.sub(r"^https?://", "", host, flags=re.I)
    host = host.split("/")[0].split("?")[0].split("#")[0]
    host = host.rsplit("@", 1)[-1]
    # IPv6
    if host.startswith("["):
        host = host[1:host.index("]")] if "]" in host else host.strip("[]")
    elif host.count(":") == 1:
        host = host.split(":")[0]
    return host.lower().rstrip(".")


def _match_domain(target_host, pattern):
    """域名匹配，支持 *.example.com 通配（只匹配一层及以上子域）。"""
    pattern = _norm_host(pattern)
    if not pattern:
        return False
    if pattern.startswith("*."):
        base = pattern[2:]
        # 通配符应匹配子域但不匹配裸域
        return target_host.endswith("." + base) and target_host != base
    return target_host == pattern or target_host.endswith("." + pattern)


def _match_url(target, pattern):
    """URL 前缀/通配匹配。"""
    pat = pattern.strip()
    if pat.endswith("*"):
        return target.startswith(pat[:-1])
    return target == pat or target.startswith(pat.rstrip("/") + "/")


def _match_ip(target, pattern):
    """IP 或 CIDR 匹配。"""
    try:
        t = ipaddress.ip_address(target)
    except ValueError:
        return False
    pat = pattern.strip()
    try:
        if "/" in pat:
            return t in ipaddress.ip_network(pat, strict=False)
        return t == ipaddress.ip_address(pat)
    except ValueError:
        return False


def classify(target, scope):
    """
    返回 (verdict, reason)
    verdict ∈ {ALLOW, DENY, UNKNOWN}
    """
    if not target or not target.strip():
        return "DENY", "空目标"

    raw = target.strip()
    host = _norm_host(raw)
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    out = scope.get("out_of_scope") or {}
    ins = scope.get("in_scope") or {}

    # 1) 先判 out_of_scope（优先级最高）
    for p in (out.get("domains") or []):
        if _match_domain(host, p):
            return "DENY", f"命中 out-of-scope 域名规则: {p}"
    for p in (out.get("ips") or []):
        if _match_ip(host, p):
            return "DENY", f"命中 out-of-scope IP 规则: {p}"
    for p in (out.get("urls") or []):
        if _match_url(raw, p):
            return "DENY", f"命中 out-of-scope URL 规则: {p}"

    # 2) 再判 in_scope
    for p in (ins.get("urls") or []):
        if _match_url(raw, p):
            return "ALLOW", f"命中 in-scope URL 规则: {p}"
    for p in (ins.get("domains") or []):
        if _match_domain(host, p):
            return "ALLOW", f"命中 in-scope 域名规则: {p}"
    for p in (ins.get("ips") or []):
        if _match_ip(host, p):
            return "ALLOW", f"命中 in-scope IP 规则: {p}"
    for p in (ins.get("mobile") or []):
        if raw.strip() == str(p).strip():
            return "ALLOW", f"命中 in-scope 移动端规则: {p}"

    if is_ip:
        return "UNKNOWN", "IP 未在任何列表中（保守视为不允许）"
    return "UNKNOWN", "目标未在任何列表中（范围不明确 = 不允许）"


# ---------------------------------------------------------------- 输出

COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text, code):
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def render(verdict, target, reason):
    if verdict == "ALLOW":
        tag = _c("ALLOW  ", "32")
    elif verdict == "DENY":
        tag = _c("DENY   ", "31")
    else:
        tag = _c("UNKNOWN", "33")
    return f"{tag}  {target}   ({reason})"


# ---------------------------------------------------------------- 命令

SCOPE_TEMPLATE = """# 授权范围清单
# 由 scope_guard.py init 生成。请如实填写，未填写的目标将被视为不允许。
# 重要：UNKNOWN（不在任何列表）一律按 DENY 处理。

project:
  name: ""                       # 项目/活动名称
  source: ""                     # 平台项目链接 或 委托方
  authorized_by: ""              # 授权依据（平台规则 / 授权书编号）
  valid_until: ""                # 授权有效期，如 2026-12-31
  notes: ""                      # 其他说明

in_scope:
  domains:
    - "example.com"              # 精确域
    - "*.example.com"            # 通配子域（不含裸域）
  ips:
    - "203.0.113.0/24"           # CIDR
  urls:
    - "https://app.example.com/*"
  mobile:
    - "com.example.app"

out_of_scope:
  domains:
    - "*.zendesk.com"            # 第三方托管
  ips:
    - "203.0.113.200"            # CDN 源站
  urls: []
  notes: "排除第三方 SaaS 与关联公司 example-holdings.com"

constraints:
  max_rps: 10                    # 最大请求速率
  no_dos: true
  no_automated_scanning: false
  no_file_upload: false
  no_real_user_data: true
  test_window: "工作日 09:00-18:00"
"""


def cmd_init(args):
    out = args.output
    if os.path.exists(out) and not args.force:
        die(f"文件已存在: {out}（用 --force 覆盖）")
    with open(out, "w", encoding="utf-8") as f:
        f.write(SCOPE_TEMPLATE)
    print(f"[OK] 已生成范围清单模板: {out}")
    print("     请填写 in_scope / out_of_scope，然后执行 check 校验目标。")
    if not HAS_YAML:
        print("[WARN] 未检测到 PyYAML，将使用内置简易解析器（建议: pip3 install pyyaml）")


def _check_one(scope, target):
    verdict, reason = classify(target, scope)
    return verdict, reason


def cmd_check(args):
    scope = load_scope(args.scope)
    if not scope.get("in_scope"):
        print("[WARN] in_scope 为空 —— 所有目标都会被判为 UNKNOWN/DENY")

    targets = []
    if args.target:
        targets.append(args.target)
    if args.targets:
        if not os.path.exists(args.targets):
            die(f"目标文件不存在: {args.targets}")
        with open(args.targets, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    if not targets:
        die("未提供目标（--target 或 --targets）")

    results = []
    for t in targets:
        verdict, reason = _check_one(scope, t)
        results.append({"target": t, "verdict": verdict, "reason": reason})

    if args.json:
        print(json.dumps({"results": results}, ensure_ascii=False, indent=2))
    else:
        for r in results:
            print(render(r["verdict"], r["target"], r["reason"]))
        allow = sum(1 for r in results if r["verdict"] == "ALLOW")
        deny = sum(1 for r in results if r["verdict"] != "ALLOW")
        print(f"\n合计 {len(results)}：ALLOW {allow} / 不可测 {deny}")
        if args.json_summary:
            print(json.dumps({"allow": allow, "blocked": deny}, ensure_ascii=False))

    # 退出码：有不可测目标时返回 1，便于脚本串联
    return 0 if all(r["verdict"] == "ALLOW" for r in results) else 1


def cmd_explain(args):
    scope = load_scope(args.scope)
    host = _norm_host(args.target)
    verdict, reason = classify(args.target, scope)
    print(f"目标      : {args.target}")
    print(f"归一化主机: {host}")
    print(f"判定      : {verdict}")
    print(f"原因      : {reason}")
    print()
    print("范围配置摘要:")

    def _show(title, key):
        vals = (scope.get(key) or {}).get("domains") or []
        print(f"  {title}: {', '.join(map(str, vals)) if vals else '(空)'}")

    _show("in-scope 域 ", "in_scope")
    _show("out-scope 域", "out_of_scope")
    print(f"  约束: {scope.get('constraints')}")
    return 0


def main():
    p = argparse.ArgumentParser(
        prog="scope_guard.py",
        description="授权范围校验器 —— 未明确即为不允许",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s_init = sub.add_parser("init", help="生成范围清单模板")
    s_init.add_argument("--output", default="scope.yaml")
    s_init.add_argument("--force", action="store_true")

    s_check = sub.add_parser("check", help="校验目标是否在范围内")
    s_check.add_argument("--scope", default="scope.yaml")
    s_check.add_argument("--target")
    s_check.add_argument("--targets", help="目标列表文件，每行一个")
    s_check.add_argument("--json", action="store_true", help="输出 JSON")
    s_check.add_argument("--json-summary", action="store_true")

    s_exp = sub.add_parser("explain", help="解释判定原因")
    s_exp.add_argument("--scope", default="scope.yaml")
    s_exp.add_argument("--target", required=True)

    args = p.parse_args()
    if args.cmd == "init":
        cmd_init(args); return 0
    if args.cmd == "check":
        return cmd_check(args)
    if args.cmd == "explain":
        return cmd_explain(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
