#!/usr/bin/env python3
"""
report_builder.py —— 漏洞报告生成、校验与脱敏

用途：
  new      从模板生成报告骨架
  check    校验报告完整性与脱敏情况
  redact   对证据目录批量脱敏（请求/响应/文本）
  summary  汇总多个发现为清单

依赖：requests（仅 summary 的在线校验用，可不用）。默认全标准库。

示例：
  python3 report_builder.py new --output findings/FINDING-001.md --title "订单越权"
  python3 report_builder.py check --file findings/FINDING-001.md
  python3 report_builder.py redact --dir findings/FINDING-001/
  python3 report_builder.py summary --dir findings/ --output SUMMARY.md
"""

import argparse
import hashlib
import os
import re
import sys
import datetime

# 定位模板
HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_ROOT = os.path.dirname(HERE)
TEMPLATE = os.path.join(SKILL_ROOT, "references", "templates", "report-template.md")


def die(msg, code=2):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------- 脱敏规则

REDACT_RULES = [
    # Authorization / Cookie / api key 头
    (re.compile(r"(?im)^(\s*(?:Authorization|Cookie|X-Api-Key|X-Auth-Token|Set-Cookie)\s*:\s*)(.+)$"),
     lambda m: m.group(1) + _mask_secret(m.group(2).strip())),
    # Bearer token
    (re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-._~+/=]{16,})"),
     lambda m: "Bearer " + _mask_secret(m.group(1))),
    # 手机号（中国大陆）
    (re.compile(r"(?<!\d)(1[3-9]\d)(\d{4})(\d{4})(?!\d)"),
     lambda m: f"{m.group(1)}****{m.group(3)}"),
    # 邮箱
    (re.compile(r"\b([A-Za-z0-9._%+\-]{1,2})[A-Za-z0-9._%+\-]*(@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b"),
     lambda m: f"{m.group(1)}***{m.group(2)}"),
    # 身份证
    (re.compile(r"(?<!\d)(\d{4})\d{10}(\d{2}[\dXx])(?!\d)"),
     lambda m: f"{m.group(1)}**********{m.group(2)}"),
    # JWT（三段式）
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{0,}\b"),
     lambda m: _mask_secret(m.group(0))),
    # 长 base64/hex 密钥
    (re.compile(r"\b([A-Za-z0-9+/]{32,}={0,2})\b"),
     lambda m: _mask_secret(m.group(1))),
    (re.compile(r"\b([a-fA-F0-9]{32,})\b"),
     lambda m: _mask_secret(m.group(1))),
    # AWS key
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), lambda m: _mask_secret(m.group(0))),
    # 常见 sk_live / sk- 密钥
    (re.compile(r"\b(sk_live_|sk_test_|sk-)[A-Za-z0-9]{16,}\b"), lambda m: _mask_secret(m.group(0))),
]


def _mask_secret(s, keep=4):
    s = s.strip()
    if len(s) <= keep * 2:
        return "***"
    return f"{s[:keep]}***...***{s[-keep:]}"


def _sha8(s):
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]


def redact_text(text, with_fingerprint=False):
    """返回脱敏后的文本。"""
    out = text
    for pattern, repl in REDACT_RULES:
        out = pattern.sub(repl, out)
    return out


# ---------------------------------------------------------------- new

def cmd_new(args):
    if not os.path.exists(TEMPLATE):
        die(f"模板不存在: {TEMPLATE}")
    with open(TEMPLATE, "r", encoding="utf-8") as f:
        tpl = f.read()

    title = args.title or "{{TITLE}}"
    fid = args.id or os.path.basename(args.output).replace(".md", "")
    today = datetime.date.today().isoformat()

    content = tpl
    content = content.replace("{{TITLE}}", title)
    content = content.replace("{{NNN}}", fid)
    content = content.replace("{{YYYY-MM-DD}}", today)

    out = args.output
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    if os.path.exists(out) and not args.force:
        die(f"文件已存在: {out}（用 --force 覆盖）")
    with open(out, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[OK] 已生成报告骨架: {out}")
    print("     下一步：填写漏洞详情，然后用 check 校验。")
    return 0


# ---------------------------------------------------------------- check

REQUIRED_SECTIONS = [
    "## 元信息",
    "## 严重等级",
    "## 一、漏洞概述",
    "## 二、影响范围",
    "## 三、复现步骤",
    "## 四、证据",
    "## 五、影响分析",
    "## 六、修复建议",
    "## 七、脱敏声明",
]

PLACEHOLDER_RE = re.compile(r"\{\{[^}]+\}\}")


def cmd_check(args):
    if not os.path.exists(args.file):
        die(f"文件不存在: {args.file}")
    with open(args.file, "r", encoding="utf-8") as f:
        text = f.read()

    problems = []
    warnings = []
    passed = []

    # 1) 必备章节
    for sec in REQUIRED_SECTIONS:
        if sec in text:
            passed.append(f"章节存在: {sec}")
        else:
            problems.append(f"缺少章节: {sec}")

    # 2) 未填占位符
    ph = sorted(set(PLACEHOLDER_RE.findall(text)))
    if ph:
        # 模板里合法的示例占位符（如 {TARGET_HOST}）不算错
        real = [x for x in ph if not x.startswith("{CVSS") and "TARGET_HOST" not in x
                and "TOKEN" not in x and "MY_" not in x and "ASSET" not in x]
        if real:
            warnings.append(f"仍含占位符 {len(real)} 处: {', '.join(real[:5])}")

    # 3) 缺 CVSS 向量（必须是真实向量：CVSS:4.0/<指标串>，排除注释与示例）
    real_vector = re.search(
        r"CVSS:[34]\.[01]/(?:AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]|AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NRA]/S:[UC]/C:[HLN])",
        text,
    )
    if not real_vector:
        problems.append("缺少有效的 CVSS 向量（需形如 CVSS:4.0/AV:N/AC:L/... 的实际向量）")
    elif re.search(r"\{\{(?:VECTOR|SCORE)\}\}", text):
        problems.append("CVSS 向量或分值仍为占位符")

    # 4) 缺原始请求（简单启发式）
    if "HTTP/1.1" not in text:
        warnings.append("未见原始 HTTP 请求（'HTTP/1.1'），确认是否已贴出请求/响应")

    # 5) 脱敏检查：未脱敏的敏感数据
    leak_patterns = [
        (re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "疑似未脱敏手机号"),
        (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "疑似未脱敏 AWS Key"),
        (re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"), "疑似未脱敏 Stripe Key"),
        (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b"), "疑似未脱敏 JWT"),
        (re.compile(r"(?im)^\s*(?:Authorization|Cookie)\s*:\s*(?!\S*\*\*\*)\S{16,}"), "疑似未脱敏认证头"),
    ]
    for pat, desc in leak_patterns:
        for m in pat.finditer(text):
            # 跳过已在"脱敏声明"章节内的示例
            warnings.append(f"{desc}: {m.group(0)[:20]}...")

    # 6) 具体性：影响描述不能太短
    m = re.search(r"## 五、影响分析(.*?)(?=\n## |\Z)", text, re.S)
    if m and len(m.group(1).strip()) < 40:
        warnings.append("影响分析过于简略（<40 字符），审核可能退回")

    # 7) 测试行为声明
    if "未使用任何真实用户数据" not in text:
        warnings.append("缺少'未使用真实用户数据'声明")

    # 输出
    print(f"\n=== 报告校验: {args.file} ===\n")
    for x in passed:
        print(f"  [PASS] {x}")
    for x in warnings:
        print(f"  [WARN] {x}")
    for x in problems:
        print(f"  [FAIL] {x}")

    print(f"\n结论: PASS {len(passed)} / WARN {len(warnings)} / FAIL {len(problems)}")
    if problems:
        print("\n❌ 存在必须修复的问题，暂不可提交。")
        return 1
    if warnings:
        print("\n⚠️ 有警告项，建议复核后再提交。")
        return 0
    print("\n✅ 校验通过。")
    return 0


# ---------------------------------------------------------------- redact

TEXT_EXTS = (".http", ".txt", ".json", ".md", ".html", ".xml", ".log", ".yaml", ".yml", ".csv")


def cmd_redact(args):
    target = args.dir
    if not os.path.isdir(target):
        die(f"目录不存在: {target}")

    changed = 0
    scanned = 0
    report = []

    for root, _dirs, files in os.walk(target):
        for fn in files:
            p = os.path.join(root, fn)
            if not fn.lower().endswith(TEXT_EXTS):
                continue
            scanned += 1
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    original = f.read()
            except OSError as e:
                report.append(f"  [SKIP] {p} ({e})")
                continue

            cleaned = redact_text(original)
            if cleaned != original:
                if args.dry_run:
                    report.append(f"  [WOULD REDACT] {p}")
                else:
                    if args.backup and not os.path.exists(p + ".orig"):
                        with open(p + ".orig", "w", encoding="utf-8") as f:
                            f.write(original)
                    with open(p, "w", encoding="utf-8") as f:
                        f.write(cleaned)
                    report.append(f"  [REDACTED] {p}")
                changed += 1
            else:
                report.append(f"  [CLEAN] {p}")

    print(f"\n=== 脱敏: {target} ===")
    print(f"扫描 {scanned} 个文本文件，处理 {changed} 个\n")
    for line in report:
        print(line)

    if args.dry_run:
        print("\n（dry-run，未实际修改。去掉 --dry-run 执行）")
    elif args.backup:
        print("\n原始文件已备份为 *.orig（提交前请删除备份）")
    return 0


# ---------------------------------------------------------------- summary

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _parse_finding(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    title = ""
    for line in text.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            break
    # 严重等级：优先取「## 元信息」表格里的 **严重等级** 行
    sev = "Unknown"
    m = re.search(r"\*\*严重等级\*\*\s*\|\s*(Critical|High|Medium|Low|Info)", text, re.I)
    if m:
        sev = m.group(1).capitalize()
    else:
        # 回退：只在「## 严重等级」章节内找
        sec = re.search(r"##\s*严重等级[^\n]*\n(.*?)(?=\n## |\Z)", text, re.S)
        if sec:
            sm = re.search(r"(Critical|High|Medium|Low)", sec.group(1), re.I)
            if sm:
                sev = sm.group(1).capitalize()
    # 向量：优先取实际向量
    vector = ""
    m = re.search(
        r"CVSS:[34]\.[01]/(?:AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]|AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NRA]/S:[UC]/C:[HLN])[A-Za-z0-9:/.\-]*",
        text,
    )
    if m:
        vector = m.group(0)
    return {"file": os.path.basename(path), "title": title, "severity": sev, "vector": vector}


def cmd_summary(args):
    if not os.path.isdir(args.dir):
        die(f"目录不存在: {args.dir}")
    findings = []
    for root, _dirs, files in os.walk(args.dir):
        for fn in files:
            if fn.endswith(".md") and not fn.endswith(".orig") and fn.lower() != "summary.md":
                findings.append(_parse_finding(os.path.join(root, fn)))

    findings.sort(key=lambda x: SEVERITY_ORDER.get(str(x["severity"]).lower(), 9))

    lines = ["# 漏洞汇总", "", f"生成时间：{datetime.datetime.now().isoformat(timespec='seconds')}", ""]
    lines.append(f"共 {len(findings)} 个发现。")
    lines.append("")
    lines.append("| # | 严重等级 | 标题 | 文件 | 向量 |")
    lines.append("|---|---|---|---|---|")
    for i, f in enumerate(findings, 1):
        lines.append(f"| {i} | {f['severity']} | {f['title']} | `{f['file']}` | `{f['vector']}` |")
    lines.append("")

    # 统计
    from collections import Counter
    cnt = Counter(str(f["severity"]).capitalize() for f in findings)
    lines.append("## 统计")
    lines.append("")
    for lvl in ("Critical", "High", "Medium", "Low", "Info", "Unknown"):
        if cnt.get(lvl):
            lines.append(f"- {lvl}: {cnt[lvl]}")
    lines.append("")

    text = "\n".join(lines)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[OK] 汇总 {len(findings)} 个发现 → {args.output}")
    else:
        print(text)
    return 0


def main():
    p = argparse.ArgumentParser(
        prog="report_builder.py",
        description="漏洞报告生成 / 校验 / 脱敏 / 汇总",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    n = sub.add_parser("new", help="生成报告骨架")
    n.add_argument("--output", required=True)
    n.add_argument("--title")
    n.add_argument("--id")
    n.add_argument("--force", action="store_true")

    c = sub.add_parser("check", help="校验报告")
    c.add_argument("--file", required=True)

    r = sub.add_parser("redact", help="证据脱敏")
    r.add_argument("--dir", required=True)
    r.add_argument("--dry-run", action="store_true")
    r.add_argument("--backup", action="store_true", help="保留 *.orig 备份")

    s = sub.add_parser("summary", help="汇总发现")
    s.add_argument("--dir", required=True)
    s.add_argument("--output")

    args = p.parse_args()
    dispatch = {"new": cmd_new, "check": cmd_check, "redact": cmd_redact, "summary": cmd_summary}
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
