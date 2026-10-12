快速开始
0. 前置：确认授权
这一步不能跳。 没有授权，后面什么都不做。
回答这六个问题：
1. 目标来自哪个平台/项目/委托方？
2. in-scope 资产清单是什么？
3. out-of-scope 排除哪些？
4. 测试时段与频率限制？
5. 平台规则禁止什么？
6. 漏洞报告提交到哪里？
第 1、2 项答不上来 → 停止，先获取授权。详见 references/methodology/00-authorization.md。
1. 建立工作目录
mkdir -p project/{recon,enum,findings,authorization}
cd project

# 初始化范围清单
python3 /path/to/authorized-src-hunter/scripts/scope_guard.py init --output scope.yaml
编辑 scope.yaml，填入 in_scope / out_of_scope / constraints。
2. 阶段 0：授权归档
# 把平台项目页截图、scope 原文、规则要点放到 authorization/
# 这是范围争议时的唯一自证材料
3. 阶段 1：信息收集（被动）
# CT 日志找子域（完全被动，最合规）
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | sort -u > raw-subs.txt

# 整理
python3 scripts/asset_organizer.py subs \
  --input raw-subs.txt --root example.com --output recon/subdomains.txt

# 历史 URL
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com*&output=text&fl=original&collapse=urlkey&limit=5000" \
  > recon/wayback-urls.txt
校验范围：
python3 scripts/scope_guard.py check \
  --scope scope.yaml --targets recon/subdomains.txt --json > recon/scope-check.json

# 只看 ALLOW 的进入下一阶段
4. 阶段 2：资产枚举
# 存活校验（串行，限速）
while read -r h; do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "https://$h/" 2>/dev/null)
  echo "$code  $h"
  sleep 1
done < recon/subdomains.txt | tee enum/live.txt

# 用浏览器打开目标，HAR 导出全部流量
# 然后提取端点与参数
python3 scripts/asset_organizer.py extract-endpoints \
  --input traffic.har --output enum/endpoints.txt
python3 scripts/asset_organizer.py extract-params \
  --input traffic.har --output enum/params.txt

# 若发现 Swagger，导出接口清单
curl -s https://{TARGET_HOST}/v3/api-docs > enum/swagger.json
python3 scripts/asset_organizer.py swagger \
  --input enum/swagger.json --output enum/api-list.md

# 按价值分档
python3 scripts/asset_organizer.py split \
  --input enum/endpoints.txt --output-dir enum/
5. 阶段 3：漏洞验证
# 先读索引，确定方向
# references/playbooks/00-index.md

# 加载对应 playbook，按其"测试流程"执行
# 每个 playbook 的最后一节"边界红线"必须读完再动手
准备工作：
[ ] 注册两个测试账号 A / B（越权、CSRF、盲打都要用）
[ ] 打开 Burp，全程留证
[ ] 自建 interactsh（禁用公共 DNSLog）
[ ] 确认速率限制符合 scope.yaml
6. 阶段 4：报告产出
# 一键生成证据目录结构
mkdir -p findings/FINDING-001/{screenshots}

# 生成报告骨架
python3 scripts/report_builder.py new \
  --output findings/FINDING-001.md \
  --title "订单接口水平越权" --id FINDING-001

# 填写报告后校验
python3 scripts/report_builder.py check --file findings/FINDING-001.md

# 脱敏证据（先 dry-run 看效果）
python3 scripts/report_builder.py redact --dir findings/FINDING-001/ --dry-run
python3 scripts/report_builder.py redact --dir findings/FINDING-001/

# 汇总
python3 scripts/report_builder.py summary --dir findings/ --output SUMMARY.md
7. 提交前自查
[ ] 每个发现都有完整请求 + 响应（没抓包 = 没发现）
[ ] 所有 PII 已脱敏（redact 脚本跑过）
[ ] CVSS 向量经过官方计算器验证
[ ] 已声明"未使用真实用户数据、未做破坏性操作"
[ ] 报告中无范围外系统的信息
[ ] 本地证据已清理（不上传 GitHub / 网盘）
[ ] 测试时间线已记录（便于平台核对日志）
常见问题
Q：目标没有公开赏金项目，能测吗？
不能。需要先获取授权：注册公开赏金平台、联系企业 SRC、走正式委托流程。
Q：我想练手怎么办？
用本地靶场：OWASP Juice Shop、DVWA、WebGoat、Pikachu。本技能的所有 playbook 同样适用。
Q：扫描器能用吗？
仅在平台规则允许时，且必须限速。多数项目禁止大规模自动化扫描。
Q：发现漏洞后能公开吗？
不能。未修复前不公开、不售卖、不投第三方平台。
Q：验证需要碰到别人的数据怎么办？
不该这么做。用自己两个账号互测，足以证明漏洞存在。
红线速查（每次动手前默读）
不做副作用   不发短信/邮件/扣款/改数据
不窃数据     不 dump、不批量导出、不下载用户数据
不越界       不打范围外、不碰第三方
不破坏       不做 DoS、不高并发
不留后门     不上传 webshell
不滥用凭据   拿到凭据只验证存在
不横向       不以目标为跳板
不社工       不钓鱼、不电话、不入企
不公开       未修复前不披露
不越权测试   无授权一律不测
