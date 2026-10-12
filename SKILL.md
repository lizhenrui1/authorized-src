---
name: authorized-src-hunter
description: 面向授权安全测试的漏洞挖掘工作流技能，用于 SRC / 众测 / Bug Bounty / 委托渗透测试场景。当用户提供已获授权的目标（域名、IP、API、App 后端等）并希望系统性推进信息收集、资产枚举、漏洞测试与报告产出时使用。覆盖 Web 常见漏洞类型（注入、XSS、SSRF、RCE、越权、逻辑缺陷、文件上传、路径穿越、认证绕过、GraphQL、竞态、配置缺陷等）。内置强制授权校验门禁、操作红线约束、结构化 playbook、payload 速查、WAF 绕过变体、组件指纹字典与 CVSS 4.0 报告模板。仅在目标具备明确授权时使用；未经授权的目标一律拒绝执行。
---
Authorized SRC Hunter
一个把授权安全测试串成闭环的工作流技能。核心理念：先证明你有权测，再谈怎么测；先确权、再收集、后验证、必留证、终报告。
使用前提（硬性门禁）
本技能仅用于以下场景：
- 公开漏洞赏金平台（HackerOne / Bugcrowd / 补天 / 漏洞盒子 / 腾讯 SRC / 阿里 SRC 等）已发布的项目
- 企业众测活动、已签署授权委托的渗透测试项目
- 目标方自有资产且已获得书面/平台规则授权的系统
不属于上述场景的目标，直接拒绝，不进入流程。详见 references/methodology/00-authorization.md。
授权确认清单（每次启动必须逐项过）
在执行任何主动测试动作（发包、扫描、fuzzing）之前，必须向用户确认并获得明确答复：
#
确认项
未满足时的处理
1
目标来源：这个目标来自哪个平台/项目/委托方？
停止，要求提供
2
授权范围：in-scope 资产清单是什么？（精确到域名/路径/参数）
停止，要求提供
3
超出范围：out-of-scope 明确排除哪些？（第三方托管、关联公司、CDN 源站等）
按保守原则自行排除并在报告中声明
4
测试窗口：是否有时段/频率限制？
按最保守频率执行
5
禁止行为：平台规则里明令禁止什么？
逐条记录为硬约束
6
报告渠道：漏洞提交到哪里？有无格式要求？
默认输出 CVSS 4.0 完整报告
六项里 1、2 任一未确认 → 不执行任何主动测试。可以向用户解释如何获取授权，但没有授权就不动手。
范围解析与校验
确认范围后，先把资产写进工作清单，再用脚本做机器校验，避免"手滑打到范围外"：
# 1) 生成范围工作清单模板
python3 scripts/scope_guard.py init --output scope.yaml

# 2) 编辑 scope.yaml 填入 in-scope / out-of-scope 后，校验每个待测目标
python3 scripts/scope_guard.py check --scope scope.yaml --target api.example.com
# 输出 ALLOW / DENY / UNKNOWN，DENY 与 UNKNOWN 一律不得测试

# 3) 批量校验目标列表
python3 scripts/scope_guard.py check --scope scope.yaml --targets targets.txt --json
UNKNOWN（既不在 in-scope 也不在 out-of-scope）按 DENY 处理——范围不明确即为不允许，这是本技能默认的保守策略。
五阶段工作流
intake ──> recon ──> enum ──> hunt ──> report
确权收集   被动侦察   资产枚举   漏洞验证   证据与报告
阶段
目标
关键产出
详细指引
0. intake
建立授权档案与范围清单
scope.yaml、项目规则摘要
references/methodology/00-authorization.md
1. recon
被动获取目标画像，不主动碰目标
子域、技术栈、公开信息、历史数据
references/methodology/01-recon.md
2. enum
枚举可达资产与攻击面
存活主机、端点、参数、接口清单
references/methodology/02-enum.md
3. hunt
按 playbook 验证漏洞
可复现的发现 + 完整证据包
references/playbooks/00-index.md
4. report
定级、脱敏、成文、提交
CVSS 4.0 报告
references/templates/report-template.md
阶段推进原则：每个阶段结束前做一次小结，确认产出物齐全再进入下一阶段。测试过程中发现新资产 → 先回 intake 校验范围，再继续。
攻击面优先级
不是所有资产价值相同。按下面顺序投入精力，高价值目标优先：
1. 认证与授权边界：登录、注册、找回密码、SSO/OAuth、JWT、权限切换
2. 业务交易链路：支付、退款、优惠券、积分、订单状态流转
3. 数据接口：REST/GraphQL API、导出功能、批量接口、内部 API 暴露
4. 文件处理：上传、下载、导入、解析、预览、转码
5. 服务端渲染与请求发起：URL 抓取、Webhook、代理、回调
6. 管理后台与运维面：Actuator、Swagger、默认凭据、暴露的中间件
7. 展示层：XSS、点击劫持、CSP 缺陷
8. 基础设施配置：CORS、缓存、HTTP 头、Smuggling
理由：越权/逻辑漏洞在 SRC 场景中数量最多、定级最高、最难被自动化发现，值得最优先投入；展示层漏洞通常定级较低。
Playbook 路由表
按怀疑的漏洞类型加载对应手册。每个 playbook 结构统一：入口定位 → 测试方法 → payload → 响应特征 → 影响判定 → 提权/扩大化 → 边界红线。
漏洞类型
文件
典型场景
索引与路由
references/playbooks/00-index.md
先读这个
访问控制 / IDOR / 越权
references/playbooks/01-authz-idor.md
改 ID 看别人的数据、水平/垂直越权
认证与会话
references/playbooks/02-auth-session.md
密码重置、JWT、OAuth/SAML、MFA 绕过
SQL 注入
references/playbooks/03-sqli.md
参数注入、报错/盲注、NoSQL 注入
XSS
references/playbooks/04-xss.md
反射、存储、DOM、盲打
SSRF / 缓存投毒
references/playbooks/05-ssrf-cache.md
URL 参数、Webhook、云元数据、缓存欺骗
RCE / 注入类
references/playbooks/06-rce-injection.md
反序列化、SSTI、XXE、命令注入、表达式注入
文件上传 / 路径穿越
references/playbooks/07-file-upload-traversal.md
上传绕过、任意读写、LFI
业务逻辑缺陷
references/playbooks/08-logic-flaws.md
支付、竞态、CSRF、点击劫持、验证码
API / GraphQL / WebSocket
references/playbooks/09-api-graphql-ws.md
批量赋值、接口暴露、GraphQL 内省
信息泄露与未授权访问
references/playbooks/10-info-disclosure.md
默认凭据、Actuator、暴露服务、源泄露
移动端与客户端
references/playbooks/11-mobile-client.md
Android/iOS 后端、证书固定、本地存储
辅助资源：
- payload 速查：references/payloads/（按漏洞类型分文件）
- WAF 绕过：references/payloads/waf-bypass.md
- 组件指纹与默认凭据：references/dictionaries/
- 工具命令：references/tools/
- CVSS 定级：references/methodology/04-cvss-scoring.md
执行姿态
参数化，不硬编码
给用户输出的所有请求示例，域名、路径、参数名、Cookie、Token 一律用占位符：
# 好
GET /api/v1/orders/{ORDER_ID} HTTP/1.1
Host: {TARGET_HOST}
Cookie: {YOUR_SESSION}

# 差（把真实目标写死在文档/报告里，造成信息泄露）
GET /api/v1/orders/88123 HTTP/1.1
Host: real-target.example.com
双账号自演
越权、密码重置、JWT、OAuth、盲打类测试，一律用自己注册的两个账号互测（A 号读 B 号数据、A 号改 B 号资料）。绝不使用陌生人账号，即使技术上能做到。
证据优先
- 没抓包 = 没发现。所有断言必须有 HTTP 请求/响应原文、截图或录屏支撑。
- 每个发现单独存证，命令和 payload 一并保留。
- 证据包结构见 references/methodology/03-evidence.md。
最小化验证
- 注入类：探到版本/库名即停，不 dump 数据。
- 越权类：1–3 条样本即停，不全量拉取。
- RCE 类：只跑 id / whoami / uname -a，不做任何后续操作。
- 服务未授权：Redis/Mongo 只 info / ping / db.version()，不写不改。
- DoS/竞态：单次复现 ≤60s，串行 5 次；并发测试 50–100 上限，绝不 1000+。
- 短信/邮件类：只发到自己手机，5–10 次为止。
红线（不可逾越）
以下行为一律不做，无论技术上是否可行、无论目标是什么：
红线
说明
❌ 副作用动作
不真发短信/邮件、不真扣款/退款、不真改数据/文件/公告/模板
❌ 数据窃取
不 dump 库、不批量导出、不下载用户数据
❌ 越界测试
不打范围外资产、不碰第三方托管、不碰关联公司
❌ 破坏可用性
不做 DoS、不做高并发压测、不做资源耗尽
❌ 留后门
不上传 webshell、不留持久化、不留调试后门
❌ 凭据滥用
拿到凭据仅验证存在性，绝不用于连接生产库/扣款/发信
❌ 横向移动
不以目标为跳板攻击其内网或第三方系统
❌ 社工与物理
不社工、不钓鱼、不电话、不入企
❌ 公开披露
未修复前不公开、不售卖、不投第三方平台
❌ 未授权目标
无授权一律不测，包括"我只是看看"
红线冲突处理：如果平台规则与本文档冲突，以更严格者为准。
敏感数据脱敏
报告与证据中所有 PII 必须脱敏：
- 手机号：138****5678（保留前 3 后 4）
- 邮箱：ab***@example.com
- 用户名/ID：保留前 2 后 2，如 zh***ng
- Token/Cookie/密钥：eyJh***...***9xQ 只留头尾
- 需要证明"确实拿到了原文"时，附 sha256 指纹而非原文
禁止公开的 OOB 平台
SSRF / XXE / 盲打类外带验证，不使用公共 DNSLog 平台（数据他人可见）。使用目标厂商提供的测试回连平台，或自建 interactsh / 自有域名 DNSLog。
报告
每个发现产出一份结构化报告，包含：标题、严重等级、CVSS 4.0 向量与分值、影响范围、复现步骤、证据、修复建议、脱敏声明。
# 从模板生成报告骨架
python3 scripts/report_builder.py new --output findings/FINDING-001.md

# 校验报告完整性（必填项、脱敏检查、证据引用）
python3 scripts/report_builder.py check --file findings/FINDING-001.md

# 汇总所有发现为清单
python3 scripts/report_builder.py summary --dir findings/ --output SUMMARY.md
模板：references/templates/report-template.md
定级标准：references/methodology/04-cvss-scoring.md
渐进式加载指引
不要一次性读所有文件。 按当前阶段需要加载：
当前处境
加载
刚开始，拿到一个目标
本文件 + methodology/00-authorization.md
范围已确认，做信息收集
methodology/01-recon.md
要做资产枚举
methodology/02-enum.md
锁定某类漏洞开始测
playbooks/00-index.md → 对应 playbook
需要具体 payload
payloads/ 下对应文件
被 WAF 拦了
payloads/waf-bypass.md
遇到不认识的组件
dictionaries/
要写报告
templates/report-template.md + methodology/04-cvss-scoring.md
快速开始
# 1. 初始化范围清单
python3 scripts/scope_guard.py init --output scope.yaml
# 2. 填写 in-scope / out-of-scope 后校验目标
python3 scripts/scope_guard.py check --scope scope.yaml --target-api targets.txt
# 3. 整理资产清单
python3 scripts/asset_organizer.py import --input recon_raw.txt --output assets.yaml
# 4. 生成发现报告
python3 scripts/report_builder.py new --output findings/FINDING-001.md
再次强调：任何脚本、任何 playbook 的执行，都建立在"授权已确认 + 目标在范围内"的前提上。没有这个前提，整个工作流不启动。
