00 · 授权与范围管理
本文件是整个技能的地基。没有通过这一关，后面所有内容都不适用。
一、什么算"有授权"
只有以下情形可以认定为授权成立：
情形
认定依据
需留存的证据
公开赏金平台项目
平台项目页面明确列出该资产为 in-scope
项目 URL、页面截图、scope 原文
企业众测
众测活动规则 + 报名成功记录
活动页面、规则截图
委托渗透测试
双方签署的授权书 / SOW / 合同
授权书编号、有效期、授权范围条款
自有资产
用户自身拥有该系统
用户声明（需明确确认）
不成立的情形（即使技术上很容易）：
- "这个站看起来没人管" —— 不成立
- "我只是扫一下端口不深入" —— 不成立
- "我在学习安全，拿它练手" —— 不成立
- "公开的漏洞本来就该被修" —— 不成立
- "客户口头说可以" —— 需书面或平台规则佐证
二、授权确认清单
向用户收集以下信息，逐项确认。1、2 项缺失则终止。
[ ] 1. 目标来源
       - 平台名称 / 项目名称 / 委托方名称
       - 项目链接（若为平台项目）

[ ] 2. 授权范围（in-scope）
       - 域名清单（支持通配符，如 *.example.com）
       - IP / CIDR 段
       - 明确路径或 API 前缀（若有细分）
       - App 包名 / Bundle ID（移动端）

[ ] 3. 排除范围（out-of-scope）
       - 第三方托管服务（如 example.zendesk.com）
       - 关联公司 / 收购业务
       - CDN 源站、共享基础设施
       - 特定路径（如 /admin 需另行授权）

[ ] 4. 测试窗口与频率
       - 允许的时段
       - 速率限制（rps / 并发数）
       - 是否禁止自动化扫描

[ ] 5. 禁止行为（平台规则）
       - 是否禁止 DoS
       - 是否禁止社工
       - 是否禁止上传文件
       - 是否禁止访问真实用户数据
       - 其他特殊限制

[ ] 6. 报告要求
       - 提交渠道
       - 语言要求
       - 格式模板
       - 是否要求 CVSS 版本
三、边界模糊时的处理原则
遇到以下模糊情形，一律按最保守方式处理：
模糊情形
处理方式
域名不在清单，但明显属于同一企业
视为范围外，先向用户/平台确认
子域在清单，但解析到第三方云服务
视为范围外（除非项目明确包含）
目标提供 API 但未在 scope 中列出
若属同一域名的路径则可测；独立域名视为范围外
发现的新资产
先记录，回到本文件重新校验，确认后才可测
平台规则与常识冲突
以平台规则为准
不清楚是否算"副作用"
视为副作用，不做
核心原则：不确定 = 不做。
四、范围清单文件格式
使用 scripts/scope_guard.py init 生成，格式如下：
project:
  name: "示例众测项目"
  source: "https://platform.example.com/program/xxx"
  authorized_by: "甲方安全部 / 平台规则"
  valid_until: "2026-12-31"
  notes: "禁止 DoS，自动化扫描限速 10 rps"

in_scope:
  domains:
    - "example.com"
    - "*.example.com"          # 通配符匹配任意子域
    - "api.example.com"
  ips:
    - "203.0.113.0/24"         # CIDR 段
    - "198.51.100.10"
  urls:
    - "https://app.example.com/*"
  mobile:
    - "com.example.app"

out_of_scope:
  domains:
    - "blog.example.com"       # 第三方博客托管
    - "*.zendesk.com"
    - "*.statuspage.io"
  ips:
    - "203.0.113.200"          # CDN 源站
  notes: "排除第三方 SaaS、关联公司 example-holdings.com"

constraints:
  max_rps: 10
  no_dos: true
  no_automated_scanning: false
  no_file_upload: false
  no_real_user_data: true
  test_window: "工作日 09:00-18:00"
五、授权档案留存
测试开始前，在工作目录建立授权档案：
project/
  scope.yaml                 # 机器可读范围清单
  authorization/
    01-project-page.png      # 平台项目页截图
    02-scope-text.md         # scope 原文摘录
    03-rules.md              # 平台规则要点
    04-authorization.pdf     # 授权书（委托测试）
留存理由：一旦出现范围争议，这是唯一的自证材料。报告提交时也可作为附录。
六、测试过程中的范围再校验
以下时点必须重新校验范围：
1. 每发现一个新子域 / 新资产时
2. 每次切换测试目标时
3. 每个阶段（recon → enum → hunt）开始时
4. 跨域跳转、发现关联系统时
# 单个校验
python3 scripts/scope_guard.py check --scope scope.yaml --target new-asset.example.com

# 批量校验（目标列表每行一个）
python3 scripts/scope_guard.py check --scope scope.yaml --targets discovered.txt

# 解析目标所属范围（调试用）
python3 scripts/scope_guard.py explain --scope scope.yaml --target dub.example.com
DENY / UNKNOWN 的处理：立即停止对该目标的任何动作；若是测试中意外触达（如重定向跳转），记录并断开，不继续深入。
七、红线速查（每次测试前默读）
不做副作用   不发短信/邮件/扣款/改数据/改配置
不窃数据     不 dump、不批量导出、不下载用户数据
不越界       不打范围外、不碰第三方、不碰关联公司
不破坏       不做 DoS、不高并发、不资源耗尽
不留后门     不上传 webshell、不留持久化
不滥用凭据   拿到凭据只验证存在，不连接生产
不横向       不以目标为跳板
不社工       不钓鱼、不电话、不入企
不公开       未修复前不披露、不售卖
不越权测试   无授权一律不测
八、如果用户没有授权
不要进入流程，按以下方式回应：
1. 说明限制：明确告知本技能只用于授权场景，无法对未授权目标执行测试。
2. 提供路径：说明如何获取授权——注册赏金平台、联系企业 SRC、走正式委托流程。
3. 提供替代：可以帮忙做防御侧工作，例如：
  - 针对自有系统做安全自查清单
  - 编写安全编码规范
  - 分析已知 CVE 对自己系统的影响
  - 搭建本地靶场（DVWA、Juice Shop、Pikachu 等）练习
4. 不提供：不提供针对具体未授权目标的任何攻击性技术指导。
靶场练习是完全合规的替代方案，推荐路径：本地 Docker 起 OWASP Juice Shop / DVWA / WebGoat，本技能的所有 playbook 同样适用。
