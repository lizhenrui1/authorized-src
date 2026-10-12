Playbook 索引
所有 playbook 采用统一结构，便于快速定位：
1. 攻击面与入口      —— 去哪找
2. 测试流程          —— 怎么测（分步骤）
3. Payload 速查      —— 用什么
4. 响应特征判读      —— 看什么
5. 影响判定与定级    —— 值多少
6. 扩大化思路        —— 怎么提分
7. 边界红线          —— 不能做什么
按漏洞类型选
#
Playbook
文件
优先级
01
访问控制 / IDOR / 越权
01-authz-idor.md
★★★★★
02
认证与会话（密码重置/JWT/OAuth/MFA）
02-auth-session.md
★★★★★
03
SQL 注入（含 NoSQL）
03-sqli.md
★★★★☆
04
XSS（反射/存储/DOM/盲打）
04-xss.md
★★★☆☆
05
SSRF / 缓存投毒
05-ssrf-cache.md
★★★★☆
06
RCE / 注入类（反序列化/SSTI/XXE/命令）
06-rce-injection.md
★★★★★
07
文件上传 / 路径穿越
07-file-upload-traversal.md
★★★★☆
08
业务逻辑缺陷（支付/竞态/CSRF）
08-logic-flaws.md
★★★★★
09
API / GraphQL / WebSocket
09-api-graphql-ws.md
★★★★☆
10
信息泄露与未授权访问
10-info-disclosure.md
★★★☆☆
11
移动端与客户端
11-mobile-client.md
★★★☆☆
按观察到的现象选
你看到什么
去看
URL 里有 id=123、order_id=、uid=
01 越权
登录/注册/找回密码/SSO
02 认证
搜索框、排序、筛选、报表
03 SQLi
输入回显在页面上
04 XSS（同时看 03）
URL 参数是网址（url=、callback=、webhook）
05 SSRF
上传头像/附件/导入 Excel
07 上传（同时看 06）
支付、退款、优惠券、积分、订单
08 逻辑
前端调 /api/... 返回 JSON
09 API（同时看 01）
响应头有 X-Powered-By、报错堆栈
10 信息泄露
有 App 包
11 移动端
通用开局动作（任何目标都先做）
1. 确认自己有两个账号（A/B）——越权、CSRF、盲打都要用
2. 打开 Burp，把浏览全部功能的过程录下来
3. 重点标注入参：id、uid、file、url、path、redirect、role、amount
4. 每个参数问三个问题：
   - 改成别人的值会怎样？（越权）
   - 塞入特殊字符会怎样？（注入）
   - 删掉/置空/改类型会怎样？（逻辑）
5. 每个接口都试一次"未登录访问"（未授权）
6. 每个接口都试一次"低权限访问"（垂直越权）
高价值信号（看到就深挖）
- 响应里有递增数字 ID → 越权
- 响应里有 role、is_admin、status 字段 → 批量赋值/越权
- 前端隐藏字段（type=hidden、disabled）→ 参数篡改
- 接口返回的数据比自己请求的多 → 过度数据暴露
- 报错信息含框架/路径/SQL → 注入与信息泄露
- 一个操作对应多个请求 → 竞态
- 金额/数量由前端传 → 逻辑绕过
- 接口用 POST 但改成 GET 也能用 → 权限校验缺失
相关 MCP / 工具锚点
Playbook
建议工具
用途
04 XSS
浏览器自动化 + CDP
验证 DOM XSS 执行
06 RCE
JS hook / AST 反混淆
分析前端加密逻辑
07 上传
代理拦截
观察上传与访问路径
09 API
浏览器 DevTools / HAR 导出
提取接口
11 移动端
adb / Frida
证书固定绕过、内存验证
工具使用前提：目标在授权范围内，且平台规则允许该类工具。
使用建议
1. 先读本索引，确定方向
2. 只加载需要的 playbook（渐进式，别一次读全部）
3. 每个 playbook 的第 7 节红线必须读完再动手
4. 测试中发现新线索 → 回到索引重新路由
