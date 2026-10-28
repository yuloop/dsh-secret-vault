[**中文**](CHANGELOG.md) | [English](CHANGELOG.en.md)

# 更新记录

## 4.5.0

三个问题都来自一次真实会话（插件被用了一上午，卡住两次）：

- **守卫收窄**：以前只要有**任何**参数里出现私密目录字符串就拒绝整个调用，连 `compress` 摘要、
  给别的 agent 的报告、只把目录写成变量名的脚本都被拦。现在只拦「参数是路径/命令且指向私密目录」
  的调用（`file_path` / `command` / `cwd` / `paths` … 或值本身是绝对路径）。
  `date`、`ls /var/tmp`、`php -l` 这类无关命令照常。
- **顺手修掉一个更严重的**：调用方没有 session id 时（`exec.agent` 缺失），旧代码
  `!owner && store.hasFiles()` 会拒绝**所有**工具 —— 一个拿不到会话身份的子代理或宿主内部调用，
  会让整机会话的工具全挂。现在只在触碰私密目录时拒绝。
- **新原语 `write_secret`**（最关键）：`private_local_process({operation:"write_secret",
  reference, target, key_path, mode})` 把保险库里的值直接写进目标配置文件的指定键。
  支持 `.env`/`.ini`/`.properties`/`.yml`/`.toml`/`.json`（点分路径）/`.php`/`.js`/`.ts`
  （`define('K',…)` 或 `'K' => …`）；文件不存在时按目标格式生成初始内容。
  返回只有 `{ok, status, target, keyPath, changed, fingerprint(8 位)}` —— **正文永不返回**。
  只改匹配到的那一处值，其余字节原样保留；保留原文件权限位。
- **`private_local_status` 一次调用给出稳定状态**：`mode: local_only | normal`、
  `restricts`（现在只限什么）、`openTools`（什么还能用）、`releaseWhen`（怎么解除）。
- **出口打码**：任何工具的返回在进入上下文前，命中 `sk-`/`AKIA`/`ghp_`/JWT/`Bearer`
  等高熵凭据样式一律替换成「前 4 字符 + 指纹」。挡的是 agent 自己 `sed`/`grep` 手滑
  （真实事故：一条没遮干净的 `sed` 把 DashScope key 打进会话记录）。按 token 线性扫描，
  1 MB 日志 ~114 ms；不误伤路径、git sha、UUID、`tmp-` 句柄。
- 守卫的拒绝信息改成给出路（要写配置就调 `write_secret`），不再只说「暂停」。

## 4.4.1

- 修 5 条 PII 误报：拉丁标签词（`code` / `name`）缺词边界，`postcode` / `decode` / `username` /
  `hostname` 里的词组会把同句数字当成验证码、把后缀当成姓名标签。
- 地址、证件/账号类取值改为在子句边界与下一个标签前收手，不再跨字段吞掉后面的手机号/账号。
- 验证码的「同句」判定补上中英文逗号与顿号：银行短信里 `验证码：123456，您正在支付 5000 元`
  不再把金额报成第二个验证码。
- 上述 5 类各补回归用例。

## 4.4.0

- 内容分类（`provider-config` / `server-login` / `db-credential` / `bank-sms` / `identity` /
  `api-keys` / `mixed` / `unknown`），带敏感级、依据与建议动作。
- 掩码骨架分类：分类器永远看不到值，占位符定长。
- TF-IDF 字符 n-gram 线性兜底（144 KB，< 1 ms）+ 带门禁的评测脚本。
- 带校验位的 PII 识别（GB 11643 身份证、Luhn + 发卡行前缀、手机号号段、同句验证码）。
- 老条目在启动时自动升级摘要。

## 4.3.0

- **破坏性变更**：保存文件不再锁会话。锁会在最需要使用文件的一刻冻结所有工具；
  字节改由「拒绝点名存储的调用」保护。
- 旧版遗留锁继续生效，并在最后一个文件消失时自动解除。

## 4.1.0 – 4.2.0

- 逐条删除，二次确认；`POST /api/secret-vault/delete`。
- 锁住的会话仍可调用 `ask_user_question`（它永远带不走值）。
- 宿主机救援命令；存储清空即自动解锁；fail-closed 收窄。
- 插入失败自动重试一次，再退到剪贴板。

## 4.0.x

- 改为本地投放：明文只落本机随机文件，离开的只有句柄。
