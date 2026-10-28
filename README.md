[**中文**](README.md) | [English](README.en.md)

# dsh-secret-vault

把密钥、API key、身份证、手机号这类东西粘进 DSH 网页的私密面板，**让 agent 拿着它干活，却读不到它**。
插件把正文落在本机一个随机名文件里，只交给模型一个不透明句柄和一份不含值的摘要；
**参数里用路径或命令指向私密目录的调用**一律拒绝，其余工具照常可用。

```text
你粘贴 ──► 本机文件（0600，随机名）            ← 正文只存在这里，不进聊天/日志
                │
                ├─► 句柄 + 字段摘要 ──► 模型    （网址、模型名、密钥长度+指纹、PII 类型、内容类型）
                └─► 掩码骨架 ──► 分类器         （[[SECRET]] / [[PII]] / [[URL]]，定长）
```

## 为什么要它

贴在聊天里的密钥是永久的：进会话日志、进发给模型服务商的请求、进这些数据的每一份备份。
这个插件把「交接」从聊天通道里挪出来，于是 agent 能用一把凭据，而明文从未进入它的上下文。

## 它做什么

- **本地投放箱**：随机 `tmp-<32 hex>` 文件名，目录 `700`、文件 `600`、单份上限 128 KiB；
  每天 04:00 清理已用文件，未用文件 24 小时后过期。
- **确定性字段抽取**（不用模型，< 1 ms）：网址、模型名、密钥（长度 + 指纹）、
  PII（大陆身份证走 GB 11643 校验位、银行卡走 Luhn + 发卡行前缀、手机号走号段、
  验证码要求同句关键词、邮箱）、标签、JSON 路径。
- **内容分类**（规则 → TF-IDF 线性模型 → 拒判）：`provider-config`、`server-login`、
  `db-credential`、`bank-sms`、`identity`、`api-keys`、`mixed`、`unknown`，
  外加 `sensitivity`、`confidence`、可审计的 `evidence` 和一行 `advice`。
- **先掩码再分类**：分类器只看到 `[[SECRET]]` / `[[PII]]` / `[[URL]]` 占位符
  （定长——带长度的占位符本身就是侧信道）。
- **守卫（4.5.0 收窄）**：只拒「参数是路径/命令且指向私密目录」的调用（`file_path`、`command`、
  `cwd`、`paths`…），`read`/`cat`/glob 拿不到字节；`date`、`ls /var/tmp`、`php -l` 这类无关命令
  以及在消息/摘要里**提到**目录都照常。理由：旧规则把「写报告给别的 agent」「压缩摘要里提路径」
  一起拦了，等于让会话没法反映问题，却挡不住真要绕的人。
- **出口打码（4.5.0）**：任何工具的返回进上下文前，`sk-`/`AKIA`/`ghp_`/JWT/`Bearer` 等高熵凭据
  样式自动替换成「前 4 字符 + 指纹」。防的是 agent 自己 `sed`/`grep` 手滑。
- **宿主机救援命令**：`secret-vault status | fields | release | purge | cleanup`；不需要浏览器，永不打印值。
- **fail-closed 收窄**：存储坏掉时只拒「会碰到存储的调用」，不再冻结所有会话的工具。

分类结果只是**建议**：这里没有任何东西会自动触发动作。把银行短信当成供应商配置去调接口是不可逆的，
所以界面只标标签，由人确认。

## 安装

DSH bundle，从 Git 安装：

```bash
# 在 DSH 插件管理器里添加 bundle spec
git+https://github.com/yuloop/dsh-secret-vault
```

或者把插件市场索引加进去，它就会出现在「发现」页（设置 → 插件 → 插件市场 → 添加索引 URL）：

```text
https://raw.githubusercontent.com/yuloop/dsh-secret-vault/main/marketplace/index.json
```

## 用法

1. 点输入框旁的钥匙图标，粘贴任何东西（一把密钥、一段配置、一条银行短信、句子中间夹着值的杂乱文本）。
2. 保存。面板显示一行：`模型供应商配置 · 敏感:secret · 网址2 · 模型1 · 密钥1`。
3. 直接说要做什么。模型调用 `private_local_status` 拿句柄、按摘要行事——不需要你把路径粘进聊天。
4. 用完删除（二次确认），或等每日清理。

## 暴露给模型的工具

| 工具 | 返回 |
|---|---|
| `private_local_status` | `mode`（`local_only`/`normal`）、限制了什么、什么还能用、怎么解除、句柄与 `shape`（类型/敏感级/依据/建议/计数），不含任何值 |
| `private_local_process` | 六种固定文本变换（`copy`、`trim_edges`、`normalize_newlines`、`json_pretty`、`json_compact`、`dedupe_lines`），返回状态和新句柄 |
| `private_local_process` + `operation:"write_secret"` | **把值写进目标配置文件的指定键**（`.env`/`.ini`/`.properties`/`.yml`/`.toml`/`.json`/`.php`/`.js`/`.ts`），返回 `{ok, status, target, keyPath, changed, fingerprint}` —— 值不出现在返回里 |

没有删除工具、没有 shell、没有 HTTP：模型够不到字节，只能在它周围干活。

`write_secret` 就是「换 API key」这个最典型的用法：

```json
{"reference": "tmp-<32hex>", "operation": "write_secret",
 "target": "/root/project/config/secrets.local.php", "key_path": "AI_API_KEY", "mode": "first-secret"}
```

`mode: "whole"`（默认）取整个文件去首尾空白；`first-secret` 取文件里识别到的第一个密钥
（取最紧的跨度，不会把后面的散文一起写进目标文件）。目标文件不存在时按它自己的格式生成初始内容；
已存在时只改匹配到的那一处值，其余字节与权限位原样保留。

## 宿主机命令

```bash
secret-vault status [session]        # 列出条目与锁定状态（只读）
secret-vault fields   [id]           # 字段摘要 + 分类，永不打印值
secret-vault cleanup                 # 立即执行 04:00 的清理
secret-vault purge <session> --yes   # 删除该会话的文件（不可恢复）
```

没有软链时等价写法：`node bin/secret-vault.mjs …`。

## 安全模型——保证什么、不保证什么

**构造上保证：**

- 正文从不经过聊天、附件或 LLM 通道；
- 私密内容的工具结果只带类型、长度和指纹；
- 分类器只看掩码骨架，骨架永不落盘；
- `state.json` 不含任何值（有测试直接 grep `state.json` 断言）。

**不保证：**

- **操作系统级隔离**。DSH 以单一用户运行；其他进程、其他插件、备份、任何 root shell 都能读到文件。
  把私密内容搬进独立低权限进程是后续工作。
- 蓄意构造的脚本仍可把值带出去；守卫拦的是误操作，不是恶意。
- 用密钥配置过的东西自己会留一份明文副本（这正是「用起来」的意思）。

## 开发

```bash
npm test                          # 102 个测试：解析、PII 校验、分类、路由、运行时、打码、write_secret
node tools/train-tfidf.mjs        # 重训 144 KB 线性分类器（合成语料）
node tools/eval-classify.mjs      # 门禁：高危错判 0 · 拒判 ≤25% · P99<100ms · macro-F1≥0.85
```

评测语料是合成的，所以 0.897 的 macro-F1 只能当上限；harness 已经搭好，换成真实样本即可复核。

MIT 许可。
