[**中文**](CHANGELOG.md) | [English](CHANGELOG.en.md)

# 更新记录

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
