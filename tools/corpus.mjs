/**
 * Synthetic corpus for training and evaluating the content classifier.
 * Everything here is masked-style text (values already replaced by [[SECRET]]/[[PII]]/[[URL]]),
 * which is exactly what the classifier sees at runtime. Two seeds must never share samples:
 * train with TRAIN_SEED, evaluate with a different one.
 */
const CH = 'abcdefghijklmnopqrstuvwxyz0123456789'
const rnd = state => () => ((state = (state * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff)

function pick(r, list) { return list[Math.floor(r() * list.length) % list.length] }
const digits = (r, n) => Array.from({ length: n }, () => CH[Math.floor(r() * 10)]).join('')
const modelName = r => pick(r, ['deepseek-v4.1-flash-1017', 'qwen3.5-4b', 'gpt-5-mini', 'grok-4-fast', 'glm-4.6'])
const ip = r => `${pick(r, ['198.51.100', '192.0.2', '203.0.113'])}.${Math.floor(r() * 200) + 2}`
const port = r => String(pick(r, ['22', '22022', '3306', '5432', '6379', '8080', '20128']))
const bank = r => pick(r, ['招商银行', '工商银行', '建设银行', '支付宝', '微信支付'])
const name = r => pick(r, ['张三', '李四', '王五', '赵六'])
const amount = r => pick(r, ['58', '500', '5000', '12800', '399.9'])
const svc = r => pick(r, ['openai', '阿里云', 'deepseek', 'stepfun', 'qiniu'])

const BUILDERS = {
  'provider-config': r => pick(r, [
    `为 [[URL]] 增加一个模型供应商，模型 ${modelName(r)}，密钥 [[SECRET]]`,
    `供应商配置：base_url [[URL]]，api_key [[SECRET]]，model ${modelName(r)}`,
    `渠道 ${pick(r, ['bj-fenliu', 'tokenrhythm', '9router'])} 地址 [[URL]] 模型 ${modelName(r)} key [[SECRET]]`,
    `接入 ${modelName(r)}，endpoint [[URL]]，apikey [[SECRET]]`,
  ]),
  'server-login': r => pick(r, [
    `服务器 ${ip(r)} 用户 root 密码 [[SECRET]] 端口 ${port(r)}`,
    `ssh root@${ip(r)} -p ${port(r)} 密码 [[SECRET]]`,
    `跳板机 ${ip(r)} 登录密码 [[SECRET]]，私钥在 [[SECRET]]`,
    `机器 ${ip(r)}：${port(r)} 端口，账号 app，密码 [[SECRET]]`,
  ]),
  'db-credential': r => pick(r, [
    `数据库 ${pick(r, ['mysql', 'postgres', 'redis'])} 地址 ${ip(r)}:${port(r)} 用户 app 密码 [[SECRET]]`,
    `mysql 连接串 [[URL]] 账号 app 密码 [[SECRET]]`,
    `生产库 ${ip(r)}，dbname prod，user app，pass [[SECRET]]`,
    `redis://${ip(r)}:${port(r)} 密码 [[SECRET]]`,
  ]),
  'bank-sms': r => pick(r, [
    `【${bank(r)}】您尾号${digits(r, 4)}的卡转出 ${amount(r)} 元。验证码：[[PII]]，5分钟内有效`,
    `${bank(r)} 提醒：账户余额 ${amount(r)} 元，验证码 [[PII]]`,
    `【${bank(r)}】支付成功 ${amount(r)} 元，尾号${digits(r, 4)}，校验码 [[PII]]`,
    `您的${bank(r)}账单已出，应还 ${amount(r)} 元，动态码 [[PII]]`,
  ]),
  identity: r => pick(r, [
    `姓名：${name(r)} 身份证 [[PII]] 住址：北京市海淀区`,
    `收件人 ${name(r)} 电话 [[PII]] 身份证号 [[PII]]`,
    `护照 [[PII]] 姓名 ${name(r)}，户籍地址 上海市浦东新区`,
    `${name(r)}，手机 [[PII]]，证件 [[PII]]`,
  ]),
  'api-keys': r => pick(r, [
    `API 清单：token [[SECRET]]`,
    `几个 key：${svc(r)} [[SECRET]]，${svc(r)} [[SECRET]]`,
    `密钥汇总：[[SECRET]] / [[SECRET]]`,
    `secret 列表 ${svc(r)}=[[SECRET]]`,
  ]),
  mixed: r => pick(r, [
    `姓名 ${name(r)} 身份证 [[PII]]，另附供应商 [[URL]] 密钥 [[SECRET]] 模型 ${modelName(r)}`,
    `客户 ${name(r)} 电话 [[PII]]，服务器 ${ip(r)} 密码 [[SECRET]]`,
    `银行验证码 [[PII]]，同时把 [[URL]] 的 key [[SECRET]] 换掉`,
  ]),
  unknown: r => pick(r, [
    '明天下午三点开会，记得带材料',
    '把那段日志再看一遍，确认有没有异常',
    '这次的方案先放着，等下周再评估',
    '帮我把这份文档的标题改一下',
    '这个接口的返回格式有点奇怪，你查一下',
  ]),
}

/** Harder variants: weaker keywords, so the rule layer is likelier to abstain. */
const HARD = {
  'provider-config': r => `要接一下 ${modelName(r)}，地址 [[URL]]，凭据 [[SECRET]]`,
  'server-login': r => `${ip(r)} 这台机器 root 的 [[SECRET]] 先记着`,
  'db-credential': r => `${ip(r)}:${port(r)} 上那个库的 [[SECRET]] 是新的`,
  'bank-sms': r => `刚才那笔 ${amount(r)} 的扣款验证码是 [[PII]]`,
  identity: r => `${name(r)} 的证件号 [[PII]]，手机 [[PII]]`,
  'api-keys': r => `${svc(r)} 换了个 [[SECRET]]`,
  mixed: r => `${name(r)} 的 [[PII]] 和 ${ip(r)} 的 [[SECRET]] 都在这里`,
  unknown: r => '这个先放一放，回头再说',
}

export const KINDS = ['provider-config', 'server-login', 'db-credential', 'bank-sms', 'identity', 'api-keys', 'mixed', 'unknown']

/**
 * @param seed integer seed (different seeds → disjoint samples)
 * @param perKind how many samples per kind
 * @param hardShare fraction of samples drawn from the weak-keyword templates
 */
export function buildCorpus(seed, perKind = 60, hardShare = 0.35) {
  const r = rnd(seed)
  const samples = []
  for (const kind of KINDS) {
    for (let i = 0; i < perKind; i++) {
      const hard = r() < hardShare
      const text = hard ? HARD[kind](r) : BUILDERS[kind](r)
      samples.push({ kind, text, hard })
    }
  }
  return samples
}
