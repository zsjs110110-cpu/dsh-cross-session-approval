/**
 * dsh-cross-session-approval 审批桥 —— 纯逻辑核心（零宿主依赖）。
 *
 * 本模块**不 import 任何 `@deepseek-ai/*` 宿主包**、不持有 cordis ctx：
 * 所有宿主事实经函数参数注入（ctx 只需暴露 `get(name)`），文件系统操作
 * 直接走 `node:fs` / `node:path`。`lib/index.js` 负责监听器与生命周期接线；
 * 本文件承载全部**同步**的授权 / 审计 / 路径 / 危险判定规则，使最小
 * harness 可以在无宿主环境下对它们做断言。
 *
 * 权限与审批契约见 README；宿主服务方法以 DSH 0.2.0-rc.2 为兼容基准。
 *
 * @module dsh-cross-session-approval/bridge-core
 */
import fs from 'node:fs';
import path from 'node:path';

/** 沙箱档位，按宽度升序（下标 = 宽度秩）。与 dsh-sandbox-policy 的 SANDBOX_MODES 一致。 */
export const SANDBOX_MODES = Object.freeze(['read-only', 'workspace-write', 'danger-full-access']);
/** 审批策略，按严格度升序（下标 = 严格度秩，0 = 最严）。never 短路提权，比 ask 更严。 */
export const APPROVAL_ORDER = Object.freeze(['never', 'ask']);
/** 已核验的提权工具（run_code / pwsh 及其 PTC 嵌套）；其余一律委托 UI。 */
export const VERIFIED_ESCALATORS = Object.freeze(new Set(['pwsh', 'run_code']));
/** 桥唯一可以返回给宿主的三种值（宿主 OUTCOMES 去掉 'unavailable'）。 */
export const HOST_OK = Object.freeze(new Set(['allowed-once', 'rejected', 'cancelled']));

/* ─────────────────────────── 审批 key ─────────────────────────── */

/**
 * 审批 key 的字符集：**base62**（A-Z a-z 0-9）。
 *
 * 使用 base62 审批 key，避免 UUID 在模型可见文本中被遮蔽：
 * 宿主/上游链路会把**模型可见文本**里「**32 位 hex**」或「**8-4-4-4-12 UUID**」形状的字符串
 * 整体替换成占位符（`00000000-0000-4000-8000-000000000000`）——**形状匹配，不看内容**
 * （大小写、带 `session-` 前缀都会被替换；而 base62 短码、纯数字、8/16 位短 hex 不受影响）。
 *
 * 后果：owner 是 **AI 会话**时，它从通知里**读到的 key 是占位符**，直接 `pending.get(key)`
 * 必然落空 ⇒ **审批失败**（要额外跑脚本从会话日志把真值编码带出来，既费时又费 token）。
 *
 * ⇒ 改用 base62 短码：**实测不被遮蔽**，通知里可直接读到，owner 一步即可批准。
 * 程序内部数据本就完好（遮蔽只作用于模型可见文本），故换 key 形状不影响任何内部逻辑。
 */
export const APPROVAL_KEY_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
/** key 的随机段长度（12 位 base62 ≈ 71 bit，远超单会话待决量级的碰撞需求）。 */
export const APPROVAL_KEY_BODY_LEN = 12;
/** key 前缀，便于在日志/通知里识别，同时确保首个字符非 hex-only 观感。 */
export const APPROVAL_KEY_PREFIX = 'apv_';

/**
 * 生成一个审批 key（base62 短码，**不被 UUID 遮蔽机制命中**）。
 * @param {() => number} [rand] 取 [0,1) 随机数的函数（测试可注入确定性实现）
 * @returns {string} 形如 `apv_I6Zj132gaBAa`
 */
export function makeApprovalKey(rand = Math.random) {
  let body = '';
  for (let i = 0; i < APPROVAL_KEY_BODY_LEN; i++) {
    const idx = Math.floor(rand() * APPROVAL_KEY_ALPHABET.length);
    body += APPROVAL_KEY_ALPHABET[idx < 0 ? 0 : (idx >= APPROVAL_KEY_ALPHABET.length ? APPROVAL_KEY_ALPHABET.length - 1 : idx)];
  }
  return APPROVAL_KEY_PREFIX + body;
}

/**
 * 校验一个字符串是否是本桥生成的审批 key 形状。
 * 用途：批准入口先做形状检查，给出**更准确的错误提示**（例如 owner 误把审计 id 当 key 传入时，
 * 可以明确告诉它"这不是桥 key"而不是笼统的"没有该 key 的待决请求"）。
 * @param {unknown} value
 * @returns {boolean}
 */
export function isApprovalKey(value) {
  if (typeof value !== 'string') return false;
  if (!value.startsWith(APPROVAL_KEY_PREFIX)) return false;
  const body = value.slice(APPROVAL_KEY_PREFIX.length);
  if (body.length !== APPROVAL_KEY_BODY_LEN) return false;
  for (const ch of body) if (APPROVAL_KEY_ALPHABET.indexOf(ch) < 0) return false;
  return true;
}

/**
 * ── 会话 id 别名（0.3.2）───────────────────────────────────────────────────────
 *
 * 与审批 key **同源**的遮蔽问题的**第二处受害者**：`session-<8-4-4-4-12 UUID>` 的
 * 44 字符会话 id，在**模型可见文本**里同样会被整体替换成占位符
 * （`session-00000000-0000-4000-8000-000000000000`）。
 *
 * 后果：`cross_session_list` 返回的 id 被复制后**无法**再喂给 `send` / `read` /
 * `rename` / `archive`——因为模型拿到的是占位符，不是真值。
 * **换工具读也没用**：遮蔽发生在「模型可见文本」层，`cmd /c dir` 一样被换。
 *
 * ⇒ 对策：为每个真实 id 派生一个 **base62 形状的短别名**（`cs_XXXXXXXXXX`），
 *   让模型只经手别名，由**程序自己**把别名解析回真实 id（程序内部数据不受遮蔽影响）。
 *
 * 设计要点：
 * 1. **确定性派生**（FNV-1a 64 位风格哈希 + 加盐），无需持久化映射表 ⇒ 重启后仍可解析；
 * 2. 别名**必须稳定**：同一 id 在任何时刻、任何进程算出的别名一致；
 * 3. 别名形状**刻意避开** hex-only 观感（前缀 `cs_` + base62 主体），且长度 10 位；
 * 4. 解析失败（未知别名/id）⇒ 返回 `undefined`，由调用方按原逻辑报错（fail-closed）。
 *
 * ⚠️ 别名是**寻址便利**，不是授权凭据：解析回真实 id 后，一切身份/权限判定仍按真实 id 走。
 */
export const SESSION_ALIAS_ALPHABET = APPROVAL_KEY_ALPHABET;
/** 别名主体长度（10 位 base62 ≈ 59 bit，单宿主会话量级下碰撞概率可忽略）。 */
export const SESSION_ALIAS_BODY_LEN = 10;
/** 别名前缀。 */
export const SESSION_ALIAS_PREFIX = 'cs_';
/** 派生盐：确保 `cs_` 别名与 `apv_` key 的哈希空间不重合。
 *  ⚠️ 改盐会导致所有已派生的 `cs_` 别名失效（旧别名寻址断，重新 list 拿新的）；
 *  v0.3.8 使用 `dsh-cross-session-approval` 作为命名空间；旧版别名需重新获取。 */
const SESSION_ALIAS_SALT = 'dsh-cross-session-approval:session-alias:v1:';

/**
 * 为一个真实会话 id 派生确定性别名。
 * @param {string} sessionId 真实会话 id（形如 `session-<uuid>`）
 * @returns {string} 形如 `cs_3fKpQ2mZaB`
 */
export function makeSessionAlias(sessionId) {
  const input = SESSION_ALIAS_SALT + String(sessionId);
  // FNV-1a 64 位（用 BigInt 保证不丢精度），再逐位取 base62。
  const FNV_OFFSET = 0xcbf29ce484222325n;
  const FNV_PRIME = 0x100000001b3n;
  const MASK64 = (1n << 64n) - 1n;
  let hash = FNV_OFFSET;
  for (let i = 0; i < input.length; i++) {
    hash = ((hash ^ BigInt(input.charCodeAt(i))) * FNV_PRIME) & MASK64;
  }
  // 用 64 位哈希生成足够长的 base62 串（再混入一轮重哈希，避免只用低位）。
  let body = '';
  let h = hash;
  for (let i = 0; i < SESSION_ALIAS_BODY_LEN; i++) {
    const idx = Number(h % 62n);
    body += SESSION_ALIAS_ALPHABET[idx];
    h = ((h ^ (h >> 13n)) * FNV_PRIME) & MASK64;
    h = h === 0n ? hash : h; // 防御：极端情况下保持非零循环
  }
  return SESSION_ALIAS_PREFIX + body;
}

/**
 * 校验一个字符串是否是本插件生成的会话别名形状。
 * @param {unknown} value
 * @returns {boolean}
 */
export function isSessionAlias(value) {
  if (typeof value !== 'string') return false;
  if (!value.startsWith(SESSION_ALIAS_PREFIX)) return false;
  const body = value.slice(SESSION_ALIAS_PREFIX.length);
  if (body.length !== SESSION_ALIAS_BODY_LEN) return false;
  for (const ch of body) if (SESSION_ALIAS_ALPHABET.indexOf(ch) < 0) return false;
  return true;
}

/**
 * 把用户给的「会话标识」解析成真实会话 id。
 *
 * - 若是 `session-<uuid>` 形态 ⇒ 原样返回（真实 id 直接可用）；
 * - 若是 `cs_XXXXXXXXXX` 别名 ⇒ 在候选集中查找匹配的真实 id；
 * - 其它（含被遮蔽的占位符 id）⇒ 返回 `undefined`。
 *
 * **故意不猜测**：别名解析不出来就是解析不出来（fail-closed），
 * 绝不用"唯一近似匹配"之类启发式，否则会把操作导向**错误的会话**。
 *
 * @param {string} input 用户提供的标识（id 或别名）
 * @param {Iterable<string>} candidates 候选真实 id 集合（列表/登记表的键）
 * @returns {string|undefined} 真实 id；无法解析时 undefined
 */
export function resolveSessionRef(input, candidates) {
  if (typeof input !== 'string' || input === '') return undefined;
  // 0) 被遮蔽的占位符 id **必须拒绝**：它是显示层替换的产物，不是真 id。
  //    若放行，会把操作指向一个"长得像 id"的伪目标（宿主查不到）⇒ 必须 fail-closed。
  if (isMaskedPlaceholderId(input)) return undefined;
  // 1) 别名形态：在候选集里找派生结果相等的那个。
  if (isSessionAlias(input)) {
    for (const id of candidates ?? []) {
      if (typeof id === 'string' && makeSessionAlias(id) === input) return id;
    }
    return undefined;
  }
  // 2) 其余一律**原样透传**（含 `session-<uuid>` 真 id，以及宿主/测试环境里的
  //    非标准 id）。本插件**不做 id 形状校验**——那是宿主的职责；这里只负责
  //    "把别名还原成真 id"与"挡住已确认的遮蔽产物"两件事。
  //    透传后若 id 无效，由下游（ensureLiveAgent / readSession）按其原有逻辑报错。
  return input;
}

/**
 * 判断一个标识是否**看起来像被遮蔽的占位符 id**（用于给出更准确的错误提示与拒绝）。
 *
 * 遮蔽产物有两种：`00000000-0000-4000-8000-000000000000`（裸 UUID）
 * 与 `session-00000000-0000-4000-8000-000000000000`（带 `session-` 前缀）。
 *
 * ⚠️ 该判据只用于**提示与拒绝**，不承担任何授权语义：真 id 与占位符无法由形状完全区分
 * （理论上真 id 也可能恰好全零），因此仅在解析入口做"拒绝更安全"的保守处理。
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isMaskedPlaceholderId(value) {
  if (typeof value !== 'string') return false;
  // 占位符是 **UUID v4 形状**（第三段以 4 开头、第四段以 8 开头），不是全零！
  // 实测产物：`00000000-0000-4000-8000-000000000000`（可带 `session-` 前缀）。
  return /^(?:session-)?0{8}-0{4}-4000-8000-0{12}$/.test(value);
}

/* ─────────────────────────── 严格路径 ─────────────────────────── */

/**
 * 严格规范化：realpath，失败即 undefined —— **绝不回退原拼写**。
 * 这是授权事实，不是便利函数：宿主 dsh-sandbox 的 canonicalPath 失败时
 * 保留原拼写，那套策略**不能**用于包含关系证明。
 * @param {string} p - 必须是绝对路径；相对路径直接拒绝（解析基准不可信）。
 * @returns {string|undefined} 规范化后的真实路径；任何失败（不存在/无权限/
 *   符号链接环/非绝对/异常）均返回 undefined。
 */
export function canonicalPathStrict(p) {
  if (typeof p !== 'string' || p === '') return undefined;
  if (!path.isAbsolute(p)) return undefined;
  try {
    const real = fs.realpathSync.native(p);
    if (typeof real !== 'string' || real === '' || !path.isAbsolute(real)) return undefined;
    // 验证解析结果是目录（普通文件不应被接受为 cwd/workspaceRoot）
    const stat = fs.statSync(real);
    if (!stat.isDirectory()) return undefined;
    return real;
  } catch {
    return undefined;
  }
}

/**
 * 严格包含：root ⊇ p，两侧都 realpath（Windows junction 指向外部 ⇒ 不包含）。
 * 任一侧解析失败 ⇒ false（判"不包含"，不判"无法判断"后放行）。
 */
export function canonicalContains(root, p) {
  const rr = canonicalPathStrict(root);
  const pp = canonicalPathStrict(p);
  if (rr === undefined || pp === undefined) return false;
  const rel = path.relative(rr, pp);
  if (rel === '') return true;            // 同一目录（child root 可以等于 caller root）
  if (rel.startsWith('..')) return false; // 在 root 外
  if (path.isAbsolute(rel)) return false; // 跨盘符（Windows）
  return true;
}

/* ─────────────────────────── 档位 / 审批 ─────────────────────────── */

/**
 * 从审计 reason 提取目标档位。宿主沙箱审批 reason 的格式：
 * `escalate sandbox to <mode>: <justification>`。
 * 只有"目标档位"是宿主事实；justification 是模型措辞，**不作权限事实**。
 * 严格枚举：格式不符 / 档位未知 ⇒ undefined。
 */
export function parseSandboxMode(reason) {
  if (typeof reason !== 'string') return undefined;
  const m = /^escalate sandbox to (read-only|workspace-write|danger-full-access)(?=:)/.exec(reason);
  return m === null ? undefined : m[1];
}

/**
 * 三维夹紧的纯计算（无 ctx）：
 * - 缺省（spec=undefined）：档位 = min(调用者, DSH默认)；审批 = 更严者。
 * - 显式预设 spec：两个维度都不得宽于调用者，否则 throw（显式更宽 ⇒ 拒绝，
 *   不静默夹紧；预检与 listener 共用同一判定）。
 * @returns {{mode: string, approval: string}}
 */
export function clampTarget(callerMode, callerApproval, defaultSandbox, defaultApproval, spec = undefined) {
  const ci = SANDBOX_MODES.indexOf(callerMode);
  const ca = APPROVAL_ORDER.indexOf(callerApproval);
  const di = SANDBOX_MODES.indexOf(defaultSandbox);
  const da = APPROVAL_ORDER.indexOf(defaultApproval);
  if (ci < 0 || ca < 0 || di < 0 || da < 0) {
    throw new Error('clampTarget: 输入含未知档位或审批策略（四个值都必须是已知值）');
  }
  if (spec !== undefined) {
    const wi = SANDBOX_MODES.indexOf(spec.sandbox);
    const wa = APPROVAL_ORDER.indexOf(spec.approval);
    if (wi < 0 || wa < 0) throw new Error('clampTarget: 预设取值无法识别');
    if (wi > ci) throw new Error(`拒绝：预设档位宽于调用者（${callerMode}）`);
    if (wa > ca) throw new Error('拒绝：预设审批策略比调用者更宽松');
    return { mode: spec.sandbox, approval: spec.approval };
  }
  return {
    mode: di <= ci ? defaultSandbox : callerMode,      // min（下标取小）
    approval: da <= ca ? defaultApproval : callerApproval, // 更严者（never < ask）
  };
}

/**
 * 显式 permission 预设的纯比较预检（服务查询由调用方做）。
 * 未知 / 更宽 ⇒ throw；通过 ⇒ 返回 {mode, approval}。
 */
export function precheckPresetSpec(name, spec, callerMode, callerApproval) {
  const ci = SANDBOX_MODES.indexOf(callerMode);
  const ca = APPROVAL_ORDER.indexOf(callerApproval);
  if (ci < 0 || ca < 0) {
    throw new Error(`预检：调用者策略无法识别（档位=${String(callerMode)}，审批=${String(callerApproval)}）`);
  }
  const wi = spec !== undefined && typeof spec === 'object' ? SANDBOX_MODES.indexOf(spec.sandbox) : -1;
  const wa = spec !== undefined && typeof spec === 'object' ? APPROVAL_ORDER.indexOf(spec.approval) : -1;
  if (wi < 0 || wa < 0) throw new Error(`预检：预设 "${name}" 的取值无法识别`);
  if (wi > ci) throw new Error(`拒绝：预设 "${name}" 的档位宽于调用者（${callerMode}）`);
  if (wa > ca) throw new Error(`拒绝：预设 "${name}" 的审批策略比调用者更宽松`);
  return { mode: spec.sandbox, approval: spec.approval };
}

/**
 * 调用者策略与 spawn 快照比对：任何一维变化 ⇒ 派活拒绝。
 * （快照只用于**比对**，绝不当授权依据；授权永远用监听器里重新解析的当前值。）
 */
export function callerPolicyUnchanged(intent, now) {
  return now.mode === intent.callerMode
    && now.workspaceRoot === intent.callerRoot
    && now.approval === intent.callerApproval;
}

/**
 * 三方档位一致性：① 审计（真话）== ② 收到的 request.reason == ③ 入口 sandbox_permissions。
 * ② 可被 internal/dispatch 载荷替换、③ 可被入口包装器改动；① 是宿主已提交的审计事实。
 * 任一不一致 / 解析不出 ⇒ false（桥不接管，回落 UI）。
 */
export function triPartiteModeConsistent(auditMode, wireReason, entryMode) {
  if (typeof auditMode !== 'string' || SANDBOX_MODES.indexOf(auditMode) < 0) return false;
  if (parseSandboxMode(wireReason) !== auditMode) return false;   // ② ≠ ①
  return entryMode === auditMode;                                 // ③ ≠ ①
}

/* ─────────────────────────── 审计绑定 ─────────────────────────── */

/**
 * 会话当前开放 turn 内**唯一未配对**的 own `approval/asked`。
 * 规则：
 * - `isOwnSeq` 排除继承前缀（fork 过来的历史事件不算）；
 * - 未开放 turn（没有 own turn/start，或已被 own turn/end 闭合）⇒ undefined；
 * - 未配对 = 没有同 id 的 own `approval/decided`（已配对的历史请求不补位）；
 * - 0 个或 >1 个未配对 ⇒ undefined（歧义不猜"最近一条"）。
 * @returns {{asked: object, seq: number, turnStartSeq: number}|undefined}
 */
export function ownUnpairedApprovalAsked(session) {
  if (session === null || typeof session !== 'object') return undefined;
  const isOwn = typeof session.isOwnSeq === 'function' ? session.isOwnSeq.bind(session) : (seq) => true;
  const snap = typeof session.snapshotEvents === 'function' ? session.snapshotEvents() : undefined;
  const events = Array.isArray(snap) ? snap : (snap?.events ?? []);
  // 第一遍只确定当前开放 turn 的起点（最后一个 turn/start，其后无 turn/end）。
  let turnStartSeq = undefined;
  let turnClosed = false;
  for (const ev of events) {
    const seq = ev?.seq;
    if (typeof seq !== 'number' || !isOwn(seq)) continue;
    if (ev?.type === 'turn/start') { turnStartSeq = seq; turnClosed = false; continue; }
    if (ev?.type === 'turn/end') { turnClosed = true; continue; }
  }
  if (turnStartSeq === undefined || turnClosed) return undefined;
  // 第二遍只在当前 turn 区间（seq >= turnStartSeq）内收集 asked 和 decided，
  // 旧 turn 的未配对 asked 不会被冠以新 turn 的起点。
  const asks = [];
  const decidedIds = new Set();
  for (const ev of events) {
    const seq = ev?.seq;
    if (typeof seq !== 'number' || !isOwn(seq)) continue;
    if (seq < turnStartSeq) continue;
    if (ev?.type === 'approval/asked') asks.push({ ev, seq });
    if (ev?.type === 'approval/decided' && typeof ev?.data?.id === 'string') decidedIds.add(ev.data.id);
  }
  const unpaired = asks.filter(({ ev }) => typeof ev?.data?.id !== 'string' || !decidedIds.has(ev.data.id));
  if (unpaired.length !== 1) return undefined;
  return { asked: unpaired[0].ev, seq: unpaired[0].seq, turnStartSeq };
}

/**
 * 审计绑定核心（请求绑定与批准前复核共用）：
 * 已核验工具 + 非空 callId + 当前开放 turn 唯一未配对 own asked，
 * 且 asked 的 toolName / callId 与入口固定值**精确相等**；
 * 目标档位**只从审计 reason 解析**（宿主事实）。
 * 全部不满足的分支返回 undefined（由调用方转成 DELEGATE 或拒绝）。
 */
export function readAuditRequestForAgent(session, toolName, callId) {
  if (typeof toolName !== 'string' || !VERIFIED_ESCALATORS.has(toolName)) return undefined;
  if (typeof callId !== 'string' || callId === '') return undefined;
  if (session === null || typeof session !== 'object') return undefined;
  const hit = ownUnpairedApprovalAsked(session);
  if (hit === undefined) return undefined;
  const asked = hit.asked;
  if (asked?.data?.toolName !== toolName) return undefined;
  if (typeof asked?.data?.callId !== 'string' || asked.data.callId === '') return undefined;
  if (asked.data.callId !== callId) return undefined;
  const mode = parseSandboxMode(asked?.data?.reason);
  if (mode === undefined) return undefined;
  return {
    mode,
    id: asked.data.id,
    seq: hit.seq,
    turnStartSeq: hit.turnStartSeq,
    reason: asked.data.reason,
  };
}

/** 从 approval/request 对象取 agent / toolName / callId（入口固定值），跑审计绑定核心。 */
export function readAuditRequest(request) {
  if (request === null || typeof request !== 'object') return undefined;
  return readAuditRequestForAgent(request.agent?.session, request.toolName, request.callId);
}

/* ─────────────────────────── cwd / 出口 ─────────────────────────── */

/**
 * spawn 前解析子会话 cwd（发布前把工作区维度定死）：
 * - 缺省 ⇒ 调用者解析出的 workspaceRoot（宿主回退值，**不再是 process.cwd()**）；
 * - 最高档调用者可传任意**已存在**的绝对目录（root 外也允许）；
 * - 非最高档 ⇒ 必须严格包含于调用者 root（两侧 realpath，失败 ⇒ 拒绝）；
 * - 相对路径 / 空串 ⇒ 拒绝。
 * @returns {string} 定下的子会话 cwd（绝对路径）。
 */
export function resolveSpawnCwd(requestedCwd, callerPolicy) {
  const callerMode = callerPolicy?.mode;
  const callerRoot = callerPolicy?.workspaceRoot;
  if (requestedCwd === undefined || requestedCwd === '') {
    // 缺省分支也验证 callerRoot 为真实存在的绝对目录（canonicalPathStrict）
    const real = canonicalPathStrict(callerRoot);
    if (real === undefined) {
      throw new Error('调用者 workspaceRoot 无法解析为真实路径：拒绝派活');
    }
    return real;
  }
  const cwd = String(requestedCwd);
  if (!path.isAbsolute(cwd)) throw new Error('cwd 必须是绝对路径：拒绝派活');
  // 所有档位统一验证路径为真实存在的绝对目录；
  // 最高档只豁免包含关系（canonicalContains），不豁免存在性。
  const real = canonicalPathStrict(cwd);
  if (real === undefined) {
    throw new Error('cwd 不存在或无法解析为真实路径：拒绝派活');
  }
  if (callerMode !== 'danger-full-access'
      && !canonicalContains(callerRoot, cwd)) {
    throw new Error('cwd 不在调用者工作区内（严格文件系统身份比较失败）：拒绝派活');
  }
  return real;
}

/**
 * 出口映射：只有三种宿主值可放行；任何内部原因
 * （DELEGATE / 'unloaded' / 'overflow' / 'deadline' / 'error' / undefined / …）
 * 都必须走 next()，否则宿主会把它归一化成 'unavailable'（= deny）并吃掉 UI 兜底。
 * @returns {{delegate: boolean, value?: string}}
 */
export function resolveExit(outcome) {
  if (typeof outcome === 'string' && HOST_OK.has(outcome)) return { delegate: false, value: outcome };
  return { delegate: true };
}

/**
 * 入口观察正文（**参考信息，不是执行事实**）：取 command / code（存在者）。
 * 工具体先捕获实参再挂起等审批 —— 观察值可能与实参不同，限制见 README。
 */
export function extractBody(argsAtEntry) {
  if (argsAtEntry === null || typeof argsAtEntry !== 'object') return undefined;
  if (typeof argsAtEntry.command === 'string') return argsAtEntry.command;
  if (typeof argsAtEntry.code === 'string') return argsAtEntry.code;
  return undefined;
}

/**
 * Pwsh workdir 的**入口观察值**（按其真实解析器适配：相对/缺省 → 会话 header.cwd）。
 * 两者都拿不到 ⇒ 执行器最终默认值不可核实 ⇒ undefined（不冒充"最终工作目录"）。
 * run_code **不套用** Pwsh 解析器（PTC 上下文未经核实，只展示 Session 事实）。
 */
export function resolvePwshWorkdir(session, argsAtEntry) {
  const wd = argsAtEntry?.workdir;
  if (typeof wd === 'string' && wd.trim() !== '') {
    if (path.isAbsolute(wd)) return wd;
    const base = session?.header?.cwd;
    if (typeof base === 'string' && base !== '' && path.isAbsolute(base)) return path.resolve(base, wd);
    return undefined;
  }
  const cwd = session?.header?.cwd;
  return typeof cwd === 'string' && cwd !== '' ? cwd : undefined;
}

/**
 * 渲染审批通知（固定结构；观察字段显式标注"仅供参考"）。
 * 整条字节数由调用方量（noticeTextBytes 是桥自己的主动配额，不是宿主容量）。
 * 措辞约束：只写"桥不自动批准"；不写"UI 已证明完整展示"；不写"参数等于执行"。
 */
export function renderApprovalNotice(input) {
  const v = (input !== null && typeof input === 'object' ? input : {}).verifiable ?? {};
  const o = input?.observed;
  const key = input?.key ?? '(无 key)';
  const lines = [
    `【跨会话审批桥】会话 ${input?.requesterId ?? '(未知)'} 请求沙箱提权。你是它的创建者（固定所有者），本次审批只发给你的会话。`,
    `  - 目标档位：${v.requestedMode ?? '(未知)'}`,
    `  - 工具：${v.toolName ?? '(未知)'}（callId: ${v.callId ?? '(未知)'}）`,
    `  - 会话事实（宿主可核）：cwd=${v.sessionCwd ?? '(无)'}, workspaceRoot=${v.workspaceRoot ?? '(部署回退值)'}`,
    `  - 审计依据：approval/asked id=${v.audit?.id ?? '(未知)'} seq=${v.audit?.seq ?? '?'} turnStart=${v.audit?.turnStartSeq ?? '?'}（当前开放 turn 唯一未配对）`,
    `⚠️ 以下为桥在派发时刻观察到的"入口观察值"，可能不等于工具体实际执行的参数（仅供参考）：`,
  ];
  if (o !== undefined && o !== null && typeof o === 'object') {
    if (typeof o.body === 'string') {
      lines.push(`  - 代码/命令（截取前 400 字符）：${o.body.slice(0, 400)}${o.body.length > 400 ? '…' : ''}`);
    }
    if (typeof o.workdir === 'string') lines.push(`  - workdir（入口观察值）：${o.workdir}`);
  }
  lines.push(
    '',
    `确认目标档位在你当前权限内且不含危险操作时回复：cross_session_approve key=${key} decision=allow`,
    `否则回复：cross_session_approve key=${key} decision=reject`,
    '⚠️ 上面的 key 是**本桥的审批 key**（形如 apv_XXXXXXXXXXXX 的短码），与上面「审计依据」里的 approval/asked id **不是同一个值**，'
      + '不要把审计 id 当作 key 传入。',
    '桥不自动批准；总截止时间到仍未决定，请求将回落到本地 UI 审批。',
  );
  return lines.join('\n');
}

/* ──────────────── 危险操作判定 ──────────────── */

/**
 * Limited shell lexer shared by dangerous and unresolvable operation checks.
 * Quoted data stays a token; only actual
 * interpreter argument positions are recursively parsed as executable text.
 * Unsupported evaluation syntax is recorded as unresolvable, never approved.
 */
function operationTokens(text, dialect = 'powershell') {
  const commands = [[]];
  let token, quote = '', uncertain = false;
  const begin = (i) => { token ??= { value: '', raw: '', quoted: false, literal: false, start: i, end: i }; };
  const flush = () => { if (token) { commands.at(-1).push(token); token = undefined; } };
  const split = () => { flush(); if (commands.at(-1).length) commands.push([]); };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i], next = text[i + 1];
    if (!quote && ch === '#' && dialect !== 'cmd' && !token) {
      while (i < text.length && text[i] !== '\n') i++;
      split(); continue;
    }
    if (!quote && text.slice(i, i + 2) === '<#' && dialect === 'powershell') {
      const end = text.indexOf('#>', i + 2);
      if (end < 0) { uncertain = true; break; }
      i = end + 1; continue;
    }
    const escape = dialect === 'cmd' ? '^' : dialect === 'posix' ? '\\' : '\x60';
    if (ch === escape && quote !== "'") {
      begin(i);
      if (!quote) token.literal = false;
      if (next === undefined) { uncertain = true; continue; }
      token.raw += ch + next; token.end = i + 2;
      if (next !== '\n' && next !== '\r') token.value += next;
      else if (next === '\r' && text[i + 2] === '\n') { token.raw += '\n'; i++; }
      i++; continue;
    }
    if (quote) {
      token.raw += ch; token.end = i + 1;
      if (ch === quote) {
        if (quote === "'" && dialect === 'powershell' && next === "'") {
          token.raw += next; token.value += ch; token.end++; i++;
        } else quote = '';
      } else {
        token.value += ch;
        if (quote === '"' && ((ch === '$' && next === '(') || (dialect === 'posix' && ch === '\x60'))) uncertain = true;
      }
      continue;
    }
    if (ch === '"' || (ch === "'" && dialect !== 'cmd')) {
      const standalone = !token;
      begin(i); token.literal = standalone; token.quoted = true; token.raw += ch; token.end = i + 1; quote = ch;
      if (text[i - 1] === '@') uncertain = true; // here-string: unsupported
      continue;
    }
    if (/\s/.test(ch)) { flush(); if (ch === '\n' || ch === '\r') split(); continue; }
    if (/[;|&]/.test(ch)) {
      flush();
      if (ch === '&' && !commands.at(-1).length && next !== '&') {
        commands.at(-1).push({ value: '&', raw: '&', start: i, end: i + 1 });
      } else split();
      if (next === ch) i++;
      continue;
    }
    // Blocks, expressions and redirection require a full language parser.
    if (/[(){}<>]/.test(ch)) uncertain = true;
    begin(i); token.literal = false; token.value += ch; token.raw += ch; token.end = i + 1;
  }
  if (quote) uncertain = true;
  flush();
  return { commands: commands.filter((c) => c.length), uncertain };
}

/** Parse known shell wrappers; depth/size bounds fail closed. No text executes. */
function operationModel(text, dialect = 'powershell', depth = 0) {
  if (typeof text !== 'string' || text === '') return { commands: [], uncertain: false };
  if (depth > 8 || text.length > 131072) return { commands: [], uncertain: true };
  const parsed = operationTokens(text, dialect);
  const commands = [];
  let uncertain = parsed.uncertain;
  const nested = (payload, kind) => {
    const child = operationModel(payload, kind, depth + 1);
    commands.push(...child.commands); uncertain ||= child.uncertain;
  };
  for (const tokens of parsed.commands) {
    let at = 0, invoked = false;
    if (tokens[0].value === '&' || tokens[0].value === '.') { at++; invoked = true; }
    const head = tokens[at];
    if (!head) { uncertain = true; continue; }
    // A standalone quoted PowerShell literal is an expression, not a command.
    if (head.literal && !invoked && dialect === 'powershell') continue;
    if (/[$+(){}]/.test(head.value)) { uncertain = true; continue; }
    const name = head.value.split(/[\\/]/).at(-1);
    const verb = name.toLowerCase().replace(/\.(exe|com|bat|cmd)$/, '');
    const args = tokens.slice(at + 1);
    if (verb === 'cmd') {
      let payload = -1;
      for (let j = 0; j < args.length; j++) {
        if (/^\/[ck]$/i.test(args[j].value)) { payload = j + 1; break; }
        if (!/^\/(?:d|s|q|a|u|e:(?:on|off)|f:(?:on|off)|v:off)$/i.test(args[j].value)) { uncertain = true; break; }
      }
      if (payload < 0 || !args[payload]) { uncertain = true; continue; }
      const rest = args.slice(payload);
      // cmd consumes the remaining raw command line, with one outer quote pair.
      const raw = rest.map((t) => t.raw).join(' ');
      const command = rest.length === 1 && rest[0].quoted ? rest[0].value : raw;
      if (/%|!/.test(command)) uncertain = true; // expansion cannot be resolved offline
      nested(command, 'cmd');
      continue;
    }
    if (verb === 'powershell' || verb === 'pwsh') {
      let payload = -1;
      for (let j = 0; j < args.length; j++) {
        const flag = args[j].value.toLowerCase().replace(/^[-/]/, '');
        if (/^[-/]/.test(args[j].value) && (flag === 'ec' || (flag && 'encodedcommand'.startsWith(flag)) || 'encodedarguments'.startsWith(flag))) {
          uncertain = true; break;
        }
        if (/^[-/]/.test(args[j].value) && flag && 'command'.startsWith(flag)) { payload = j + 1; break; }
        if (/^-(?:noprofile|nop|nologo|nol|noninteractive|noni|sta|mta)$/i.test(args[j].value)) continue;
        if (/^-(?:executionpolicy|ep|ex|inputformat|outputformat|windowstyle|workingdirectory)$/i.test(args[j].value) && args[j + 1]) { j++; continue; }
        uncertain = true; break;
      }
      if (payload < 0 || !args[payload]) { uncertain = true; continue; }
      const rest = args.slice(payload);
      // The first -Command argument is script even when single-quoted by caller.
      if (rest[0].quoted && /\$(?!\()/.test(rest[0].value) && !rest[0].raw.startsWith("'")) uncertain = true;
      nested(rest.map((t, j) => j === 0 && t.quoted ? t.value : t.raw).join(' '), 'powershell');
      continue;
    }
    if (/^(?:sh|bash|zsh)$/.test(verb)) {
      const j = args.findIndex((t) => /^-[a-z]*c[a-z]*$/.test(t.value));
      if (j < 0 || !args[j + 1]) uncertain = true;
      else nested(args[j + 1].value, 'posix');
      continue;
    }
    if (/^(?:iex|invoke-expression|eval|source|start-process|invoke-command|invoke-item|node|python\d*|perl|ruby|wscript|cscript|mshta|rundll32)$/.test(verb)) uncertain = true;
    // Executable scripts / unknown executable names cannot be inspected here.
    const known = /^(?:rm|rd|rmdir|del|erase|mv|format|mkfs(?:\..+)?|fdisk|diskpart|parted|sfdisk|wipefs|dd|ri|rim|mi|ls|dir|cat|type|echo|pwd|cd|git|npm|npx|pnpm|yarn|dotnet|where|whoami|hostname|date|sleep|test|true|false)$/.test(verb)
      || /^(?:get-(?:childitem|content|item|itemproperty|location|date|command|process|service|variable|module|help)|set-(?:content|location|item|itemproperty|variable|disk)|add-content|new-(?:item|partition)|remove-(?:item|partition|disk)|move-item|copy-item|rename-item|write-(?:output|host|warning|error|verbose|debug)|read-host|select-(?:object|string)|sort-object|where-object|measure-object|test-path|join-path|split-path|resolve-path|clear-(?:content|disk)|out-(?:file|string|null|host)|format-(?:table|list|wide)|convert(?:to|from)-json|start-sleep)$/i.test(verb);
    if (/\.(?:ps1|bat|cmd)$/i.test(name)) uncertain = true;
    if (!known) uncertain = true;
    const destructive = /^(?:rm|rd|rmdir|del|erase|remove-item|ri|rim|move-item|mi|mv|format|clear-disk|remove-partition|remove-disk|set-disk|new-partition)$/.test(verb);
    if (args.some((t) => t.value === '--%')) uncertain = true;
    if (destructive && args.some((t) =>
      /[,+{}()]/.test(t.value) || (!t.raw.startsWith("'") && /[$%@]/.test(t.value)))) uncertain = true;
    commands.push({ name, verb, dialect, args: args.map((t) => t.value) });
  }
  return { commands, uncertain };
}

/** Best-effort hard rejection on entry observations; never executes them. */
export function isDangerousOperation(text, opts = {}) {
  const model = operationModel(text);
  // Windows format command names are case insensitive.
  const formatRe = /^format(?:\.(?:com|exe|bat|cmd))?\s+(?:(?:\/|-)\S+\s+)*[a-zA-Z]:/i;
  for (const { name, verb, args, dialect } of model.commands) {
    const targets = dialect === 'cmd' ? args.filter((a) => !/^\/[a-z](?:\/[a-z])*$/i.test(a)) : args;
    const endOptions = args.indexOf('--');
    const flags = endOptions < 0 ? args : args.slice(0, endOptions);
    // PowerShell 参数扫描器还接受 U+2013/2014/2015 等破折号作为参数前缀，
    // 原正则只认 ASCII '-'（U+002D）⇒ –Recurse/—Force 可绕过递归强删判定。
    // 把已知 Unicode 破折号类字符归一为 ASCII '-' 后再匹配；posix 风格（下方
    // recursive/force 的 --recursive / -[rR] 分支）保留原 flags（posix 不认 Unicode 破折号）。
    const normFlags = flags.map((a) => a.replace(/[\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]/g, '-'));
    const psRecursive = normFlags.some((a) => /^-(?:r|re|rec|recu|recur|recurs|recurse)(?::true|:\$true)?$/i.test(a));
    const psForce = normFlags.some((a) => /^-(?:f|fo|for|forc|force)(?::true|:\$true)?$/i.test(a));
    const recursive = psRecursive || flags.some((a) => a === '--recursive' || /^-[a-zA-Z]*[rR][a-zA-Z]*$/.test(a));
    const force = psForce || flags.some((a) => a === '--force' || /^-[a-zA-Z]*f[a-zA-Z]*$/.test(a));
    // fail-closed：文件破坏性动词的 flag 若以非 ASCII 字符开头且后跟 ASCII 字母，
    // 可能是未列入上表的 Unicode 破折号参数前缀 ⇒ 无法准确识别 ⇒ 拒绝（宁可误拒不可漏放）。
    if (/^(?:rm|rd|rmdir|del|erase|remove-item|ri|rim|move-item|mi|mv)$/.test(verb)
        && flags.some((a) => /^[^\x00-\x7F][A-Za-z]/.test(a))) return true;
    if (/^(?:rm|remove-item|ri|rim)$/.test(verb) && recursive && force) return true;
    const cmdSwitches = args.filter((a) => /^\/[a-z](?:\/[a-z])*$/i.test(a)).join('').toLowerCase();
    if (/^(?:rd|rmdir|del|erase)$/.test(verb) && cmdSwitches.includes('/s')
        && (cmdSwitches.includes('/q') || cmdSwitches.includes('/f'))) return true;
    if (/^(?:rm|rd|rmdir|del|erase|remove-item|ri|rim)$/.test(verb)
        && targets.some((a) => isWideTarget(a, opts))) return true;
    if (/^(?:rm|rd|rmdir|del|erase|remove-item|ri|rim|move-item|mi|mv)$/.test(verb)
        && targets.some((a) => isProtectedTarget(a, opts))) return true;
    if (formatRe.test(name + ' ' + args.join(' '))) return true;
    if (/^(?:mkfs(?:\..+)?|fdisk|diskpart|parted|sfdisk|wipefs|clear-disk|remove-partition|remove-disk|set-disk|new-partition)$/.test(verb)) return true;
    if (verb === 'dd' && args.some((a) => /^of=(?:\/dev\/|\\\\\?\\)/i.test(a))) return true;
  }
  return false;
}

/** Unsupported executable syntax / expansion => deny under the approved rule. */
export function isUnresolvableOperation(text) {
  return operationModel(text).uncertain;
}

/* ─────────────────────────── 官方写入口 ─────────────────────────── */

/**
 * 写档位：与宿主 dsh-sandbox-policy 的 setSandboxMode 逐字节同路
 * （`session.append("sandbox/mode", { mode })`，非法档位先抛）。
 * 不静态 import 宿主包，直接复刻官方入口的 append 语义。
 */
export function writeSandboxMode(session, mode) {
  if (SANDBOX_MODES.indexOf(mode) < 0) throw new Error('writeSandboxMode: 未知档位 ' + String(mode));
  session.append('sandbox/mode', { mode });
}

/**
 * 写审批策略：与宿主 dsh-user-approval 的 setApprovalPolicy 同路
 * （先校验 APPROVAL_POLICIES，再 `session.append("approval/policy", { policy })`）。
 */
export function writeApprovalPolicy(session, policy) {
  if (APPROVAL_ORDER.indexOf(policy) < 0) throw new Error('writeApprovalPolicy: 未知审批策略 ' + String(policy));
  session.append('approval/policy', { policy });
}

/* ─────────────────────────── 授权包含 ─────────────────────────── */

/**
 * 授权包含（**同步**函数：读权限与放行之间没有任何 await 间隙）。
 * 规则：
 *  - 档位 ≥：**两个下标都必须 ≥ 0** 且 owner ≥ target；
 *  - 工作区包含：严格 realpath（宿主回退值也过一遍）；
 *  - ① 最高档 owner 不受工作区限制（root 本就无限制）；
 *  - ② requester 无 header.cwd 时 resolve() 给宿主回退值 —— **不拒绝**；
 *  - ③ owner 有效审批必须为 `ask`（`never` 会在宿主拒绝提权审批请求）；
 *  - 服务缺失 / 冷 owner / 档位未知 ⇒ 不接管（allowed:false，调用方 DELEGATE）。
 * @param {object} ctx  只需 `get(name)` 的宿主 ctx（测试可注入假 ctx）
 * @returns {{allowed: boolean, why?: string, ownerSession?, requesterSession?,
 *            ownerSnapshot?: {mode, workspaceRoot, approval},
 *            targetPolicy?: {mode, workspaceRoot}}}
 */
export function checkAuthority(ctx, ownerId, requesterId, requestedMode) {
  let policy, sessions, approval;
  try {
    policy = ctx?.get?.('sandboxPolicy');
    sessions = ctx?.get?.('sessions');
    approval = ctx?.get?.('approval');
  } catch { return { allowed: false, why: 'service-error' }; }
  if (policy === undefined || sessions === undefined || approval === undefined) {
    return { allowed: false, why: 'service-missing' };
  }
  let ownerSession, requesterSession;
  try {
    ownerSession = typeof sessions.get === 'function' ? sessions.get(ownerId) : undefined;
    requesterSession = typeof sessions.get === 'function' ? sessions.get(requesterId) : undefined;
  } catch { return { allowed: false, why: 'service-error' }; }
  if (ownerSession === undefined) return { allowed: false, why: 'owner-not-live' };
  if (requesterSession === undefined) return { allowed: false, why: 'requester-not-live' };

  let ownerPolicy, requesterPolicy, ownerApproval;
  try {
    ownerPolicy = policy.resolve?.({ session: ownerSession });
    requesterPolicy = policy.resolve?.({ session: requesterSession });
    ownerApproval = approval.effectivePolicy?.(ownerSession);
  } catch { return { allowed: false, why: 'service-error' }; }
  if (ownerPolicy === undefined || requesterPolicy === undefined || ownerApproval === undefined) {
    return { allowed: false, why: 'service-missing' };
  }
  const oi = SANDBOX_MODES.indexOf(ownerPolicy.mode);
  const ti = SANDBOX_MODES.indexOf(requestedMode);
  if (oi < 0 || ti < 0) return { allowed: false, why: 'mode-unknown' };
  if (oi < ti) return { allowed: false, why: 'mode' };
  if (ownerApproval !== 'ask') return { allowed: false, why: 'approval' };

  const ownerRoot = canonicalPathStrict(ownerPolicy.workspaceRoot);
  const requesterRoot = canonicalPathStrict(requesterPolicy.workspaceRoot);
  if (ownerRoot === undefined || requesterRoot === undefined) {
    return { allowed: false, why: 'path-resolution' };
  }
  // 工作区维度只约束 workspace-write 目标；最高档 owner 无 root 限制。
  if (ownerPolicy.mode !== 'danger-full-access'
      && requestedMode === 'workspace-write'
      && !canonicalContains(ownerRoot, requesterRoot)) {
    return { allowed: false, why: 'workspace' };
  }
  return {
    allowed: true,
    ownerSession,
    requesterSession,
    ownerSnapshot: { mode: ownerPolicy.mode, workspaceRoot: ownerRoot, approval: ownerApproval },
    targetPolicy: { mode: requestedMode, workspaceRoot: requesterRoot },
  };
}

/* ─────────────────────────── A：发布前三维夹紧 ─────────────────────────── */

/**
 * A：发布前三维夹紧（**同步**；任何一步失败 ⇒ throw ⇒ 工厂回滚 attach ⇒
 * agents.create() 拒绝、任务不投递）。
 *
 * 落点：session/created 监听器（prepend，同步）。
 * 规则：
 *  - 调用者**当前**策略在**这里**重新解析，绝不用 spawn 快照当授权依据
 *    （快照只做比对：任何变化 ⇒ 拒绝，既不静默放行也不静默收窄）；
 *  - 档位 = min(调用者, DSH 默认预设)；审批 = 更严者（never < ask）；
 *  - 工作区 = intent.cwd（① 已按调用者边界校验过；非最高档调用者在
 *    listener 里再复核一次包含关系）；
 *  - 显式更宽的预设 ⇒ 预检已拒，这里**再拒一次**（双保险）；
 *  - sandbox／approval 无条件写，preset 名仅当实际旋钮恰好等于默认预设时写；
 *  - 写完**逐项精确读回复核**（不是"不更宽"）。
 * @param {object} ctx  宿主 ctx（get: permissionPresets / sandboxPolicy / approval / sessions）
 * @param {object} intent spawnIntents 条目（见 lib/index.js）
 * @param {object} childSession 刚创建（未发布）的 Session
 * @param {{epoch: number}} env 当前实例世代
 * @returns {{mode, approval, presetName?}}
 */
export function clampChildPermission(ctx, intent, childSession, env) {
  const perms = ctx.get('permissionPresets');
  const policy = ctx.get('sandboxPolicy');
  const approval = ctx.get('approval');
  const sessions = ctx.get('sessions');
  if (perms === undefined || policy === undefined || approval === undefined || sessions === undefined) {
    throw new Error('权限服务缺失：拒绝派活（fail-closed）');
  }
  // 失效 intent 不得发布（调用者销毁后仍可能走到这里）
  if (intent.cancelled === true) throw new Error('意图已失效（调用者已销毁）：拒绝派活');
  if (intent.epoch !== env.epoch) throw new Error('实例世代已变：拒绝派活');
  const callerNow = sessions.get(intent.callerId);
  if (callerNow === undefined) throw new Error('调用者已不是活会话：拒绝派活');
  if (callerNow !== intent.callerSession) throw new Error('调用者会话实例已变：拒绝派活');

  const callerNowPolicy = policy.resolve({ session: callerNow });
  const callerNowApproval = approval.effectivePolicy(callerNow);
  if (!callerPolicyUnchanged(intent, {
    mode: callerNowPolicy.mode,
    workspaceRoot: callerNowPolicy.workspaceRoot,
    approval: callerNowApproval,
  })) {
    throw new Error('调用者权限在派活期间发生变化：拒绝派活（请重试）');
  }
  // 再复核 cwd 仍在新解析边界内（最高档调用者跳过包含检查）
  if (callerNowPolicy.mode !== 'danger-full-access'
      && !canonicalContains(callerNowPolicy.workspaceRoot, intent.cwd)) {
    throw new Error('cwd 不再位于调用者工作区内：拒绝派活');
  }

  const dflt = perms.resolve(perms.defaultPreset);
  let target;
  if (typeof intent.requestedPreset === 'string' && intent.requestedPreset !== '') {
    const name = intent.requestedPreset;
    const names = Array.isArray(perms.names) ? perms.names : [];
    if (!names.includes(name)) {
      throw new Error(`未知权限预设 "${name}"（可用：${names.join(', ')}）`);
    }
    const spec = perms.resolve(name);
    target = { presetName: name, ...precheckPresetSpec(name, spec, callerNowPolicy.mode, callerNowApproval) };
  } else {
    const c = clampTarget(callerNowPolicy.mode, callerNowApproval, dflt.sandbox, dflt.approval);
    target = { mode: c.mode, approval: c.approval };
    // 只有"实际旋钮恰好等于默认预设"才写 preset 名，否则只写旋钮（避免名不副实）
    if (target.mode === dflt.sandbox && target.approval === dflt.approval) {
      target.presetName = perms.defaultPreset;
    }
  }

  // sandbox／approval 无条件写；preset 匹配时写（不依赖宿主 apply()）
  if (target.presetName !== undefined) childSession.append('permission/preset', { preset: target.presetName });
  writeSandboxMode(childSession, target.mode);
  writeApprovalPolicy(childSession, target.approval);

  // 逐项精确读回复核
  const st = perms.permissionState(childSession);
  if (st.sandbox !== target.mode) {
    throw new Error(`档位写入未生效（期望 ${target.mode}，实得 ${String(st.sandbox)}）`);
  }
  if (st.approval !== target.approval) {
    throw new Error(`审批策略写入未生效（期望 ${target.approval}，实得 ${String(st.approval)}）`);
  }
  if (policy.resolve({ session: childSession }).workspaceRoot !== intent.cwd) {
    throw new Error('工作区写入未生效');
  }
  return target;
}

/* ─────────────────────────── F：派生入口夹紧 ─────────────────────────── */

/**
 * F：派生入口（fork / 恢复派生 announcement）三维夹紧（**同步**；失败 ⇒ throw 阻断发布）。
 * 合同：
 *  - 只处理**非 A**（spawnIntents 未命中）且 `session.header.parentSession` 非空者；
 *  - 活源：上限 = 源**本次**当前 mode／approval／root，子值逐维取 min；
 *  - 冷源 cap：上限 = 部署 defaultPreset 的 mode／approval + `sandboxPolicy.workspaceRoot`；
 *    冷源 strict：直接拒绝（**服务缺失不是冷源**，独立拒绝）；
 *  - 非最高档上限要求 child root 包含于上限 root（严格 realpath，解析失败拒绝）；
 *  - 只改 sandbox／approval 旋钮，**不重写 preset 名**；
 *  - 越界 / 解析失败 / 写入读回不符 ⇒ throw。
 */
export function clampDerivedPermission(ctx, session, forkPermission) {
  if (forkPermission === 'off') return;
  const parentId = session.header?.parentSession;
  if (typeof parentId !== 'string' || parentId === '') return;
  const perms = ctx.get('permissionPresets');
  const policy = ctx.get('sandboxPolicy');
  const approval = ctx.get('approval');
  const sessions = ctx.get('sessions');
  if (perms === undefined || policy === undefined || approval === undefined || sessions === undefined) {
    throw new Error('权限服务缺失：拒绝派生会话（fail-closed）');
  }
  const parent = sessions.get(parentId);
  let upperMode, upperApproval, upperRoot;
  if (parent !== undefined) {
    const current = policy.resolve({ session: parent });
    upperMode = current.mode;
    upperApproval = approval.effectivePolicy(parent);
    upperRoot = current.workspaceRoot;
  } else {
    if (forkPermission === 'strict') throw new Error(`拒绝：源 "${parentId}" 不是活会话（strict）`);
    const dflt = perms.resolve(perms.defaultPreset);
    upperMode = dflt.sandbox;
    upperApproval = dflt.approval;
    upperRoot = policy.workspaceRoot;   // 部署回退根，不是 child 的 header.cwd
    if (ctx.logger?.warn !== undefined) {
      ctx.logger.warn(`cross-session-approval: 源 "${parentId}" 不活，采用部署默认三维上限（forkPermission=cap）`);
    }
  }
  const pi = SANDBOX_MODES.indexOf(upperMode);
  const pa = APPROVAL_ORDER.indexOf(upperApproval);
  const st = perms.permissionState(session);
  const childPolicy = policy.resolve({ session });
  const ci = SANDBOX_MODES.indexOf(st.sandbox ?? childPolicy.mode);
  const ca = APPROVAL_ORDER.indexOf(st.approval ?? approval.effectivePolicy(session));
  if (pi < 0 || pa < 0 || ci < 0 || ca < 0) throw new Error('派生会话／上限策略无法识别');
  if (canonicalPathStrict(upperRoot) === undefined
      || canonicalPathStrict(childPolicy.workspaceRoot) === undefined) {
    throw new Error('派生会话工作区解析失败（严格 realpath 拒绝）');
  }
  if (upperMode !== 'danger-full-access'
      && !canonicalContains(upperRoot, childPolicy.workspaceRoot)) {
    throw new Error('拒绝：派生会话工作区超出上限');
  }
  const targetMode = SANDBOX_MODES[Math.min(ci, pi)];
  const targetApproval = APPROVAL_ORDER[Math.min(ca, pa)];
  if (targetMode !== st.sandbox) writeSandboxMode(session, targetMode);
  if (targetApproval !== st.approval) writeApprovalPolicy(session, targetApproval);
  const after = perms.permissionState(session);
  if (after.sandbox !== targetMode
      || after.approval !== targetApproval
      || policy.resolve({ session }).workspaceRoot !== childPolicy.workspaceRoot) {
    throw new Error('派生会话权限读回复核失败');
  }
}

/* ─────────────────────────── 配置校验（纯函数）─────────────────────────── */

/**
 * 校验 approvalBridge 配置段。
 * 任何字段非法 ⇒ 整桥**停用**（fail-closed，不是崩溃）+ 返回原因供告警。
 * @returns {{enabled: boolean, reason?: string, timeoutMs?: number,
 *            maxActiveRequests?: number, maxPending?: number,
 *            noticeTextBytes?: number, showObservedArgs?: string, injectWithdraw?: boolean}}
 */
export function validateBridgeConfig(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    return { enabled: false, reason: 'approvalBridge 未配置' };
  }
  if (raw.enabled !== true) return { enabled: false, reason: 'approvalBridge 未启用' };
  const check = (v, lo, hi, integer) => {
    if (typeof v !== 'number' || !Number.isFinite(v)) return false;
    if (integer && !Number.isInteger(v)) return false;
    return v >= lo && v <= hi;
  };
  const timeoutMs = raw.timeoutMs === undefined ? 300000 : raw.timeoutMs;
  const maxActiveRequests = raw.maxActiveRequests === undefined ? 64 : raw.maxActiveRequests;
  const maxPending = raw.maxPending === undefined ? 64 : raw.maxPending;
  const noticeTextBytes = raw.noticeTextBytes === undefined ? 32768 : raw.noticeTextBytes;
  const showObservedArgs = raw.showObservedArgs === undefined ? 'advisory' : raw.showObservedArgs;
  const injectWithdraw = raw.injectWithdraw === undefined ? true : raw.injectWithdraw;
  if (!check(timeoutMs, 1000, 3600000, false)) {
    return { enabled: false, reason: 'approvalBridge.timeoutMs 非法（需 1000–3600000 的有限正数）' };
  }
  if (!check(maxActiveRequests, 1, 1024, true)) {
    return { enabled: false, reason: 'approvalBridge.maxActiveRequests 非法（需 1–1024 整数）' };
  }
  if (!check(maxPending, 1, 1024, true)) {
    return { enabled: false, reason: 'approvalBridge.maxPending 非法（需 1–1024 整数）' };
  }
  if (!check(noticeTextBytes, 1024, 1048576, false)) {
    return { enabled: false, reason: 'approvalBridge.noticeTextBytes 非法（需 1024–1048576）' };
  }
  if (showObservedArgs !== 'advisory' && showObservedArgs !== 'off') {
    return { enabled: false, reason: 'approvalBridge.showObservedArgs 非法（需 advisory|off）' };
  }
  if (typeof injectWithdraw !== 'boolean') {
    return { enabled: false, reason: 'approvalBridge.injectWithdraw 必须是 boolean' };
  }
  return {
    enabled: true,
    timeoutMs,
    maxActiveRequests,
    maxPending,
    noticeTextBytes,
    showObservedArgs,
    injectWithdraw,
  };
}

/** spawnPermission 归一化：非法值取最严合法值 "cap" 并告警。 */
export function resolveSpawnPermission(v, onInvalid) {
  if (v === undefined) return 'cap';
  if (v === 'cap' || v === 'off') return v;
  onInvalid?.(`spawnPermission 配置值非法（"${String(v)}"），按最严值 "cap" 处理`);
  return 'cap';
}

/** forkPermission 归一化：非法值取最严合法值 "strict" 并告警。 */
export function resolveForkPermission(v, onInvalid) {
  if (v === undefined) return 'cap';
  if (v === 'cap' || v === 'strict' || v === 'off') return v;
  onInvalid?.(`forkPermission 配置值非法（"${String(v)}"），按最严值 "strict" 处理`);
  return 'strict';
}

/** 硬耦合：桥启用时 spawnPermission 必须为 cap，否则桥停用 + 告警。 */
export function hardCouplingBridge(bridgeEnabled, spawnPermission) {
  return !(bridgeEnabled && spawnPermission !== 'cap');
}

/** A path-bearing abbreviated PowerShell parameter may use a colon value. */
function pathArgument(target) {
  const m = /^-([a-z]+):(.*)$/i.exec(target);
  if (!m) return target;
  const key = m[1].toLowerCase();
  return 'literalpath'.startsWith(key) || 'path'.startsWith(key) ? m[2] : target;
}

/** 宽目标：通配符、盘根、家目录、~/.dsh、.cross-session。 */
function isWideTarget(target, opts) {
  if (target === '') return false;
  let first = pathArgument(target);
  // PowerShell provider 前缀规范化。已知 FileSystem provider ⇒ 剥离后比较
  // 文件系统身份；未知 provider 前缀 ⇒ 无法确定文件系统身份 ⇒ 拒绝（fail-closed）。
  const fsStripped = stripFsProvider(first);
  if (fsStripped === null) return true;
  first = fsStripped;
  // PowerShell -Path 接受 [...] 字符组通配，单引号不取消通配解释。
  if (/[?*\[\]]/.test(first)) return true;
  if (first === '.' || first === '..') return true;
  if (path.posix.normalize(first) === '/' || /^[a-zA-Z]:[\\/]$/.test(path.win32.normalize(first))) return true;
  if (first === '/' || first === '~' || first === '~/' || first === '~\\' || first === '\\\\') return true;
  if (/^[a-zA-Z]:[\\/]\??\s*$/.test(first)) return true;   // Windows 盘符根目录
  if (/^[a-zA-Z]:$/.test(first)) return true;             // 盘根相对（C: 当前目录）
  return isProtectedTarget(first, opts);
}

/** 受保护目标：~/.dsh（DSH 家）、DSH 安装目录、工作区根、.cross-session 登记表。 */
function isProtectedTarget(target, opts) {
  if (typeof target !== 'string' || target === '') return false;
  target = pathArgument(target);
  // provider 前缀（isWideTarget 已剥离；直接调用本函数时也防御性剥离）。
  const sp = stripFsProvider(target);
  if (sp === null) return true;            // 未知 provider ⇒ 无法确定文件系统身份 ⇒ fail-closed
  target = sp;
  target = target.replace(/\//g, '\\').split('\\')
    .map((s) => s === '.' || s === '..' ? s : s.replace(/[ .]+$/, '')).join('\\');
  if (/\.dsh(?:[\\/]|$)/i.test(target) || /~[\\\/]\.dsh/i.test(target)) return true;
  if (/DeepSeek[\s_-]?Harness[\\/](?:resources|bin|node_modules)/i.test(target)) return true;
  if (/AppData[\\\/]Local[\\\/]Programs[\\\/]DeepSeek/i.test(target)) return true;
  if (/\.cross-session(?:[\\/]|$)/i.test(target)) return true;
  // 工作区根**本身**（精确匹配）是受保护目标；其子目录不算（递归删子目录是合法操作）。
  // Windows 反斜杠／正斜杠先归一，避免同一根因拼写不同漏判。
  const root = opts?.workspaceRoot;
  if (typeof root === 'string' && root !== '') {
    // These identities require ambient drive state or filesystem lookup.
    if (/^(?:\\|[a-z]:[^\\/]|~)/i.test(target)) return true;
    // Do not resolve ordinary option names as file paths.
    if (/^(?:-|[$@%])/.test(target)) return false;
    const normalize = (value) => path.win32.normalize(String(value).replace(/\//g, '\\')
      .split('\\').map((s) => s === '.' || s === '..' ? s : s.replace(/[ .]+$/, '')).join('\\'))
      .replace(/\\+$/, '').toLowerCase();
    const norm = normalize(root);
    const base = opts?.workdir;
    const absolute = /^[a-z]:[\\/]/i.test(target);
    if (!absolute && (typeof base !== 'string' || !/^[a-z]:[\\/]/i.test(base))) return true;
    const hay = normalize(absolute ? target : path.win32.resolve(normalize(base), normalize(target)));
    if (norm !== '') {
      if (hay === norm) return true;                          // 工作区根本身
      if (norm.startsWith(hay + '\\')) return true;           // root 的祖先（移走它会连带移走 root）
    }
  }
  return false;
}

/**
 * 剥离 PowerShell provider 前缀，返回纯文件系统路径。
 * 已知 FileSystem provider（FileSystem:: / Microsoft.PowerShell.Core\FileSystem::）⇒ 剥离；
 * 其他 provider 前缀（形如 XXX::）⇒ null（无法确定文件系统身份，调用方按 fail-closed 拒绝）。
 */
function stripFsProvider(target) {
  if (typeof target !== 'string' || target === '') return target;
  if (/^Microsoft\.PowerShell\.Core\\FileSystem::/i.test(target)) {
    return target.slice('Microsoft.PowerShell.Core\\FileSystem::'.length);
  }
  if (/^FileSystem::/i.test(target)) return target.slice('FileSystem::'.length);
  if (/^[a-zA-Z][\w.\\-]*::/.test(target)) return null;
  return target;
}
