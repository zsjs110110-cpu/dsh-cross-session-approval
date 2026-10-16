/**
 * dsh-cross-session-approval — 跨会话派活（0.2.x 宿主）。
 *
 * 宿主平面 bundle：把 `cross_session_*` 工具注册进共享 `tools` 注册表。
 * 任意会话都能：
 *   - cross_session_spawn   新建顶层会话并投递任务，立即返回；
 *   - cross_session_send    给任意会话发消息（默认插队，未打开的从磁盘叫醒）；
 *   - cross_session_reply   任务会话把结果回给指定会话（与发送对称）；
 *   - cross_session_status  登记总览；
 *   - cross_session_read    读某会话最近的工作过程（无需叫醒）；
 *   - cross_session_list    列出工作区顶层会话；
 *   - cross_session_broadcast  一对多派发；
 *   - cross_session_rename  改会话名；
 *   - cross_session_archive 归档会话；
 *   - cross_session_approve 处理创建者收到的提权审批请求。
 *
 * DSH 0.2.x 宿主集成要点：
 *   - 服务必须经 cordis.patch.yml 的 `inject:` 声明后才能访问（实测无 inject
 *     时 ctx.get('tools') 为 undefined、ctx.tools 直接抛错）。
 *   - 投递原语 steer/followup/inject 位于运行时 Agent 对象上（TS 类型未声明）。
 *   - `sessionPersistence.inspect()` 已不存在 → 用 stat()/open(id,'read')。
 *   - `@deepseek-ai/dsh-agent-presets`（复数）与 `resolveSessionPreset` 不存在
 *     → preset 以 `agentPreset` 投影（agent-preset/selected 事件）为准、静态
 *     header 兜底；创建时把解析后的 id 写进 `meta.agentPreset` 持久化（与宿主
 *     composeAgent 同款），恢复时优先用登记表记录的 preset 重建能力集。
 *   - 消息通过 createUserMessage 构造；reasoningEffort 与 sessionId 使用字符串。
 *
 * 跨会话审批桥与发布前权限夹紧：
 *   - 纯逻辑核心在 ./bridge-core.js（零宿主 import，可离宿主单测）；
 *   - 四个权限服务（sandboxPolicy / permissionPresets / approval / sessions）
 *     **不进 inject**，运行时 ctx.get() 可选获取（缺失 ⇒ 桥/对应创建 fail-closed，
 *     其余工具不受影响）；
 *   - 审批桥 answerer 的 carrier 校验依赖 @deepseek-ai/dsh-scope 的 carrierKeyOf
 *     （**动态 import**：失败 ⇒ 桥不注册 + 告警，不影响既有 9 个工具）。
 *
 * @module dsh-cross-session-approval
 */
import { Buffer } from 'node:buffer';
import { randomUUID } from 'node:crypto';
import { RegistryReadError, readRegistryOnly, withRegistry } from './state.js';

// 零 @deepseek-ai/* 静态 import——link 插件裸包名 import 未命中宿主
// resolution.entries 就退回 Node 原生解析，而 link 目录向上无 node_modules ⇒ 整条
// entry 死掉（failed to import 无堆栈）。改为动态 import + fallback，失败只降级不崩。
import { defineTool as fallbackDefineTool, createUserMessage as fallbackCreateUserMessage, installModelSelection as fallbackInstallModelSelection } from './host-fallback.js';
let defineTool = fallbackDefineTool;
let installModelSelection = fallbackInstallModelSelection;
let createUserMessage = fallbackCreateUserMessage;
import {
  APPROVAL_ORDER,
  HOST_OK,
  SANDBOX_MODES,
  VERIFIED_ESCALATORS,
  callerPolicyUnchanged,
  canonicalContains,
  canonicalPathStrict,
  checkAuthority,
  clampChildPermission,
  clampDerivedPermission,
  clampTarget,
  extractBody,
  hardCouplingBridge,
  isApprovalKey,
  isDangerousOperation,
  isUnresolvableOperation,
  makeApprovalKey,
  makeSessionAlias,
  isMaskedPlaceholderId,
  isSessionAlias,
  ownUnpairedApprovalAsked,
  parseSandboxMode,
  precheckPresetSpec,
  readAuditRequest,
  readAuditRequestForAgent,
  renderApprovalNotice,
  resolveExit,
  resolveForkPermission,
  resolvePwshWorkdir,
  resolveSessionRef,
  resolveSpawnCwd,
  resolveSpawnPermission,
  triPartiteModeConsistent,
  validateBridgeConfig,
  writeApprovalPolicy,
  writeSandboxMode,
} from './bridge-core.js';

/** 稳定 Cordis 插件名（须与 cordis.patch.yml 的 name 一致）。 */
export const name = 'cross-session-approval';

/** err(e) → 简短错误文本。 */
function err(e) {
  return e instanceof Error ? e.message : String(e);
}

/** 单条派活文本的 UTF-8 字节上限（防止消息体与登记表无界膨胀）。 */
const MAX_TEXT_BYTES = 32 * 1024;
/** 登记表 worker 上限：超出时淘汰最久未活动的记录。 */
const MAX_REGISTRY_WORKERS = 200;
/** 一次 broadcast 的目标数上限。 */
const MAX_BROADCAST_TARGETS = 20;

/** 按 UTF-8 字节数截断文本（截断后仍是合法 UTF-8）。 */
function clampText(value, maxBytes = MAX_TEXT_BYTES) {
  const text = typeof value === 'string' ? value : '';
  if (Buffer.byteLength(text, 'utf8') <= maxBytes) return text;
  let end = text.length;
  while (end > 0 && Buffer.byteLength(text.slice(0, end), 'utf8') > maxBytes) end -= 1;
  return `${text.slice(0, end)}\n…（已按 ${maxBytes} 字节上限截断）`;
}

/** 派活消息末尾的回信指引（reply_to 缺省时不加）。 */
function directiveFor(replyTo) {
  if (replyTo) replyTo = isSessionAlias(replyTo) ? replyTo : makeSessionAlias(replyTo);
  return replyTo
    ? `\n\n（本次任务完成后，请调用 cross_session_reply，把结果回复给会话 ${replyTo}：to = ${replyTo}。）`
    : '';
}

/** 淘汰最久未活动的登记记录，让登记表保持在 max 条以内。 */
function pruneRegistry(registry, max = MAX_REGISTRY_WORKERS) {
  const entries = Object.entries(registry.workers ?? {});
  if (entries.length <= max) return 0;
  const activity = ([, worker]) => worker?.lastTaskAt ?? worker?.lastReplyAt ?? worker?.createdAt ?? 0;
  const doomed = entries.sort((a, b) => activity(a) - activity(b)).slice(0, entries.length - max);
  for (const [id] of doomed) delete registry.workers[id];
  return doomed.length;
}

/** 规范化 cwd 用于跨平台字符串比较（Windows 忽略大小写与尾分隔符）。 */
function normalizeCwd(p) {
  if (!p) return '';
  const trimmed = p.endsWith('/') || p.endsWith('\\') ? p.slice(0, -1) : p;
  return process.platform === 'win32' ? trimmed.toLowerCase() : trimmed;
}

/** 提取调用者 Agent，缺失时报错。 */
function requireAgent(exec) {
  if (!exec.agent) {
    throw new Error('cross_session 工具需要一个调用中的 Agent（exec.agent 缺失）。');
  }
  return exec.agent;
}

/**
 * 提取调用者对应的 Session 实例。
 *
 * `exec.agent` 是 Agent，**不是 Session**：Agent 上没有 `header`/`snapshotEvents`/
 * `isOwnSeq`，也没有 `sessionProjections` 认得的状态。把 Agent 当 Session 传给
 * 权限服务会**静默**退化成"部署默认"：
 *   - `sandboxPolicy.resolve({session: agent})` ⇒ `session?.header.cwd` 为 undefined
 *     ⇒ `workspaceRoot` 回退成**部署根**（`process.cwd()`）；
 *     `overrideOf(agent)` 查不到 ⇒ `mode` 回退成**部署默认档位**。
 *   - 夹紧基准于是变成部署默认而非调用者真实权限 ⇒ 若部署默认更宽，
 *     子会话就拿到**超出调用者的权限**——违反权限夹紧约束。
 * 宿主 Agent 的 session 字段提供对应的 Session 实例：
 * `agent.session` 就是该 Agent 对应的真实 Session（`agent.session.id === agent.id`）。
 */
function requireSession(ctx, exec) {
  const agent = requireAgent(exec);
  const inline = agent.session;
  if (inline !== undefined && inline !== null) return inline;
  // 回退：Agent 未直接暴露 session 时，用 id 去 sessions 服务取。
  try {
    const sessions = ctx.get('sessions');
    const session = sessions?.get?.(agent.id);
    if (session !== undefined && session !== null) return session;
  } catch {
    // 落到下面统一报错。
  }
  throw new Error('cross_session 工具无法解析调用者 Session（agent.session 与 sessions.get 均不可用）。');
}

/**
 * ── 会话标识解析（0.3.2）──────────────────────────────────────────────────────
 *
 * 背景：`session-<8-4-4-4-12 UUID>` 的 44 字符 id 在**模型可见文本**里会被显示层
 * 整体替换成占位符 `session-00000000-0000-4000-8000-000000000000`
 * （与审批 key 同一个遮蔽机制）。⇒ 模型从 `cross_session_list` 复制到的 id 是**假的**，
 * 喂回 `send`/`read`/`rename`/`archive` 必然失败（宿主查不到那个会话）。
 *
 * 对策：给每个真实 id 派生一个 **base62 形状短别名**（`cs_XXXXXXXXXX`），
 * 模型只经手别名，由**程序自己**解析回真 id（程序内部数据不受遮蔽影响）。
 *
 * 本函数是**所有接收会话标识的入口**的统一解析点：
 * - 真 id ⇒ 原样返回；
 * - 别名 ⇒ 在候选集（登记表 + 当前工作区可见会话）里解析；
 * - 被遮蔽的占位符 / 未知别名 ⇒ 抛出**带指引的错误**（不静默当成真 id 放行）。
 *
 * @param {string} input 用户给的标识（id 或 `cs_` 别名）
 * @param {Map<string, unknown>|Set<string>|Iterable<string>} candidates 候选真实 id
 * @returns {string} 真实会话 id
 */
function resolveSessionIdOrThrow(input, candidates) {
  const resolved = resolveSessionRef(input, candidates);
  if (resolved !== undefined) return resolved;
  if (isMaskedPlaceholderId(input)) {
    throw new Error(
      `会话 id 看起来是被显示层替换的占位符（${input}），不是真实 id。`
      + `请改用 cross_session_list 返回的 cs_ 短别名（别名不会被遮蔽）。`,
    );
  }
  if (isSessionAlias(input)) {
    throw new Error(`找不到该别名对应的会话（${input}）：可能已归档、已删除，或不在当前工作区。`
      + `请用 cross_session_list 重新确认可用别名。`);
  }
  throw new Error(`无法解析会话标识（${input}）。请用 cross_session_list 取 cs_ 短别名。`);
}

/**
 * 汇总「本工作区已知的会话 id 候选集」：登记表 + 宿主可见会话。
 * 用于把 `cs_` 别名解析回真实 id。
 *
 * ⚠️ 枚举口径必须与 `cross_session_list` **完全同源**（同一 API、同一过滤），
 *    否则会出现"列表给得出别名、发送却解析不到"的分叉。详见下面第 2 段的注释。
 */
async function collectSessionIdCandidates(ctx, cwd, stateDir) {
  const ids = new Set();
  // ⚠️ 口径收口：调用方传进来的 cwd **有的已归一化**（list / status），**有的是裸值**
  //    （send / reply / read / rename / archive 直接传 `workspaceOf(...)`）。
  //    0.3.9 曾写成 `normalizeCwd(header.cwd) !== cwd`：裸值进布尔比较时
  //    `'g:\work' !== 'G:\work'` **恒真**（normalizeCwd 在 Windows 下小写化）⇒ 候选集为空。
  //    必须在本函数内统一归一化，8 个调用点才能全部正确。
  const root = normalizeCwd(cwd);
  try {
    const registry = await readRegistryOnly(cwd, stateDir);
    for (const id of Object.keys(registry.workers ?? {})) ids.add(id);
    // 登记表里也记录了 leadSessionId（派活方的 id），一并纳入候选。
    for (const worker of Object.values(registry.workers ?? {})) {
      if (typeof worker?.leadSessionId === 'string' && worker.leadSessionId !== '') ids.add(worker.leadSessionId);
    }
  } catch { /* 登记表不可读时只靠宿主列表 */ }
  try {
    const query = ctx.get('sessionQuery');
    if (query && typeof query.listSessions === 'function') {
      // 🐞 0.3.8 及以前的 bug（"列表有别名、send 说没有"，约半数会话中招）：
      //   宿主契约是 `listSessions(signal?: AbortSignal)`——**不接受选项对象**。
      //   旧代码传的是 `{ cwd }`，进入宿主后 `signal?.throwIfAborted()` 直接抛
      //   TypeError（signal?.throwIfAborted is not a function），又被本函数原来
      //   的空 `catch {}` 静默吞掉 ⇒ 候选集退化成"仅登记表 workers + leadSessionId"，
      //   于是列表里凡不是登记 worker/lead 的宿主会话，别名永远解析不到。
      //   （同时旧代码读 `r?.id ?? r?.session_id` 也是错的：宿主返回
      //    `{ header, live, persisted }`，真实 id 在 `record.header.id`。）
      // 修法：与 cross_session_list 用同一套调用 + 同一套过滤；cwd 归一化收口到本函数入口。
      const records = (await query.listSessions()) ?? [];
      for (const record of records) {
        const header = record?.header ?? record;
        const id = header?.id;
        if (typeof id !== 'string' || id === '') continue;
        if (header.parentSession !== undefined) continue;       // 与 list 一致：排除派生子会话
        if (normalizeCwd(header.cwd ?? '') !== root) continue;  // 与 list 一致：按调用者工作区过滤（两侧均归一化）
        ids.add(id);
      }
    }
  } catch (error) {
    // 不再静默降级：枚举失败必须留痕，否则"列表有、发消息没有"会再次悄悄发生。
    try {
      ctx.logger?.warn?.(`[cross-session-approval] 会话候选集枚举失败（别名解析退化为仅登记表）：${err(error)}`);
    } catch { /* logger 不可用时至少保留返回值 */ }
  }
  return ids;
}

/** 收紧成 lossless-JSON 安全的有限数字或 null。 */
function numberOrNull(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** 顶层会话判定：无父会话且委派深度为 0。 */
function isTopHeader(header) {
  return header?.parentSession === undefined && (header?.delegationDepth ?? 0) === 0;
}

/** 汇总事件内容里的纯文本（仅 text 块；兼容 0.2.x 的 data.content 与旧 data.message.content）。 */
function textOfBlocks(blocks) {
  return (Array.isArray(blocks) ? blocks : [])
    .filter((b) => b && b.type === 'text' && typeof b.text === 'string')
    .map((b) => b.text)
    .join('');
}

function eventText(event) {
  const data = event?.data;
  return textOfBlocks(data?.content ?? data?.message?.content);
}

/**
 * 当前部署默认模型选择（可为 undefined）。
 * @returns {{provider?: string, model?: string, reasoningEffort?: string} | undefined}
 */
function currentSelection(ctx) {
  let svc;
  try { svc = ctx.get('agentDefaultModel'); } catch { return undefined; }
  if (svc && typeof svc.currentSelection === 'function') {
    return svc.currentSelection() ?? undefined;
  }
  return undefined;
}

/** 调用者会话的工作区目录（sessions 服务优先，失败回退 process.cwd()）。 */
function workspaceOf(ctx, agent) {
  try {
    const sessions = ctx.get('sessions');
    const session = sessions?.get?.(agent.id);
    const cwd = session?.header?.cwd;
    if (typeof cwd === 'string' && cwd !== '') return cwd;
  } catch {
    // 会话服务不可用时回退。
  }
  return process.cwd();
}

/**
 * 会话当前生效的 preset id。
 *
 * 宿主 0.2.x 用 `agentPreset` 投影重建 preset，`agent-preset/selected` 事件可以
 * 改变它；`SessionHeader.agentPreset` 只在创建时写入，可能过期或缺失。因此
 * 先折叠事件流取最新的 selected 事件，再回退静态 header。
 */
function presetOfSession(ctx, sessionId) {
  try {
    const sessions = ctx.get('sessions');
    const session = sessions?.get?.(sessionId);
    const snapshot = session?.snapshotEvents?.();
    const events = Array.isArray(snapshot) ? snapshot : (snapshot?.events ?? []);
    for (let i = events.length - 1; i >= 0; i--) {
      const event = events[i];
      if (event?.type !== 'agent-preset/selected') continue;
      const selected = event?.data?.agentPreset;
      if (typeof selected === 'string' && selected !== '') return selected;
    }
    const preset = session?.header?.agentPreset;
    return typeof preset === 'string' && preset !== '' ? preset : undefined;
  } catch {
    return undefined;
  }
}

/**
 * 为新会话组合 preset（挂工具/能力）并安装模型选择快照。
 * 与宿主 composeAgent 同语义：先 resolve 再 mount；任一步不可用则静默降级，
 * 保证"会话一定能创建"优先于"能力一定齐全"。
 */
async function installPreset(ctx, agentCtx, presetId, selection) {
  const chosen = selection ?? currentSelection(ctx);
  const installModel = () => {
    if (chosen === undefined) return;
    try {
      installModelSelection(agentCtx, { current: chosen, assembled: undefined });
    } catch {
      // 模型选择服务形态不符时静默降级。
    }
  };
  let presets;
  try { presets = ctx.get('agentPresets'); } catch { presets = undefined; }
  if (presets && typeof presets.mount === 'function' && presetId) {
    try {
      let resolvedId = presetId;
      if (typeof presets.resolve === 'function') {
        const resolved = await presets.resolve(presetId);
        resolvedId = resolved?.id ?? presetId;
      }
      installModel();
      await presets.mount(agentCtx, resolvedId);
      return resolvedId;
    } catch {
      // preset 解析/挂载失败：仍安装模型选择，返回 undefined。
      installModel();
      return undefined;
    }
  }
  installModel();
  return undefined;
}

/** 组装 spawn 的模型选择。
 * "默认继承调用者"的实测正确实现：折叠调用者会话日志里最新的 request/header，
 * 拿它实际生效的 provider/model/reasoningEffort —— 而 agentDefaultModel 的全局
 * 默认（settings 里的配置）指向的模型在部分环境传输不可用（DeepSeek Messages
 * TRANSPORT），调用者正在用的路由才是被证明可用的。
 *
 * 跨 provider 支持（v0.2.1）：
 *  - 显式 `provider` 参数优先级最高；
 *  - `model` 支持复合写法 "provider/model"（第一个 / 前视为 provider）——若模型
 *    id 本身含 /，请改用显式 provider 参数 + 完整 model id，避免误拆；
 *  - provider 与调用者不同时不继承 reasoningEffort（不同 provider 的合法档位
 *    集合不同，继承大概率非法），显式 reasoning_effort 仍生效。 */
function buildSelection(ctx, args, callerId) {
  const inherited = inheritCallerRoute(ctx, callerId);
  const base = inherited ?? currentSelection(ctx) ?? {};

  // 解析 provider：显式参数 > model 复合写法 > 调用者继承 > 部署默认
  let provider = args.provider !== undefined ? String(args.provider).trim() : undefined;
  let model = args.model !== undefined ? String(args.model) : undefined;
  if (provider === undefined && model !== undefined && model.includes('/') && model.indexOf('/') > 0) {
    const idx = model.indexOf('/');
    const maybeProvider = model.slice(0, idx).trim();
    if (maybeProvider !== '') {
      provider = maybeProvider;
      model = model.slice(idx + 1).trim();
    }
  }
  if (provider === '' ) provider = undefined;
  if (model === '') model = undefined;

  const sameProviderAsCaller = inherited !== undefined && provider !== undefined &&
    provider === (inherited.provider ?? currentSelection(ctx)?.provider);
  const noSpec = provider === undefined && model === undefined && args.reasoning_effort === undefined && inherited === undefined;
  if (noSpec) return undefined;

  const selection = {};
  if (provider !== undefined) selection.provider = provider;
  else if (base.provider !== undefined) selection.provider = base.provider;
  if (model !== undefined) selection.model = model;
  else if (base.model !== undefined) selection.model = base.model;
  if (args.reasoning_effort !== undefined) {
    selection.reasoningEffort = String(args.reasoning_effort);
  } else if (inherited !== undefined && base.reasoningEffort !== undefined &&
             (provider === undefined || sameProviderAsCaller)) {
    selection.reasoningEffort = base.reasoningEffort;
  }
  return selection;
}

/** 折叠调用者会话最新的 request/header，取实际生效的模型路由（无记录返回 undefined）。 */
function inheritCallerRoute(ctx, callerId) {
  try {
    const store = ctx.get('sessions');
    const session = store?.get?.(callerId);
    if (session === undefined || session === null) return undefined;
    const snap = session.snapshotEvents?.();
    const events = Array.isArray(snap) ? snap : (snap?.events ?? []);
    for (let i = events.length - 1; i >= 0; i--) {
      const event = events[i];
      if (event?.type !== 'request/header') continue;
      const config = event?.data?.header?.config ?? event?.data?.config;
      if (config && typeof config.model === 'string' && config.model !== '') {
        const route = { model: config.model };
        if (typeof config.provider === 'string') route.provider = config.provider;
        if (typeof config.reasoningEffort === 'string') route.reasoningEffort = config.reasoningEffort;
        return route;
      }
    }
  } catch {
    // 折叠失败：回退部署默认。
  }
  return undefined;
}

/** 把新会话附着到工作区（侧边栏项目下可见）；找不到工作区则跳过。 */
async function attachWorkspace(ctx, cwd, sessionId, alive = () => true) {
  let registry;
  try { registry = ctx.get('workspaceRegistry'); } catch { return; }
  if (!registry) return;
  try {
    const workspace = typeof registry.resolveByPath === 'function'
      ? await registry.resolveByPath(cwd)
      : undefined;
    if (alive() && workspace && typeof workspace.attachSession === 'function') {
      await workspace.attachSession(sessionId);
    }
  } catch {
    // 依附失败不影响任务投递本身。
  }
}

/**
 * 登记表写入的安全包装。
 *
 * 写入失败只告警不抛：副作用（消息已投递）已经发生，抛错会让调用方误判成
 * "没送出去"而重试。投递前的读取失败必须重抛；已投递后只告警，
 * 不把已完成的投递误报成失败，不改变 spawn 提交前的失败处理。
 */
async function safeRegistry(workspace, stateDir, mutate, label, { alreadyDelivered = false } = {}) {
  try {
    await withRegistry(workspace, stateDir, mutate);
  } catch (error) {
    if (error instanceof RegistryReadError && !alreadyDelivered) throw error;
    console.warn(`[dsh-cross-session-approval] 登记表写入失败（${label}）：${err(error)}`);
  }
}

/**
 * 把一条 user 消息投递给目标 Agent（对称通道的唯一原语）。
 *
 * 0.2.x 原生语义（dsh-agent README）：
 *   - preempt=true（默认）→ steer（next-step：空闲立刻开轮，忙碌时当前步骤后立即注入）；
 *   - preempt=false → followup（next-turn：等当前整轮结束）；
 *   - wake=false → inject（只投递不唤醒，落在下一个被接纳的步骤里）。
 * 目标对象上方法缺失时回退 followup，保证降级不丢消息。
 */
function deliver(targetAgent, text, { preempt = true, wake = true } = {}) {
  // 与 headless runner 同款构造：createUserMessage 规范化消息结构
  // （裸字面量缺字段会被 DeepSeek Messages 传输拒绝，表现为 TRANSPORT）。
  const message = createUserMessage({
    content: [{ type: 'text', text }],
    source: { kind: 'user' },
  });
  const agent = targetAgent;
  // 每个模式都检查它真正需要的方法：无法兑现时明确拒绝并说明替代参数，
  // 绝不静默降级——把"别唤醒"变成唤醒比报错更糟。
  if (!wake) {
    if (typeof agent.inject !== 'function') {
      throw new Error('目标 Agent 不支持 inject，无法兑现 wake:false（只投递不唤醒）；请改用 wake:true。');
    }
    agent.inject(message);
    return 'injected';
  }
  if (preempt) {
    if (typeof agent.steer !== 'function') {
      throw new Error('目标 Agent 不支持 steer，无法兑现 interrupt:true（插队）；请改用 interrupt:false。');
    }
    agent.steer(message);
    return 'steered';
  }
  if (typeof agent.followup !== 'function') {
    throw new Error('目标 Agent 不支持 followup，无法排队投递。');
  }
  agent.followup(message);
  return 'followed';
}

/** Agent 对象是否暴露投递原语（0.2.x 运行时对象才有；TS 契约类型的裸对象没有）。 */
function hasDelivery(agent) {
  return typeof agent?.steer === 'function' || typeof agent?.followup === 'function';
}

/**
 * 确保目标会话"在运行中"并拿到可投递的 Agent：
 *   1) 本插件进程内保存的 handle（spawn/resume 拿到的，一定可投递）；
 *   2) agents.get(id) 的活跃对象（能力检测通过才用）；
 *   3) 从磁盘 resume（叫醒未打开的会话，恢复其记录的 preset）。
 * 任何失败返回 { error }，绝不抛出（调用方转成工具错误）。
 *
 * @returns {Promise<{agent: object, resumed: boolean, via: string} | {error: string}>}
 */
/** 登记表里记录的 preset（读不到时返回 undefined，由调用方退回投影）。 */
async function storedPresetOf(workspace, stateDir, sessionId) {
  try {
    const registry = await readRegistryOnly(workspace, stateDir);
    const worker = registry.workers?.[sessionId];
    return typeof worker?.preset === 'string' && worker.preset !== '' ? worker.preset : undefined;
  } catch {
    return undefined;
  }
}

/** 会话是否已被用户归档（名单不可用时视为未归档，与旧行为一致）。 */
function isArchived(ctx, sessionId) {
  try {
    const wreg = ctx.get('workspaceRegistry');
    const archivedIds = Array.isArray(wreg?.archivedSessionIds) ? wreg.archivedSessionIds : [];
    return archivedIds.includes(sessionId);
  } catch {
    return false;
  }
}

async function ensureLiveAgent(ctx, agents, handles, resuming, sessionId, signal, storedPreset, blocked, isLive) {
  if (blocked?.has(sessionId)) return { error: '该会话的 spawn 尚未提交或已失败，禁止投递及冷恢复。' };
  if (signal?.aborted === true) return { error: '调用已取消，未执行投递。' };
  if (isLive && !isLive()) return { error: '插件实例已卸载，未执行投递。' };

  // 归档判定前置：归档是用户"收起来"的意志，任何路径（含缓存句柄与活跃会话）
  // 都不该给它派活。
  if (isArchived(ctx, sessionId)) {
    return { error: `会话 ${sessionId} 已归档，请先在侧边栏恢复（取消归档）后再给它派活。` };
  }

  const cached = handles.get(sessionId);
  if (cached !== undefined) {
    return { agent: cached.agent, resumed: false, via: 'handle' };
  }

  let live;
  try { live = agents.get(sessionId); } catch { live = undefined; }
  if (live !== undefined) {
    if (hasDelivery(live)) return { agent: live, resumed: false, via: 'live' };
    return { error: `会话 ${sessionId} 处于活跃状态，但未暴露投递接口（steer/followup 缺失），无法跨会话投递。` };
  }

  // 同一会话的并发冷恢复必须共享同一次 resume：宿主持久层有独占写锁，第二次
  // 会报"已被持有"，那条消息就丢了。
  const inflight = resuming.get(sessionId);
  if (inflight !== undefined) {
    const shared = await inflight;
    // 共享恢复等待后复核取消 + 实例世代（卸载后不投递）
    if (signal?.aborted === true) return { error: '调用已取消（恢复等待期间），未投递。' };
    if (isLive && !isLive()) return { error: '插件实例已卸载（恢复等待期间），未投递。' };
    if (shared?.error) return shared;
    return { agent: shared.agent, resumed: true, via: 'resumed-shared' };
  }

  const pending = resumeColdAgent(ctx, agents, handles, sessionId, signal, storedPreset, isLive);
  resuming.set(sessionId, pending);
  try {
    return await pending;
  } finally {
    resuming.delete(sessionId);
  }
}

/** 冷恢复单个会话（供 ensureLiveAgent 与并发合并共用）。 */
async function resumeColdAgent(ctx, agents, handles, sessionId, signal, storedPreset, isLive) {
  let persistence;
  try { persistence = ctx.get('sessionPersistence'); } catch { persistence = undefined; }
  let header;
  if (persistence && typeof persistence.stat === 'function') {
    try {
      header = (await persistence.stat(sessionId))?.header;
    } catch (error) {
      return { error: `会话 ${sessionId} 不存在或无法读取（${err(error)}）。` };
    }
  }
  if (header && !isTopHeader(header)) {
    return { error: `会话 ${sessionId} 是子会话/代理会话，不可被独立恢复。` };
  }

  // preset 优先级：登记表记录（spawn 时解析并持久化的那个，最接近"该会话被
  // 创建时的能力集"）→ agentPreset 投影 → 静态 header。
  const presetId = storedPreset ?? presetOfSession(ctx, sessionId);
  try {
    if (signal?.aborted || (isLive && !isLive())) return { error: '恢复已取消或实例已卸载。' };
    const handle = await agents.resume({
      resumeSessionId: sessionId,
      setup: async (agentCtx) => {
        await installPreset(ctx, agentCtx, presetId, undefined);
      },
    });
    if (signal?.aborted === true) {
      // 恢复期间被取消：释放句柄且绝不投递，否则调用方重试会造成重复执行。
      try { await handle.dispose?.(); } catch { /* 清理失败不改变取消语义 */ }
      return { error: '调用已取消，未投递消息。' };
    }
    // 卸载期间恢复完成 ⇒ dispose 不缓存不投递（旧续体不得动手）
    if (isLive && !isLive()) {
      try { await handle.dispose?.(); } catch { /* 清理失败不改变卸载语义 */ }
      return { error: '插件实例已卸载，未投递消息。' };
    }
    handles.set(sessionId, handle);
    return { agent: handle.agent, resumed: true, via: 'resumed' };
  } catch (error) {
    return { error: `恢复会话 ${sessionId} 失败：${err(error)}` };
  }
}

/**
 * 注册全部 cross_session_* 工具。
 * @param {object} ctx - 插件上下文（inject 已保证 tools/agents 等服务可解析）。
 * @param {{ stateDir?: string }} config - bundle patch 提供的配置。
 */
export async function apply(ctx, config) {
  const stateDir = config?.stateDir ?? '.cross-session';

  const tools = ctx.get('tools');
  const agents = ctx.get('agents');
  if (!tools || typeof tools.register !== 'function') {
    throw new Error('[dsh-cross-session-approval] 需要 tools 服务（register）；请使用 dsh-base 类 profile。');
  }
  if (!agents || typeof agents.create !== 'function' || typeof agents.resume !== 'function') {
    throw new Error('[dsh-cross-session-approval] 需要 agents 服务（create/resume）；请使用 dsh-base 类 profile。');
  }

  // ── 配置校验：非法值不崩溃，取最严合法值 + 告警 ──────────────────
  const logWarn = (msg) => {
    const line = `[dsh-cross-session-approval] ${msg}`;
    const logger = ctx?.logger;
    if (logger && typeof logger.warn === 'function') {
      try { logger.warn(line); return; } catch { /* 落到 console */ }
    }
    console.warn(line);
  };
  const spawnPermission = resolveSpawnPermission(config?.spawnPermission, logWarn);
  const forkPermission = resolveForkPermission(config?.forkPermission, logWarn);
  let bridgeCfg = validateBridgeConfig(config?.approvalBridge);
  if (bridgeCfg.enabled === true && !hardCouplingBridge(true, spawnPermission)) {
    logWarn('硬耦合：approvalBridge.enabled 要求 spawnPermission=cap；桥已停用（A 仍是前提）。');
    bridgeCfg = { enabled: false, reason: '硬耦合不满足（spawnPermission 非 cap）' };
  }

  // 四个权限服务**不进 inject**：缺失只影响桥/对应创建，
  // 不能让整插件 pending。加载期查一次并告警（缺失时 answerer 不注册、A/F fail-closed）。
  let permServicesComplete = false;
  try {
    permServicesComplete = ctx.get('sandboxPolicy') !== undefined
      && ctx.get('permissionPresets') !== undefined
      && ctx.get('approval') !== undefined
      && ctx.get('sessions') !== undefined;
  } catch { permServicesComplete = false; }
  if (!permServicesComplete) {
    logWarn('权限服务（sandboxPolicy/permissionPresets/approval/sessions）不全：'
      + '审批桥 answerer 不注册；A cap / F cap|strict 的对应创建将 fail-closed 拒绝；既有工具不受影响。');
  }

  // carrier 校验器（动态 import：失败 ⇒ 桥不注册 + 告警，既有工具不受影响）。
  // 用动态而非静态 import：裸包名 import 一旦脱离宿主 ResolutionRouter 会让整条
  // entry 死掉；动态失败只失去桥，其余 9 个工具照常。
  let carrierKeyOfFn = undefined;
  try {
    const mod = await import('@deepseek-ai/dsh-scope');
    if (mod && typeof mod.carrierKeyOf === 'function') carrierKeyOfFn = mod.carrierKeyOf;
  } catch { /* 落到下方告警 */ }
  // 其余 @deepseek-ai/* 也改动态 import（失败用 fallback，既有工具不崩）
  try { const tm = await import('@deepseek-ai/dsh-tools'); if (tm?.defineTool) defineTool = tm.defineTool; } catch { /* fallback identity */ }
  try { const am = await import('@deepseek-ai/dsh-agent'); if (am?.installModelSelection) installModelSelection = am.installModelSelection; } catch { /* spawn 模型选择降级 */ }
  try { const lm = await import('@deepseek-ai/dsh-llm'); if (lm?.createUserMessage) createUserMessage = lm.createUserMessage; } catch { /* deliver 用 fallback 规范化 */ }
  const answererAvailable = bridgeCfg.enabled === true && permServicesComplete && carrierKeyOfFn !== undefined;
  if (bridgeCfg.enabled === true && !answererAvailable) {
    logWarn(carrierKeyOfFn === undefined
      ? '@deepseek-ai/dsh-scope 不可用（carrierKeyOf 缺失）：审批桥 answerer 不注册（fail-closed）。'
      : '权限服务不全：审批桥 answerer 不注册（fail-closed）。');
  }

  /** 本进程内 spawn/resume 拿到的 AgentHandle（携带投递能力与 dispose 能力）。 */
  const handles = new Map();
  /** 同一会话的并发冷恢复共享同一次 resume（避免"已被持有"导致消息丢失）。 */
  const resuming = new Map();
  // Failed or still-creating children cannot be reached via handles, live lookup or resume.
  const blockedSpawns = new Set();

  // ── 审批桥实例状态（全部实例级；卸载时统一清理）─────────────────────
  let instanceDisposed = false;
  const guardCall = (signal) => {
    const epoch = instanceEpoch;
    const live = () => !instanceDisposed && instanceEpoch === epoch;
    const check = () => {
      if (signal?.aborted) throw new Error('调用已取消，未执行副作用。');
      if (!live()) throw new Error('插件实例已卸载，未执行副作用。');
    };
    check();
    return { check, live };
  };
  let instanceEpoch = 0;                 // 实例世代：重载/卸载后旧续体不得再动手
  const spawnIntents = new Map();        // sessionId -> intent（仅 spawn 写，发布前消费）
  const taskOwners = new Map();          // childSessionId -> ownerSessionId（仅 spawn 写）
  const activeRequests = new Set();      // 活动请求（入口即计，含未进 pending 的阶段）
  const pending = new Map();             // key -> entry（已登记、待决）
  const liveExecs = new Map();           // callId -> [rec]（活动取证；结算即删）
  const resultWatch = new WeakMap();     // exec -> rec（结果期审计；自动回收）
  const DELEGATE = Symbol('cross-session-approval: delegate');

  // A 与 F 共享这一个 session/created 监听器（prepend，**同步**执行；
  // 同步 throw ⇒ 工厂回滚 attach ⇒ agents.create 拒绝、任务不投递）。
  // 记录监听器注册结果——失败时 cap/strict spawn 必须拒绝（fail-closed）。
  let clampHookReady = false;
  try {
    ctx.on('session/created', (session) => {
      const intent = spawnIntents.get(session.id);
      if (intent !== undefined) {
        if (intent.clamped === true) {
          if (intent.clampedSession !== session) throw new Error('夹紧凭证会话实例不一致。');
          return;
        }
        if (spawnPermission === 'cap') {
          clampChildPermission(ctx, intent, session, { epoch: instanceEpoch });
        }
        intent.clampedSession = session;
        intent.clamped = true;  // 凭证绑定本次 Session 实例
        return;
      }
      if (forkPermission === 'off') return;
      clampDerivedPermission(ctx, session, forkPermission);
    }, { prepend: true });
    clampHookReady = true;
  } catch (error) {
    if (spawnPermission === 'cap' || forkPermission !== 'off') {
      throw new Error('session/created 防护监听器注册失败：拒绝加载 cap/strict 插件（fail-closed）：' + err(error));
    }
    logWarn('session/created 监听器不可用；A/F 均显式 off。');
  }

  // 会话被外部拆掉时：清本地句柄缓存 + 桥清理（payload 形态做防御解析；
  // agent id == session id，dsh 的 agents 服务按会话键控）。
  // 桥规则：它是 requester ⇒ finish('cancelled')；它是 owner ⇒ finish(DELEGATE)。
  const onDisposedSessionId = (id) => {
    handles.delete(id);
    for (const entry of [...activeRequests]) {
      if (entry.requesterSession?.id === id) entry.finish('cancelled');
    }
    for (const entry of [...activeRequests]) {
      if (entry.owner === id) entry.finish(DELEGATE);
    }
    spawnIntents.forEach((intent, sessionId) => {
      // 不删除 intent（删除 = 丢失防护依据，等待中的 spawn 恢复后绕过 A）；
      // 标记失效，spawn 在 await 恢复后同步拒绝。
      if (intent.callerId === id || sessionId === id) {
        intent.cancelled = true;
        intent.cancelReason = intent.callerId === id ? 'caller-disposed' : 'child-disposed';
      }
    });
    taskOwners.forEach((owner, sessionId) => {
      if (owner === id || sessionId === id) taskOwners.delete(sessionId);
    });
  };
  try {
    ctx.on('agent/disposed', (payload) => {
      const id = typeof payload === 'string' ? payload : payload?.id ?? payload?.agent?.id;
      if (typeof id === 'string') onDisposedSessionId(id);
    });
  } catch {
    // 事件不可用时句柄缓存只多不少，不影响正确性（live 检测在 handle 之后兜底）。
  }
  try {
    ctx.on('session/disposed', (payload) => {
      const id = typeof payload === 'string' ? payload : payload?.id ?? payload?.session?.id;
      if (typeof id === 'string') onDisposedSessionId(id);
    });
  } catch {
    // 事件不可用时桥清理少一条路径，卸载清理（ctx.effect）仍兜底。
  }

  // ── cross_session_spawn ────────────────────────────────────────────────────
  tools.register(defineTool({
    name: 'cross_session_spawn',
    description: '新建顶层持久会话，把 task 作为其首条消息投递并唤醒执行；立即返回、绝不等待完成。完成后对方会调用 cross_session_reply 回信。返回的 session_id 供 send/status/read 使用。model/reasoning_effort/agent_preset 默认继承调用者。',
    parameters: {
      name: { type: 'string', required: true, description: '新会话的名字（侧边栏可见）。' },
      task: { type: 'string', required: true, description: '交给新会话的任务，务必完整、可验收。' },
      reply_to: { type: 'string', description: '可选：结果回复给哪个会话 id（默认 = 调用者）。' },
      provider: { type: 'string', description: '可选：新会话使用的 provider id（默认继承调用者）。跨 provider 派活用；也可省略此参数、在 model 里写 "provider/model" 复合形式。' },
      model: { type: 'string', description: '可选：新会话模型 id（默认继承调用者）。支持 "provider/model" 复合写法（第一个 / 前视为 provider）；模型 id 本身含 / 时请改用显式 provider 参数。' },
      reasoning_effort: { type: 'string', description: '可选：推理程度（off/low/medium/high/max 等，默认继承调用者）。' },
      permission: {
        type: 'string',
        description: '可选：子会话的权限预设名（宿主 permissionPresets.names）。缺省 = DSH 默认预设且不超过调用者；显式更宽 ⇒ 拒绝本次 spawn（不静默夹紧）。',
      },
      agent_preset: {
        type: 'string',
        description: '可选：新会话的 agent preset（自定义模式）id，如 standard/std-compact/game-dev（宿主 agentPresets.list 的 id）。缺省 = 继承调用者当前 preset。指定的 preset 不存在则报错带可用列表（不静默降级）。注意：preset 只影响 agent 平面的工具/提示词，不改沙箱/模型路由（由 permission/host 平面管）。',
      },
      cwd: {
        type: 'string',
        description: '可选：子会话工作区（绝对路径）。缺省 = 调用者解析出的 workspaceRoot；调用者非最高档时必须是其子目录（严格 realpath 比较）。',
      },
      tags: {
        type: 'array',
        description: '可选：任务域标签（最多 5 个），供 list 按 tag 过滤。',
        items: { type: 'string' },
      },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{
        type: 'text',
        text: `已创建会话「${value.name}」（${value.session_id}），模型 ${value.provider ? value.provider + '/' : ''}${value.model || '(未选定)'} · 推理 ${value.reasoning_effort || '(默认)'}${value.agent_preset ? ` · 模式:${value.agent_preset}` : ''}${value.tags?.length ? ` · 标签:${value.tags.join('/')}` : ''}，任务已投递，对方已开始执行。你可以继续做别的工作；完成后它会通过 cross_session_reply 回复给你。`,
      }],
    },
    async execute(args, exec) {
      const caller = requireAgent(exec);
      const callerSession = requireSession(ctx, exec);
      const sessionId = `session-${randomUUID()}`;
      const captain = args.reply_to ?? caller.id;
      const captainAlias = captain.startsWith('cs_') ? captain : makeSessionAlias(captain);  // 回信目标用别名（UUID 会被遮蔽）
      const selection = buildSelection(ctx, args, caller.id);
      const callerPreset = presetOfSession(ctx, caller.id);
      // agent preset：显式指定则验证存在（不存在报错带可用列表），缺省继承调用者。
      let desiredPreset = callerPreset;
      if (args.agent_preset !== undefined && args.agent_preset !== '') {
        const wantedPreset = String(args.agent_preset);
        let ap;
        try { ap = ctx.get('agentPresets'); } catch { ap = undefined; }
        if (!ap || typeof ap.resolve !== 'function') {
          throw new Error('宿主未提供 agentPresets.resolve，无法验证指定的 agent_preset');
        }
        try {
          await ap.resolve(wantedPreset);
        } catch (e) {
          const avail = e?.details?.available;
          throw new Error(`未知 agent preset "${wantedPreset}"${Array.isArray(avail) && avail.length ? `（可用：${avail.join(', ')}）` : `：${err(e)}`}`);
        }
        desiredPreset = wantedPreset;
      }
      const tags = [...new Set((Array.isArray(args.tags) ? args.tags : [])
        .map((t) => String(t).trim().slice(0, 20))
        .filter((t) => t !== ''))].slice(0, 5);

      // ── A：发布前预检——cwd 定界 + 显式预设纯比较 ────────────
      // 服务缺失 + spawnPermission=cap ⇒ 拒绝派活（fail-closed，绝不放行旧行为）。
      let cwd;
      let callerMode = undefined;
      let callerRoot = undefined;
      let callerApproval = undefined;
      let requestedPreset = undefined;
      if (spawnPermission === 'cap') {
        // A/F 夹紧防线依赖 session/created 监听器；未注册成功时拒绝派活
        if (clampHookReady !== true) {
          throw new Error('session/created 监听器未注册：A/F 夹紧防线不存在，拒绝派活（fail-closed）。');
        }
        const perms = ctx.get('permissionPresets');
        const policy = ctx.get('sandboxPolicy');
        const approval = ctx.get('approval');
        const sessions = ctx.get('sessions');
        if (perms === undefined || policy === undefined || approval === undefined || sessions === undefined) {
          throw new Error('权限服务缺失：无法执行发布前三维夹紧，拒绝派活（fail-closed）。');
        }
        // 必须传真实 Session，传 Agent 会静默退化成"部署默认档位 + 部署根"。
        const callerPolicy = policy.resolve({ session: callerSession });
        callerMode = callerPolicy.mode;
        callerRoot = callerPolicy.workspaceRoot;
        callerApproval = approval.effectivePolicy(callerSession);
        cwd = resolveSpawnCwd(args.cwd, callerPolicy);
        if (args.permission !== undefined && args.permission !== '') {
          const name = String(args.permission);
          const names = Array.isArray(perms.names) ? perms.names : [];
          if (!names.includes(name)) {
            throw new Error(`未知权限预设 "${name}"（可用：${names.join(', ')}）`);
          }
          // 纯比较预检（fail-fast）：显式更宽 ⇒ 拒绝，不静默夹紧。
          precheckPresetSpec(name, perms.resolve(name), callerMode, callerApproval);
          requestedPreset = name;
        }
      } else {
        // off：恢复旧行为（调用者工作区，process.cwd() 兜底路径）。
        cwd = workspaceOf(ctx, caller);
      }

      // ── 意图与所有者登记（发布前；listener 消费 intent 固定所有者）──
      if (spawnIntents.size >= 1024 || blockedSpawns.size >= 4096) {
        throw new Error('派活意图或失败隔离表已满：拒绝派活（fail-closed）。');
      }
      spawnIntents.set(sessionId, {
        // agent.id 与 session.id 恒等（宿主断言
        // `id !== agent.session.id` 即抛错）⇒ 用 caller.id 去 sessions.get 能取到 Session。
        callerId: caller.id,
        callerSession,
        epoch: instanceEpoch,
        // 快照只用于 listener 里**比对**（任何变化 ⇒ 拒绝），绝不当授权依据。
        callerMode, callerRoot, callerApproval,
        requestedPreset,
        cwd,
      });
      blockedSpawns.add(sessionId);
      taskOwners.set(sessionId, caller.id);   // 固定任务所有者（仅 spawn 写）

      // 与宿主 composeAgent 同序：先 resolve 出 preset id 写进 meta（持久化，
      // 冷恢复时宿主据此重建能力集），setup 里再 mount。
      let resolvedPreset = desiredPreset;
      try {
        const presets = ctx.get('agentPresets');
        if (presets && typeof presets.resolve === 'function' && desiredPreset) {
          resolvedPreset = (await presets.resolve(desiredPreset))?.id ?? desiredPreset;
        }
      } catch { /* resolve 失败时退回原 id，保证会话仍能创建 */ }

      // 第一个 await 恢复后检查 intent 有效性——调用者销毁 / 世代变化 / 取消
      const intentNow = spawnIntents.get(sessionId);
      if (intentNow === undefined || intentNow.cancelled === true) {
        spawnIntents.delete(sessionId);
        taskOwners.delete(sessionId);
        blockedSpawns.delete(sessionId);
        throw new Error('派活中止：调用者已销毁或意图已失效。');
      }
      if (intentNow.epoch !== instanceEpoch) {
        spawnIntents.delete(sessionId);
        taskOwners.delete(sessionId);
        blockedSpawns.delete(sessionId);
        throw new Error('实例世代已变：派活中止。');
      }
      if (exec.signal?.aborted === true) {
        spawnIntents.delete(sessionId);
        taskOwners.delete(sessionId);
        blockedSpawns.delete(sessionId);
        throw new Error('派活中止：调用已取消。');
      }

      let handle;
      const quarantineCreatedSession = () => {
        const known = new Set([intentNow.clampedSession, handle?.agent?.session]);
        try { known.add(ctx.get('sessions')?.get?.(sessionId)); } catch { /* service unavailable */ }
        for (const session of known) {
          if (!session || session.id !== sessionId) continue;
          // Failed creations also lose persistent grants before disposal; never grants escalation.
          try { writeApprovalPolicy(session, 'never'); writeSandboxMode(session, 'read-only'); }
          catch (error) { logWarn('失败 spawn 的持久权限撤销失败（本实例已隔离）：' + err(error)); }
        }
      };
      try {
        handle = await agents.create({
          sessionId,
          meta: {
            cwd,
            ...(resolvedPreset === undefined ? {} : { agentPreset: resolvedPreset }),
          },
          agentOptions: selection === undefined ? undefined : {
            provider: selection.provider,
            model: selection.model,
            reasoningEffort: selection.reasoningEffort,
          },
          setup: async (agentCtx) => {
            // meta 用解析后的 id；mount 交给 installPreset 自己 resolve 一次，
            // 否则同一个 id 会被连续 resolve 两次。
            await installPreset(ctx, agentCtx, desiredPreset, selection);
          },
        });
      } catch (error) {
        // create 失败（含 session/created 同步拒绝的工厂回滚）⇒ 不留孤儿登记。
        quarantineCreatedSession();
        spawnIntents.delete(sessionId);
        taskOwners.delete(sessionId);
        throw error;
      }
      // All post-create failures use one cleanup path, including registry/deliver exceptions.
      let registryTouched = false;
      const aliveSpawn = () => {
        const intent = spawnIntents.get(sessionId);
        return intent === intentNow && intent.cancelled !== true
          && intent.epoch === instanceEpoch && exec.signal?.aborted !== true;
      };
      const requireAliveSpawn = () => {
        if (!aliveSpawn()) throw new Error('派活中止：创建恢复后意图已失效或已取消。');
      };
      const cleanupCreated = async () => {
        blockedSpawns.add(sessionId);
        quarantineCreatedSession();
        spawnIntents.delete(sessionId);
        taskOwners.delete(sessionId);
        handles.delete(sessionId);
        try { await handle?.dispose?.(); }
        catch (error) { logWarn('失败 spawn 的句柄释放失败（会话已隔离）：' + err(error)); }
        if (registryTouched) {
          try {
            await safeRegistry(cwd, stateDir, (registry) => {
              delete registry.workers[sessionId];
            }, 'spawn-cleanup');
          } catch (error) { logWarn('失败 spawn 的登记撤销失败（会话已隔离）：' + err(error)); }
        }
      };
      try {
        requireAliveSpawn();
        if (spawnPermission === 'cap'
            && (intentNow.clamped !== true || intentNow.clampedSession !== handle?.agent?.session)) {
          throw new Error('发布前夹紧凭证缺失或会话实例不匹配：拒绝投递（fail-closed）。');
        }
        const taskText = clampText(args.task);
        const taskMessage = `[dsh-cross-session-approval] 你是由会话 ${makeSessionAlias(caller.id)} 创建的任务会话「${args.name}」。
你自身的 session_id = ${makeSessionAlias(sessionId)}（如需归档/读取自己，用这个别名；不要猜测）。
任务：${taskText}

工作完成后（或无法完成时），你必须调用 cross_session_reply 工具，把最终结果/结论回复给指定会话：
  - to = ${captainAlias}
  - text 里给出完整的结果摘要（或失败原因）。
回复完成后本次任务即告结束；若创建者后续通过 cross_session_send 再次给你发消息，你将收到新的任务。`;
        registryTouched = true;
        await safeRegistry(cwd, stateDir, (registry) => {
          requireAliveSpawn();
          registry.workers[sessionId] = {
            name: args.name, leadSessionId: captain, createdAt: Date.now(), lastTaskAt: Date.now(),
            task: taskText, tags, preset: desiredPreset ?? null,
            model: selection?.model ?? null, reasoningEffort: selection?.reasoningEffort ?? null, replies: [],
          };
          pruneRegistry(registry);
        }, 'spawn');
        requireAliveSpawn();
        // Commit and first delivery are synchronous; no attachment await creates a rollback window.
        handles.set(sessionId, handle);
        deliver(handle.agent, taskMessage);
        blockedSpawns.delete(sessionId);
        spawnIntents.delete(sessionId);
        // Optional sidebar attachment belongs only to a successfully delivered task.
        const committedEpoch = instanceEpoch;
        void attachWorkspace(ctx, cwd, sessionId, () => committedEpoch === instanceEpoch && handles.get(sessionId) === handle);
      } catch (error) {
        await cleanupCreated();
        throw error;
      }

      return {
        session_id: makeSessionAlias(sessionId),  // 返回别名（UUID 会被遮蔽）
        name: args.name,
        status: 'task_sent',
        tags,
        provider: selection?.provider ?? '',
        model: selection?.model ?? '',
        reasoning_effort: selection?.reasoningEffort ?? '',
        agent_preset: desiredPreset ?? '',
      };
    },
  }));

  // ── 跨会话审批桥：请求处理、执行关联、决定与收尾──
  // 所有内部原因（DELEGATE/unloaded/deadline/error/overflow）都在出口被
  // resolveExit 挡回 next()；桥只返回 allowed-once / rejected / cancelled。

  /** 活动请求资源：finish 是唯一出口（幂等），统一收尾 timer/监听/pending/active。 */
  function createEntry(request, requesterId) {
    let resolveFn;
    const promise = new Promise((resolve) => { resolveFn = resolve; });
    const entry = {
      epoch: instanceEpoch,
      deferred: { promise, resolve: resolveFn },
      terminal: promise,
      done: false,
      deadlineAt: Date.now() + bridgeCfg.timeoutMs,   // 总截止：从 handler 入口起算
      timer: undefined,
      onAbort: undefined,
      key: undefined,
      owner: undefined,
      ownerSnapshot: undefined,
      targetPolicy: undefined,
      ownerSession: undefined,
      requesterAgent: undefined,
      requesterSession: undefined,
      rec: undefined,
      audit: undefined,
      callId: undefined,
      toolName: undefined,
      noticeDelivered: false,
      withdrawSent: false,
      finalOutcome: undefined,              // 首次终结 outcome，出口优先用它
    };
    entry.finish = (outcome) => {
      if (entry.done) return;
      entry.done = true;
      entry.finalOutcome = outcome;        // 保存首次终结 outcome，出口优先用它
      if (entry.timer !== undefined) clearTimeout(entry.timer);
      if (request.signal && entry.onAbort !== undefined) {
        try { request.signal.removeEventListener('abort', entry.onAbort); } catch { /* 已销毁 */ }
      }
      activeRequests.delete(entry);
      if (entry.key !== undefined) pending.delete(entry.key);
      entry.deferred.resolve(outcome);
      // 撤单提取为方法（sendWithdraw），投递返回后也可补发——noticeDelivered
      // 在 steer 返回后才置 true，若 steer 期间被取消，finish 时 noticeDelivered 仍
      // false ⇒ 不撤单；deliverToApprover 返回后补发。sendWithdraw 幂等且只对已投递撤单。
      const ownerActed = outcome === 'allowed-once' || outcome === 'rejected';
      if (!ownerActed) entry.sendWithdraw(
        outcome === DELEGATE ? '桥已委托本地 UI 审批'
        : outcome === 'deadline' ? '总截止时间到'
        : outcome === 'unloaded' ? '插件卸载'
        : '请求已取消');
    };
    // 撤单通知（幂等；只对已投递且非 owner 决定的请求发）
    entry.sendWithdraw = (reason) => {
      if (entry.finalOutcome === 'allowed-once' || entry.finalOutcome === 'rejected') return;
      if (entry.withdrawSent) return;
      if (entry.noticeDelivered !== true) return;
      if (entry.owner === undefined) return;
      if (bridgeCfg.injectWithdraw !== true) return;
      entry.withdrawSent = true;
      try {
        const live = typeof agents.get === 'function' ? agents.get(entry.owner) : undefined;
        if (live !== undefined && typeof live.steer === 'function') {
          live.steer(createUserMessage({
            content: [{ type: 'text', text: `【跨会话审批桥】此前的审批请求（key=${entry.key}）已终止（${reason}）。请勿再用该 key 调用 cross_session_approve；请求已由本地 UI 通道处理或已取消。` }],
            source: { kind: 'user' },
          }));
        }
      } catch { /* 撤单通知失败不影响终结本身 */ }
    };
    return entry;
  }

  /** 仅对**活** owner 投递（本版不用冷恢复）：解析不到 ⇒ false（委托 UI）。 */
  async function deliverToApprover(ownerId, notice, entry) {
    if (entry.done) return false;
    let live;
    try { live = agents.get(ownerId); } catch { return false; }
    if (live === undefined || typeof live.steer !== 'function') return false;
    live.steer(createUserMessage({
      content: [{ type: 'text', text: notice }],
      source: { kind: 'user' },
    }));
    entry.noticeDelivered = true;
    // 投递返回后若已终结（steer 期间被取消），补发撤单
    if (entry.done) entry.sendWithdraw('请求已取消');
    return true;
  }

  /**
   * 取证：同 Session 唯一首次 rec + 三方档位一致。
   * 任一不符 ⇒ undefined（不接管）。rec 一旦固定，后续绝不换成同 callId 的另一个。
   */
  function executionEvidence(request, audit, entry) {
    const session = entry.requesterSession;   // 绑定的 Session 实例（不是 id）
    const callId = request.callId;
    const list = liveExecs.get(callId);
    if (!Array.isArray(list)) return undefined;
    const candidates = list.filter((rec) => rec.session === session);
    if (candidates.length !== 1) return undefined;      // 0 个或歧义 ⇒ 不猜
    const rec = candidates[0];
    if (rec.name !== request.toolName) return undefined;
    if (Object.isFrozen(rec.argsAtEntry) !== true) return undefined;
    if (rec.exec.arguments !== rec.argsAtEntry) return undefined;   // 属性被换过 ⇒ 不接管
    if (rec.diverged === true) return undefined;                    // 结果期已记分歧
    if (!triPartiteModeConsistent(audit.mode, request.reason, rec.argsAtEntry?.sandbox_permissions)) {
      return undefined;
    }
    let workspaceRoot;
    try { workspaceRoot = ctx.get('sandboxPolicy')?.resolve?.({ session })?.workspaceRoot; } catch { workspaceRoot = undefined; }
    return {
      rec,
      verifiable: {
        audit: { id: audit.id, seq: audit.seq, turnStartSeq: audit.turnStartSeq, reason: audit.reason },
        requestedMode: audit.mode,
        toolName: rec.name,
        callId,
        sessionCwd: session?.header?.cwd,
        workspaceRoot,
      },
      // ⚠️ observed 是"入口观察值"，**非执行事实**（参数原文只作参考，showObservedArgs）
      observed: bridgeCfg.showObservedArgs === 'off' ? undefined : {
        body: extractBody(rec.argsAtEntry),
        workdir: rec.name === 'pwsh' ? resolvePwshWorkdir(session, rec.argsAtEntry) : undefined,
      },
    };
  }

  /**
   * 内部计算：一次都不碰 next（只返回 DELEGATE 或宿主可认值）。
   * 在登记审批前完成请求绑定、取证与危险操作判定。
   */
  async function compute(request, entry, requesterId, stage, alive) {
    // 1) 固定所有者（内存，仅 spawn 写）——★ 第一个 await 之前就绑定
    const owner = taskOwners.get(requesterId);
    if (typeof owner !== 'string' || owner === '' || owner === requesterId) return DELEGATE;
    entry.owner = owner;

    // 1.5) ★ 独立危险拒绝门：在审计绑定/取证之前，best-effort 从 liveExecs
    // 取入口观察命令文本查危险。命中 ⇒ rejected（不落 UI）；取不到 ⇒ 不拦（交给后续步骤）。
    // 审计或取证不可靠时，明确危险命令不得因"无法证明安全"而流入可批准的下游。
    {
      const list = liveExecs.get(request.callId);
      if (Array.isArray(list) && list.length > 0) {
        const matching = list.filter((r) => r.session === entry.requesterSession);
        const candidates = matching.length > 0 ? matching : list;
        for (const pick of candidates) {
          const body = extractBody(pick.argsAtEntry);
          if (body === undefined) continue;
          let root;
          try {
            root = canonicalPathStrict(ctx.get('sandboxPolicy')?.resolve?.(
              { session: entry.requesterSession })?.workspaceRoot);
          } catch { root = undefined; }
          const workdir = pick.name === 'pwsh'
            ? resolvePwshWorkdir(entry.requesterSession, pick.argsAtEntry) : undefined;
          if (isDangerousOperation(body, { workspaceRoot: root, workdir })
              || isUnresolvableOperation(body)) return 'rejected';
        }
      }
    }

    // 2) 审计绑定：目标档位以**已提交的审计事件**为准，不是收到的 request.reason
    const audit = readAuditRequest(request);
    if (audit === undefined) return DELEGATE;
    entry.audit = audit;                 // 固定 {id, seq, turnStartSeq, reason, mode}
    entry.callId = request.callId;
    entry.toolName = request.toolName;

    // 3) 授权包含（**同步**：读权限与放行之间无 await 间隙）
    const auth = checkAuthority(ctx, owner, requesterId, audit.mode);
    // 不因 !auth.allowed 立即 DELEGATE——先保存快照、取证、危险判定，
    // 危险硬拒绝优先于 owner 授权与容量兜底。
    entry.ownerSnapshot = auth.ownerSnapshot;
    entry.targetPolicy = auth.targetPolicy;
    entry.ownerSession = auth.ownerSession;
    // 即使 auth 不通过，也要独立取得 requester 的保护路径事实
    // （不要因 auth.allowed === false 就丢掉 root 保护）
    let requesterRoot = entry.targetPolicy?.workspaceRoot;
    if (requesterRoot === undefined) {
      try {
        const reqSession = ctx.get('sessions')?.get?.(requesterId);
        const reqPolicy = ctx.get('sandboxPolicy')?.resolve?.({ session: reqSession });
        requesterRoot = canonicalPathStrict(reqPolicy?.workspaceRoot);
      } catch { /* 不可用时危险检查仍尽力而为 */ }
    }

    // 4) 取证：唯一首次 rec + 三方档位一致；任一不符 ⇒ 不接管
    const ev = executionEvidence(request, audit, entry);
    if (!alive() || ev === undefined) return DELEGATE;

    // 4.5) ★ 危险操作判定（登记 pending 之前）：命中 ⇒ 强制 rejected，
    //      不发给 owner（owner 也无权放行）。基于入口观察值，尽力而为。
    // 危险硬拒绝优先于 owner 授权——即使 owner 降权也先判危险。
    // 不可判定的命令（动态命令名/编码命令）也必须拒绝（宁可误拒不可漏放）。
    if (isDangerousOperation(extractBody(ev.rec.argsAtEntry),
        { workspaceRoot: requesterRoot, workdir: ev.rec.name === 'pwsh'
            ? resolvePwshWorkdir(entry.requesterSession, ev.rec.argsAtEntry) : undefined })
        || isUnresolvableOperation(extractBody(ev.rec.argsAtEntry))) {
      return 'rejected';
    }

    // 4.6) owner 授权检查移到危险判定之后——已识别的危险请求
    // 不得因 owner 降权而流入可批准的下游（DELEGATE → next()）。
    if (!alive() || !auth.allowed) return DELEGATE;

    // 5) 容量 → key → 渲染通知 → 量字节 → 登记 + 投递
    // 容量检查移到危险判定之后——已识别的危险请求已在 4.5 拒绝
    if (pending.size >= bridgeCfg.maxPending) return DELEGATE;      // 待决请求容量上限
    if (activeRequests.size > bridgeCfg.maxActiveRequests) return DELEGATE; // activeRequests 容量兜底
    // 审批 key 用 base62 短码，**不用 UUID**：UUID/32 位 hex 形状会被宿主/上游链路在
    // 「模型可见文本」里替换成占位符，使 AI owner 从通知里读到的 key 无效
    // UUID 可能被显示为占位符，导致审批 key 无法匹配；base62 避免此显示问题。
    // 通知中可直接使用 base62 审批 key。
    const key = makeApprovalKey();
    const notice = renderApprovalNotice({
      key,
      requesterId,
      owner,
      verifiable: ev.verifiable,
      observed: ev.observed,
    });
    if (Buffer.byteLength(notice, 'utf8') > bridgeCfg.noticeTextBytes) return DELEGATE;
    entry.key = key;
    if (auth.requesterSession !== entry.requesterSession
        || ev.rec.session !== entry.requesterSession) return DELEGATE;
    entry.rec = ev.rec;                          // ★ 固定首次匹配实例
    pending.set(key, entry);                     // 与上一条 alive() 之间无 await ⇒ 原子

    // 6) 仅对活 owner 投递（不 await；挂起由 deadline 兜底）
    void deliverToApprover(owner, notice, entry)
      .then((delivered) => { if (!delivered) entry.finish(DELEGATE); },
            () => entry.finish(DELEGATE));

    // finish 是唯一出口，所有路径都会 resolve；此处不再查 alive（决出值即答案）
    const settled = await entry.deferred.promise;
    return settled;
  }

  // ── cross_session_send ─────────────────────────────────────────────────────
  tools.register(defineTool({
    name: 'cross_session_send',
    description: '给任意会话投一条 user 消息。默认插队（目标当前步骤结束后立即注入）；interrupt=false 等当前整轮结束；wake=false 只排队不唤醒。未打开的顶层会话自动从磁盘恢复后投递。session_id 传 cross_session_list 给的 cs_ 短别名或真实 id 均可。',
    parameters: {
      session_id: { type: 'string', required: true, description: '目标会话：cross_session_list 返回的 cs_ 短别名，或真实 session-<uuid> id。' },
      message: { type: 'string', required: true, description: '发给该会话的消息/新任务。' },
      wake: { type: 'boolean', description: '是否唤醒目标执行（默认 true）。' },
      interrupt: { type: 'boolean', description: '是否插队（默认 true）。' },
      reply_to: { type: 'string', description: '可选：本次任务的回复目标会话 id（同样支持 cs_ 别名）。' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (args, value) => [{
        type: 'text',
        text: `消息已投递给会话 ${value.session_id}（${value.mode === 'resumed' ? '未打开，已从磁盘叫醒' : '原本就活跃'}；${args.wake === false ? '已排队未唤醒' : args.interrupt === false ? '已投递（整轮结束后处理）' : '已投递（插队）'}）。`,
      }],
    },
    async execute(args, exec) {
      const callGuard = guardCall(exec.signal);
      requireAgent(exec);
      const caller = requireAgent(exec);
      // 登记根与 spawn 一致：调用者会话的工作区（跨会话协作通常在同一项目内）。
      const cwd = workspaceOf(ctx, caller);
      // 0.3.2：先把别名解析成真实 id（模型从列表复制到的 id 是占位符，不可用）。
      const targetId = resolveSessionIdOrThrow(args.session_id, await collectSessionIdCandidates(ctx, cwd, stateDir));
      const storedPreset = await storedPresetOf(cwd, stateDir, targetId);
      callGuard.check();
      const resolved = await ensureLiveAgent(ctx, agents, handles, resuming, targetId, exec.signal, storedPreset, blockedSpawns, callGuard.live);
      callGuard.check();
      if (resolved.error) throw new Error(resolved.error);
      const { agent, resumed } = resolved;
      const directive = directiveFor(args.reply_to);
      deliver(agent, clampText(args.message) + directive, { preempt: args.interrupt !== false, wake: args.wake !== false });
      await safeRegistry(cwd, stateDir, (registry) => {
        const worker = registry.workers[targetId];
        if (worker) worker.lastTaskAt = Date.now();
      }, 'send', { alreadyDelivered: true });
      return {
        session_id: makeSessionAlias(targetId),  // 返回别名（UUID 会被遮蔽）
        status: args.wake === false ? 'queued' : 'delivered',
        mode: resumed ? 'resumed' : 'live',
      };
    },
  }));

  // ── cross_session_reply ────────────────────────────────────────────────────
  tools.register(defineTool({
    name: 'cross_session_reply',
    description: '把结果投递给指定会话并唤醒（与 send 对称）。任务会话用它回报工作结果；目标未打开会自动恢复，回信永远送得到。',
    parameters: {
      to: { type: 'string', required: true, description: '要回复给的目标会话：cs_ 短别名或真实 id（通常取自任务消息里的"回信目标"）。' },
      text: { type: 'string', required: true, description: '结果摘要、结论或失败原因。' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (args, value) => [{
        type: 'text',
        text: `回复已投递给会话 ${isSessionAlias(args.to) ? args.to : makeSessionAlias(args.to)} 并唤醒它（${value.mode === 'resumed' ? '目标未打开，已从磁盘叫醒' : '目标原本活跃'}）。`,
      }],
    },
    async execute(args, exec) {
      const callGuard = guardCall(exec.signal);
      const caller = requireAgent(exec);
      const cwd = workspaceOf(ctx, caller);
      // 0.3.2：别名解析（回信目标常由模型从任务书里抄，同样可能是占位符）。
      const toId = resolveSessionIdOrThrow(args.to, await collectSessionIdCandidates(ctx, cwd, stateDir));
      const storedPreset = await storedPresetOf(cwd, stateDir, toId);
      callGuard.check();
      const resolved = await ensureLiveAgent(ctx, agents, handles, resuming, toId, exec.signal, storedPreset, blockedSpawns, callGuard.live);
      callGuard.check();
      if (resolved.error) throw new Error(resolved.error);
      const { agent, resumed } = resolved;
      const replyText = `[dsh-cross-session-approval] 来自会话 ${makeSessionAlias(caller.id)} 的回复：\n${clampText(args.text)}`;
      deliver(agent, replyText);

      await safeRegistry(cwd, stateDir, (registry) => {
        const worker = registry.workers[caller.id];
        if (worker) {
          const replies = Array.isArray(worker.replies) ? worker.replies : [];
          replies.push({ at: Date.now(), to: toId, text: clampText(args.text) });
          worker.replies = replies.slice(-20); // 防膨胀：只保留最近 20 条
          // 累计次数单独记：replies 只留最近 20 条，用它的长度当总数会在第 21
          // 次之后失真。
          worker.replyCount = (typeof worker.replyCount === 'number'
            ? worker.replyCount
            : replies.length - 1) + 1;
          worker.lastReplyAt = Date.now();
        }
      }, 'reply', { alreadyDelivered: true });
      return { delivered: true, woken: true, mode: resumed ? 'resumed' : 'live' };
    },
  }));

  // ── cross_session_status ───────────────────────────────────────────────────
  tools.register(defineTool({
    name: 'cross_session_status',
    description: '查看派活登记：各任务会话的运行状态（running/idle/stopped）、回复次数与最近回复。session_id 可传 cs_ 短别名或真实 id。',
    parameters: {
      session_id: { type: 'string', description: '可选：只看这个会话（cs_ 短别名或真实 id）。' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{
        type: 'text',
        text: value.sessions.length === 0
          ? '没有登记的任务会话。'
          : value.sessions.map((s) => {
              const stateText = s.state === 'running' ? '运行中' : s.state === 'idle' ? '空闲' : '已停止';
              return `- ${s.name}（alias=${s.alias}）：${stateText}，创建于 ${new Date(s.createdAt).toLocaleString()}，回复 ${s.replyCount} 次`
                + (s.tags?.length ? `，标签：${s.tags.join('/')}` : '')
                + (s.model ? `，模型 ${s.model}${s.reasoning_effort ? ` · 推理 ${s.reasoning_effort}` : ''}` : '')
                + (s.lastReplyText ? `，最近回复：${s.lastReplyText}` : '');
            }).join('\n'),
      }],
    },
    async execute(args, exec) {
      // 以调用者工作区为登记根（跨会话协作通常在同一项目内）。
      const cwd = normalizeCwd(workspaceOf(ctx, requireAgent(exec)));
      // 0.3.2：可选过滤条件也支持别名（先解析再比对）。
      const filterId = args.session_id === undefined
        ? undefined
        : resolveSessionIdOrThrow(args.session_id, await collectSessionIdCandidates(ctx, cwd, stateDir));
      const sessions = [];
      const registry = await readRegistryOnly(cwd, stateDir);
      for (const [id, worker] of Object.entries(registry.workers)) {
        if (filterId !== undefined && filterId !== id) continue;
        let state = 'stopped';
        try {
          const agent = agents.get(id);
          if (agent !== undefined) {
            // 0.2.x Agent.status getter：'idle' | 'running'（源码实测）
            state = typeof agent.status === 'string' ? agent.status : 'running';
          }
        } catch { state = 'stopped'; }
        const replies = Array.isArray(worker.replies) ? worker.replies : [];
        const last = replies.length > 0 ? replies[replies.length - 1] : undefined;
        sessions.push({
          session_id: makeSessionAlias(id),  // 返回别名（alias 字段保留，冗余但无害）
          alias: makeSessionAlias(id),
          name: typeof worker.name === 'string' ? worker.name : '',
          state,
          tags: Array.isArray(worker.tags) ? worker.tags : [],
          createdAt: numberOrNull(worker.createdAt),
          replyCount: typeof worker.replyCount === 'number' ? worker.replyCount : replies.length,
          lastReplyText: last && typeof last.text === 'string'
            ? `${last.text.slice(0, 120)}${last.text.length > 120 ? '…' : ''}`
            : '',
          leadSessionId: typeof worker.leadSessionId === 'string' && worker.leadSessionId !== ''
            ? (isSessionAlias(worker.leadSessionId) ? worker.leadSessionId : makeSessionAlias(worker.leadSessionId)) : '',
          model: typeof worker.model === 'string' ? worker.model : '',
          reasoning_effort: typeof worker.reasoningEffort === 'string' ? worker.reasoningEffort : '',
        });
      }
      sessions.sort((a, b) => a.createdAt - b.createdAt);
      return { sessions };
    },
  }));

  // ── cross_session_read ─────────────────────────────────────────────────────
  tools.register(defineTool({
    name: 'cross_session_read',
    description: '读某会话最近的用户/助手消息（不唤醒对方）。活跃会话读内存，其余从磁盘读。include_attempts 为传输失败诊断参数。',
    parameters: {
      session_id: { type: 'string', required: true, description: '要读取的会话：cs_ 短别名或真实 id。' },
      tail: { type: 'number', description: '最近几条消息（默认 10，最大 50）。' },
      include_attempts: { type: 'boolean', description: 'true 时附带 attempt/header/title 诊断事件，用于排查子会话无输出等问题。' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{
        type: 'text',
        text: value.messages.length === 0
          ? `会话 ${value.session_id} 还没有任何消息。`
          : value.messages.map((m) => {
              const label = m.role === 'assistant' ? '[助手]'
                : m.role === 'user' ? '[用户]'
                : m.role === 'attempt' ? '[尝试]'
                : m.role === 'header' ? '[请求头]'
                : m.role === 'title' ? '[标题]'
                : `[${m.role}]`;
              return `${label} ${m.text}`;
            }).join('\n'),
      }],
    },
    async execute(args, exec) {
      // 跨会话读取会把目标会话的内容带回调用方，因此必须来自某个会话的调用
      // 上下文；缺少 exec.agent 时拒绝，避免成为无归属的读取通道。
      const caller = requireAgent(exec);
      // 0.3.2：别名解析（从 list 复制的 id 是显示层占位符，不可直接用）。
      const targetId = resolveSessionIdOrThrow(
        args.session_id,
        await collectSessionIdCandidates(ctx, workspaceOf(ctx, caller), stateDir),
      );
      const tail = typeof args.tail === 'number' ? Math.min(Math.max(1, Math.floor(args.tail)), 50) : 10;
      const includeAttempts = args.include_attempts === true;
      const messages = [];
      // 从最新事件往前收集，达到 tail 即停——不必为了取最后几条而遍历整份日志。
      const collect = (events, limit) => {
        const list = events ?? [];
        for (let index = list.length - 1; index >= 0 && messages.length < limit; index -= 1) {
          const event = list[index];
          if (event?.type === 'assistant/attempt') {
            if (includeAttempts) {
              messages.push({ role: 'attempt', text: JSON.stringify(event?.data)?.slice(0, 800) ?? '' });
            }
            continue;
          }
          if (includeAttempts && event?.type === 'request/header') {
            const config = event?.data?.header?.config ?? event?.data?.config;
            if (config) {
              messages.push({
                role: 'header',
                text: `request/header → provider=${config.provider ?? '?'} model=${config.model ?? '?'} reasoningEffort=${config.reasoningEffort ?? '?'}`,
              });
            }
            continue;
          }
          if (includeAttempts && event?.type === 'session/title') {
            messages.push({ role: 'title', text: `session/title → ${event?.data?.title ?? '(空)'}` });
            continue;
          }
          if (event?.type !== 'user/message' && event?.type !== 'assistant/message') continue;
          const text = eventText(event);
          if (text.trim() === '') continue;
          messages.push({ role: event.type === 'assistant/message' ? 'assistant' : 'user', text });
        }
      };

      // 1) 活跃会话 → 直接读内存事件快照。
      let liveSession;
      try {
        const store = ctx.get('sessions');
        liveSession = store?.get?.(targetId);
      } catch { liveSession = undefined; }
      if (liveSession !== undefined && liveSession !== null) {
        let events = [];
        try {
          const snap = liveSession.snapshotEvents?.();
          events = Array.isArray(snap) ? snap : (snap?.events ?? []);
        } catch (error) {
          // 快照读取失败不等于"没有消息"：如实上报，别让调用方误判成空会话。
          throw new Error(`会话 ${targetId} 的内存事件快照读取失败（${err(error)}）。`);
        }
        collect(events, tail);
        return { session_id: makeSessionAlias(targetId), messages: messages.reverse() };  // 返回别名
      }

      // 2) 未打开 → sessionQuery 读盘（实时+持久化统一视图，回放校验）。
      let query;
      try { query = ctx.get('sessionQuery'); } catch { query = undefined; }
      if (!query || typeof query.readSession !== 'function') {
        throw new Error(`会话 ${targetId} 当前不在运行中，且 sessionQuery 服务不可用，无法从磁盘读取。`);
      }
      let events = [];
      try {
        const result = await query.readSession(targetId);
        events = Array.isArray(result) ? result : (result?.events ?? []);
      } catch (error) {
        throw new Error(`会话 ${targetId} 不存在或日志无法读取（${err(error)}）。`);
      }
      collect(events, tail);
      return { session_id: makeSessionAlias(targetId), messages: messages.reverse() };  // 返回别名
    },
  }));

  // ── cross_session_list ─────────────────────────────────────────────────────
  tools.register(defineTool({
    name: 'cross_session_list',
    description: '列出顶层会话（别名/标题/运行状态/模型/标签），用于给已有会话 cross_session_send 派新任务。默认只看当前工作区；all_workspaces=true 才跨项目。为避免真实 ID 在显示链路中被遮蔽，请使用 `alias`（cs_ 短码）作为各工具的 session_id 参数。',
    parameters: {
      limit: { type: 'number', description: '最多列出多少个会话（默认 20）。' },
      include_archived: { type: 'boolean', description: '是否同时列出已归档会话（默认 false）。' },
      cwd: { type: 'string', description: '可选：指定工作区目录（默认取调用者会话的工作区）。' },
      all_workspaces: { type: 'boolean', description: '显式 true 时跨项目列出所有工作区的顶层会话（默认 false 只看当前工作区）。' },
      tag: { type: 'string', description: '可选：按标签过滤（只匹配 spawn 时带 tags 的任务会话）。' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{
        type: 'text',
        text: (value.sessions.length === 0
          ? '没有找到顶层会话。'
          : value.sessions.map((s) => (
              `- 「${s.title || '(无标题)'}」 alias=${s.alias}`
              + `${s.model ? ` · ${s.model}${s.reasoning_effort ? ` · 推理 ${s.reasoning_effort}` : ''}` : ''}`
              + `${s.state === 'running' ? ' · 运行中' : ''}`
              + `${s.tags?.length ? ` · 标签:${s.tags.join('/')}` : ''}`
              + `${s.archived ? ' · 已归档' : ''}${s.spawned ? ' · 本插件派生' : ''}`
              + `${s.stale ? ' · ⚠登记残留（宿主已无此会话）' : ''}`
              + `${s.workspace ? ` · [${s.workspace}]` : ''}`
            )).join('\n'))
        + (value.sessions.length
          ? '\n\n上表使用 alias：请使用 cs_ 别名寻址，避免真实 session_id 在显示链路中被替换为占位符。\n'
            + '把 alias（cs_ 开头的短码）直接当 session_id 传给 send/read/status/rename/archive 即可，插件会自行还原。'
          : '')
        + (value.title_errors?.length ? `\n[标题读取错误]\n${value.title_errors.join('\n')}` : ''),
      }],
    },
    async execute(args, exec) {
      const cwd = normalizeCwd(args.cwd ?? workspaceOf(ctx, requireAgent(exec)));
      const limit = typeof args.limit === 'number' ? Math.min(Math.max(1, Math.floor(args.limit)), 100) : 20;
      const includeArchived = args.include_archived === true;
      const crossWorkspace = args.all_workspaces === true;
      const tagFilter = typeof args.tag === 'string' && args.tag.trim() !== '' ? args.tag.trim() : undefined;

      // 归档名单先取，供下面标注 archived。
      let archived = new Set();
      try {
        const wreg = ctx.get('workspaceRegistry');
        if (Array.isArray(wreg?.archivedSessionIds)) archived = new Set(wreg.archivedSessionIds);
      } catch { /* 归档信息缺失时降级 */ }

      // 登记表（spawn 记录）优先，补齐 sessionQuery 能看到的其余会话。
      const merged = new Map(); // id → record
      const titleErrors = [];
      const listErrors = [];
      const registry = await readRegistryOnly(cwd, stateDir);
      for (const [id, worker] of Object.entries(registry.workers)) {
        merged.set(id, {
          session_id: id,
          // 登记名只作缺省：宿主标题在下面覆盖它（否则 rename 后仍显示旧名）。
          title: typeof worker.name === 'string' ? worker.name : '',
          state: 'stopped',
          tags: Array.isArray(worker.tags) ? worker.tags : [],
          archived: archived.has(id),
          spawned: true,
          stale: false,
          model: typeof worker.model === 'string' ? worker.model : '',
          reasoning_effort: typeof worker.reasoningEffort === 'string' ? worker.reasoningEffort : '',
          ...(crossWorkspace ? { workspace: cwd } : {}),
        });
      }

      let query;
      try { query = ctx.get('sessionQuery'); } catch { query = undefined; }
      const visibleIds = new Set();
      if (query && typeof query.listSessions === 'function') {
        let records = [];
        try {
          records = (await query.listSessions()) ?? [];
        } catch (error) {
          // 查询失败不等于"没有会话"：如实上报，别让调用方误判成空列表。
          listErrors.push(`会话列表读取失败：${err(error)}`);
          records = [];
        }
        for (const record of records) {
          const header = record?.header ?? record;
          const id = header?.id;
          if (typeof id !== 'string' || id === '') continue;
          visibleIds.add(id);
          if (header.parentSession !== undefined) continue;
          const recordCwd = normalizeCwd(header.cwd ?? '');
          // ⚠️ 这里的过滤口径必须与 collectSessionIdCandidates 保持一致（同一 API + 同一过滤），
          //    否则会再次出现"列表给得出别名、发送解析不到"的分叉（见 0.3.9 修复）。
          if (!crossWorkspace && recordCwd !== cwd) continue;
          const existing = merged.get(id);
          if (existing) {
            if (record?.live === true) existing.state = 'running';
            existing.archived = archived.has(id);
            if (crossWorkspace && existing.workspace === undefined) existing.workspace = header.cwd ?? '';
            continue;
          }
          merged.set(id, {
            session_id: id,
            title: '',
            state: record?.live === true ? 'running' : 'stopped',
            tags: [],
            archived: archived.has(id),
            spawned: false,
            stale: false,
            model: '',
            reasoning_effort: '',
            // 无损 JSON 校验禁止 undefined 属性：非跨工作区时整个键省略
            ...(crossWorkspace ? { workspace: header.cwd ?? '' } : {}),
          });
        }
      }

      const sessions = [...merged.values()];
      let statusCache;
      const agentStateOf = (id) => {
        if (statusCache === undefined) {
          statusCache = new Map();
          try {
            for (const a of agents.list?.() ?? []) {
              statusCache.set(a.id, typeof a.status === 'string' ? a.status : 'running');
            }
          } catch { /* 忽略 */ }
        }
        return statusCache.get(id);
      };
      for (const s of sessions) {
        // 本进程能拿到 agent 就用精确 status（idle/running）；跨进程或纯持久化
        // 会话退回 listSessions 的 live 推断。
        const precise = agentStateOf(s.session_id);
        if (precise !== undefined) s.state = precise;
      }
      // 登记表里有、宿主列表里没有的：标 stale，而不是继续伪装成 stopped。
      if (visibleIds.size > 0) {
        for (const s of sessions) {
          if (s.spawned && !visibleIds.has(s.session_id)) s.stale = true;
        }
      }
      const visible = sessions
        .filter((s) => tagFilter === undefined || (Array.isArray(s.tags) && s.tags.includes(tagFilter)))
        .filter((s) => includeArchived || !archived.has(s.session_id))
        .slice(0, limit);
      // 标题补齐：一次批量 readTitleSnapshots，只补这一屏要显示的会话。
      // 旧实现是逐个 readSession + slice(0, 10)，名额先被登记表 worker 占满，
      // 登记表一超过 10 条，宿主会话就永远补不到标题（全显示「(无标题)」）。
      // 登记会话也补：宿主标题优先于登记名（rename 后登记名会过期）。
      if (visible.length > 0 && query) {
        if (typeof query.readTitleSnapshots !== 'function') {
          titleErrors.push('宿主未提供 readTitleSnapshots，本次列表标题可能不完整');
        } else {
          try {
            const results = await query.readTitleSnapshots(visible.map((s) => s.session_id));
            for (const r of results ?? []) {
              if (r?.status === 'rejected') {
                titleErrors.push(`标题读取失败：${err(r.reason)}`);
                continue;
              }
              const id = r?.value?.session?.id;
              const title = r?.value?.title;
              // readTitleSnapshots 返回的 title 是 titleSnapshot 对象
              // {title, messageSeqs, source, eventSeq, updatedAt}，不是字符串；
              // 取 .title 字段，兼容直接返回字符串的实现。
              const titleText = typeof title === 'string' ? title : title?.title;
              const target = id ? merged.get(id) : undefined;
              if (target && typeof titleText === 'string' && titleText !== '') target.title = titleText;
            }
          } catch (error) {
            titleErrors.push(`readTitleSnapshots 批量失败：${err(error)}`);
          }
        }
      }
      // 0.3.2：给每条记录附上**不被遮蔽的短别名**（模型侧唯一可用的寻址方式）。
      // 真实 id 仍保留在 session_id 字段（程序内部/日志可用），但渲染层不展示它。
      for (const s of visible) s.alias = makeSessionAlias(s.session_id);
      const result = { sessions: visible };
      if (titleErrors.length > 0) result.title_errors = titleErrors;
      if (listErrors.length > 0) result.errors = listErrors;
      return result;
    },
  }));

  // ── cross_session_broadcast ────────────────────────────────────────────────
  tools.register(defineTool({
    name: 'cross_session_broadcast',
    description: '批量给多个会话投递各自不同的任务，逐条报告成功/失败；单个失败不影响其他。',
    parameters: {
      targets: {
        type: 'array',
        required: true,
        description: '目标列表：每项 { session_id, message, wake?, interrupt?, reply_to? }。',
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            session_id: { type: 'string', required: true, description: '目标会话 id。' },
            message: { type: 'string', required: true, description: '发给该会话的任务。' },
            wake: { type: 'boolean', description: '是否唤醒（默认 true）。' },
            interrupt: { type: 'boolean', description: '是否插队（默认 true）。' },
            reply_to: { type: 'string', description: '可选：该会话完成后把结果回复给谁。' },
          },
        },
      },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{
        type: 'text',
        text: value.results.length === 0
          ? '没有目标会话。'
          : value.results.map((r) => `- ${r.ok ? '✅' : '❌'} ${r.session_id}：${r.ok ? (r.resumed ? '未打开，已叫醒并投递' : '已投递（原本活跃）') : (r.error ?? '失败')}`).join('\n'),
      }],
    },
    async execute(args, exec) {
      const callGuard = guardCall(exec.signal);
      const caller = requireAgent(exec);
      const results = [];
      const registryCwd = workspaceOf(ctx, caller);
      const allTargets = Array.isArray(args.targets) ? args.targets : [];
      const targets = allTargets.slice(0, MAX_BROADCAST_TARGETS);
      if (allTargets.length > targets.length) {
        results.push({
          session_id: '',
          ok: false,
          error: `目标数超过上限 ${MAX_BROADCAST_TARGETS}，仅处理前 ${targets.length} 个。`,
        });
      }
      const candidates = await collectSessionIdCandidates(ctx, registryCwd, stateDir);  // 与 send/reply 共用解析器
      for (const target of targets) {
        try {
          const targetId = resolveSessionIdOrThrow(target.session_id, candidates);
          const storedPreset = await storedPresetOf(registryCwd, stateDir, targetId);
          callGuard.check();
          const resolved = await ensureLiveAgent(ctx, agents, handles, resuming, targetId, exec.signal, storedPreset, blockedSpawns, callGuard.live);
          callGuard.check();
          if (resolved.error) {
            results.push({ session_id: makeSessionAlias(targetId), ok: false, error: resolved.error });
            continue;
          }
          const directive = directiveFor(target.reply_to);
          deliver(resolved.agent, clampText(target.message) + directive, { preempt: target.interrupt !== false, wake: target.wake !== false });
          await safeRegistry(registryCwd, stateDir, (registry) => {
            const worker = registry.workers[targetId];
            if (worker) worker.lastTaskAt = Date.now();
          }, 'broadcast', { alreadyDelivered: true });
          results.push({
            session_id: makeSessionAlias(targetId),
            ok: true,
            resumed: resolved.resumed,
            wake: target.wake !== false,
            interrupt: target.interrupt !== false,
          });
        } catch (error) {
          results.push({ session_id: target.session_id.startsWith('cs_') ? target.session_id : makeSessionAlias(target.session_id), ok: false, error: err(error) });
        }
      }
      return { results };
    },
  }));

  // ── cross_session_rename ───────────────────────────────────────────────────
  tools.register(defineTool({
    name: 'cross_session_rename',
    description: '修改会话标题。未打开的会先自动恢复再走官方 rename 通道（标题被钉住，不再被自动生成覆盖）。',
    parameters: {
      session_id: { type: 'string', required: true, description: '目标会话：cs_ 短别名或真实 id。' },
      name: { type: 'string', required: true, description: '新标题（1-60 字符）。' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{
        type: 'text',
        text: `已将会话 ${value.session_id} 改名为「${value.title}」。`,
      }],
    },
    async execute(args, exec) {
      const callGuard = guardCall(exec.signal);
      const caller = requireAgent(exec);
      const rawTitle = String(args.name ?? '').trim();
      if (rawTitle.length === 0) throw new Error('会话名不能为空或纯空白。');
      const normalized = String(rawTitle)
        .replace(/[\u0000-\u001f\u007f]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
      if (normalized.length === 0) throw new Error('会话名规范化后为空，请使用可见字符。');
      const title = Array.from(normalized).slice(0, 60).join('');

      // 0.3.2：别名解析。
      const targetId = resolveSessionIdOrThrow(
        args.session_id,
        await collectSessionIdCandidates(ctx, workspaceOf(ctx, caller), stateDir),
      );
      callGuard.check();
      const resolved = await ensureLiveAgent(ctx, agents, handles, resuming, targetId, exec.signal, undefined, blockedSpawns, callGuard.live);
      callGuard.check();
      // `titles` 必须显式声明。本文件是 ESM（严格模式），对未声明标识符赋值
      // 会抛 ReferenceError，连 catch 分支里的赋值同样会抛 ⇒ 改名工具必然崩溃。
      let titles;
      try { titles = ctx.get('sessionTitle'); } catch { titles = undefined; }
      let session;
      try { session = ctx.get('sessions')?.get?.(targetId); } catch { session = undefined; }
      if (!titles || typeof titles.rename !== 'function' || session === undefined || session === null) {
        throw new Error('sessionTitle/sessions 服务不可用，无法改名。');
      }
      if (resolved?.error !== undefined && resolved.error !== null) {
        throw new Error(`无法连接目标会话：${err(resolved.error)}`);
      }
      const snap = titles.rename(session, title);
      return {
        session_id: makeSessionAlias(targetId),  // 返回别名
        title: snap?.title ?? title,
        seq: numberOrNull(snap?.eventSeq),
        mode: resolved.resumed ? 'resumed' : 'live',
      };
    },
  }));

  // ── cross_session_archive ──────────────────────────────────────────────────
  tools.register(defineTool({
    name: 'cross_session_archive',
    description: '归档会话（与 GUI 归档同通道，持久化、幂等）。归档后侧边栏隐藏、内容保留，且不可再被跨会话唤醒。session_id 可传 cs_ 短别名或真实 id。',
    parameters: {
      session_id: { type: 'string', required: true, description: '要归档的会话：cs_ 短别名或真实 id。' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{
        type: 'text',
        text: `已归档会话 ${value.session_id}（当前共 ${value.archived_count} 个已归档会话）。`,
      }],
    },
    async execute(args, exec) {
      const caller = requireAgent(exec);
      // 0.3.2：别名解析。
      const targetId = resolveSessionIdOrThrow(
        args.session_id,
        await collectSessionIdCandidates(ctx, workspaceOf(ctx, caller), stateDir),
      );
      let registry;
      try { registry = ctx.get('workspaceRegistry'); } catch { registry = undefined; }
      if (!registry || typeof registry.archiveSession !== 'function') {
        throw new Error('workspaceRegistry 服务不可用：当前宿主组合未挂载工作区注册服务，无法归档。');
      }
      await registry.archiveSession(targetId);
      const archived = Array.isArray(registry.archivedSessionIds) ? registry.archivedSessionIds : [];
      handles.delete(targetId);
      return { session_id: makeSessionAlias(targetId), archived_count: archived.length };  // 返回别名
    },
  }));

  // ── 取证观察者：登记/结算即删 + 结果期分歧留证 ─────────────
  if (answererAvailable) {
    ctx.on('tools/execute', (exec, next) => {
      const rec = {
        exec,
        callId: exec.callId,
        name: exec.name,
        argsAtEntry: exec.arguments,
        session: exec.agent?.session,
        sessionId: exec.agent?.session?.id,
        at: Date.now(),
        diverged: false,
      };
      const list = liveExecs.get(rec.callId);
      if (list === undefined) liveExecs.set(rec.callId, [rec]); else list.push(rec);
      resultWatch.set(exec, rec);                    // 结果期还要用 ⇒ 单独一张 WeakMap
      const drop = () => {
        const l = liveExecs.get(rec.callId);
        if (l === undefined) return;
        const i = l.indexOf(rec);
        if (i >= 0) l.splice(i, 1);
        if (l.length === 0) liveExecs.delete(rec.callId);   // 不动 resultWatch
      };
      let p;
      try { p = next(); } catch (error) { drop(); throw error; }   // 同步抛错：drop 后重抛
      Promise.resolve(p).then(drop, drop);
      return p;
    }, { prepend: true });

    // 结果期核对（此时 exec 已被宿主 freeze）：分歧绑在**执行实例**上
    ctx.on('tools/result', (exec) => {
      const rec = resultWatch.get(exec);
      if (rec === undefined) return;
      if (exec.arguments !== rec.argsAtEntry) {
        rec.diverged = true;
        logWarn(`tool "${exec.name}" (${exec.callId}) 的执行参数在派发后被改写（结果期取证；批准前检查优先）`);
      }
    });
  }

  // ── answerer：prepend 最先拿到 approval/request ──────────────
  if (answererAvailable) {
    ctx.on('approval/request', async function (request, next) {
      // ★ carrier 校验：this 必须是 request.agent
      let carrierAgent;
      try { carrierAgent = carrierKeyOfFn(this); } catch { carrierAgent = undefined; }
      if (carrierAgent === undefined || carrierAgent !== request.agent) return next();
      const requesterId = request.agent?.session?.id;
      if (typeof requesterId !== 'string' || requesterId === '') return next();
      // ★ abort 检查在资源创建之前；容量检查移到 compute 内部（危险判定之后）
      if (request.signal?.aborted === true) return 'cancelled';
      const entry = createEntry(request, requesterId);
      entry.requesterAgent = carrierAgent;
      entry.requesterSession = carrierAgent.session;   // ★ 绑定实例，不能只存 id
      activeRequests.add(entry);
      entry.onAbort = () => entry.finish('cancelled');
      if (request.signal) {
        try { request.signal.addEventListener('abort', entry.onAbort, { once: true }); } catch { /* signal 失效 */ }
      }
      entry.timer = setTimeout(() => entry.finish('deadline'), bridgeCfg.timeoutMs);
      entry.timer.unref?.();

      const stage = (p) => Promise.race([
        Promise.resolve(p).then((v) => ({ ok: true, v }), () => ({ ok: false, why: 'error' })),
        entry.terminal.then((v) => ({ ok: false, why: v })),   // 必须包含终结方 promise
      ]);
      const alive = () => !entry.done && entry.epoch === instanceEpoch && Date.now() < entry.deadlineAt;

      let outcome;
      try {
        outcome = await compute(request, entry, requesterId, stage, alive);
      } catch {
        entry.finish('error');                      // 内部异常只做收尾
        outcome = DELEGATE;
      }
      // 取消/deadline/unloaded 等首次终结 outcome 优先于 compute 返回值——
      // abort 触发 finish('cancelled') 后 compute 因 !alive() 返回 DELEGATE，
      // 出口必须用首次终结的 cancelled，不可被 DELEGATE 覆盖而委托下游 UI。
      if (entry.done) outcome = entry.finalOutcome;
      else entry.finish(outcome);
      // ── 出口（★ 唯一一次下游委托：物理上在 try/catch 之外）──────────────
      const exit = resolveExit(outcome);
      if (exit.delegate) {
        return next();                              // next() 的同步异常向外传播
      }
      return exit.value;                            // 'allowed-once' | 'rejected' | 'cancelled'
    }, { prepend: true });
  }

  // ── cross_session_approve：owner 的答复入口 ────────────────────────
  tools.register(defineTool({
    name: 'cross_session_approve',
    description: '批准/拒绝跨会话审批桥发来的提权请求。key 来自桥通知；decision 只能是 allow|reject。只有创建该请求会话的会话（owner）可批准；请求者会话不能自行批准。',
    parameters: {
      key: { type: 'string', required: true, description: '桥通知里的审批 key（形如 apv_XXXXXXXXXXXX 的 base62 短码）。注意它与通知里「审计依据」的 approval/asked id 不是同一个值，不要混用。' },
      decision: { type: 'string', required: true, description: 'allow 或 reject。' },
      note: { type: 'string', description: '可选：备注（仅记录，不影响判定）。' },
    },
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [{
        type: 'text',
        text: value.outcome === 'allowed-once'
          ? `已批准（key ${value.key}）：该会话可以提权档位执行一次。`
          : `已拒绝（key ${value.key}）。`,
      }],
    },
    execute(args, exec) {
      const caller = requireAgent(exec);
      const entry = pending.get(args.key);
      if (entry === undefined) {
        // 形状检查：给出更有用的提示，避免 owner 把「审计 id」等其它 UUID 当成桥 key。
        if (!isApprovalKey(args.key)) {
          throw new Error(
            `不是本桥的审批 key（期望形如 apv_XXXXXXXXXXXX 的短码）。`
            + `请注意：桥通知里的「审计依据 approval/asked id=...」是另一个值，不能用来批准；`
            + `必须用通知里明写的 key=${'<apv_...>'}。`
            + `若 key 已被显示侧遮蔽成占位符，请从通知原文或 owner 会话日志取真值。`,
          );
        }
        throw new Error('没有该 key 的待决审批请求（可能已决定、已过期、已终止，或桥未启用）。');
      }
      // 1) 身份：回答者必须 === owner，且 ≠ requester（一次性 + 绑定）
      // 身份错误仅报错，不调 finish（正确 owner 可能仍会来）
      if (typeof entry.owner !== 'string' || entry.owner === '' || caller.id !== entry.owner) {
        throw new Error('无权批准该请求（你不是该会话的创建者）。');
      }
      if (entry.requesterSession?.id !== undefined && caller.id === entry.requesterSession.id) {
        throw new Error('请求者会话不能批准自己。');
      }
      // 核对回答者的 caller.session 与绑定的 entry.ownerSession 是否为同一实例
      // （id 相同但 Session 不同 ⇒ 拒绝，防止实例替换绕过身份检查）
      if (caller.session !== entry.ownerSession) {
        throw new Error('回答者会话实例与绑定的 owner 不一致：审批无效。');
      }
      // 2) 终结 / 世代 / 截止 / 取消 检查（入口处）
      if (entry.done) {
        throw new Error('该请求已终结（不可重复审批）。');
      }
      if (entry.epoch !== instanceEpoch) {
        throw new Error('实例世代已变：审批无效。');
      }
      if (Date.now() >= entry.deadlineAt) {
        // 已过期立即终结（不得放行）
        entry.finish('deadline');
        throw new Error('该请求已超时（截止时间已过）：审批无效。');
      }
      // 3) reject 在身份与存活检查之后直接拒绝（不需走完整复核）
      if (String(args.decision) === 'reject') {
        entry.finish('rejected');
        return { key: args.key, outcome: 'rejected' };
      }
      if (String(args.decision) !== 'allow') {
        throw new Error('decision 只能是 allow 或 reject。');
      }

      // ── 以下为 allow 专属复核（提权包含检查仅用于 allow）──
      //    所有检查与 finish 连续同步（无 await/Promise 续体间隙）

      // 4) 固定审计 / 首次 rec / 当前权限 / 快照三维
      if (entry.rec === undefined || entry.audit === undefined) {
        // 合法 owner 对失效项的操作应收尾
        entry.finish('rejected');
        throw new Error('该请求缺少取证：审批无效（已终结）。');
      }
      const auth = checkAuthority(ctx, entry.owner, entry.requesterSession?.id, entry.audit.mode);
      if (!auth.allowed) {
        // 复核失败 → 终结申请，不再占 pending
        entry.finish('rejected');
        throw new Error('审批者权限复核失败（当前权限不再包含目标执行策略，或请求者会话已不活）：审批拒绝（已终结）。');
      }
      // 精确比较 owner 三维快照（mode + workspaceRoot + approval）
      if (auth.ownerSession !== entry.ownerSession) {
        entry.finish('rejected');
        throw new Error('审批者会话实例已变：审批无效（已终结）。');
      }
      if (auth.requesterSession !== entry.requesterSession) {
        entry.finish('rejected');
        throw new Error('请求者会话实例已变：审批无效（已终结）。');
      }
      if (auth.ownerSnapshot.mode !== entry.ownerSnapshot?.mode
          || auth.ownerSnapshot.approval !== entry.ownerSnapshot?.approval
          || auth.ownerSnapshot.workspaceRoot !== entry.ownerSnapshot?.workspaceRoot) {
        entry.finish('rejected');
        throw new Error('审批者权限与决策时快照不一致（期间被改动）：审批无效（已终结）。');
      }
      // targetPolicy 完整比对（mode + workspaceRoot）
      if (auth.targetPolicy?.mode !== entry.targetPolicy?.mode
          || auth.targetPolicy?.workspaceRoot !== entry.targetPolicy?.workspaceRoot) {
        entry.finish('rejected');
        throw new Error('目标策略已变化：审批无效（已终结）。');
      }
      // 5) 固定审计仍未决：同 Session、同 turn、同 id/seq（固定值重查）
      // 审计读取抛异常时也要统一收尾（否则 pending 泄漏，恢复后可再次批准）
      let reAudit;
      try {
        reAudit = readAuditRequestForAgent(entry.requesterSession, entry.toolName, entry.callId);
      } catch {
        entry.finish('rejected');
        throw new Error('审计读取异常：审批拒绝（已终结）。');
      }
      if (reAudit === undefined
          || reAudit.id !== entry.audit.id
          || reAudit.seq !== entry.audit.seq
          || reAudit.turnStartSeq !== entry.audit.turnStartSeq) {
        entry.finish('rejected');
        throw new Error('固定审计已失效（已配对、turn 变化或消失）：审批拒绝（已终结）。');
      }
      // 6) 首次 rec 仍是唯一候选、同 Session、入口引用相等且冻结
      const list = liveExecs.get(entry.callId);
      const candidates = Array.isArray(list) ? list.filter((r) => r.session === entry.requesterSession) : [];
      if (candidates.length !== 1 || candidates[0] !== entry.rec) {
        entry.finish('rejected');
        throw new Error('执行实例唯一匹配已变化：审批无效（已终结）。');
      }
      if (Object.isFrozen(entry.rec.argsAtEntry) !== true) {
        entry.finish('rejected');
        throw new Error('入口参数已不冻结：审批无效（已终结）。');
      }
      if (entry.rec.exec.arguments !== entry.rec.argsAtEntry) {
        entry.finish('rejected');
        throw new Error('入口实参已被改写：审批拒绝（已终结）。');
      }
      if (entry.rec.diverged === true) {
        entry.finish('rejected');
        throw new Error('该执行实例已记录派发后参数改写：审批拒绝（已终结）。');
      }
      // 7) 放行前再检查终结与截止（finish 是幂等的，但防御 double-check）
      if (entry.done) {
        throw new Error('该请求在复核期间已终结。');
      }
      if (Date.now() >= entry.deadlineAt) {
        entry.finish('deadline');
        throw new Error('该请求在复核期间已超时：审批无效。');
      }
      // 8) ★ 危险操作判定（优先于所有者授权；尽力检查）
      // 不可判定的命令也必须拒绝（宁可误拒不可漏放）。
      if (isDangerousOperation(extractBody(entry.rec.argsAtEntry),
          { workspaceRoot: entry.targetPolicy?.workspaceRoot,
            workdir: entry.rec?.name === 'pwsh' ? resolvePwshWorkdir(entry.requesterSession, entry.rec.argsAtEntry) : undefined })
          || isUnresolvableOperation(extractBody(entry.rec.argsAtEntry))) {
        entry.finish('rejected');
        throw new Error('强制拒绝：该请求命中危险操作或不可判定命令判定（递归强制删除/盘根或受保护路径删除/磁盘覆写/动态命令/编码命令类）。任何会话（含所有者）都不得放行。');
      }
      entry.finish('allowed-once');
      return {
        key: args.key,
        outcome: 'allowed-once',
        note: typeof args.note === 'string' ? args.note.slice(0, 500) : '',
      };
    },
  }));

  // ── 卸载收尾（通过 ctx.effect 注册清理）──────────
  ctx.effect(() => () => {
    instanceDisposed = true;
    instanceEpoch += 1;                                  // 让所有旧续体失效（alive() 立刻 false）
    for (const entry of [...activeRequests]) entry.finish('unloaded');
    activeRequests.clear();
    pending.clear();
    taskOwners.clear();
    spawnIntents.clear();                                // 不留跨世代的意图
    liveExecs.clear();                                   // 观察器表必须清空（resultWatch 自回收）
    // 卸载时清理共享 handle（resumeColdAgent 缓存的），避免旧续体投递到已卸载实例
    for (const h of handles.values()) { try { h.dispose?.(); } catch { /* 清理失败不影响卸载 */ } }
    handles.clear();
    resuming.clear();
    // session/created / tools/execute / tools/result / approval/request /
    // agent|session/disposed 五个监听随 fiber 自动移除。
  }, 'cross-session-approval: approval bridge drain');
}
