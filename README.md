# dsh-cross-session-approval（0.3.10）

DeepSeek Harness（DSH）**0.2.x** 的跨会话任务派发插件（bundle），提供 **10 个工具**：创建顶层持久会话、发送任务、回传结果、查询状态与消息、列出会话、批量投递、改名、归档及跨会话审批。

插件包含跨会话审批桥、子会话权限夹紧（A：发布前三维；F：派生入口），以及用于会话寻址的 `cs_` base62 别名。创建任务后即可继续当前会话，任务结果通过回信返回。

派活登记保存在 `<工作区>/.cross-session/registry.json`，以临时文件加原子重命名写入。它包含任务正文和回复摘要，可能涉及敏感信息，应作为工作区本地数据保管。登记读取失败会阻止依赖该读取的操作；写入失败会告警，已完成的投递不会因此撤回。

## 安装与加载

需要 Node.js **18 或以上**，以及已配置可用模型的 DeepSeek Harness **0.2.x** profile。宿主 peer 依赖要求为 `>=0.2.0-rc.2 <0.3.0`；具体依赖见 `package.json`。本插件是宿主 bundle，不是独立运行的 MCP 服务。

以下以名为 `dev` 的 profile 为例；请替换为实际 profile 名。插件已发布到 npm（`dsh-cross-session-approval@0.3.10`），安装方式有三种。

**方式一（npm，推荐）**：在目标 profile 目录下安装，npm 会自动解析 `@deepseek-ai/*` peer 依赖（`0.2.0-rc.2` 系）。

```powershell
$profileDir = Join-Path $HOME ".dsh/profiles/dev"
cd $profileDir
npm install dsh-cross-session-approval@0.3.10
```

**方式二（GitHub Release tarball）**：适用于通过 `dsh plugin` 安装的场景；awesome-dsh-plugin 市场目录也使用此 URL。

```powershell
dsh plugin --profile dev add "https://github.com/zsjs110110-cpu/dsh-cross-session-approval/releases/latest/download/dsh-cross-session-approval.tgz"
```

**方式三（源码）**：克隆需要具备该 GitHub 仓库的读取权限。

```powershell
$profileName = 'dev'
$profileDir = Join-Path $HOME ".dsh/profiles/$profileName"
$bundleDir = Join-Path $profileDir 'node_modules/dsh-cross-session-approval'
git clone https://github.com/zsjs110110-cpu/dsh-cross-session-approval.git $bundleDir
```

在该 profile 的 `package.json` 中，将 `dsh-cross-session-approval` **追加**到 `dsh.profile.bundles`。以下仅展示相关字段，保留已有配置与其他 bundle：

```json
{
  "dsh": {
    "profile": {
      "bundles": ["dsh-cross-session-approval"]
    }
  }
}
```

校验组合配置，再启动宿主加载插件：

```powershell
dsh --profile $profileName --dump-config
dsh --profile $profileName --no-open --port 0
```

配置输出应包含 `cross-session-approval`，且无该 bundle 的 `skipping`；启动时应无该插件的 `failed to import`。进入该 profile 的会话后，确认可用工具包含下列 10 项。配置校验成功不代表审批桥已启用；还需检查启动告警及下文的服务要求。

## 快速使用

下面是 **DSH 会话内的工具调用示例**，不是 PowerShell 命令或可直接导入的 JavaScript API。`cs_XXXXXXXXXX` 表示工具实际返回的别名，使用时必须替换。

```text
cross_session_spawn({ name: "检查文档", task: "阅读 README，列出安装步骤中的歧义；完成后回复结果。" })
// 保存返回的 session_id（cs_ 别名）；spawn 返回后任务仍可能在执行。
cross_session_status({ session_id: "cs_XXXXXXXXXX" })
cross_session_read({ session_id: "cs_XXXXXXXXXX", tail: 10 })
cross_session_send({ session_id: "cs_XXXXXXXXXX", message: "请再核对配置示例。", interrupt: false })
```

默认继承调用者的模型、推理程度与 agent preset（自定义模式）。`spawn` 会在任务消息中自动附上回信目标；任务会话应按指引调用 `cross_session_reply({ to: "<回信目标别名>", text: "结果摘要或失败原因" })`。回信按用户消息投递，并唤醒目标。投递成功与任务完成是两个不同状态，请结合回信及 `read` 判断结果。

建议先不传 `permission` 和 `cwd`，使用默认权限夹紧与当前工作区。显式权限、跨工作区寻址和审批桥的限制见下文。

## 工具一览

| 工具 | 必填参数 | 可选参数与行为 |
|---|---|---|
| `cross_session_spawn` | `name`, `task` | `reply_to`, `provider`, `model`, `reasoning_effort`, `permission`, `agent_preset`, `cwd`, `tags`；创建顶层持久会话并投递任务，不等待完成 |
| `cross_session_send` | `session_id`, `message` | `wake`、`interrupt` 默认 `true`；`reply_to` 指定回信目标；未打开的顶层会话自动恢复 |
| `cross_session_reply` | `to`, `text` | 向指定会话回信并唤醒，目标未打开时自动恢复 |
| `cross_session_status` | 无 | `session_id` 筛选当前工作区的派活登记，省略则查看登记总览 |
| `cross_session_read` | `session_id` | `tail` 默认 10、最大 50；`include_attempts` 附带诊断事件；读取不唤醒目标 |
| `cross_session_list` | 无 | `limit` 默认 20；`include_archived`, `cwd`, `all_workspaces`, `tag`；默认列当前工作区的顶层会话 |
| `cross_session_broadcast` | `targets` | 最多 20 项，每项为 `{ session_id, message, wake?, interrupt?, reply_to? }`；逐项报告成功或失败 |
| `cross_session_rename` | `session_id`, `name` | 标题长度为 1–60 字符 |
| `cross_session_archive` | `session_id` | 归档会话 |
| `cross_session_approve` | `key`, `decision` | `decision` 为 `allow` 或 `reject`；`note` 为可选备注；仅请求会话的创建者可处理 |

`send` 默认在目标当前步骤结束后插入消息；`interrupt: false` 等当前整轮结束；`wake: false` 只投递、不唤醒。所有会话标识优先使用工具返回的 `cs_` 别名；参数名仍为 `session_id`、`to` 或 `reply_to`。

单条任务或消息正文按 32 KiB UTF-8 配额截断。登记表最多保留 200 条任务记录，超出时淘汰最久未活动的登记；登记表不是完整会话历史。读取与广播可能涉及其他会话的任务内容，请按实际授权范围选择目标。

## 会话 ID 与短别名

部分宿主或上游显示链路会将模型可见文本中的 32 位十六进制串或 UUID 替换为占位符，例如 `session-00000000-0000-4000-8000-000000000000`。这不改变内存或磁盘中的真实会话 ID，但从显示文本复制占位符无法正确寻址。

插件用 FNV-1a 确定性派生 `cs_` 加 10 位 base62 字符的别名（总长 13），例如 `cs_xwx698M4Wa`。`cross_session_list` 和 `cross_session_status` 返回 `alias`，文本列表使用该别名。别名不单独落盘，同一版本下由真实 ID 按需重算，重启不改变结果；0.3.8 的别名迁移见版本记录。

| 输入 | 解析行为 |
|---|---|
| 被遮蔽的占位符，含 `session-` 前缀形式 | 拒绝，并提示使用别名 |
| `cs_` 别名 | 在登记表与宿主当前工作区可见会话中匹配；找不到则报错 |
| 其他字符串 | 作为真实 ID 原样交给宿主处理 |

`session_id`、`to` 等参数名保持不变，没有单独的 `alias` 参数。别名用于寻址，**不是授权凭据**，也不构成权限隔离；解析后仍按真实会话 ID 做身份与权限判断。短哈希不保证数学上无碰撞。

## 子会话权限夹紧（发布前三维 + 派生入口，0.3.0）

权限夹紧同时检查沙箱档位、审批策略和工作区。沙箱档位从窄到宽为 `read-only`、`workspace-write`、`danger-full-access`；审批策略中 `never` 比 `ask` 更严格：它会拒绝需要提权审批的请求。

### A：发布前三维夹紧

默认 `spawnPermission: cap`。`cross_session_spawn` 的可选参数：

- `permission`：宿主权限预设名。省略时，档位取调用者与部署默认预设中较窄者，审批取更严格者；显式预设的任一维比调用者更宽则拒绝，不静默降级。
- `agent_preset`：宿主提供的 agent preset（自定义模式）ID。默认继承调用者；显式指定不存在的模式会报错并附可用列表。它影响工具和提示词，沙箱权限及模型路由由各自配置控制。
- `cwd`：已存在的绝对目录，默认取调用者解析出的工作区根目录。非最高档调用者只能选择其工作区根目录或内部目录，按 realpath 校验，指向外部的 junction 不算包含；最高档调用者可指定任意已存在绝对目录。选择不同目录会另开工作区，见下文已知边界。

插件在 `session/created` 的同步前置监听器中重新解析调用者当前策略，写入沙箱档位与审批策略，再逐项精确读回复核。工作区须与创建意图一致；预设名仅在实际权限值与所选预设匹配时写入。任一步失败则拒绝创建，不投递任务。派发期间调用者权限发生变化也会拒绝，调用者需重试；投递前还须核对绑定该 Session 实例的夹紧凭证。

以部署默认 `workspace-write/ask` 为例（省略 `permission`、`cwd`）：

| 调用者档位 / 审批 | 子会话档位 / 审批 |
|---|---|
| `workspace-write/ask` | `workspace-write/ask` |
| `danger-full-access/ask` | `workspace-write/ask` |
| `danger-full-access/never` | `workspace-write/never` |
| `read-only/ask` | `read-only/ask` |
| `read-only/never` | `read-only/never` |

上述子会话工作区均为调用者工作区。`spawnPermission: off` 关闭 A，恢复宿主默认创建行为，可能使低权限调用者创建出更高权限的会话；启用审批桥必须使用 `cap`。

### 显式同档权限的边界

显式 `permission` 只拒绝比调用者更宽的权限，**允许与调用者相同的权限**。例如部署配置了 `full-ask`（`danger-full-access/ask`）时，同档调用者显式指定 `permission: "full-ask"` 可以创建同档子会话；省略该参数则仍按部署默认值夹紧。

这是当前契约的结果。插件没有独立的子会话最高预设配置，无法保证子会话始终严格低于创建者。非必要时省略 `permission`；确需最高档权限时，应先向用户说明并取得授权。使用约定与界面提示不能替代权限限制。

### F：派生入口夹紧

同一监听器处理非 A、带 `parentSession` 的会话创建通知，包括 fork 和恢复派生会话。默认 `forkPermission: cap`：

- 源会话活跃：按源当前策略限制三维权限。工作区必须在源工作区内，源为最高档时跳过此包含检查。
- 源会话未加载：`cap` 按部署默认预设与部署根目录限制；越界或 realpath 解析失败则拒绝。此上限不代表源会话的当前权限。`strict` 直接拒绝未加载源的派生。
- `off`：关闭 F，不访问 F 的可选权限服务。

F 只修改需要收窄的沙箱档位和审批策略，不写 `permission/preset`，写后读回复核。权限服务缺失时，启用的 A/F 对应创建路径拒绝。A/F 独立于审批桥：关闭桥不关闭 A/F，关闭 F 不影响 A。恢复派生会话也可能被收窄或拒绝。

## 跨会话审批桥（0.3.0）

由 `cross_session_spawn` 创建的任务会话，在 `pwsh` 或 `run_code` 请求沙箱提权时，可将审批交给其创建者会话（下称 owner）。owner 必须在同一宿主中保持活跃；本版不会为审批恢复未加载的 owner。

桥在宿主根上下文中优先处理 `approval/request`，处理链如下：

1. **身份与所有者**：用 `carrierKeyOf(this) === request.agent` 校验请求载体。所有者只在 spawn 时按真实调用者写入内存；`send`、`broadcast`、`reply` 不转移所有权，也不从登记表或父会话字段推断。
2. **审计绑定**：目标档位取自已提交的 `approval/asked` 事件。它须为当前开放轮次中唯一未配对的本会话事件，工具名和非空 callId 精确匹配；可被监听器修改的 `request.reason` 只参与一致性校验。
3. **授权包含**：目标档位不能高于 owner，档位必须已知，owner 审批策略必须为 `ask`。对 `workspace-write` 目标，工作区按 realpath 校验包含关系；最高档 owner 不受工作区包含限制。owner 未加载、服务缺失或档位未知时不接管。
4. **执行关联**：要求同一 Session 中唯一的首次执行记录、入口实参引用一致且被冻结，并校验审计、请求 reason 与入口 `sandbox_permissions` 三者档位一致。
5. **危险与不可判定操作**：命中危险规则或无法判定时强制 `rejected`，不交给 owner；owner 无权放行。
6. **通知与决定**：向活跃 owner 发送通知，入口观察值明确标为仅供参考。owner 调用 `cross_session_approve`；允许前同步复核实例世代、会话实例、owner 与目标策略快照、固定审计的配对状态、执行记录及危险规则。
7. **统一终结**：每个活动请求通过幂等 `finish()` 收尾，覆盖超时、卸载、取消、销毁和异常。桥只直接返回 `allowed-once`、`rejected` 或 `cancelled`；需要回落的内部结果精确一次委托本地 UI 审批，不自行追加审批审计事件。下游错误正常传播。

所有者映射不持久化。插件或宿主重启后，旧任务会话不再由此桥接管审批，回落本地 UI。

### 审批 key 与调用

通知中的审批 key 形如 `apv_XXXXXXXXXXXX`（12 位 base62 随机段），用于避免 UUID 在模型可见文本中被遮蔽。它与通知中作为审计依据的 `approval/asked` ID 是不同的值。

```text
cross_session_approve({ key: "apv_XXXXXXXXXXXX", decision: "allow", note: "已核对任务与提权范围" })
cross_session_approve({ key: "apv_XXXXXXXXXXXX", decision: "reject" })
```

以上是两种备选决定，实际使用通知中的 key，只调用一次。`allow` 表示本次允许；过期、已终结或非本人拥有的请求不能批准。`note` 不影响授权判定。

### 配置（`cordis.patch.yml` → `config`）

```yaml
config:
  stateDir: .cross-session
  spawnPermission: cap        # cap | off；开桥必须 cap
  forkPermission: cap         # cap | strict | off
  approvalBridge:
    enabled: true
    timeoutMs: 300000         # 从处理入口起算，1000–3600000 毫秒
    maxActiveRequests: 64     # 活动请求上限，1–1024 的整数
    maxPending: 64            # 已登记待决请求上限，1–1024 的整数
    noticeTextBytes: 32768    # 桥通知文本配额，1024–1048576 字节
    showObservedArgs: advisory  # advisory | off；观察值仅供参考
    injectWithdraw: true     # 超时、卸载、取消或委托时向活跃 owner 注入撤单通知
```

任一 `approvalBridge` 字段非法则停用整个桥并告警。`spawnPermission` 非法时按 `cap` 处理；`forkPermission` 非法时按 `strict` 处理。启用桥却未设 `spawnPermission: cap` 时，桥停用并告警。

### 保证范围与残余风险

**创建时权限保证**覆盖 A cap 的 `cross_session_spawn`，以及 F cap/strict 的 `SessionStore.fork()` 与远程 fork 控制器。启用 A/F 时防护监听器注册失败会阻止插件加载；服务缺失则拒绝对应创建。该保证限创建时刻，不能推导出所有会话在整个生命周期中始终不高于创建者。

subagent 工厂、GUI 新建、普通远程 `session.create`、其他插件的通用创建与恢复、独立宿主进程**没有完整保证**。带父会话字段的恢复通知可能受 F 影响，但这些工厂的全部写入路径未验证。

**入口观察值无法保证与执行实参一致**：工具可能先捕获实参，再等待审批；其他监听器可能改写并恢复同一参数对象。桥的载体、审计与执行关联检查、批准前复核及 `tools/result` 事后留证不能完整检测这种瞬态修改。关联校验成功也不能认证审计来源。实际安全边界仍依赖沙箱与宿主权限。

**危险操作识别是尽力检查**：规则覆盖递归强制删除、盘根或通配目标删除、对 `~/.dsh`、DSH 安装目录、工作区根及 `.cross-session` 的删除或移动，以及格式化、分区和磁盘覆写。它基于入口观察文本，无法保证与实际执行一致。

解析器保留带引号的目标，仅将 `cmd /c` 或 `/k`、PowerShell `-Command`、`sh/bash -c` 的执行载荷递归分析；打印数据和注释不作为命令。未知命令、未读取的脚本、编码执行、变量命令、插值、复杂表达式、无法解析的解释器选项及深度或大小超限，均按不可判定拒绝。支持的普通命令（如 `Get-ChildItem`、`Get-Content`、`Write-Output`、`git`、`npm install`）仍走审批路径。解析不认证命令运行时身份、别名或函数重定义，也不分析外部工具内部行为，不能保证解释任意程序或拦截所有危险操作。

## 已知边界：`cwd` 会另开工作区（0.3.8 实测）

`cwd` 指向**与调用者工作区根目录不同的目录（包括根目录下的子目录）**时，子会话会落到**另一个工作区**，登记在 `<cwd>/.cross-session/registry.json`（每个工作区一份登记表）。由此产生一条**按设计的**寻址边界：

- `cross_session_send` / `cross_session_read` / `cross_session_status` / `cross_session_rename` / `cross_session_archive` 按**调用者工作区**解析别名，**都没有 `cwd` 参数**。目标不在当前工作区候选集中时，使用其别名会报 `找不到该别名对应的会话（…或不在当前工作区）`；
- **但它的 `reply` 能送达回来**（回信方向不受影响）；
- 可用 `cross_session_list({ cwd: "<目标工作区绝对路径>" })` 列出目标工作区会话；或用 `cross_session_list({ all_workspaces: true })` 查看各工作区，列表会标注工作区。列出别名不会扩大其他工具的寻址范围。

**这是设计如此（不跨工作区寻址），不是缺陷。** 如果需要创建者持续查询或追加任务，应让子会话留在同一工作区；另开工作区时，需要接受创建者通过别名无法主动寻址、只能等待其回信的限制。0.3.8 的验证结果：目标工作区登记表含新会话记录，创建者通过别名调用 `status` / `read` / `send` / `archive` 均失败，而子会话回信成功送达。

非最高档调用者传越界 `cwd` 会被直接拒绝。最高档调用者虽可指定任意已存在绝对目录，但若沙箱无法为其授予写权限（例如系统保护目录），会话可能**创建成功却不可用**，Windows 上可能出现 `SetNamedSecurityInfoW failed (Win32 5): grantWrite(...)`。应选择沙箱可访问的工作目录。

## 宿主集成与仓库结构

- `cordis.patch.yml` 的 `name` 是包名 `dsh-cross-session-approval`；组合条目 `id: cross-session-approval` 对应插件导出的运行时名称。两者用途不同。
- 必需服务通过 Cordis `inject` 声明：`tools`、`agents`、`sessionPersistence`、`agentDefaultModel`、`agentPresets`、`workspaceRegistry`、`sessionQuery`、`sessionTitle`。缺少必需服务时，Cordis 可能使插件等待，工具不会完成注册。
- 四个权限服务 `sandboxPolicy`、`permissionPresets`、`sessions`、`approval` 在运行时可选获取，不列入 `inject`。缺少任一服务会告警、停用桥并拒绝启用的 A/F 对应创建；其余工具仍可使用。`@deepseek-ai/dsh-scope` 导入失败只停用桥并告警，不关闭 A/F 或其他 9 个工具。
- 投递使用运行时 Agent 的 `steer`、`followup`、`inject` 能力；会话持久化查询使用 `stat(id).header`。agent preset 通过投影与静态 header 解析，创建时写入 `meta.agentPreset`，恢复时优先使用登记的 preset。
- `package.json` 声明 8 个宿主 peer 依赖；兼容性实现以 DSH 0.2.0-rc.2 为基准，其他 0.2.x 版本仍需验证服务契约。

| 路径 | 用途 |
|---|---|
| `lib/index.js` | 工具注册、宿主服务集成及审批生命周期 |
| `lib/bridge-core.js` | 同步权限、审计、路径与危险操作判定 |
| `lib/state.js` | 登记表读写与锁管理 |
| `lib/host-fallback.js`、`lib/compat/*.js` | 宿主模块解析失败时使用的兼容实现；运行所需 |
| `cordis.patch.yml` | bundle 挂载与默认配置 |
| `package.json` | 包元数据、导出及宿主依赖 |
| `LICENSE` | MIT 许可证 |

## 打包分发

在仓库根目录先预览分发清单：

```powershell
npm pack --dry-run
```

清单应仅包含 `package.json`、`README.md`、`LICENSE`、`cordis.patch.yml` 和 `lib/` 下的 8 个 `.js` 文件，共 12 个文件。确认后运行 `npm pack` 生成分发包。请勿将备份放入包目录；`.gitignore` 不能保证 npm 排除所有备份文件。

## 版本记录

- **0.3.10**：补齐 0.3.9 **没修完**的那一半——0.3.9 把候选集的 cwd 比较写成 `normalizeCwd(header.cwd) !== cwd`，但 `send` / `reply` / `read` / `rename` / `archive` 传进来的是**未归一化的裸 `workspaceOf()`**，而 `normalizeCwd` 在 Windows 下会把路径小写化 ⇒ 比较恒不相等、候选集仍为空（症状：`status` 好了、`read`/`send` 照旧"找不到该别名"）。现在把归一化**收口到 `collectSessionIdCandidates` 入口**（`const root = normalizeCwd(cwd)`），8 个调用点一次覆盖。
- **0.3.9**：修复「`cross_session_list` 给出的别名有一半解析不到」。`collectSessionIdCandidates` 曾把 `{ cwd }` 当作 signal 传给宿主的 `listSessions(signal?)`——宿主内 `signal?.throwIfAborted()` 会抛 `TypeError`，又被空 `catch` 静默吞掉，于是别名解析的候选集退化成「仅登记表」：凡不是登记 worker / `leadSessionId` 的宿主会话，都无法用别名寻址（`send` / `reply` / `read` / `rename` / `archive` 全部受影响）。现改为与 `cross_session_list` **完全同源**的枚举 + 同一套工作区过滤，并在枚举失败时记录警告而不是静默降级。
- **0.3.8**：包名由 `dsh-cross-session-2` 改为 `dsh-cross-session-approval`，别名派生盐同步更新。旧 `cs_` 别名失效，请重新调用 `cross_session_list` 获取；真实会话 ID、登记表和会话内容不受影响。
- **0.3.7**：修复指定不存在的 `agent_preset` 时，错误消息缺少可用列表的问题。
- **0.3.6**：`cross_session_spawn` 新增可选参数 `agent_preset`，支持指定子会话的自定义模式；默认继承调用者。
- **0.3.5**：修复 `cross_session_list` 无法正确读取标题快照、导致全部显示「(无标题)」的问题。

