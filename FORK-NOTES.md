# 与上游的差异（fork 说明）

本仓库是 [javis603/token-monitor](https://github.com/javis603/token-monitor) 的 fork，基于 **上游 v0.71.0**（`a514e206`）。
分支 `feat/stepfun-signin-071` 上只有**一处功能差异**：给 StepFun 额度加了浏览器自动登录。除此之外上游的所有特性（sessions、edge dock、notion、goose 等）都原样保留。

| | 内容 |
|---|---|
| 基线 | 上游 v0.71.0（`a514e206`） |
| 分支 | `feat/stepfun-signin-071` |
| 改动规模 | 14 个文件，+3800 / −120，其中 74% 是测试 |

---

## 一、StepFun 自动登录

### 为什么需要它

StepFun 的额度接口要一对 cookie：`Oasis-Token` + `Oasis-Webid`。手工获取的方式是打开浏览器 devtools 从已登录页面复制——而且它**半小时就会过期**，过期后面板变黄，用户得再来一次。

官方 v0.71.0 的解法是 refresh 通道（`#1002`）：token 是一对 JWT，用 `...` 连接，access 半 ~30 分钟、refresh 半 ~30 天。access 半过期时调站点的 `PassportService/RefreshToken` 换一个新的，**手工粘贴一次可以用一个月**。

但 refresh 救不了另一件事：**最初那份 cookie 从哪来**。账号密码登录走 `GlobalPassportService`，这个 service 被火山 WAF 整体挡死——已知的 `Ping` 端点同样返回 403 空 body，而同目录的 `PassportService` 正常 200，说明是 service 级 gate。绕过它的常规路子也不通：Chrome/Edge 用 v20 app-bound encryption，任何外部进程（哪怕调 DPAPI）都解不开 `Oasis-Token`。

所以这个 fork 让应用**自己在 Electron 窗口里打开真实登录页**，让站点自己的 JS 完成 WAF 挑战，再在浏览器进程内读回 cookie。Token Monitor 本身就是 Electron，零新依赖。

### 两条通道怎么配合

两半过期时间差了两个数量级，所以**顺序很重要**：

```
401/403
  │
  ├─ 1. 花 refresh 半换新的 access 半 → 重试        ← 每半小时一次，一次 HTTP，零打扰
  │      └─ refresh 半也没了（~30 天后）
  │
  └─ 2. 打开浏览器窗口，用存储的账号密码登录 → 重试   ← 极罕见
```

反过来做是错的：每半小时弹一次登录框，而 refresh 半本来就能静默解决。

`deviceId()` 读的是 refresh 半，所以续期后的 token 保持同一个 webid，请求头不用改。

### 登录态的几个坑（都在代码注释里）

- **"有 cookie" ≠ "已登录"**。`platform.stepfun.com` 页面一加载就下发**匿名** `Oasis-Token`，登录后几秒才替换成登录态。两者在 jar 里同时存在。所以 `verifyStepfunSession()` 每次都问站点 `GetStepPlanStatus`，由站点的状态码裁决；传输失败也算未登录（"没验成"不等于"验过了"）。
- **登录态在 `account.stepfun.com`，而且是 host-only**。只在 platform 域过滤的话，登录后读到的还是登录前的状态。
- **窗口永不销毁**。Electron 43.4 上销毁持久化 partition 上的窗口会连带打挂网络栈（此后所有 `net.fetch` 永久挂起）。Clear 是唯一例外，因为那是用户明确要求的拆除。
- **Clear 要清当前账号的分区**。分区按账号哈希隔离，否则新账号的登录会把旧账号的会话顶掉。

### 代码位置

| 文件 | 作用 |
|---|---|
| `src/electron/providers/stepfun/login.js` | 浏览器窗口流程、分区隔离、cookie 读取 |
| `src/shared/providers/stepfun/limits.js` | `requestWithRefresh()`：refresh 优先、登录兜底 |
| `src/shared/providers/stepfun/account.js` | 三条凭据通道的账号表单与状态投影 |
| `src/electron/main.js` | `electronStepfunSignIn` / `clearStepfunLoginSession` / 采集与保存路径的 signer 注入 |

上游 v0.71.0 自带的 `src/shared/providers/stepfun/refresh.js` 原样保留，本 fork 只是把它接到登录通道前面。

### 测试

```bash
node --test tests/shared/stepfunLimits.test.js tests/shared/stepfunRefresh.test.js \
           tests/shared/stepfunLogin.test.js tests/electron/stepfunBrowserLogin.test.js \
           tests/electron/stepfunMainSignIn.test.js
```

共 177 个用例，含上游的 refresh 用例。另有 5 个变异逐一验证这些判据真的有鉴别力（回退任一修复都必须变红）。

---

## 二、本 fork 自己修掉的 4 个缺陷

需要说明的是：**这 4 条是这个 fork 在开发过程中引入并修掉的缺陷，不是上游的 bug**，列出它们是因为它们改动了行为，评审 diff 时应该能看到。

1. **Clear 清不掉环境变量配置的账号**。登录用 `stepfunAccount()` 派生分区（含 `STEPFUN_USERNAME`），Clear 原本只读 `settings.stepfunUsername`——用户点了清除，已认证会话还在。现在两个身份都通过 `stepfunAccount()` 解析，env 别名只在 `limits.js` 里定义一次。
2. **纯 token 配置显示「Not set」**。`defaultAccountStatus()` 只能解析一个字段，而表单明确支持"只粘贴 cookie"这条通道（headless agent 的唯一出路）。改成同时接受两条通道。
3. **诊断日志写入原始 `Oasis-Webid`**。面板用六种语言告诉用户把 `stepfun-diagnostic.log` 附到 bug 报告里，而日志里有认证 cookie 对的后半截原文。改为只记长度。
4. **一个测试名不符实**。坏密码用例把 `stepfunToken` 传在 `deps` 里，而 `fetchStepfunLimits` 从 `options` 读，所以 401 重试从未执行，测试通过的原因和名字无关。改成断言端点级调用顺序。

---

## 三、构建与安装

```bash
npm ci
npm run verify      # lint + 全量测试
npm run dist:win    # Windows x64 安装包（NSIS + portable），产物在 dist/
```

安装包与官方版结构一致：`resources/app.asar` 里是 Electron 应用，native 模块（`koffi.node`、`tokscale.exe`）留在 `app.asar.unpacked`。

**未签名**：构建产物没有代码签名证书，Windows SmartScreen 可能提示"未知发布者"。安装需要自行确认来源。

## 四、状态

- 全量测试 7059 用例，6 个失败**全部是环境性的**（symlink EPERM、真实网络时序、本机用户目录污染），已在官方 v0.71.0 基线上复现确认，非本 fork 引入
- lint 干净
- 浏览器登录链路已实机验证：自动恢复耗时 <150ms，零人工干预

## 五、许可

沿用上游 MIT（见 `LICENSE`）。上游代码版权归 Javis603，本 fork 未修改其署名。
