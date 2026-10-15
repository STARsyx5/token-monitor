---
summary: StepFun platform quota from a browser sign-in or a pasted Oasis-Token
ids: [stepfun]
read_when:
  - Changing StepFun authentication, plan detection, or quota windows
---

## Identity and ids

`stepfun` is a limits provider. Token Monitor does not collect StepFun token usage.

## Data sources

The StepFun platform's `QueryStepPlanRateLimit` response supplies the authoritative quota. A successful `GetStepPlanStatus` response adds the optional plan name. The Coding Plan has five-hour and weekly reset windows. The Token Plan uses `plan_credit_rate_limit` for a monthly credit percentage; its zero reset-time rate fields are inactive windows, not exhausted quotas.

## Source precedence

A live five-hour or weekly reset identifies the Coding Plan even if `plan_family` says otherwise. Without a live rate window, credit fields identify the Token Plan; `plan_family: 2` is the fallback. Complete credit buckets are weighted by `credit_total`; only a response without buckets falls back to the subscription rate, then the top-up rate. The two rates must never be added. Incomplete buckets, a missing credit rate, or a missing Coding Plan window return unavailable rather than a false percentage.

## Credentials and transport

Three lanes resolve in order: a pasted cookie string (token and `Oasis-Webid` together) is the manual override; a stored username + password drives the browser sign-in; `STEPFUN_TOKEN` / `STEPFUN_USERNAME` + `STEPFUN_PASSWORD` are the environment fallbacks. The password login cannot run over plain HTTP — the site's `GlobalPassportService` answers 403 to non-browsers behind a Volcengine WAF token that only clears once page JavaScript runs — so the app opens the real login page in a BrowserWindow on a session partition scoped to the username and reads the resulting Oasis cookies back inside the browser process. The partition persists unless "remember this login" is switched off, and Clear removes the cookies from every partition, not just the stored values.

The cookie is a pair of JWTs joined by `...`: a short-lived access half (30 minutes in practice) and a long-lived refresh half (~30 days), and the refresh half also carries the request's `oasis-webid` device ID. The two halves expire on completely different schedules, so the probe answers each with the cheapest tool that fits — **an expired access half is refreshed; an expired refresh half is signed in again.**

On a rejected quota call `requestWithRefresh` spends the refresh half first: the platform's own `POST /passport/proto.api.passport.v1.PassportService/RefreshToken` (connect-JSON, empty body, authenticated by the same cookie), combined back into the pair and retried once. That is one HTTP round trip and no window. The rotation is reported through `deps.onStepfunTokenRenewed` only after the retry succeeds; Electron persists it into the stored credential only while the setting still holds the token that was refreshed (a fresh paste mid-flight wins), and a save-time probe collects it into the draft instead. The server does not rotate the refresh half, so a runtime without the callback (the agent) keeps working by refreshing from the stored value every poll, and a renewal that cannot be persisted only costs one extra refresh on the next poll. Network failures, invalid refresh responses and HTTP 5xx remain unavailable, and HTTP 429 remains sourceRateLimited; a 401/403 from refresh retains the unauthorized verdict.

Only when the refresh half is refused too does the sign-in window open. `deviceId()` reads the refresh half, so a renewed token keeps the same webid and the request headers stay valid. That ordering is the whole reason the two lanes are merged rather than one replacing the other: opening the window first would make the ordinary half-hourly expiry pop a login dialog that the refresh token could have settled silently.

The browser jar holds both an anonymous and a signed-in Oasis-Token, so neither "a cookie exists" nor "the cookie changed" is evidence of a session: `verifyStepfunSession` asks `GetStepPlanStatus` and the site's status code decides, in the cookie-reuse path and in the sign-in wait alike. A 200 body is exactly the plan-name lookup the probe wants next, so it rides along on the session and saves one request per probe. The sign-in window is never destroyed — on Electron 43.4 a destroyed window on a persistent partition takes the network stack down with it — so a failed sign-in is left on screen for the user to finish by hand. The optional plan-name lookup has its own short deadline so it cannot discard valid quota windows.

The account key hashes the refresh half when there is no username, so rotating the access half never opens a second row; a username-keyed setup keeps hashing the username. `/step-plan` is the live quota page — the `/plan-usage` path in older notes 404s.

## Verification

`node --test tests/shared/stepfunLimits.test.js tests/shared/stepfunRefresh.test.js tests/shared/stepfunLogin.test.js tests/electron/stepfunBrowserLogin.test.js tests/electron/stepfunMainSignIn.test.js` covers plan detection, bucket weighting, token device ID, the refresh/retry flow, the refresh-before-sign-in ordering, injected requests and failures. `tests/shared/stepfunLogin.test.js` covers how limits asks for a token and what it does with the answer, `tests/electron/stepfunBrowserLogin.test.js` the window flow against a fake page, and `tests/electron/stepfunMainSignIn.test.js` main.js's signer: partition scoping, cookie reuse, Clear. A signed-in StepFun account is needed to confirm the live endpoint and both plan variants.
