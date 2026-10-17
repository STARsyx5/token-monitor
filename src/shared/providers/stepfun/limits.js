'use strict';

const { hashKey } = require('../../hashKey');
const { normalizeLimitProvider } = require('../../limits/core');
const { errorWithStatus, numberOrNull, providerStatusFromError } = require('../../limits/providerHelpers');
const { runWithProbeDeadline } = require('../../probeDeadline');
const { BROWSER_USER_AGENT } = require('../../browserUserAgent');
// Upstream's refresh lane (v0.71 #1002): spend the long half of the Oasis pair
// on a fresh short half when only the short one aged out. Kept rather than
// dropped because the two lanes cover different expiries — see
// requestWithRefresh below.
const { isStepfunAuthFailure, refreshStepfunToken } = require('./refresh');

const ORIGIN = 'https://platform.stepfun.com';
const RATE_URL = `${ORIGIN}/api/step.openapi.devcenter.Dashboard/QueryStepPlanRateLimit`;
const PLAN_URL = `${ORIGIN}/api/step.openapi.devcenter.Dashboard/GetStepPlanStatus`;

// Oasis-Token is a JWT, and it does not travel alone: the quota endpoints pair
// it with `Oasis-Webid`, the device id the session was registered under, and
// answer 401 "oasis-token is embezzled" without one. What a user pastes is
// nearly always a whole cookie string copied out of devtools, which carries
// both halves:
//
//   Oasis-Token=eyJ…; Oasis-Webid=0c1f…; INGRESSCOOKIE=…
//
// so both are parsed out of that one paste here. Keeping them in a single
// field is what makes the pair survive the round trip: they are stored
// together, resolved together, and can never be half-present.
//
// Reading them apart costs more than it looks. The webid used to be its own
// setting, and the form framework marks every text/textarea field as a secret
// (accountPanels maps `fields` to `{secret: input !== 'select'}`), which meant
// the webid was stored through the credential path, could satisfy
// credentialCommands' "at least one secret holds something" floor on its own —
// so "username alone" could be saved as if it were a working login — and was
// re-masked on every save, so the panel could never read it back.
function normalizeOasisCookie(value) {
  const raw = String(value || '').trim();
  const field = (name) => {
    const hit = new RegExp(`(?:^|;)\\s*${name}=([^;]*)`, 'iu').exec(raw)?.[1];
    return String(hit || '').trim();
  };
  // A bare token with no `Oasis-Token=` prefix is the other shape devtools
  // produces, and has to keep working.
  const token = String(field('Oasis-Token') || raw).replace(/^Oasis-Token\s*:\s*/iu, '').trim();
  // A control character or a `;` means the paste is a header fragment rather
  // than a value; sending it on would smuggle a second cookie into the header.
  const clean = (text) => (text && !/[\u0000-\u001f\u007f;]/u.test(text) ? text : '');
  return { token: clean(token), webid: clean(field('Oasis-Webid')) };
}

function normalizeOasisToken(value) {
  return normalizeOasisCookie(value).token;
}

// The token + device id a manual paste (or the environment) supplies, read as
// one pair so neither half can be used without the other being available.
function stepfunSession(env = process.env, options = {}) {
  const input = String(
    options.stepfunToken || env?.TOKEN_MONITOR_STEPFUN_TOKEN || env?.STEPFUN_TOKEN || ''
  ).trim();
  return normalizeOasisCookie(input);
}

// A pasted or environment token wins when present — it is the manual escape
// hatch. Otherwise the stored username + password drive the sign-in, which is
// what keeps the quota live: an Oasis-Token is a short-lived session JWT with no
// refresh, so a stored token alone expires and the provider goes unauthorized
// until the user re-pastes one.
function stepfunToken(env = process.env, options = {}) {
  return stepfunSession(env, options).token;
}

// The username is an account identity, not a credential, so it is read on its
// own rather than only out of a complete username+password pair.
function stepfunAccount(env = process.env, options = {}) {
  return String(
    options.stepfunUsername || env?.TOKEN_MONITOR_STEPFUN_USERNAME || env?.STEPFUN_USERNAME || ''
  ).trim();
}

function stepfunCredentials(env = process.env, options = {}) {
  const username = String(
    options.stepfunUsername || env?.TOKEN_MONITOR_STEPFUN_USERNAME || env?.STEPFUN_USERNAME || ''
  ).trim();
  const password = String(
    options.stepfunPassword || env?.TOKEN_MONITOR_STEPFUN_PASSWORD || env?.STEPFUN_PASSWORD || ''
  );
  return username && password ? { username, password } : null;
}

// `STEPFUN_WEBID` stays as an environment override for a deployment that
// cannot paste a cookie string. There is no longer a settings FIELD for it: the
// webid is parsed out of the same paste as the token (normalizeOasisCookie), so
// the two are stored and resolved as one pair and a half-filled form is no
// longer a reachable state.
function stepfunWebid(env = process.env) {
  return String(env?.TOKEN_MONITOR_STEPFUN_WEBID || env?.STEPFUN_WEBID || '').trim();
}

// `oasis-webid` must be the device id this session was registered under — the
// site issues it from RegisterDevice and rejects a foreign one, so there is no
// usable constant.
//
// Three sources, in descending order of trust:
//   1. the cookie issued alongside a browser sign-in (readOasisSession returns
//      it, so the pair cannot drift apart);
//   2. the webid the user pasted next to a manual token;
//   3. the JWT payload, decoded as a last resort below.
//
// Source 3 is a heuristic, not a verified contract: `device_id` was read off a
// payload shape that no live capture has confirmed, and a wrong value fails the
// same way as a missing one (401 "oasis-token is embezzled"). It is used only
// after the two real sources come up empty, and whatever it decides is written
// to the diagnostic log so a failure can be told apart from a wrong token
// instead of being guessed at.
function deviceId(token) {
  for (const jwt of String(token || '').split('...').reverse()) {
    const part = jwt.split('.')[1];
    if (!part || !/^[A-Za-z0-9_-]+$/u.test(part)) continue;
    try {
      const id = JSON.parse(Buffer.from(part, 'base64url').toString('utf8')).device_id;
      if (typeof id === 'string' && /^[A-Za-z0-9_-]{1,128}$/u.test(id)) return id;
    } catch { /* Not a JWT payload — try the next segment. */ }
  }
  return '';
}

function fraction(value) {
  const n = numberOrNull(value);
  return n !== null && n >= 0 && n <= 1 ? n : null;
}

function usedPercent(left) {
  return Math.round((1 - left) * 100000) / 1000;
}

function resetAt(value) {
  const seconds = numberOrNull(value);
  if (seconds === null || !Number.isSafeInteger(seconds) || seconds <= 0) return null;
  const date = new Date(seconds * 1000);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function parseStepfunUsage(body, deps = {}) {
  const log = (line) => { if (typeof deps.logger === 'function') deps.logger(line); };
  if (!body || body.status !== 1) throw errorWithStatus(body?.status === 0 && /auth|token|login|登录/i.test(`${body?.message || ''} ${body?.desc || ''}`) ? 'unauthorized' : 'unavailable', 'StepFun rate limit request failed');
  const credit = body.plan_credit_rate_limit;
  const sessionReset = resetAt(body.five_hour_usage_reset_time);
  const weeklyReset = resetAt(body.weekly_usage_reset_time);
  const hasCreditShape = credit?.subscription_credit_left_rate != null
    || credit?.topup_credit_left_rate != null
    || (Array.isArray(credit?.credit_buckets) && credit.credit_buckets.length > 0)
    || numberOrNull(body.plan_family) === 2;
  const isCredit = !sessionReset && !weeklyReset && hasCreditShape;
  // A plan that carries BOTH rate windows and a credit balance is not a shape
  // any live capture has shown, so the branch that reports the windows and
  // drops the credit balance is a guess. Say so on every occurrence rather than
  // letting a silently under-reported account look like a complete one.
  if (!isCredit && hasCreditShape) {
    log('stepfun returned both rate windows and a credit balance; the rate windows are reported and the credit balance is dropped (mixed-plan shape unverified)');
  }
  if (isCredit) {
    let left = null;
    const buckets = credit?.credit_buckets;
    if (Array.isArray(buckets) && buckets.length) {
      let total = 0;
      let remaining = 0;
      let valid = true;
      for (const bucket of buckets) {
        const limit = numberOrNull(bucket?.credit_total);
        const residual = numberOrNull(bucket?.credit_residual);
        if (limit === null || residual === null || limit <= 0 || residual < 0 || residual > limit) { valid = false; break; }
        total += limit;
        remaining += residual;
      }
      if (!valid || !Number.isFinite(total) || !Number.isFinite(remaining)) {
        throw errorWithStatus('unavailable', 'StepFun credit buckets incomplete');
      }
      left = remaining / total;
    }
    if (left === null) left = fraction(credit?.subscription_credit_left_rate) ?? fraction(credit?.topup_credit_left_rate);
    if (left === null) throw errorWithStatus('unavailable', 'StepFun credit balance missing');
    const reset = resetAt(credit?.subscription_credit_reset_time);
    return [{ kind: 'billing', label: 'Credit', usedPercent: usedPercent(left),
      ...(reset ? { resetsAt: reset, windowMinutes: 30 * 24 * 60 } : {}) }];
  }
  const sessionLeft = fraction(body.five_hour_usage_left_rate);
  const weeklyLeft = fraction(body.weekly_usage_left_rate);
  if (sessionLeft === null || weeklyLeft === null || !sessionReset || !weeklyReset) {
    throw errorWithStatus('unavailable', 'StepFun rate windows missing');
  }
  return [
    { kind: 'session', label: '5-hour', usedPercent: usedPercent(sessionLeft), resetsAt: sessionReset, windowMinutes: 300 },
    { kind: 'weekly', label: 'Weekly', usedPercent: usedPercent(weeklyLeft), resetsAt: weeklyReset, windowMinutes: 10080 }
  ];
}

// Every Oasis call is the same envelope: fixed app headers, plus the token and
// the device id it was registered under. Factored out because the sign-in
// layer has to be able to ask "is this cookie pair signed in?" without a second
// hand-built copy of it — two copies of a header block is how the probe ends up
// authenticating with a webid the check never uses.
function oasisHeaders(token, webid) {
  const id = String(webid || '').trim();
  return {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    'User-Agent': BROWSER_USER_AGENT,
    'oasis-appid': '10300',
    'oasis-platform': 'web',
    ...(id ? { 'oasis-webid': id } : {}),
    Cookie: `Oasis-Token=${token}${id ? `; Oasis-Webid=${id}` : ''}`
  };
}

/**
 * Ask whether a cookie pair belongs to a signed-in session.
 *
 * The sign-in partition holds both kinds of token: platform.stepfun.com hands
 * out an ANONYMOUS Oasis-Token the moment its page loads, and the signed-in one
 * only replaces it after a successful login. The jar does not record which is
 * which, and the two fail differently downstream — the anonymous one answers
 * 401 "not a logined oasis account" — so "a cookie exists" is not evidence of a
 * session. Without this check, a stale anonymous cookie is handed straight back
 * as a credential, the quota probe 401s, the re-login path asks for a session
 * again, reads the very same anonymous cookie, and the provider is stuck
 * unauthorized with no window ever shown.
 *
 * The site's own answer is the verdict. Timing and string comparison cannot do
 * better: both states look like a well-formed cookie.
 *
 * The 200 response is also `PLAN_URL`, so the body is returned alongside the
 * verdict rather than thrown away. The caller is about to fetch exactly that
 * endpoint for the account label; handing the body back saves one round trip
 * per probe, which on the happy path is the difference between two requests and
 * three.
 *
 * @returns {Promise<{ok: boolean, body: object|null}>} ok is true only on a 200.
 *   A transport failure answers false as well — "could not check" must send the
 *   caller to the window rather than trust a cookie it never validated.
 */
async function verifyStepfunSession({ token, webid } = {}, deps = {}) {
  const normalized = normalizeOasisToken(token);
  const log = (line) => { if (typeof deps.logger === 'function') deps.logger(line); };
  if (!normalized) return { ok: false, body: null };
  const run = deps.fetch || fetch;
  try {
    const response = await run(PLAN_URL, {
      method: 'POST', body: '{}', redirect: 'error', credentials: 'omit',
      headers: oasisHeaders(normalized, webid),
      ...(deps.signal ? { signal: deps.signal } : {})
    });
    log(`stepfun session check -> ${response.status} (token ${normalized.length} chars)`);
    if (response.status !== 200) return { ok: false, body: null };
    // A 200 that is not the documented envelope is still a signed-in session —
    // it is the status code that decides that, not the payload shape.
    try {
      return { ok: true, body: await response.json() };
    } catch {
      return { ok: true, body: null };
    }
  } catch (error) {
    log(`stepfun session check failed: ${error.message || error}`);
    return { ok: false, body: null };
  }
}

// Which half of the Oasis pair names the account.
//
// Upstream's rule, and it matters: the access half rotates every ~30 minutes
// while the refresh half holds for ~30 days. Keying a row on the whole token
// therefore renames the account twice an hour. An input with no refresh half
// (a bare token pasted by hand) falls back to the whole string, which is the
// best available identity for something that cannot be renewed anyway.
function accountTokenIdentity(token) {
  const parts = String(token || '').split('...');
  return parts.length > 1 ? parts.slice(1).join('...') : String(token || '');
}

// A renewal that cannot be stored only costs one extra refresh on the next
// poll; the quota itself is unaffected, so this must not fail the probe.
async function reportStepfunRenewal(deps, previousToken, token) {
  try {
    await deps.onStepfunTokenRenewed?.({ previousToken, token });
  } catch (persistenceError) {
    deps.logger?.(`[limits] StepFun token renewal could not be persisted: ${persistenceError?.message || persistenceError}`);
  }
}

// The quota request self-heals before anything the user can see happens.
//
// An Oasis pair has two expiries and the cheap one is far more common: the
// access half dies every ~30 minutes, the refresh half lasts ~30 days. So when
// the quota call is rejected, spend the refresh half first — one HTTP round
// trip, no window, no password. Only when THAT fails is the long half gone too,
// and only then does the browser sign-in become the answer.
//
// Ordering matters and it is the whole point of merging the two lanes: putting
// the window first would make the ordinary 30-minute expiry pop a login dialog
// that the refresh token could have settled silently. `get` is called with the
// token to use and must throw the shared unauthorized error for the retry to
// trigger — deviceId() reads the refresh half, so a renewed token keeps the
// same webid and the caller's headers stay valid.
async function requestWithRefresh(get, previousToken, deps = {}) {
  try {
    return { body: await get(previousToken), token: previousToken };
  } catch (error) {
    if (!isStepfunAuthFailure(error)) throw error;
    // The three outcomes of a refresh stay exactly as upstream defined them,
    // because the caller routes on them:
    //   - renewed  → the access half was the only thing wrong; retry with it.
    //   - null     → the refresh half is spent too; re-raise the ORIGINAL 401,
    //                which is the only verdict that means "sign in again".
    //   - throw    → network, 5xx, 429 or an unusable body. That is a
    //                RETRYABLE condition and must not be laundered into a 401:
    //                doing so would both drop the status the scheduler retries
    //                on and pop a login window at a moment when the network
    //                cannot carry it either.
    const renewed = await refreshStepfunToken(previousToken, deviceId(previousToken), deps);
    if (!renewed) throw error;
    const body = await get(renewed);
    await reportStepfunRenewal(deps, previousToken, renewed);
    return { body, token: renewed };
  }
}

async function fetchStepfunLimits(options = {}, deps = {}) {
  const updatedAt = new Date((deps.now || Date.now)()).toISOString();
  const base = { provider: 'stepfun', source: 'web', updatedAt };
  const env = deps.env || process.env;
  const run = deps.fetch || fetch;
  const credentials = stepfunCredentials(env, options);
  const log = (line) => { if (typeof deps.logger === 'function') deps.logger(line); };
  // An explicit/env token is authoritative when present; otherwise the stored
  // credentials mint one here, which is what makes the lane renewable.
  //
  // The paste is read as a PAIR, so a manual token that arrived with its
  // device id already has `oasis-webid` before anything is attempted — without
  // it the quota call 401s with a message that names neither a missing header
  // nor a wrong token.
  const pasted = stepfunSession(env, options);
  let token = pasted.token;
  let pastedWebid = pasted.webid;
  if (!token && !credentials) {
    return normalizeLimitProvider({ ...base, status: 'notConfigured', windows: [] });
  }

  // Signing in needs a browser: the site's password login hangs off
  // GlobalPassportService, which answers 403 with an empty body to every
  // non-browser caller (Ping, a known-good endpoint, fails the same way) while
  // the WAF token in the ingress jar only clears once page JavaScript runs.
  // main.js injects the Electron implementation through deps.signIn; the headless
  // agent has no BrowserWindow, so there the credentials simply cannot renew a
  // token and a manual paste stays the only lane.
  const signIn = typeof deps.signIn === 'function' ? deps.signIn : null;
  // The window gets the full budget; the wrapper deadline outlives it so a slow
  // WAF challenge is reported as the sign-in failing, not as a probe timeout
  // that says nothing about what happened.
  const loginTimeoutMs = Number(deps.stepfunLoginTimeoutMs || 110000);
  const login = async () => {
    if (!signIn) {
      const error = new Error('StepFun sign-in needs the desktop app; paste an Oasis-Token instead');
      error.status = 'unavailable';
      throw error;
    }
    const fresh = await runWithProbeDeadline(
      ({ signal }) => signIn({ ...credentials, signal, logger: deps.logger, timeoutMs: loginTimeoutMs }),
      { signal: deps.signal, deadlineMs: loginTimeoutMs + 15000 }
    );
    // The sign-in answers with a bare token, or with a session descriptor when
    // the implementation also read the device id the site issued next to it.
    // Accept both so `oasis-webid` can be a real value rather than a guess.
    //
    // `plan` rides along when the sign-in had to ask the site whether its
    // candidate session was signed in — that check is a PLAN_URL call, and its
    // 200 body is the very account label this probe would otherwise fetch for
    // itself a moment later.
    const value = normalizeOasisToken(typeof fresh === 'string' ? fresh : fresh?.token);
    if (!value) {
      const error = new Error('StepFun sign-in returned no token');
      error.status = 'unavailable';
      throw error;
    }
    return {
      token: value,
      webid: String(fresh?.webid || '').trim(),
      plan: fresh && typeof fresh === 'object' ? fresh.plan ?? null : null
    };
  };

  // Which device id to pair with the token, in descending order of trust:
  //   1. the cookie issued alongside a browser sign-in (readOasisSessions
  //      returns it, so the pair cannot drift apart);
  //   2. the webid parsed out of the pasted cookie string;
  //   3. the environment override;
  //   4. the JWT payload, decoded as a last resort.
  //
  // Source 4 is a heuristic, not a verified contract: `device_id` was read off a
  // payload shape that no live capture has confirmed, and a wrong value fails
  // the same way as a missing one (401 "oasis-token is embezzled"). It is used
  // only after the real sources come up empty, and whatever it decides is
  // written to the diagnostic log so a failure can be told apart from a wrong
  // token instead of being guessed at.
  const resolveWebid = (sessionWebid, activeToken) => {
    const fromSession = String(sessionWebid || '').trim();
    if (fromSession) return fromSession;
    if (pastedWebid) {
      log(`stepfun webid taken from the pasted cookie string (${pastedWebid.length} chars)`);
      return pastedWebid;
    }
    const declared = stepfunWebid(env);
    if (declared) {
      log(`stepfun webid taken from the environment (${declared.length} chars)`);
      return declared;
    }
    const decoded = deviceId(activeToken);
    if (decoded) {
      log(`stepfun webid decoded from the token payload as a last resort (${decoded.length} chars, unverified)`);
    }
    return decoded;
  };

  try {
    // Mint a token before probing when we have credentials and none pasted:
    // an absent token would otherwise cost a wasted 401 round trip.
    let webid = '';
    // Carries the PLAN_URL body the sign-in already fetched, if any, so the
    // label lookup below can be skipped instead of repeating that request.
    let planFromSignIn = null;
    if (!token && credentials) {
      const session = await login();
      token = session.token;
      webid = session.webid;
      planFromSignIn = session.plan;
    }
    webid = resolveWebid(webid, token);

    const request = async (url, signal, activeToken) => {
      const startedAt = (deps.now || Date.now)();
      let response;
      try {
        response = await run(url, {
          method: 'POST', body: '{}', signal, redirect: 'error', credentials: 'omit',
          headers: oasisHeaders(activeToken, webid)
        });
      } catch (error) {
        log(`stepfun request to ${url.slice(-28)} threw after ${(deps.now || Date.now)() - startedAt}ms: ${error.message}`);
        throw error;
      }
      const elapsedMs = (deps.now || Date.now)() - startedAt;
      // Lengths only. This log is written verbatim to stepfun-diagnostic.log,
      // and the settings panel tells the user in six languages that this exact
      // file is what to attach to a bug report — so a raw webid here would ship
      // one half of the authenticating cookie pair to whoever reads the report.
      // Every other line in this file already reports presence or length.
      log(`stepfun ${url.slice(-28)} -> ${response.status} in ${elapsedMs}ms (token ${activeToken.length} chars, webid ${webid ? `${webid.length} chars` : 'none'})`);
      if (!response.ok) throw errorWithStatus(response.status === 401 || response.status === 403 ? 'unauthorized' : response.status === 429 ? 'sourceRateLimited' : 'unavailable', `StepFun returned ${response.status}`);
      try { return await response.json(); } catch { throw errorWithStatus('unavailable', 'Invalid StepFun response'); }
    };

    let body;
    const quotaProbe = async (tokenValue) => {
      const parsed = await runWithProbeDeadline(
        async ({ signal }) => request(RATE_URL, signal, tokenValue),
        { signal: deps.signal, deadlineMs: Number(deps.stepfunFetchTimeoutMs || 15000) }
      );
      // Parse before handing the body on, so that a 200 carrying an unusable
      // envelope throws HERE rather than after the renewal was already
      // reported. Upstream gets this for free because its attempt() includes
      // the parse; a probe that splits them would persist a rotation the quota
      // never actually confirmed.
      parseStepfunUsage(parsed, { logger: deps.logger });
      return parsed;
    };
    try {
      // Refresh ahead of the window, because the expiry that actually happens
      // every half hour is the one the refresh half can settle on its own.
      const renewed = await requestWithRefresh(quotaProbe, token, deps);
      body = renewed.body;
      token = renewed.token;
    } catch (error) {
      // The refresh half is spent too, so nothing this token carries can renew
      // it. Sign in once more and retry, so a dead credential self-heals instead
      // of waiting for the next manual paste.
      if (!credentials || providerStatusFromError(error) !== 'unauthorized') throw error;
      const session = await login();
      token = session.token;
      // Re-read the device id with it: reusing the aged-out session's value
      // would fail the retry for a second, unrelated reason and hide the real
      // one behind a misleading "wrong credentials" status.
      webid = resolveWebid(session.webid, token);
      planFromSignIn = session.plan;
      body = await quotaProbe(token);
    }

    const windows = parseStepfunUsage(body, { logger: deps.logger });
    let accountLabel = '';
    try {
      // Reuse the body the sign-in already pulled from PLAN_URL rather than
      // asking for the same endpoint a second time in the same probe. Only the
      // sign-in that actually verified a session has one to hand over; a
      // pasted token has no such call behind it and still fetches it.
      const plan = planFromSignIn ?? await runWithProbeDeadline(
        ({ signal }) => request(PLAN_URL, signal, token),
        { signal: deps.signal, deadlineMs: Number(deps.stepfunPlanFetchTimeoutMs || 1500) }
      );
      if (plan && (plan.status === 1 || plan.status == null) && typeof plan.subscription?.name === 'string') {
        accountLabel = plan.subscription.name;
      }
    } catch (error) {
      if (deps.signal?.aborted) throw error;
      // Plan name is optional; quota remains authoritative.
    }
    // Keyed on the account, not on the credential that happened to reach it.
//
// `credentials` requires a username AND a password, so gating on it split one
// account into two rows: the probe that ran the browser login was keyed on the
// username, and the very next probe — after the user pasted a token, or after
// the password was removed from the form — keyed on the token and became a
// second row for the same person. The username alone is the stable identity
// and does not depend on which lane is currently winning.
//
// The `password:` prefix is kept so existing rows keep their key; only the
// condition behind it changes.
//
// With no username there is no account to name, and the token is then the only
// identity left. It is taken through accountTokenIdentity() rather than used
// whole: a renewed access half is a different string for the same session, so
// keying on it would open a second row every 30 minutes for a token-only
// setup that is quietly self-renewing behind the scenes.
const accountIdentity = stepfunAccount(env, options).toLowerCase();
const accountKey = accountIdentity
  ? hashKey('stepfun', `password:${accountIdentity}`)
  : hashKey('stepfun', accountTokenIdentity(token));
return normalizeLimitProvider({ ...base, status: 'ok', accountKey, accountLabel, windows });
  } catch (error) {
    log(`stepfun probe finished as ${providerStatusFromError(error)}: ${error.message || error}`);
    return normalizeLimitProvider({ ...base, status: providerStatusFromError(error), windows: [] });
  }
}

module.exports = {
  deviceId,
  fetchStepfunLimits,
  normalizeOasisCookie,
  normalizeOasisToken,
  oasisHeaders,
  parseStepfunUsage,
  stepfunAccount,
  stepfunCredentials,
  stepfunSession,
  stepfunToken,
  stepfunWebid,
  verifyStepfunSession
};
