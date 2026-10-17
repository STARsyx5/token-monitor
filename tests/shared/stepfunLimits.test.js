'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { fetchStepfunLimits, parseStepfunUsage, stepfunToken, deviceId } = require('../../src/shared/providers/stepfun/limits');

function jwt(device) {
  return `header.${Buffer.from(JSON.stringify({ device_id: device })).toString('base64url')}.signature`;
}

test('StepFun token pair uses refresh device id for the Oasis cookie', async () => {
  const token = `${jwt('access-id')}...${jwt('refresh-id')}`;
  assert.equal(deviceId(token), 'refresh-id');
  const requests = [];
  const result = await fetchStepfunLimits({ stepfunToken: token }, {
    env: {}, now: () => 1770000000000,
    fetch: async (url, init) => {
      requests.push({ url, init });
      return { ok: true, json: async () => url.includes('QueryStepPlanRateLimit')
        ? { status: 1, five_hour_usage_left_rate: 0.8, weekly_usage_left_rate: 0.6,
          five_hour_usage_reset_time: '1780000000', weekly_usage_reset_time: '1780500000' }
        : { status: 1, subscription: { name: 'Coding Plan' } } };
    }
  });
  assert.equal(result.status, 'ok');
  assert.equal(result.accountLabel, 'Coding Plan');
  assert.deepEqual(result.windows.map(({ kind, usedPercent }) => [kind, usedPercent]), [['session', 20], ['weekly', 40]]);
  assert.equal(requests.length, 2);
  for (const { init } of requests) {
    assert.equal(init.headers['oasis-webid'], 'refresh-id');
    assert.equal(init.headers.Cookie, `Oasis-Token=${token}; Oasis-Webid=refresh-id`);
    assert.equal(init.credentials, 'omit');
  }
});

test('StepFun credit plans use weighted buckets and omit inactive rate windows', () => {
  const windows = parseStepfunUsage({ status: 1, plan_family: 2,
    five_hour_usage_left_rate: 0, weekly_usage_left_rate: 0,
    five_hour_usage_reset_time: '0', weekly_usage_reset_time: '0',
    plan_credit_rate_limit: { subscription_credit_left_rate: 0.9, topup_credit_left_rate: 0.1,
      subscription_credit_reset_time: '1786288293', credit_buckets: [
        { credit_total: '400', credit_residual: '300' },
        { credit_total: '100', credit_residual: '100' }
      ] } });
  assert.equal(windows.length, 1);
  assert.equal(windows[0].kind, 'billing');
  assert.equal(windows[0].usedPercent, 20);
  assert.equal(windows[0].windowMinutes, 43200);
});

test('StepFun missing credit amount and invalid windows do not publish a false quota', () => {
  assert.throws(() => parseStepfunUsage({ status: 1, plan_family: 2 }), /credit balance missing/);
  assert.throws(() => parseStepfunUsage({ status: 1, plan_family: 2,
    plan_credit_rate_limit: { subscription_credit_left_rate: 0.8, credit_buckets: [
      { credit_total: 100, credit_residual: 80 }, { credit_total: 100 }
    ] } }), /credit buckets incomplete/);
  assert.equal(parseStepfunUsage({ status: 1, plan_family: 2,
    plan_credit_rate_limit: { subscription_credit_left_rate: 0.8, credit_buckets: [] }
  })[0].usedPercent, 20);
  assert.throws(() => parseStepfunUsage({ status: 1, five_hour_usage_left_rate: 0,
    weekly_usage_left_rate: 0, five_hour_usage_reset_time: '0', weekly_usage_reset_time: '0' }), /rate windows missing/);
});

test('a stalled optional plan lookup cannot discard a successful quota response', async () => {
  let planSignal;
  const result = await fetchStepfunLimits({ stepfunToken: 'token' }, {
    env: {}, stepfunPlanFetchTimeoutMs: 10,
    fetch: async (url, { signal }) => {
      if (url.includes('QueryStepPlanRateLimit')) return { ok: true, json: async () => ({
        status: 1, five_hour_usage_left_rate: 0.8, weekly_usage_left_rate: 0.6,
        five_hour_usage_reset_time: '1780000000', weekly_usage_reset_time: '1780500000'
      }) };
      planSignal = signal;
      return new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
    }
  });
  assert.equal(result.status, 'ok');
  assert.equal(result.accountLabel, '');
  assert.deepEqual(result.windows.map(({ kind }) => kind), ['session', 'weekly']);
  assert.equal(planSignal.aborted, true);
});

test('StepFun classifies rejected credentials and missing settings', async () => {
  assert.equal(stepfunToken({}, { stepfunToken: 'Oasis-Token=abc...def; Oasis-Webid=device' }), 'abc...def');
  assert.equal((await fetchStepfunLimits({}, { env: {} })).status, 'notConfigured');
  const rejected = await fetchStepfunLimits({ stepfunToken: 'token' }, {
    env: {}, fetch: async () => ({ ok: false, status: 401 })
  });
  assert.equal(rejected.status, 'unauthorized');
});

const QUOTA_BODY = { status: 1, five_hour_usage_left_rate: 0.8, weekly_usage_left_rate: 0.6,
  five_hour_usage_reset_time: '1780000000', weekly_usage_reset_time: '1780500000' };

// Stale access half 401s → PassportService/RefreshToken → the renewed token
// answers both the retried quota request and the plan lookup; the rotation is
// reported through onStepfunTokenRenewed so the runtime persists it.
test('StepFun rotates an expired Oasis token through the passport refresh endpoint', async () => {
  const stale = `${jwt('access-old')}...${jwt('device-id')}`;
  const freshAccess = jwt('access-new');
  const refreshRaw = jwt('device-id');
  const fresh = `${freshAccess}...${refreshRaw}`;
  const requests = [];
  const renewals = [];
  const result = await fetchStepfunLimits({ stepfunToken: stale }, {
    env: {},
    onStepfunTokenRenewed: async (renewal) => {
      assert.equal(requests.length, 3, 'quota retry completes before reporting a renewal');
      renewals.push(renewal);
    },
    fetch: async (url, init) => {
      requests.push({ url, init });
      const cookie = init.headers.Cookie;
      if (url.includes('PassportService/RefreshToken')) {
        return cookie.includes(stale)
          ? { ok: true, json: async () => ({ accessToken: { raw: freshAccess }, refreshToken: { raw: refreshRaw } }) }
          : { ok: false, status: 401 };
      }
      const authorized = cookie.includes(fresh);
      if (url.includes('QueryStepPlanRateLimit')) {
        return authorized
          ? { ok: true, json: async () => QUOTA_BODY }
          : { ok: false, status: 401 };
      }
      return authorized
        ? { ok: true, json: async () => ({ status: 1, subscription: { name: 'Coding Plan' } }) }
        : { ok: false, status: 401 };
    }
  });
  assert.equal(result.status, 'ok');
  assert.equal(result.accountLabel, 'Coding Plan');
  assert.deepEqual(result.windows.map(({ kind, usedPercent }) => [kind, usedPercent]), [['session', 20], ['weekly', 40]]);
  assert.deepEqual(renewals, [{ previousToken: stale, token: fresh }]);
  // rate(stale) → refresh(stale) → rate(fresh) → plan(fresh): the plan lookup
  // must use the effective token; the stale one would only 401 again.
  assert.deepEqual(requests.map(({ url }) => url.split('/').pop()), [
    'QueryStepPlanRateLimit', 'RefreshToken', 'QueryStepPlanRateLimit', 'GetStepPlanStatus'
  ]);
  assert.match(requests[1].init.headers.Cookie, /Oasis-Webid=device-id/);
  assert.ok(requests[2].init.headers.Cookie.includes(fresh));
  assert.ok(requests[3].init.headers.Cookie.includes(fresh));
});

test('a rejected refresh keeps the unauthorized verdict and reports nothing', async () => {
  const renewals = [];
  const result = await fetchStepfunLimits({ stepfunToken: 'a...b' }, {
    env: {},
    onStepfunTokenRenewed: async (renewal) => { renewals.push(renewal); },
    fetch: async () => ({ ok: false, status: 401 })
  });
  assert.equal(result.status, 'unauthorized');
  assert.deepEqual(renewals, []);
});

test('transient refresh failures can be saved and schedule a limits retry', async (t) => {
  const { createCredentialCommands } = require('../../src/electron/limits/credentialCommands');
  const { createLimitsRuntime } = require('../../src/shared/limits/runtime');
  for (const [failure, status] of [['network', 'unavailable'], [503, 'unavailable'], [429, 'sourceRateLimited']]) {
    const renewals = [];
    const deps = {
      env: {},
      onStepfunTokenRenewed: (renewal) => { renewals.push(renewal); },
      fetch: async (url) => {
        if (!url.includes('PassportService/RefreshToken')) return { ok: false, status: 401 };
        if (failure === 'network') throw new Error('offline');
        return { ok: false, status: failure };
      }
    };
    const token = 'expired-access...valid-refresh';
    const row = await fetchStepfunLimits({ stepfunToken: token }, deps);
    assert.equal(row.status, status, String(failure));
    assert.deepEqual(renewals, []);

    const patches = [];
    const commands = createCredentialCommands({
      getSettings: () => ({}),
      applySettingsPatch: (patch) => { patches.push(patch); return {}; },
      probeDeps: () => deps,
      env: {}
    });
    const saved = await commands.saveCredential('stepfun', { stepfunToken: token });
    assert.equal(saved.saved, true);
    assert.equal(saved.verdict, 'indeterminate');
    assert.equal(saved.status, status);
    assert.equal(patches[0].stepfunToken, token);

    const events = [];
    const runtime = createLimitsRuntime({ limitProviders: ['stepfun'], stepfunToken: token }, {
      ...deps, retryBaseMs: 60000, random: () => 0.5,
      onEvent: (event) => { events.push(event); }
    });
    t.after(() => runtime.stop());
    await runtime.refresh({ provider: 'stepfun' });
    assert.equal(runtime.getSnapshot().providers[0].status, status);
    assert.equal(events.find((event) => event.type === 'retry-scheduled')?.reason, status);
    runtime.stop();
  }
});

test('a failed quota retry never reports a renewal or retries again', async () => {
  for (const [failure, status] of [[401, 'unauthorized'], [503, 'unavailable'], ['network', 'unavailable'], ['invalid', 'unavailable']]) {
    const renewals = [];
    const requests = [];
    const result = await fetchStepfunLimits({ stepfunToken: 'old...refresh' }, {
      env: {},
      onStepfunTokenRenewed: (renewal) => { renewals.push(renewal); },
      fetch: async (url, init) => {
        requests.push(url);
        if (url.includes('PassportService/RefreshToken')) {
          return { ok: true, json: async () => ({ accessToken: { raw: 'new' }, refreshToken: { raw: 'refresh' } }) };
        }
        if (init.headers.Cookie.includes('old...refresh')) return { ok: false, status: 401 };
        if (failure === 'network') throw new Error('offline');
        if (failure === 'invalid') return { ok: true, json: async () => ({ status: 1 }) };
        return { ok: false, status: failure };
      }
    });
    assert.equal(result.status, status, String(failure));
    assert.deepEqual(renewals, []);
    assert.deepEqual(requests.map((url) => url.split('/').pop()), [
      'QueryStepPlanRateLimit', 'RefreshToken', 'QueryStepPlanRateLimit'
    ]);
  }
});

test('a failing renewal callback cannot discard a refreshed quota', async () => {
  const stale = `${jwt('old')}...${jwt('device-id')}`;
  const fresh = `${jwt('new')}...${jwt('device-id')}`;
  const result = await fetchStepfunLimits({ stepfunToken: stale }, {
    env: {},
    onStepfunTokenRenewed: async () => { throw new Error('settings write failed'); },
    fetch: async (url, init) => {
      if (url.includes('PassportService/RefreshToken')) {
        return { ok: true, json: async () => ({ accessToken: { raw: fresh.split('...')[0] }, refreshToken: { raw: jwt('device-id') } }) };
      }
      return init.headers.Cookie.includes(stale)
        ? { ok: false, status: 401 }
        : { ok: true, json: async () => QUOTA_BODY };
    }
  });
  assert.equal(result.status, 'ok');
  assert.deepEqual(result.windows.map(({ kind }) => kind), ['session', 'weekly']);
});

test('StepFun account identity survives access-half rotation', async () => {
  const run = (token) => fetchStepfunLimits({ stepfunToken: token }, {
    env: {},
    fetch: async (url) => (url.includes('QueryStepPlanRateLimit')
      ? { ok: true, json: async () => QUOTA_BODY }
      : { ok: true, json: async () => ({ status: 1 }) })
  });
  const first = await run(`${jwt('access-a')}...${jwt('device-id')}`);
  const second = await run(`${jwt('access-b')}...${jwt('device-id')}`);
  assert.equal(first.status, 'ok');
  assert.equal(first.accountKey, second.accountKey);
});

test('the diagnostic log records how long the webid is, never the webid', async () => {
  // main.js wraps every logger in stepfunErrorLogger, which writes the line
  // verbatim to stepfun-diagnostic.log — and the settings panel tells the user
  // in six languages that this exact file is what to attach to a bug report. So
  // the raw Oasis-Webid in the request line put one half of the authenticating
  // cookie pair into the one artifact this feature actively asks people to
  // share. Every other line in this file reports presence or length.
  //
  // Written as a leak check against a marker value rather than a source pattern:
  // a source pattern on the log call would still be satisfied by a build that
  // logs the webid somewhere else in the same line.
  const lines = [];
  const secretDevice = 'webid-MUST-NOT-APPEAR-4f2b';
  const token = `${jwt('access-id')}...${jwt(secretDevice)}`;
  await fetchStepfunLimits({ stepfunToken: token }, {
    env: {}, now: () => 1770000000000,
    logger: (line) => lines.push(line),
    fetch: async () => ({ ok: true, json: async () => ({
      status: 1, five_hour_usage_left_rate: 0.8, weekly_usage_left_rate: 0.6,
      five_hour_usage_reset_time: '1780000000', weekly_usage_reset_time: '1780500000'
    }) })
  });

  assert.ok(lines.length > 0, 'a silent run would make the leak check below vacuous');
  assert.ok(lines.some((line) => line.includes('webid')),
    'the request line being checked has to exist, or this only proves the logger is quiet');
  for (const line of lines) {
    assert.equal(line.includes(secretDevice), false,
      `the diagnostic log must not carry the raw webid, but this line does: ${line}`);
  }
});

test('both credential lanes report as configured', () => {
  // defaultAccountStatus() resolves exactly ONE field — status.credential — so
  // with the password declared there, a token-only setup rendered "Not set"
  // while its quota probe worked and its manual paste lane was live. That is
  // the lane the form documents for the headless agent, so the pill was wrong
  // for a supported configuration rather than for a broken one.
  const declaration = require('../../src/shared/providers/stepfun/account');
  // The registry hands accountStatus the provider's whole limits module, and the
  // projection resolves through it — so the test passes the same shape.
  const limits = require('../../src/shared/providers/stepfun/limits');
  assert.equal(typeof declaration.accountStatus, 'function',
    'the provider has to project both lanes itself; status.credential can only ever name one');

  const tokenOnly = declaration.accountStatus({
    settings: { stepfunToken: 'Oasis-Token=abc' }, env: {}, limits
  });
  assert.equal(tokenOnly.stepfunTokenConfigured, true, 'a pasted token alone is a working lane');
  assert.equal(tokenOnly.stepfunTokenSource, 'settings');

  const passwordOnly = declaration.accountStatus({
    settings: { stepfunUsername: 'me@example.com', stepfunPassword: 'pw' }, env: {}, limits
  });
  assert.equal(passwordOnly.stepfunTokenConfigured, true, 'the browser sign-in lane counts too');
  assert.equal(passwordOnly.stepfunTokenSource, 'settings');

  const fromEnv = declaration.accountStatus({ settings: {}, env: { STEPFUN_TOKEN: 'Oasis-Token=abc' }, limits });
  assert.equal(fromEnv.stepfunTokenConfigured, true, 'and so does the environment lane');
  assert.equal(fromEnv.stepfunTokenSource, 'env');

  const empty = declaration.accountStatus({ settings: {}, env: {}, limits });
  assert.equal(empty.stepfunTokenConfigured, false, 'nothing configured still has to read as not set');
  assert.equal(empty.stepfunTokenSource, '');
});
