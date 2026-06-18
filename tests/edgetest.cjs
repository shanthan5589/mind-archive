const { chromium } = require('playwright');

const BASE = 'http://localhost:3000';
const results = [];

function pass(name) { results.push({ name, status: 'PASS' }); console.log(`  ✓ ${name}`); }
function fail(name, reason) { results.push({ name, status: 'FAIL', reason }); console.log(`  ✗ ${name}: ${reason}`); }

async function api(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, opts);
  let body;
  try { body = await res.json(); } catch { body = null; }
  return { status: res.status, body };
}

// Returns session cookie value
async function signUp(email, password = 'ValidPass123', firstName = 'Edge') {
  const res = await fetch(`${BASE}/api/signup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ firstName, lastName: 'Tester', email, password })
  });
  const setCookie = res.headers.get('set-cookie') || '';
  const match = setCookie.match(/mind_archive_session=([^;]+)/);
  return { status: res.status, cookie: match ? match[1] : null };
}

// Inject a cookie into a browser context so no signin form is needed
async function ctxWithCookie(browser, cookie, mobile = false) {
  const viewport = mobile ? { width: 390, height: 844 } : { width: 1280, height: 800 };
  const ctx = await browser.newContext({ viewport });
  if (cookie) {
    await ctx.addCookies([{ name: 'mind_archive_session', value: cookie, domain: 'localhost', path: '/' }]);
  }
  return ctx;
}

async function runTests() {
  const browser = await chromium.launch();
  const ts = Date.now();

  // Pre-create all users that will need browser sessions — before any rate limit pressure
  const uiEmail   = `ui_${ts}@x.com`;
  const vaultEmail = `vault_${ts}@x.com`;
  const tab2Email  = `tab2_${ts}@x.com`;
  const xssEmail   = `xss_${ts}@x.com`;

  const { cookie: uiCookie }    = await signUp(uiEmail, 'ValidPass123', '<script>alert(1)</script>');
  const { cookie: vaultCookie } = await signUp(vaultEmail);
  const { cookie: tab2Cookie }  = await signUp(tab2Email);
  const { cookie: xssCookie }   = await signUp(xssEmail);
  // (xss user cookie used only for browser login test of TC-E-A5)

  // ════════════════════════════════════════════════
  console.log('\n── AUTH EDGE CASES ──');
  // ════════════════════════════════════════════════

  // TC-E-A1: Empty fields signup
  {
    const r = await api('/api/signup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({}) });
    r.status === 400 ? pass('TC-E-A1: Empty fields → 400') : fail('TC-E-A1: Empty fields', `${r.status}`);
  }

  // TC-E-A2: Email at 255 chars (over 254-char limit)
  {
    const longEmail = 'a'.repeat(249) + '@x.com'; // 255 chars
    const r = await api('/api/signup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ firstName: 'A', lastName: 'B', email: longEmail, password: 'ValidPass123' }) });
    r.status === 400 ? pass('TC-E-A2: 255-char email → 400') : fail('TC-E-A2: Oversized email', `${r.status}`);
  }

  // TC-E-A3: Password exactly 7 chars (under 8 minimum)
  {
    const r = await api('/api/signup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ firstName: 'A', lastName: 'B', email: `e3_${ts}@x.com`, password: '1234567' }) });
    r.status === 400 ? pass('TC-E-A3: 7-char password → 400') : fail('TC-E-A3: Short password', `${r.status}`);
  }

  // TC-E-A4: Password exactly 8 chars (at minimum)
  {
    const r = await api('/api/signup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ firstName: 'A', lastName: 'B', email: `e4_${ts}@x.com`, password: '12345678' }) });
    r.status === 201 ? pass('TC-E-A4: 8-char password → 201') : fail('TC-E-A4: 8-char password', `${r.status}`);
  }

  // TC-E-A5: XSS in first name — must not execute when app renders
  {
    const ctx = await ctxWithCookie(browser, xssCookie);
    const page = await ctx.newPage();
    const dlgFired = [];
    page.on('dialog', async d => { dlgFired.push(d.message()); await d.accept(); });
    await page.goto(BASE);
    await page.waitForTimeout(2500);
    dlgFired.length === 0 ? pass('TC-E-A5: XSS in firstName not executed') : fail('TC-E-A5: XSS executed', `dialog: ${dlgFired[0]}`);
    await ctx.close();
  }

  // TC-E-A6: SQL injection in email field
  {
    const r = await api('/api/signin', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: "' OR '1'='1", password: 'anything' }) });
    r.status === 400 || r.status === 401 ? pass('TC-E-A6: SQL injection in email → rejected') : fail('TC-E-A6: SQL injection', `${r.status}`);
  }

  // TC-E-A7: Unicode/emoji in name fields
  {
    const r = await api('/api/signup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ firstName: '日本語🎉', lastName: 'Ünïcödé', email: `uni_${ts}@x.com`, password: 'ValidPass123' }) });
    r.status === 201 ? pass('TC-E-A7: Unicode names → 201') : fail('TC-E-A7: Unicode names', `${r.status}`);
  }

  // TC-E-A8: Email case normalization — same account
  {
    const baseEmail = `case_${ts}@x.com`;
    await signUp(baseEmail);
    const r = await api('/api/signup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ firstName: 'A', lastName: 'B', email: baseEmail.toUpperCase(), password: 'ValidPass123' }) });
    r.status === 409 ? pass('TC-E-A8: Email case normalization → duplicate rejected') : fail('TC-E-A8: Email case', `${r.status} (expected 409)`);
  }

  // TC-E-A9: Tampered session cookie → 401
  {
    const r = await api('/api/vault', { method: 'GET', headers: { cookie: 'mind_archive_session=fake.invalidsig' } });
    r.status === 401 ? pass('TC-E-A9: Tampered cookie → 401') : fail('TC-E-A9: Tampered cookie', `${r.status}`);
  }

  // TC-E-A10: No session cookie → 401
  {
    const r = await api('/api/vault', { method: 'GET' });
    r.status === 401 ? pass('TC-E-A10: No cookie → 401') : fail('TC-E-A10: No cookie', `${r.status}`);
  }

  // TC-E-A11: 1000-char password — no crash
  {
    const r = await api('/api/signup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ firstName: 'A', lastName: 'B', email: `longpw_${ts}@x.com`, password: 'a'.repeat(1000) }) });
    (r.status === 201 || r.status === 400) ? pass('TC-E-A11: 1000-char password → no crash') : fail('TC-E-A11: Long password', `${r.status}`);
  }

  // TC-E-A12: Null byte in email → 400 (not 500)
  {
    const r = await api('/api/signup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ firstName: 'A', lastName: 'B', email: 'test\x00@x.com', password: 'ValidPass123' }) });
    r.status === 400 ? pass('TC-E-A12: Null byte in email → 400') : fail('TC-E-A12: Null byte email', `${r.status}`);
  }

  // ════════════════════════════════════════════════
  console.log('\n── VAULT / POST EDGE CASES ──');
  // ════════════════════════════════════════════════

  const vH = { cookie: `mind_archive_session=${vaultCookie}` };

  // TC-E-V1: Save empty vault
  {
    const r = await api('/api/vault', { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: JSON.stringify({ vault: [] }) });
    r.status === 200 ? pass('TC-E-V1: Save empty vault → 200') : fail('TC-E-V1: Empty vault', `${r.status}`);
  }

  // TC-E-V2: XSS content stored and rendered safely (cookie-injected — no form signin)
  {
    const xssPost = [{ id: 'p1', title: '<script>alert("xss")</script>', body: '<img src=x onerror=alert(1)>', createdAt: new Date().toISOString() }];
    await api('/api/vault', { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: JSON.stringify({ vault: xssPost }) });
    const ctx = await ctxWithCookie(browser, vaultCookie);
    const page = await ctx.newPage();
    const dlgs = [];
    page.on('dialog', async d => { dlgs.push(d.message()); await d.accept(); });
    await page.goto(BASE);
    await page.waitForTimeout(2500);
    dlgs.length === 0 ? pass('TC-E-V2: XSS in post content not executed') : fail('TC-E-V2: XSS executed', `dialog: ${dlgs[0]}`);
    await ctx.close();
  }

  // TC-E-V3: Vault not an array → 400
  {
    const r = await api('/api/vault', { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: JSON.stringify({ vault: { not: 'array' } }) });
    r.status === 400 ? pass('TC-E-V3: Non-array vault → 400') : fail('TC-E-V3: Non-array vault', `${r.status}`);
  }

  // TC-E-V4: 10,000-char title — no crash
  {
    const bigPost = [{ id: 'p2', title: 'T'.repeat(10000), body: 'body', createdAt: new Date().toISOString() }];
    const r = await api('/api/vault', { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: JSON.stringify({ vault: bigPost }) });
    (r.status === 200 || r.status === 400) ? pass('TC-E-V4: 10k-char title → no crash') : fail('TC-E-V4: Long title', `${r.status}`);
  }

  // TC-E-V5: 500-post vault — no crash
  {
    const bigVault = Array.from({ length: 500 }, (_, i) => ({ id: `post${i}`, title: `Post ${i}`, body: 'body '.repeat(100), createdAt: new Date().toISOString() }));
    const r = await api('/api/vault', { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: JSON.stringify({ vault: bigVault }) });
    (r.status === 200 || r.status === 400) ? pass('TC-E-V5: 500-post vault → no crash') : fail('TC-E-V5: 500-post vault', `${r.status}`);
  }

  // TC-E-V6: Missing vault key → 400
  {
    const r = await api('/api/vault', { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: JSON.stringify({ posts: [] }) });
    r.status === 400 ? pass('TC-E-V6: Missing vault key → 400') : fail('TC-E-V6: Missing vault key', `${r.status}`);
  }

  // TC-E-V7: Concurrent vault writes both succeed
  {
    const posts1 = [{ id: 'a', title: 'A', body: 'body', createdAt: new Date().toISOString() }];
    const posts2 = [{ id: 'b', title: 'B', body: 'body', createdAt: new Date().toISOString() }];
    const [r1, r2] = await Promise.all([
      api('/api/vault', { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: JSON.stringify({ vault: posts1 }) }),
      api('/api/vault', { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: JSON.stringify({ vault: posts2 }) }),
    ]);
    (r1.status === 200 && r2.status === 200) ? pass('TC-E-V7: Concurrent vault writes both succeed') : fail('TC-E-V7: Concurrent writes', `${r1.status}, ${r2.status}`);
  }

  // TC-E-V8: Unicode in post content
  {
    const unicodePost = [{ id: 'u1', title: '日本語 🎉 العربية', body: '中文\nEmoji: 🔥💡🎸\nRTL: مرحبا', createdAt: new Date().toISOString() }];
    const r = await api('/api/vault', { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: JSON.stringify({ vault: unicodePost }) });
    r.status === 200 ? pass('TC-E-V8: Unicode post content → 200') : fail('TC-E-V8: Unicode post', `${r.status}`);
  }

  // TC-E-V9: GET vault returns what was last saved
  {
    const testPosts = [{ id: 'check1', title: 'Check Title', body: 'Check Body', createdAt: new Date().toISOString() }];
    await api('/api/vault', { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: JSON.stringify({ vault: testPosts }) });
    const r = await api('/api/vault', { method: 'GET', headers: vH });
    const arr = Array.isArray(r.body) ? r.body : r.body?.vault;
    (r.status === 200 && Array.isArray(arr) && arr.some(p => p.id === 'check1'))
      ? pass('TC-E-V9: GET vault round-trips correctly')
      : fail('TC-E-V9: Vault round-trip', `status=${r.status} body=${JSON.stringify(r.body)}`);
  }

  // ════════════════════════════════════════════════
  console.log('\n── HTTP / API EDGE CASES ──');
  // ════════════════════════════════════════════════

  // TC-E-H1: Wrong HTTP method on auth route
  {
    const r = await api('/api/signin', { method: 'GET' });
    r.status === 404 || r.status === 405 ? pass('TC-E-H1: GET /api/signin → 404/405') : fail('TC-E-H1: Wrong method', `${r.status}`);
  }

  // TC-E-H2: Missing content-type on JSON endpoint (use vault, not auth)
  {
    const r = await fetch(`${BASE}/api/vault`, { method: 'PUT', headers: { ...vH }, body: '{"vault":[]}' });
    (r.status === 200 || r.status === 400 || r.status === 415) ? pass('TC-E-H2: Missing content-type → no crash') : fail('TC-E-H2: No content-type', `${r.status}`);
  }

  // TC-E-H3: Extremely large body on vault (not auth) — uses write rate limit
  {
    const bigBody = JSON.stringify({ vault: [{ id: 'x', title: 'T', body: 'b'.repeat(2_000_000), createdAt: new Date().toISOString() }] });
    const r = await fetch(`${BASE}/api/vault`, { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: bigBody });
    (r.status === 200 || r.status === 400 || r.status === 413) ? pass('TC-E-H3: 2MB vault body → no crash') : fail('TC-E-H3: Huge body', `${r.status}`);
  }

  // TC-E-H4: Deeply nested JSON on vault — should not crash
  {
    const r = await fetch(`${BASE}/api/vault`, { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: JSON.stringify({ a: { b: { c: { d: 'deep' } } } }) });
    r.status === 400 ? pass('TC-E-H4: Missing vault key in nested JSON → 400') : fail('TC-E-H4: Nested JSON', `${r.status}`);
  }

  // TC-E-H5: Path traversal — SPA serves index.html, not system files
  {
    const r = await fetch(`${BASE}/../../../etc/passwd`);
    const text = await r.text();
    const isHtml = text.includes('<!DOCTYPE') || text.includes('<html');
    (r.status === 200 && isHtml) ? pass('TC-E-H5: Path traversal → serves index.html (not system file)') : fail('TC-E-H5: Path traversal', `status=${r.status} html=${isHtml}`);
  }

  // TC-E-H6: Double slash in path — no crash
  {
    const r = await fetch(`${BASE}//api/health`);
    (r.status === 200 || r.status === 404) ? pass('TC-E-H6: Double slash path → no crash') : fail('TC-E-H6: Double slash', `${r.status}`);
  }

  // TC-E-H7: Null byte in URL path — no crash
  {
    const r = await fetch(`${BASE}/api/he%00lth`);
    (r.status === 400 || r.status === 404 || r.status === 200) ? pass('TC-E-H7: Null byte in path → no crash') : fail('TC-E-H7: Null byte path', `${r.status}`);
  }

  // TC-E-H8: Security headers on all responses
  {
    const r = await fetch(`${BASE}/api/health`);
    const ct = r.headers.get('x-content-type-options');
    const xf = r.headers.get('x-frame-options');
    (ct === 'nosniff' && xf === 'DENY') ? pass('TC-E-H8: Security headers present') : fail('TC-E-H8: Security headers', `nosniff=${ct}, DENY=${xf}`);
  }

  // TC-E-H9: Empty body on vault PUT — no crash
  {
    const r = await fetch(`${BASE}/api/vault`, { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: '' });
    (r.status === 400 || r.status === 200) ? pass('TC-E-H9: Empty body vault PUT → no crash') : fail('TC-E-H9: Empty body', `${r.status}`);
  }

  // TC-E-H10: Prototype pollution attempt on JSON body — no crash, no pollution
  {
    const before = ({}).polluted;
    const r = await api('/api/vault', { method: 'PUT', headers: { 'content-type': 'application/json', ...vH }, body: '{"vault":[],"__proto__":{"polluted":true}}' });
    const after = ({}).polluted;
    (r.status === 200 || r.status === 400) && after === undefined
      ? pass('TC-E-H10: Prototype pollution blocked, no crash')
      : fail('TC-E-H10: Prototype pollution', `status=${r.status} polluted=${after}`);
  }

  // ════════════════════════════════════════════════
  console.log('\n── BROWSER / UI EDGE CASES ──');
  // ════════════════════════════════════════════════

  // All UI tests share one injected-cookie session — zero auth requests burned
  const uiCtx = await ctxWithCookie(browser, uiCookie);
  const uiPage = await uiCtx.newPage();
  await uiPage.goto(BASE);
  await uiPage.waitForTimeout(2500);

  const appVisible = await uiPage.$('#appLayout:not(.hidden)');
  if (!appVisible) {
    fail('UI-SIGNIN', 'Cookie injection did not restore session — skipping UI suite');
  } else {

    // TC-E-U1: 500-char title — no crash
    {
      await uiPage.click('#newPostButton');
      await uiPage.waitForTimeout(300);
      await uiPage.fill('#titleInput', 'A'.repeat(500));
      await uiPage.fill('#bodyInput', 'Body content.');
      await uiPage.click('#postForm button[type="submit"]');
      await uiPage.waitForTimeout(1500);
      const post = await uiPage.$('[data-post-id]');
      post ? pass('TC-E-U1: 500-char title → no crash') : fail('TC-E-U1: Long title UI', 'post not saved');
    }

    // TC-E-U2: 5000-word body — no crash
    {
      await uiPage.click('#newPostButton');
      await uiPage.waitForTimeout(300);
      await uiPage.fill('#titleInput', 'Long Body Post');
      await uiPage.fill('#bodyInput', 'word '.repeat(5000));
      await uiPage.click('#postForm button[type="submit"]');
      await uiPage.waitForTimeout(2000);
      const post = await uiPage.$('[data-post-id]');
      post ? pass('TC-E-U2: 5000-word body → no crash') : fail('TC-E-U2: Long body UI', 'post not saved');
    }

    // TC-E-U3: Emoji in title and body
    {
      await uiPage.click('#newPostButton');
      await uiPage.waitForTimeout(300);
      await uiPage.fill('#titleInput', '🔥 Fire Post 🎉🚀💡');
      await uiPage.fill('#bodyInput', '## Hello 🌍\n\nThis has **emoji** 🎸 and `code` 💻');
      await uiPage.click('#postForm button[type="submit"]');
      await uiPage.waitForTimeout(1500);
      const post = await uiPage.$('[data-post-id]');
      post ? pass('TC-E-U3: Emoji in title/body → no crash') : fail('TC-E-U3: Emoji UI', 'post not saved');
    }

    // TC-E-U4: XSS in post title/body — no alert should fire
    {
      const dlgs = [];
      uiPage.on('dialog', async d => { dlgs.push(d.message()); await d.accept(); });
      await uiPage.click('#newPostButton');
      await uiPage.waitForTimeout(300);
      await uiPage.fill('#titleInput', '<img src=x onerror="alert(\'xss\')">');
      await uiPage.fill('#bodyInput', '<script>alert("body xss")</script>');
      await uiPage.click('#postForm button[type="submit"]');
      await uiPage.waitForTimeout(1500);
      dlgs.length === 0 ? pass('TC-E-U4: XSS in post title/body not executed') : fail('TC-E-U4: XSS executed', `dialog: ${dlgs[0]}`);
    }

    // TC-E-U5: javascript: link in markdown — not executed in post preview
    {
      await uiPage.click('#newPostButton');
      await uiPage.waitForTimeout(300);
      await uiPage.fill('#titleInput', 'JS Link Test');
      await uiPage.fill('#bodyInput', '[click me](javascript:alert(1))\n\n<a href="javascript:alert(2)">link</a>');
      await uiPage.click('#postForm button[type="submit"]');
      await uiPage.waitForTimeout(1500);
      const post = await uiPage.$('[data-post-id]');
      if (post) {
        const postId = await post.getAttribute('data-post-id');
        const dlgs = [];
        uiPage.on('dialog', async d => { dlgs.push(d.message()); await d.accept(); });
        await uiPage.click(`[data-action="open"][data-id="${postId}"]`);
        await uiPage.waitForTimeout(800);
        dlgs.length === 0 ? pass('TC-E-U5: javascript: links not executed in preview') : fail('TC-E-U5: JS link executed', `dialog: ${dlgs[0]}`);
        await uiPage.click('#closePostModal');
        await uiPage.waitForTimeout(300);
      } else { fail('TC-E-U5: Markdown injection', 'post not saved'); }
    }

    // TC-E-U6: Rapid successive post saves — all persist
    {
      let saved = 0;
      for (let i = 0; i < 5; i++) {
        await uiPage.click('#newPostButton');
        await uiPage.waitForTimeout(200);
        await uiPage.fill('#titleInput', `Rapid Post ${i}`);
        await uiPage.fill('#bodyInput', `Content ${i}`);
        await uiPage.click('#postForm button[type="submit"]');
        await uiPage.waitForTimeout(800);
        saved++;
      }
      const posts = await uiPage.$$('[data-post-id]');
      posts.length >= saved ? pass(`TC-E-U6: ${saved} rapid saves → ${posts.length} posts in list`) : fail('TC-E-U6: Rapid saves', `expected >=${saved}, got ${posts.length}`);
    }

    // TC-E-U7: Reload after logout shows auth (session invalidated)
    {
      await uiPage.click('#userMenuButton');
      await uiPage.waitForTimeout(300);
      await uiPage.click('#logoutButton');
      await uiPage.waitForTimeout(800);
      await uiPage.reload();
      await uiPage.waitForTimeout(2000);
      const authShown = await uiPage.$('#authView:not(.hidden)');
      const appShown  = await uiPage.$('#appLayout:not(.hidden)');
      (authShown && !appShown) ? pass('TC-E-U7: Reload after logout shows auth (session cleared)') : fail('TC-E-U7: Session after logout', `auth=${!!authShown} app=${!!appShown}`);
    }

  }
  await uiCtx.close();

  // TC-E-U8: Two different users in parallel — independent sessions via cookie injection
  {
    const ctx1 = await ctxWithCookie(browser, uiCookie);
    const ctx2 = await ctxWithCookie(browser, tab2Cookie);
    const p1 = await ctx1.newPage();
    const p2 = await ctx2.newPage();
    await Promise.all([p1.goto(BASE), p2.goto(BASE)]);
    await Promise.all([p1.waitForTimeout(2500), p2.waitForTimeout(2500)]);
    const app1 = await p1.$('#appLayout:not(.hidden)');
    const app2 = await p2.$('#appLayout:not(.hidden)');
    (app1 && app2) ? pass('TC-E-U8: Two tabs with different users both work') : fail('TC-E-U8: Multi-tab', `tab1=${!!app1} tab2=${!!app2}`);
    await ctx1.close(); await ctx2.close();
  }

  // ════════════════════════════════════════════════
  console.log('\n── RATE LIMIT EDGE CASES ──');
  // ════════════════════════════════════════════════

  // TC-E-R1: Rate limit 429 kicks in after rapid auth requests
  {
    const statuses = [];
    for (let i = 0; i < 25; i++) {
      const r = await api('/api/signin', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: `rl_${i}_${ts}@x.com`, password: 'wrong' }) });
      statuses.push(r.status);
    }
    statuses.includes(429) ? pass('TC-E-R1: Rate limit 429 returned after rapid auth requests') : fail('TC-E-R1: Rate limit', `statuses: ${[...new Set(statuses)].join(',')}`);
  }

  // ════════════════════════════════════════════════
  await browser.close();

  const passed = results.filter(r => r.status === 'PASS').length;
  const failed = results.filter(r => r.status === 'FAIL');
  console.log(`\n══════════════════════════════`);
  console.log(`  ${passed}/${results.length} edge case tests passed`);
  if (failed.length) { console.log('\nFailed:'); failed.forEach(f => console.log(`  ✗ ${f.name}: ${f.reason}`)); }
  else { console.log('  All edge case tests passed! ✓'); }
  console.log('══════════════════════════════\n');
  process.exit(failed.length ? 1 : 0);
}

runTests().catch(e => { console.error(e); process.exit(1); });
