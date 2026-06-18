const { chromium } = require('playwright');

const BASE = 'http://localhost:3000';
const results = [];

function pass(name) { results.push({ name, status: 'PASS' }); console.log(`  ✓ ${name}`); }
function fail(name, reason) { results.push({ name, status: 'FAIL', reason }); console.log(`  ✗ ${name}: ${reason}`); }

async function signIn(page, email, password) {
  await page.goto(BASE);
  await page.fill('#signinEmail', email);
  await page.fill('#signinPassword', password);
  await page.click('#signinForm button[type="submit"]');
  await page.waitForTimeout(2500);
}

async function runTests() {
  const browser = await chromium.launch();

  async function newPage(mobile = false) {
    const ctx = await browser.newContext(mobile ? { viewport: { width: 390, height: 844 } } : { viewport: { width: 1280, height: 800 } });
    return ctx.newPage();
  }

  const EMAIL = `test_${Date.now()}@example.com`;
  const PASS  = 'password123';

  // ════════════════════════════════════════════════
  console.log('\n── AUTH ──');
  // ════════════════════════════════════════════════

  // TC-A1: Signup with email+password
  {
    const page = await newPage();
    await page.goto(BASE);
    await page.click('button[data-auth-mode="signup"]');
    await page.fill('#signupFirstName', 'Alice');
    await page.fill('#signupLastName', 'Test');
    await page.fill('#signupEmail', EMAIL);
    await page.fill('#signupPassword', PASS);
    await page.fill('#signupPasswordAgain', PASS);
    await page.click('#signupForm button[type="submit"]');
    await page.waitForTimeout(8000);
    const appVisible = await page.$('#appLayout:not(.hidden)');
    appVisible ? pass('TC-A1: Signup email+password') : fail('TC-A1: Signup email+password', 'app not shown after 8s');
    await page.close();
  }

  // TC-A2: Duplicate email shows correct server error
  {
    const page = await newPage();
    await page.goto(BASE);
    await page.click('button[data-auth-mode="signup"]');
    await page.fill('#signupFirstName', 'Alice');
    await page.fill('#signupLastName', 'Test');
    await page.fill('#signupEmail', EMAIL);
    await page.fill('#signupPassword', PASS);
    await page.fill('#signupPasswordAgain', PASS);
    await page.click('#signupForm button[type="submit"]');
    await page.waitForTimeout(2000);
    const status = await page.$eval('#signupStatus', el => el.textContent);
    status.toLowerCase().includes('already') ? pass('TC-A2: Duplicate email correct error') : fail('TC-A2: Duplicate email', `Got: "${status}"`);
    await page.close();
  }

  // TC-A3: Wrong password
  {
    const page = await newPage();
    await page.goto(BASE);
    await page.fill('#signinEmail', EMAIL);
    await page.fill('#signinPassword', 'wrongpassword');
    await page.click('#signinForm button[type="submit"]');
    await page.waitForTimeout(2000);
    const status = await page.$eval('#signinStatus', el => el.textContent);
    status.toLowerCase().includes('wrong') || status.toLowerCase().includes('password') ? pass('TC-A3: Wrong password error') : fail('TC-A3: Wrong password', `Got: "${status}"`);
    await page.close();
  }

  // TC-A4: Correct signin
  {
    const page = await newPage();
    await signIn(page, EMAIL, PASS);
    const appVisible = await page.$('#appLayout:not(.hidden)');
    appVisible ? pass('TC-A4: Correct signin') : fail('TC-A4: Correct signin', 'app not shown');
    await page.close();
  }

  // TC-A5/6/7: Logout + field clear + button re-enable
  {
    const page = await newPage();
    await signIn(page, EMAIL, PASS);
    await page.click('#userMenuButton');
    await page.waitForTimeout(300);
    await page.click('#logoutButton');
    await page.waitForTimeout(1000);
    const authVisible = await page.$('#authView:not(.hidden)');
    authVisible ? pass('TC-A5: Logout works') : fail('TC-A5: Logout', 'auth not shown');
    const emailVal = await page.$eval('#signinEmail', el => el.value);
    emailVal === '' ? pass('TC-A6: Signin email cleared after logout') : fail('TC-A6: Email cleared', `"${emailVal}"`);
    const btnEnabled = await page.$('#signupForm button[type="submit"]:not([disabled])');
    btnEnabled ? pass('TC-A7: Signup button re-enabled after logout') : fail('TC-A7: Signup btn re-enable', 'still disabled');
    await page.close();
  }

  // TC-A8: Session restore on reload
  {
    const page = await newPage();
    await signIn(page, EMAIL, PASS);
    await page.reload();
    await page.waitForTimeout(2500);
    const appVisible = await page.$('#appLayout:not(.hidden)');
    appVisible ? pass('TC-A8: Session restore on reload') : fail('TC-A8: Session restore', 'app not shown');
    await page.close();
  }

  // TC-A9: Password mismatch
  {
    const page = await newPage();
    await page.goto(BASE);
    await page.click('button[data-auth-mode="signup"]');
    await page.fill('#signupFirstName', 'Bob');
    await page.fill('#signupLastName', 'Test');
    await page.fill('#signupEmail', `other_${Date.now()}@example.com`);
    await page.fill('#signupPassword', PASS);
    await page.fill('#signupPasswordAgain', 'different123');
    await page.click('#signupForm button[type="submit"]');
    await page.waitForTimeout(1000);
    const status = await page.$eval('#signupStatus', el => el.textContent);
    status.toLowerCase().includes('match') ? pass('TC-A9: Password mismatch error') : fail('TC-A9: Password mismatch', `Got: "${status}"`);
    await page.close();
  }

  // TC-A10: Malformed JSON → 400
  {
    const r = await fetch(`${BASE}/api/signin`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad json' });
    r.status === 400 ? pass('TC-A10: Malformed JSON → 400') : fail('TC-A10: Malformed JSON', `Got ${r.status}`);
  }

  // ════════════════════════════════════════════════
  console.log('\n── POST CRUD ──');
  // ════════════════════════════════════════════════

  const postPage = await newPage();
  await signIn(postPage, EMAIL, PASS);

  // TC-P1: Create post
  await postPage.click('#newPostButton');
  await postPage.waitForTimeout(300);
  await postPage.fill('#titleInput', 'Test Post One');
  await postPage.fill('#bodyInput', 'This is the body of the test post.');
  await postPage.click('#postForm button[type="submit"]');
  await postPage.waitForTimeout(1500);
  const firstPost = await postPage.$('[data-post-id]');
  firstPost ? pass('TC-P1: Create post') : fail('TC-P1: Create post', 'no post in list');
  const postId = firstPost ? await firstPost.getAttribute('data-post-id') : null;

  // TC-P2: Pin post
  if (postId) {
    await postPage.click(`[data-action="pin"][data-id="${postId}"]`);
    await postPage.waitForTimeout(800);
    const pinned = await postPage.$(`[data-post-id="${postId}"].pinned`);
    pinned ? pass('TC-P2: Pin post') : fail('TC-P2: Pin post', 'no .pinned class');
    // TC-P3: Unpin
    await postPage.click(`[data-action="pin"][data-id="${postId}"]`);
    await postPage.waitForTimeout(800);
    const unpinned = !(await postPage.$(`[data-post-id="${postId}"].pinned`));
    unpinned ? pass('TC-P3: Unpin post') : fail('TC-P3: Unpin post', 'still pinned');
  } else { fail('TC-P2: Pin post', 'no postId'); fail('TC-P3: Unpin post', 'no postId'); }

  // TC-P4: Favourite post — check for fav-star span inside post
  if (postId) {
    const favBtn = await postPage.$(`[data-action="favourite"][data-id="${postId}"]`);
    const beforeText = favBtn ? await favBtn.textContent() : '';
    await postPage.click(`[data-action="favourite"][data-id="${postId}"]`);
    await postPage.waitForTimeout(800);
    const afterText = await postPage.$eval(`[data-action="favourite"][data-id="${postId}"]`, el => el.textContent);
    const starSpan = await postPage.$(`[data-post-id="${postId}"] .fav-star`);
    (starSpan || afterText !== beforeText) ? pass('TC-P4: Favourite post') : fail('TC-P4: Favourite post', 'star not shown');
  } else { fail('TC-P4: Favourite post', 'no postId'); }

  // TC-P5: Edit post
  if (postId) {
    await postPage.click(`[data-action="edit"][data-id="${postId}"]`);
    await postPage.waitForTimeout(500);
    await postPage.fill('#titleInput', 'Test Post One Edited');
    await postPage.click('#postForm button[type="submit"]');
    await postPage.waitForTimeout(1500);
    const titles = await postPage.$$eval('.post-title', els => els.map(e => e.textContent));
    titles.some(t => t.includes('Edited')) ? pass('TC-P5: Edit post') : fail('TC-P5: Edit post', `Titles: ${JSON.stringify(titles)}`);
  } else { fail('TC-P5: Edit post', 'no postId'); }

  // TC-P6: Open post modal
  if (postId) {
    await postPage.click(`[data-action="open"][data-id="${postId}"]`);
    await postPage.waitForTimeout(500);
    const modal = await postPage.$('#postModal:not(.hidden)');
    modal ? pass('TC-P6: Open post modal') : fail('TC-P6: Open post modal', 'not visible');
    if (modal) { await postPage.click('#closePostModal'); await postPage.waitForTimeout(300); }
  } else { fail('TC-P6: Open post modal', 'no postId'); }

  // TC-P7: Delete post
  {
    await postPage.click('#newPostButton');
    await postPage.waitForTimeout(300);
    await postPage.fill('#titleInput', 'Post to Delete');
    await postPage.fill('#bodyInput', 'Delete me.');
    await postPage.click('#postForm button[type="submit"]');
    await postPage.waitForTimeout(1500);
    const allPosts = await postPage.$$('[data-post-id]');
    if (allPosts.length > 0) {
      const delEl = allPosts[0];
      const delId = await delEl.getAttribute('data-post-id');
      postPage.once('dialog', d => d.accept());
      await postPage.click(`[data-action="delete"][data-id="${delId}"]`);
      await postPage.waitForTimeout(1500);
      const gone = !(await postPage.$(`[data-post-id="${delId}"]`));
      gone ? pass('TC-P7: Delete post') : fail('TC-P7: Delete post', 'still visible');
    } else { fail('TC-P7: Delete post', 'no posts found'); }
  }

  // TC-P8: Meta panel checkboxes
  {
    await postPage.click('#newPostButton');
    await postPage.waitForTimeout(300);
    await postPage.click('#detailsToolButton');
    await postPage.waitForTimeout(300);
    const pinInput = await postPage.$('#pinnedInput');
    const hiddenInput = await postPage.$('#hiddenInput');
    (pinInput && hiddenInput) ? pass('TC-P8: Meta panel checkboxes exist') : fail('TC-P8: Meta panel', 'inputs missing');
    if (pinInput) {
      const box = await pinInput.boundingBox();
      box && box.width < 30 ? pass('TC-P8b: Pin checkbox normal size') : fail('TC-P8b: Checkbox size', `w=${box?.width}`);
    }
  }

  await postPage.close();

  // ════════════════════════════════════════════════
  console.log('\n── EDITOR ──');
  // ════════════════════════════════════════════════

  const edPage = await newPage();
  await signIn(edPage, EMAIL, PASS);

  // TC-E1: Draft autosave
  await edPage.click('#newPostButton');
  await edPage.waitForTimeout(300);
  await edPage.fill('#titleInput', 'Draft Title');
  await edPage.fill('#bodyInput', 'Draft body content.');
  await edPage.waitForTimeout(1200);
  const draftSaved = await edPage.evaluate(() => !!localStorage.getItem('mind-archive-draft'));
  draftSaved ? pass('TC-E1: Draft autosave') : fail('TC-E1: Draft autosave', 'no draft');

  // TC-E2: Markdown preview
  await edPage.fill('#bodyInput', '## Hello\n\nThis is **bold** text.');
  await edPage.waitForTimeout(300);
  const previewHtml = await edPage.$eval('#markdownPreview', el => el.innerHTML);
  (previewHtml.includes('<h2>') && previewHtml.includes('<strong>')) ? pass('TC-E2: Markdown preview') : fail('TC-E2: Markdown', 'no h2/strong');

  // TC-E3: Word count
  await edPage.fill('#bodyInput', 'one two three four five');
  await edPage.waitForTimeout(300);
  const wc = await edPage.$eval('#editorWordCount', el => el.textContent);
  wc.includes('5') ? pass('TC-E3: Word count') : fail('TC-E3: Word count', `"${wc}"`);

  // TC-E4: Focus mode toggle
  const focusBtnBefore = await edPage.$eval('#focusButton', el => el.textContent);
  await edPage.click('#focusButton');
  await edPage.waitForTimeout(300);
  const focusBtnAfter = await edPage.$eval('#focusButton', el => el.textContent);
  focusBtnBefore !== focusBtnAfter ? pass('TC-E4: Focus mode toggles') : fail('TC-E4: Focus mode', 'text unchanged');

  await edPage.close();

  // ════════════════════════════════════════════════
  console.log('\n── IMPORT / EXPORT ──');
  // ════════════════════════════════════════════════

  const importPage = await newPage();
  await signIn(importPage, EMAIL, PASS);

  // Persistent dialog handler — auto-accepts alerts so evaluate() never deadlocks
  const capturedDialogs = [];
  importPage.on('dialog', async (dlg) => { capturedDialogs.push(dlg.message()); await dlg.accept(); });

  // Navigate to settings via menu
  await importPage.click('#userMenuButton');
  await importPage.waitForTimeout(300);
  await importPage.click('#settingsMenuItem');
  await importPage.waitForTimeout(800);

  // TC-I1: Export JSON
  {
    const [download] = await Promise.all([
      importPage.waitForEvent('download', { timeout: 4000 }).catch(() => null),
      importPage.click('#downloadJson')
    ]);
    download ? pass('TC-I1: Export JSON download') : fail('TC-I1: Export JSON', 'no download');
  }

  // TC-I2: Oversized file rejected
  // We use evaluate() and let the persistent dialog handler accept the alert automatically
  {
    capturedDialogs.length = 0;
    await importPage.evaluate(() => {
      const dt = new DataTransfer();
      const big = new Uint8Array(6_000_000).fill(65);
      dt.items.add(new File([big], 'big.json', { type: 'application/json' }));
      const input = document.getElementById('importFile');
      Object.defineProperty(input, 'files', { value: dt.files, configurable: true });
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await importPage.waitForTimeout(500);
    capturedDialogs.some(m => m.toLowerCase().includes('large'))
      ? pass('TC-I2: Oversized import rejected')
      : fail('TC-I2: Oversized import', capturedDialogs.length ? `"${capturedDialogs[0]}"` : 'no dialog');
  }

  // TC-I3: Invalid JSON rejected
  {
    capturedDialogs.length = 0;
    await importPage.evaluate(() => {
      const dt = new DataTransfer();
      dt.items.add(new File(['not json{{{'], 'bad.json', { type: 'application/json' }));
      const input = document.getElementById('importFile');
      Object.defineProperty(input, 'files', { value: dt.files, configurable: true });
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await importPage.waitForTimeout(1500); // wait for async file.text() + alert
    capturedDialogs.length > 0
      ? pass('TC-I3: Invalid JSON rejected')
      : fail('TC-I3: Invalid JSON', 'no dialog');
  }

  // TC-I4: Non-array JSON rejected
  {
    capturedDialogs.length = 0;
    await importPage.evaluate(() => {
      const dt = new DataTransfer();
      dt.items.add(new File(['{"key":"value"}'], 'obj.json', { type: 'application/json' }));
      const input = document.getElementById('importFile');
      Object.defineProperty(input, 'files', { value: dt.files, configurable: true });
      input.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await importPage.waitForTimeout(1500);
    capturedDialogs.some(m => m.toLowerCase().includes('array'))
      ? pass('TC-I4: Non-array JSON rejected')
      : fail('TC-I4: Non-array JSON', capturedDialogs.length ? `"${capturedDialogs[0]}"` : 'no dialog');
  }

  await importPage.close();

  // ════════════════════════════════════════════════
  console.log('\n── MOBILE VIEWPORT ──');
  // ════════════════════════════════════════════════

  const mobilePage = await newPage(true);
  await mobilePage.goto(BASE);

  const authMobile = await mobilePage.$('#authView:not(.hidden)');
  authMobile ? pass('TC-M1: Auth renders on mobile') : fail('TC-M1: Auth on mobile', 'not visible');

  const inputFontSize = await mobilePage.$eval('#signinEmail', el => window.getComputedStyle(el).fontSize);
  inputFontSize === '16px' ? pass('TC-M2: Input font-size 16px (no iOS zoom)') : fail('TC-M2: Font size', `Got ${inputFontSize}`);

  await mobilePage.fill('#signinEmail', EMAIL);
  await mobilePage.fill('#signinPassword', PASS);
  await mobilePage.click('#signinForm button[type="submit"]');
  await mobilePage.waitForTimeout(2500);

  await mobilePage.click('#newPostButton');
  await mobilePage.waitForTimeout(500);
  const editorMobile = await mobilePage.$('#editorView:not(.hidden)');
  editorMobile ? pass('TC-M3: Editor opens on mobile') : fail('TC-M3: Editor mobile', 'not visible');

  await mobilePage.click('#detailsToolButton');
  await mobilePage.waitForTimeout(300);
  const metaMobile = await mobilePage.$('#metaDetailsPanel:not(.hidden)');
  metaMobile ? pass('TC-M4: Meta panel on mobile') : fail('TC-M4: Meta panel mobile', 'not visible');
  if (metaMobile) {
    const box = await mobilePage.$eval('#pinnedInput', el => { const b = el.getBoundingClientRect(); return { w: b.width }; });
    box.w < 30 ? pass('TC-M4b: Checkbox normal size on mobile') : fail('TC-M4b: Checkbox mobile', `w=${box.w}`);
  }

  await mobilePage.close();

  // ════════════════════════════════════════════════
  console.log('\n── API EDGE CASES ──');
  // ════════════════════════════════════════════════

  { const r = await fetch(`${BASE}/api/health`); r.status === 200 ? pass('TC-API1: Health 200') : fail('TC-API1: Health', `${r.status}`); }
  { const r = await fetch(`${BASE}/api/vault`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ vault: [] }) }); r.status === 401 ? pass('TC-API2: Vault no auth → 401') : fail('TC-API2: Vault no auth', `${r.status}`); }
  { const r = await fetch(`${BASE}/api/ai`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ feature: 'suggest', payload: {} }) }); r.status === 401 ? pass('TC-API3: AI no auth → 401') : fail('TC-API3: AI no auth', `${r.status}`); }
  { const r = await fetch(`${BASE}/api/nonexistent`); r.status === 404 ? pass('TC-API4: Unknown route → 404') : fail('TC-API4: Unknown route', `${r.status}`); }
  { const r = await fetch(`${BASE}/api/signup`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{bad json' }); r.status === 400 ? pass('TC-API5: Malformed JSON → 400') : fail('TC-API5: Malformed JSON', `${r.status}`); }
  { const r = await fetch(`${BASE}/api/signup`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ firstName: 'A', lastName: 'B', email: 'x@x.com', password: '123' }) }); r.status === 400 ? pass('TC-API6: Short password → 400') : fail('TC-API6: Short password', `${r.status}`); }
  { const r = await fetch(`${BASE}/api/signup`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ firstName: 'A', lastName: 'B', email: 'notanemail', password: 'password123' }) }); r.status === 400 ? pass('TC-API7: Invalid email → 400') : fail('TC-API7: Invalid email', `${r.status}`); }

  // ════════════════════════════════════════════════
  await browser.close();

  const passed = results.filter(r => r.status === 'PASS').length;
  const failed = results.filter(r => r.status === 'FAIL');
  console.log(`\n══════════════════════════════`);
  console.log(`  ${passed}/${results.length} tests passed`);
  if (failed.length) { console.log('\nFailed:'); failed.forEach(f => console.log(`  ✗ ${f.name}: ${f.reason}`)); }
  else { console.log('  All tests passed! ✓'); }
  console.log('══════════════════════════════\n');
  process.exit(failed.length ? 1 : 0);
}

runTests().catch(e => { console.error(e); process.exit(1); });
