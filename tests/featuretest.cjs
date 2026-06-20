/**
 * Feature regression tests for changes merged on fix/favourite-star:
 *  - Star / favourite: aria-pressed, amber state, modal sync, persistence
 *  - Filter state reset on login
 *  - "New" button removed from editor
 *  - Product tour: signup auto-start, step count, completion, dropdown, skip, mobile
 */
const { chromium } = require('playwright');

const BASE = 'http://localhost:3000';
const results = [];

function pass(name) { results.push({ name, status: 'PASS' }); console.log(`  ✓ ${name}`); }
function fail(name, reason) { results.push({ name, status: 'FAIL', reason }); console.log(`  ✗ ${name}: ${reason}`); }

async function signUpApi(email, password = 'ValidPass123', firstName = 'Feature') {
  const res = await fetch(`${BASE}/api/signup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ firstName, lastName: 'Tester', email, password })
  });
  const setCookie = res.headers.get('set-cookie') || '';
  const match = setCookie.match(/mind_archive_session=([^;]+)/);
  return { status: res.status, cookie: match ? match[1] : null };
}

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

  // Pre-create users via API to avoid burning rate-limit budget
  const starEmail   = `star_${ts}@x.com`;
  const filterEmail = `filter_${ts}@x.com`;
  const { cookie: starCookie }   = await signUpApi(starEmail);
  const { cookie: filterCookie } = await signUpApi(filterEmail);

  // ════════════════════════════════════════════════
  console.log('\n── STAR / FAVOURITE ──');
  // ════════════════════════════════════════════════

  // Set up: inject cookie, create one post so there's something to star
  const starCtx = await ctxWithCookie(browser, starCookie);
  const starPage = await starCtx.newPage();
  await starPage.goto(BASE);
  await starPage.waitForTimeout(1500);

  // Create a post to star
  await starPage.click('#newPostButton');
  await starPage.waitForTimeout(300);
  await starPage.fill('#titleInput', 'Post to Star');
  await starPage.fill('#bodyInput', 'Body content for starring test.');
  await starPage.click('#postForm button[type="submit"]');
  await starPage.waitForTimeout(1500);

  const post = await starPage.$('[data-post-id]');
  const postId = post ? await post.getAttribute('data-post-id') : null;

  // TC-F-S1: Star button starts unstarred (aria-pressed="false")
  if (postId) {
    const pressed = await starPage.$eval(
      `[data-action="favourite"][data-id="${postId}"]`,
      el => el.getAttribute('aria-pressed')
    );
    pressed === 'false' ? pass('TC-F-S1: Star button aria-pressed="false" initially') : fail('TC-F-S1: Initial aria-pressed', `Got "${pressed}"`);
  } else { fail('TC-F-S1: Initial aria-pressed', 'no post found'); }

  // TC-F-S2: After clicking star, aria-pressed="true"
  if (postId) {
    await starPage.click(`[data-action="favourite"][data-id="${postId}"]`);
    await starPage.waitForTimeout(600);
    const pressed = await starPage.$eval(
      `[data-action="favourite"][data-id="${postId}"]`,
      el => el.getAttribute('aria-pressed')
    );
    pressed === 'true' ? pass('TC-F-S2: Star button aria-pressed="true" after starring') : fail('TC-F-S2: aria-pressed after star', `Got "${pressed}"`);
  } else { fail('TC-F-S2: aria-pressed after star', 'no postId'); }

  // TC-F-S3: Star button shows ★ character when starred
  if (postId) {
    const text = await starPage.$eval(
      `[data-action="favourite"][data-id="${postId}"]`,
      el => el.textContent.trim()
    );
    text === '★' ? pass('TC-F-S3: Star button shows ★ when starred') : fail('TC-F-S3: Star character', `Got "${text}"`);
  } else { fail('TC-F-S3: Star character', 'no postId'); }

  // TC-F-S4: fav-star span appears in post meta when starred
  if (postId) {
    const favStar = await starPage.$(`[data-post-id="${postId}"] .fav-star`);
    favStar ? pass('TC-F-S4: .fav-star span appears in post meta when starred') : fail('TC-F-S4: fav-star span', 'span not found');
  } else { fail('TC-F-S4: fav-star span', 'no postId'); }

  // TC-F-S5: Unstar — aria-pressed goes back to "false"
  if (postId) {
    await starPage.click(`[data-action="favourite"][data-id="${postId}"]`);
    await starPage.waitForTimeout(600);
    const pressed = await starPage.$eval(
      `[data-action="favourite"][data-id="${postId}"]`,
      el => el.getAttribute('aria-pressed')
    );
    pressed === 'false' ? pass('TC-F-S5: Unstar sets aria-pressed="false"') : fail('TC-F-S5: Unstar aria-pressed', `Got "${pressed}"`);
    // Re-star for persistence test; wait 2s for debounce (500ms) + HTTP save to complete
    await starPage.click(`[data-action="favourite"][data-id="${postId}"]`);
    await starPage.waitForTimeout(2000);
  } else { fail('TC-F-S5: Unstar aria-pressed', 'no postId'); }

  // TC-F-S6: Starred state persists after page reload
  if (postId) {
    await starPage.reload();
    await starPage.waitForTimeout(2000);
    const pressed = await starPage.$eval(
      `[data-action="favourite"][data-id="${postId}"]`,
      el => el.getAttribute('aria-pressed')
    ).catch(() => null);
    pressed === 'true' ? pass('TC-F-S6: Star persists after page reload') : fail('TC-F-S6: Star persistence', `aria-pressed="${pressed}"`);
  } else { fail('TC-F-S6: Star persistence', 'no postId'); }

  // TC-F-S7: Modal star button has correct aria-pressed when post is starred
  if (postId) {
    await starPage.click(`[data-action="open"][data-id="${postId}"]`);
    await starPage.waitForTimeout(500);
    const modalPressed = await starPage.$eval(
      '[data-action="modal-favourite"]',
      el => el.getAttribute('aria-pressed')
    ).catch(() => null);
    modalPressed === 'true' ? pass('TC-F-S7: Modal star aria-pressed="true" for starred post') : fail('TC-F-S7: Modal star aria-pressed', `Got "${modalPressed}"`);
    await starPage.click('#closePostModal');
    await starPage.waitForTimeout(300);
  } else { fail('TC-F-S7: Modal star aria-pressed', 'no postId'); }

  // TC-F-S8: Starring from modal reflects in post list button
  if (postId) {
    // Unstar first via list button
    await starPage.click(`[data-action="favourite"][data-id="${postId}"]`);
    await starPage.waitForTimeout(500);
    // Open modal and star from there
    await starPage.click(`[data-action="open"][data-id="${postId}"]`);
    await starPage.waitForTimeout(500);
    await starPage.click('[data-action="modal-favourite"]');
    await starPage.waitForTimeout(500);
    await starPage.click('#closePostModal');
    await starPage.waitForTimeout(300);
    const listPressed = await starPage.$eval(
      `[data-action="favourite"][data-id="${postId}"]`,
      el => el.getAttribute('aria-pressed')
    ).catch(() => null);
    listPressed === 'true' ? pass('TC-F-S8: Modal star reflects in post list button') : fail('TC-F-S8: Modal star sync', `List aria-pressed="${listPressed}"`);
  } else { fail('TC-F-S8: Modal star sync', 'no postId'); }

  await starCtx.close();

  // ════════════════════════════════════════════════
  console.log('\n── FILTER STATE RESET ON LOGIN ──');
  // ════════════════════════════════════════════════

  // Use a fresh browser page with form-based login to test filter reset after logout/login
  const filterCtx = await ctxWithCookie(browser, filterCookie);
  const filterPage = await filterCtx.newPage();
  await filterPage.goto(BASE);
  await filterPage.waitForTimeout(1500);

  // Expand the Find box and check the onlyFavourite checkbox
  const findBox = await filterPage.$('#findBox');
  if (findBox) {
    const isCollapsed = await filterPage.$('#findBox.collapsed');
    if (isCollapsed) {
      await filterPage.click('#findBoxTitle');
      await filterPage.waitForTimeout(300);
    }
    await filterPage.check('#onlyFavourite');
    await filterPage.waitForTimeout(300);
    const checked = await filterPage.$eval('#onlyFavourite', el => el.checked);
    if (!checked) { fail('TC-F-FL0: Setup — could not check onlyFavourite', 'checkbox not checked'); }
  }

  // Logout
  await filterPage.click('#userMenuButton');
  await filterPage.waitForTimeout(300);
  await filterPage.click('#logoutButton');
  await filterPage.waitForTimeout(800);

  // Log back in via form
  await filterPage.fill('#signinEmail', filterEmail);
  await filterPage.fill('#signinPassword', 'ValidPass123');
  await filterPage.click('#signinForm button[type="submit"]');
  await filterPage.waitForTimeout(2500);

  // TC-F-FL1: onlyFavourite checkbox is unchecked after login
  {
    const checked = await filterPage.$eval('#onlyFavourite', el => el.checked).catch(() => null);
    checked === false ? pass('TC-F-FL1: onlyFavourite checkbox unchecked after login') : fail('TC-F-FL1: Filter reset', `checked=${checked}`);
  }

  // TC-F-FL2: searchFrom, searchTo, minWords inputs are empty after login
  {
    const searchFrom = await filterPage.$eval('#searchFrom', el => el.value).catch(() => '');
    const searchTo   = await filterPage.$eval('#searchTo',   el => el.value).catch(() => '');
    const minWords   = await filterPage.$eval('#minWords',   el => el.value).catch(() => '');
    (searchFrom === '' && searchTo === '' && minWords === '')
      ? pass('TC-F-FL2: searchFrom/searchTo/minWords reset on login')
      : fail('TC-F-FL2: Filter inputs reset', `from="${searchFrom}" to="${searchTo}" words="${minWords}"`);
  }

  await filterCtx.close();

  // ════════════════════════════════════════════════
  console.log('\n── EDITOR: NEW BUTTON REMOVED ──');
  // ════════════════════════════════════════════════

  // TC-F-ED1: #clearEditor element must not exist in the DOM
  {
    const tmpEmail = `editor_${ts}@x.com`;
    const { cookie: edCookie } = await signUpApi(tmpEmail);
    const edCtx = await ctxWithCookie(browser, edCookie);
    const edPage = await edCtx.newPage();
    await edPage.goto(BASE);
    await edPage.waitForTimeout(1500);
    await edPage.click('#newPostButton');
    await edPage.waitForTimeout(300);
    const clearEditorExists = await edPage.$('#clearEditor');
    !clearEditorExists ? pass('TC-F-ED1: #clearEditor (New) button not in DOM') : fail('TC-F-ED1: New button removed', '#clearEditor still exists');
    // TC-F-ED2: Save button still present
    const saveBtn = await edPage.$('#postForm button[type="submit"]');
    saveBtn ? pass('TC-F-ED2: Save button still present in editor') : fail('TC-F-ED2: Save button', 'not found');
    await edCtx.close();
  }

  // ════════════════════════════════════════════════
  console.log('\n── PRODUCT TOUR (DESKTOP) ──');
  // ════════════════════════════════════════════════

  const DESKTOP_TOTAL = 12;

  // TC-F-T1: Tour auto-starts after signup and backdrop is visible
  // TC-F-T2: Skip button hidden on signup tour (non-skippable)
  // TC-F-T3: Step label says "Step 1 of 12"
  {
    const tourEmail = `tour_desk_${ts}@x.com`;
    const tourCtx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    const tourPage = await tourCtx.newPage();
    await tourPage.goto(BASE);
    await tourPage.waitForSelector('#authView:not(.hidden)', { timeout: 5000 });
    await tourPage.click('button[data-auth-mode="signup"]');
    await tourPage.fill('#signupFirstName', 'Tour');
    await tourPage.fill('#signupLastName', 'Test');
    await tourPage.fill('#signupEmail', tourEmail);
    await tourPage.fill('#signupPassword', 'ValidPass123');
    await tourPage.fill('#signupPasswordAgain', 'ValidPass123');
    await tourPage.click('#signupForm button[type="submit"]');
    await tourPage.waitForSelector('#appLayout:not(.hidden)', { timeout: 10000 });
    await tourPage.waitForTimeout(900);

    const backdropVisible = await tourPage.locator('#tourBackdrop:not(.hidden)').count();
    backdropVisible === 1 ? pass('TC-F-T1: Tour auto-starts after signup') : fail('TC-F-T1: Tour auto-start', 'backdrop not visible');

    const skipHidden = await tourPage.locator('#tourSkip.hidden').count();
    skipHidden === 1 ? pass('TC-F-T2: Skip button hidden on signup tour') : fail('TC-F-T2: Skip hidden', 'skip not hidden');

    const label = await tourPage.$eval('#tourStepLabel', el => el.textContent).catch(() => '');
    label === `Step 1 of ${DESKTOP_TOTAL}` ? pass(`TC-F-T3: Step label "Step 1 of ${DESKTOP_TOTAL}"`) : fail('TC-F-T3: Step label', `Got "${label}"`);

    // TC-F-T4: Navigate steps 1–5 and check each label; then check editorView on step 6
    let allStepsPassed = true;
    for (let i = 1; i <= 5; i++) {
      await tourPage.click('#tourNext');
      await tourPage.waitForTimeout(320);
      const lbl = await tourPage.$eval('#tourStepLabel', el => el.textContent).catch(() => '');
      if (!lbl.startsWith(`Step ${i + 1} of`)) { allStepsPassed = false; }
    }

    // TC-F-T5: After step 6 (first editorView step), editorView should be active
    const editorStepVisible = await tourPage.locator('#editorView:not(.hidden)').count();
    editorStepVisible === 1 ? pass('TC-F-T5: Tour navigates to editorView for editor steps') : fail('TC-F-T5: Editor view during tour', 'editorView not visible');

    // Continue steps 6–11 and verify labels
    for (let i = 6; i < DESKTOP_TOTAL; i++) {
      await tourPage.click('#tourNext');
      await tourPage.waitForTimeout(320);
      const lbl = await tourPage.$eval('#tourStepLabel', el => el.textContent).catch(() => '');
      if (!lbl.startsWith(`Step ${i + 1} of`)) { allStepsPassed = false; }
    }
    allStepsPassed ? pass(`TC-F-T4: All ${DESKTOP_TOTAL} steps navigable`) : fail('TC-F-T4: Steps navigable', 'step label mismatch mid-tour');

    // Click Done on last step
    await tourPage.click('#tourNext');
    await tourPage.waitForTimeout(400);

    // TC-F-T6: Tour ends — backdrop hidden
    const backdropGone = await tourPage.locator('#tourBackdrop.hidden').count();
    backdropGone === 1 ? pass('TC-F-T6: Tour ends after Done') : fail('TC-F-T6: Tour ends', 'backdrop still visible');

    // TC-F-T7: ma_tour_done saved to localStorage after completion
    const stored = await tourPage.evaluate(() => localStorage.getItem('ma_tour_done'));
    stored === '1' ? pass('TC-F-T7: ma_tour_done=1 saved after tour completion') : fail('TC-F-T7: localStorage', `Got "${stored}"`);

    // TC-F-T8: Tour returns to postsView after completion (editor navigated back)
    const postsVisible = await tourPage.locator('#postsView:not(.hidden)').count();
    postsVisible === 1 ? pass('TC-F-T8: postsView restored after tour completes') : fail('TC-F-T8: View after tour', 'postsView not active');

    // TC-F-T9: Product tour item exists in user dropdown
    await tourPage.click('#userMenuButton');
    await tourPage.waitForTimeout(200);
    const tourMenuItem = await tourPage.locator('#tourMenuItem').count();
    tourMenuItem === 1 ? pass('TC-F-T9: "Product tour" item in user dropdown') : fail('TC-F-T9: Tour menu item', 'not found');

    // TC-F-T10: Tour restarted from dropdown has skip button visible
    await tourPage.click('#tourMenuItem');
    await tourPage.waitForTimeout(300);
    const skipVisible = await tourPage.locator('#tourSkip:not(.hidden)').count();
    skipVisible === 1 ? pass('TC-F-T10: Skip button visible when tour triggered from dropdown') : fail('TC-F-T10: Skip from dropdown', 'skip not visible');

    // TC-F-T11: Skip immediately ends tour
    await tourPage.click('#tourSkip');
    await tourPage.waitForTimeout(300);
    const skipped = await tourPage.locator('#tourBackdrop.hidden').count();
    skipped === 1 ? pass('TC-F-T11: Skip button ends tour') : fail('TC-F-T11: Skip ends tour', 'backdrop still visible');

    await tourCtx.close();
  }

  // TC-F-T12: Tour does NOT auto-start on regular signin (only on signup)
  {
    const existingEmail = `noauto_${ts}@x.com`;
    await signUpApi(existingEmail); // create user
    const signinCtx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    const signinPage = await signinCtx.newPage();
    await signinPage.goto(BASE);
    await signinPage.waitForSelector('#authView:not(.hidden)', { timeout: 5000 });
    await signinPage.fill('#signinEmail', existingEmail);
    await signinPage.fill('#signinPassword', 'ValidPass123');
    await signinPage.click('#signinForm button[type="submit"]');
    await signinPage.waitForSelector('#appLayout:not(.hidden)', { timeout: 8000 });
    await signinPage.waitForTimeout(900);
    const backdropVisible = await signinPage.locator('#tourBackdrop:not(.hidden)').count();
    backdropVisible === 0 ? pass('TC-F-T12: Tour does NOT auto-start on regular signin') : fail('TC-F-T12: No auto-start on signin', 'backdrop was shown');
    await signinCtx.close();
  }

  // ════════════════════════════════════════════════
  console.log('\n── PRODUCT TOUR (MOBILE) ──');
  // ════════════════════════════════════════════════

  const MOBILE_TOTAL = 10;

  {
    const mTourEmail = `tour_mob_${ts}@x.com`;
    const mCtx = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const mPage = await mCtx.newPage();
    await mPage.goto(BASE);
    await mPage.waitForSelector('#authView:not(.hidden)', { timeout: 5000 });
    await mPage.click('button[data-auth-mode="signup"]');
    await mPage.fill('#signupFirstName', 'Mobile');
    await mPage.fill('#signupLastName', 'Tour');
    await mPage.fill('#signupEmail', mTourEmail);
    await mPage.fill('#signupPassword', 'ValidPass123');
    await mPage.fill('#signupPasswordAgain', 'ValidPass123');
    await mPage.click('#signupForm button[type="submit"]');
    await mPage.waitForSelector('#appLayout:not(.hidden)', { timeout: 10000 });
    await mPage.waitForTimeout(900);

    // TC-F-T13: Mobile tour auto-starts
    const mBackdrop = await mPage.locator('#tourBackdrop:not(.hidden)').count();
    mBackdrop === 1 ? pass('TC-F-T13: Tour auto-starts on mobile after signup') : fail('TC-F-T13: Mobile tour start', 'backdrop not visible');

    // TC-F-T14: Step label says "Step 1 of 10" on mobile (2 steps skipped)
    const mLabel = await mPage.$eval('#tourStepLabel', el => el.textContent).catch(() => '');
    mLabel === `Step 1 of ${MOBILE_TOTAL}` ? pass(`TC-F-T14: Mobile step label "Step 1 of ${MOBILE_TOTAL}"`) : fail('TC-F-T14: Mobile step count', `Got "${mLabel}"`);

    // TC-F-T15: Navigate all 10 steps, ensure Search & filter and Shortcuts steps are absent
    const titlesShown = [];
    const firstTitle = await mPage.$eval('#tourTitle', el => el.textContent).catch(() => '');
    titlesShown.push(firstTitle);
    for (let i = 1; i < MOBILE_TOTAL; i++) {
      await mPage.click('#tourNext');
      await mPage.waitForTimeout(320);
      const t = await mPage.$eval('#tourTitle', el => el.textContent).catch(() => '');
      titlesShown.push(t);
    }
    // Click Done
    await mPage.click('#tourNext');
    await mPage.waitForTimeout(300);
    const mDone = await mPage.locator('#tourBackdrop.hidden').count();
    const hasSearch = titlesShown.includes('Search & filter');
    const hasShortcuts = titlesShown.includes('Shortcuts & help');
    (!hasSearch && !hasShortcuts) ? pass('TC-F-T15: Mobile tour skips Search & filter and Shortcuts steps') : fail('TC-F-T15: Mobile skips', `search=${hasSearch} shortcuts=${hasShortcuts}`);
    mDone === 1 ? pass('TC-F-T16: Mobile tour completes successfully') : fail('TC-F-T16: Mobile tour complete', 'backdrop still visible');

    await mCtx.close();
  }

  // ════════════════════════════════════════════════
  await browser.close();

  const passed = results.filter(r => r.status === 'PASS').length;
  const failed = results.filter(r => r.status === 'FAIL');
  console.log('\n══════════════════════════════');
  console.log(`  ${passed}/${results.length} feature tests passed`);
  if (failed.length) {
    console.log('\nFailed:');
    failed.forEach(f => console.log(`  ✗ ${f.name}: ${f.reason}`));
  } else {
    console.log('  All feature tests passed! ✓');
  }
  console.log('══════════════════════════════\n');
  process.exit(failed.length ? 1 : 0);
}

runTests().catch(e => { console.error(e); process.exit(1); });
