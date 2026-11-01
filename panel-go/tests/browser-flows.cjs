const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const backend = process.env.FLUX_BROWSER_BACKEND;
const oracle = process.env.FLUX_BROWSER_ORACLE;
const output = process.env.FLUX_BROWSER_EVIDENCE || '/tmp/flux-browser-evidence';
fs.mkdirSync(output, { recursive: true });

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    const management = await browser.newContext();
    const api = async (p, data, token) => {
      const response = await management.request.post(backend + '/api/v1/' + p, {
        data, headers: token ? { Authorization: token } : {},
      });
      const value = await response.json();
      if (value.code !== 0) throw new Error(p + ': ' + value.code + ' ' + value.msg);
      return value.data;
    };
    const login = await api('user/login', { username: 'browser_用户~?', password: 'browser-password' });
    const token = login.token;
    await api('user/package', {}, token);
    const failures = [];
    const newPage = async () => {
      const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
      await context.route('**/*', route => {
        const u = new URL(route.request().url());
        if (['127.0.0.1', 'localhost'].includes(u.hostname) || ['data:', 'blob:'].includes(u.protocol)) return route.continue();
        return route.abort();
      });
      const page = await context.newPage();
      page.on('pageerror', e => failures.push(e.message));
      return { context, page };
    };
    const enterCredentials = async page => {
      await page.goto('http://127.0.0.1:13000/', { waitUntil: 'networkidle' });
      await page.getByPlaceholder('请输入用户名').fill('browser_用户~?');
      await page.getByPlaceholder('请输入密码').fill('browser-password');
    };
    for (const kind of ['SLIDER', 'ROTATE', 'CONCAT', 'WORD_IMAGE_CLICK']) {
      await api('config/update', { captcha_enabled: 'true', captcha_type: kind }, token);
      const { context, page } = await newPage();
      await enterCredentials(page);
      const generatedResponse = page.waitForResponse(r => r.url().endsWith('/api/v1/captcha/generate'));
      await page.getByRole('button', { name: '登录', exact: true }).click();
      const generated = await (await generatedResponse).json();
      await page.locator('#tianai-captcha').waitFor({ state: 'visible' });
      await page.waitForTimeout(600);
      await page.screenshot({ path: path.join(output, 'captcha-' + kind + '.png') });
      const expected = JSON.parse(fs.readFileSync(oracle, 'utf8'))[generated.id];
      if (!expected || expected.kind !== kind) throw new Error('private test oracle unavailable');
      const verification = page.waitForResponse(r => r.url().endsWith('/api/v1/captcha/verify'));
      if (kind === 'WORD_IMAGE_CLICK') {
        const box = await page.locator('#bg-img-click-mask').boundingBox();
        for (const point of expected.points) {
          await page.mouse.click(box.x + point.X * box.width / 300, box.y + point.Y * box.height / 180);
          await page.waitForTimeout(200);
        }
      } else {
        const box = await page.locator('#tianai-captcha-slider-move-btn').boundingBox();
        const distance = kind === 'ROTATE' ? expected.x * 242 / 360 : expected.x;
        await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
        await page.mouse.down();
        for (let i = 1; i <= 25; i++) {
          await page.mouse.move(box.x + box.width / 2 + distance * i / 25, box.y + box.height / 2);
          await page.waitForTimeout(12);
        }
        await page.mouse.up();
      }
      const result = await (await verification).json();
      if (result.code !== 200) throw new Error(kind + ' real TAC interaction rejected: ' + result.code);
      await page.waitForURL('**/dashboard', { timeout: 15000 });
      await page.waitForLoadState('networkidle');
      console.log('PASS real existing TAC ' + kind + ' → verified login → dashboard');
      await context.close();
    }
    await api('config/update', { captcha_enabled: 'false' }, token);
    const { context, page } = await newPage();
    await enterCredentials(page);
    await page.getByRole('button', { name: '登录', exact: true }).click();
    await page.waitForURL('**/dashboard');
    for (const route of ['dashboard', 'node', 'tunnel', 'forward', 'user', 'limit', 'config', 'profile']) {
      await page.goto('http://127.0.0.1:13000/' + route, { waitUntil: 'networkidle' });
      if (new URL(page.url()).pathname !== '/' + route) throw new Error('unexpected route ' + page.url());
      await page.screenshot({ path: path.join(output, 'page-' + route + '.png') });
      console.log('PASS existing frontend ' + route + ' with real Go API');
    }
    await context.close();
    if (failures.length) throw new Error('browser errors: ' + failures.join('; '));
    fs.writeFileSync(path.join(output, 'result.json'), JSON.stringify({
      success: true, captchaModes: 4, pages: 8,
      network: 'loopback only; external browser requests blocked',
      privateTestOracle: 'test binary only; not compiled into product',
    }, null, 2));
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exit(1); });
