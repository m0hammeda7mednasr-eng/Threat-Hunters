import { chromium } from 'playwright';
import fs from 'node:fs';

function parseNetscapeCookies(path) {
  const text = fs.readFileSync(path, 'utf8');
  const lines = text.split(/\r?\n/).filter((line) => line && !line.startsWith('#'));

  return lines
    .map((line) => {
      const [domain, _includeSubdomains, cookiePath, secure, expires, name, value] = line.split('\t');
      return {
        name,
        value,
        domain: domain.replace(/^#HttpOnly_/, ''),
        path: cookiePath,
        expires: Number(expires),
        secure: secure === 'TRUE',
        httpOnly: false,
        sameSite: 'Lax',
      };
    })
    .filter((cookie) => cookie.name && cookie.value);
}

async function main() {
  const fileKey = 'xMX0emW7NexbXS6JSCoNsd';
  const endpoint = `https://www.figma.com/api/user/state?file_key=${fileKey}`;

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    viewport: { width: 1366, height: 900 },
  });

  const browserCookies = parseNetscapeCookies('figma-new-cookies.txt');
  browserCookies.push({
    name: '__Host-figma.authn-state',
    value: '1',
    domain: 'www.figma.com',
    path: '/',
    secure: true,
    httpOnly: false,
    sameSite: 'Lax',
  });
  await context.addCookies(browserCookies);

  const page = await context.newPage();

  page.on('response', async (response) => {
    if (response.url().includes('/api/user/state?file_key=')) {
      console.log('STATE_RESPONSE', response.status());
    }
  });

  await page.goto(`https://www.figma.com/file/${fileKey}/Final-2.1?node-id=241-1787`, {
    waitUntil: 'domcontentloaded',
    timeout: 60000,
  });

  await page.waitForTimeout(6000);

  const result = await page.evaluate(async (url) => {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 15000);
    try {
      const resp = await fetch(url, { credentials: 'include', signal: controller.signal });
      const text = await resp.text();
      return { status: resp.status, head: text.slice(0, 300), length: text.length };
    } catch (error) {
      return { error: String(error) };
    } finally {
      clearTimeout(id);
    }
  }, endpoint);

  fs.writeFileSync('figma-user-state-browser.json', JSON.stringify(result, null, 2));
  fs.writeFileSync('figma-browser-page.html', await page.content());
  await page.screenshot({ path: 'figma-browser-page.png' });

  await browser.close();
  console.log('done');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
