import { chromium } from 'playwright';
import fs from 'node:fs';

function parseNetscapeCookies(path) {
  const text = fs.readFileSync(path, 'utf8');
  return text
    .split(/\r?\n/)
    .filter((line) => line && !line.startsWith('#'))
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

async function zoomAt(page, x, y, iterations, deltaY = -1200) {
  await page.mouse.move(x, y);
  await page.keyboard.down('Control');
  for (let i = 0; i < iterations; i += 1) {
    await page.mouse.wheel(0, deltaY);
    await page.waitForTimeout(280);
  }
  await page.keyboard.up('Control');
}

async function main() {
  const fileKey = 'xMX0emW7NexbXS6JSCoNsd';
  const url = `https://www.figma.com/design/${fileKey}/Final-2.1?node-id=241-1787&m=auto&t=e6SMKs2LJjou8CoE-6`;

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    viewport: { width: 1920, height: 1080 },
  });

  const cookies = parseNetscapeCookies('figma-new-cookies.txt');
  cookies.push({
    name: '__Host-figma.authn-state',
    value: '1',
    domain: 'www.figma.com',
    path: '/',
    secure: true,
    httpOnly: false,
    sameSite: 'Lax',
  });
  await context.addCookies(cookies);

  const page = await context.newPage();
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 90000 });
  await page.waitForTimeout(10000);
  await page.mouse.click(960, 540);
  await page.screenshot({ path: 'figma-wheel-base.png' });

  await zoomAt(page, 1370, 170, 8, -900);
  await page.waitForTimeout(1200);
  await page.screenshot({ path: 'figma-wheel-zoom-desktop-8x.png' });

  await zoomAt(page, 1370, 170, 6, -900);
  await page.waitForTimeout(1200);
  await page.screenshot({ path: 'figma-wheel-zoom-desktop-14x.png' });

  await zoomAt(page, 180, 530, 6, -900);
  await page.waitForTimeout(1200);
  await page.screenshot({ path: 'figma-wheel-zoom-reports-plus6.png' });

  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
