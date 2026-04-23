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
  await page.keyboard.press('Shift+1').catch(() => {});
  await page.waitForTimeout(2500);
  await page.screenshot({ path: 'figma-candidates-base.png' });

  const candidates = [
    { name: 'reports', x: 110, y: 545 },
    { name: 'homepage-left', x: 260, y: 545 },
    { name: 'signup-left', x: 370, y: 560 },
    { name: 'signin-left', x: 530, y: 520 },
    { name: 'desktop-1', x: 1360, y: 160 },
    { name: 'signup-right', x: 1620, y: 160 },
    { name: 'signin-right', x: 1760, y: 190 },
    { name: 'homepage-right', x: 1635, y: 360 },
    { name: 'signup-right-lower', x: 1780, y: 350 },
    { name: 'securityawareness', x: 390, y: 760 },
  ];

  for (const item of candidates) {
    console.log(`zooming ${item.name}`);
    await page.keyboard.press('Shift+1').catch(() => {});
    await page.waitForTimeout(700);
    await page.mouse.click(item.x, item.y);
    await page.waitForTimeout(500);
    await page.keyboard.press('Shift+2').catch(() => {});
    await page.waitForTimeout(2200);
    await page.screenshot({ path: `figma-zoom-${item.name}.png` });
  }

  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
