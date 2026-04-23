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
  const url = `https://www.figma.com/design/${fileKey}/Final-2.1?m=auto&t=e6SMKs2LJjou8CoE-6`;

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1366, height: 900 },
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
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
  await page.waitForTimeout(12000);
  await page.keyboard.press('v').catch(() => {});
  await page.waitForTimeout(700);

  const picks = [
    { name: 'reports', x: 64, y: 398 },
    { name: 'home-left', x: 157, y: 398 },
    { name: 'signup-left', x: 253, y: 397 },
    { name: 'signin-left', x: 368, y: 397 },
    { name: 'security-awareness', x: 285, y: 571 },
    { name: 'desktop-1', x: 1015, y: 196 },
    { name: 'signup-right', x: 1146, y: 200 },
    { name: 'signin-right', x: 1256, y: 214 },
    { name: 'homepage-right', x: 1164, y: 325 },
    { name: 'signup-right-lower', x: 1268, y: 312 },
  ];

  const results = [];

  for (const item of picks) {
    await page.mouse.click(item.x, item.y, { delay: 80 });
    await page.waitForTimeout(1300);
    const current = page.url();
    console.log(item.name, current);
    results.push({ ...item, url: current });
  }

  fs.writeFileSync('figma-click-node-ids.json', JSON.stringify(results, null, 2));
  await page.screenshot({ path: 'figma-click-node-ids-final.png' });
  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
