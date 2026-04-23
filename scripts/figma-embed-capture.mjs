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
  const url =
    process.argv[2] ||
    'https://embed.figma.com/file/xMX0emW7NexbXS6JSCoNsd/Final-2.1?embed-host=oembed&kind=file&node-id=241%3A1787&page-selector=1&theme=light&version=2&viewer=1';
  const prefix = process.argv[3] || 'figma-embed-node';

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
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
  cookies.push({
    name: '__Host-figma.authn-state',
    value: '1',
    domain: 'embed.figma.com',
    path: '/',
    secure: true,
    httpOnly: false,
    sameSite: 'Lax',
  });

  await context.addCookies(cookies);
  const page = await context.newPage();

  page.on('response', (response) => {
    const u = response.url();
    if (u.includes('/api/') || u.includes('/multiplayer/')) {
      console.log('response', response.status(), u.slice(0, 150));
    }
  });

  console.log('goto-start');
  await page.goto(url, { waitUntil: 'commit', timeout: 60000 });
  console.log('goto-commit');
  await page.waitForTimeout(3000);
  await page.screenshot({ path: `${prefix}-commit.png`, fullPage: true });

  await page.waitForTimeout(12000);
  console.log('after-wait');
  await page.screenshot({ path: `${prefix}-loaded.png`, fullPage: true });
  fs.writeFileSync(`${prefix}-loaded.html`, await page.content());

  await browser.close();
  console.log('done');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
