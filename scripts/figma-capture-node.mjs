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

async function capture(page, label, url) {
  console.log(`capturing ${label}...`);
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 90000 });
  await page.waitForTimeout(8000);
  await page.screenshot({ path: `figma-${label}-initial.png`, fullPage: true });

  await page.mouse.click(960, 540);
  await page.keyboard.press('Shift+2').catch(() => {});
  await page.waitForTimeout(2500);
  await page.screenshot({ path: `figma-${label}-shift2.png`, fullPage: true });

  await page.keyboard.press('Shift+1').catch(() => {});
  await page.waitForTimeout(2500);
  await page.screenshot({ path: `figma-${label}-shift1.png`, fullPage: true });
}

async function main() {
  const fileKey = 'xMX0emW7NexbXS6JSCoNsd';
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

  const urls = [
    {
      label: 'design-node',
      url: `https://www.figma.com/design/${fileKey}/Final-2.1?node-id=241-1787&m=auto&t=e6SMKs2LJjou8CoE-6`,
    },
    {
      label: 'design-node-pf',
      url: `https://www.figma.com/design/${fileKey}/Final-2.1?node-id=241-1787&p=f&m=auto&t=e6SMKs2LJjou8CoE-6`,
    },
    {
      label: 'file-node',
      url: `https://www.figma.com/file/${fileKey}/Final-2.1?node-id=241-1787`,
    },
  ];

  for (const item of urls) {
    const page = await context.newPage();
    try {
      await capture(page, item.label, item.url);
    } finally {
      await page.close();
    }
  }

  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
