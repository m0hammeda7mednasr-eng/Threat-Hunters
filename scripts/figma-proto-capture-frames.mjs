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
    'https://embed.figma.com/proto/xMX0emW7NexbXS6JSCoNsd/Final-2.1?content-scaling=fixed&embed-host=oembed&node-id=241%3A1787&scaling=scale-down&theme=light';

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
  await context.addCookies(cookies);

  const page = await context.newPage();
  await page.goto(url, { waitUntil: 'commit', timeout: 60000 });
  await page.waitForTimeout(14000);

  for (let i = 1; i <= 10; i += 1) {
    console.log(`capture frame ${i}`);
    await page.screenshot({ path: `figma-proto-frame-${i}-full.png`, fullPage: true });

    const canvas = page.locator('#viewerContainer canvas').first();
    if (await canvas.count()) {
      await canvas.screenshot({ path: `figma-proto-frame-${i}-canvas.png` });
    }

    if (i < 10) {
      const nextButton = page.getByRole('button', { name: 'Next frame' });
      if (await nextButton.count()) {
        await nextButton.click();
        await page.waitForTimeout(1200);
      } else {
        console.log('next frame button not found');
        break;
      }
    }
  }

  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
