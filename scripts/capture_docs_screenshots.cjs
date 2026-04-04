#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const baseUrl = process.env.GATESCOPE_BASE_URL || 'http://192.168.79.134:8080';
const outputDir = process.env.GATESCOPE_SCREENSHOT_DIR || path.join(process.cwd(), 'docs', 'screenshots');
const username = process.env.GATESCOPE_USERNAME || 'admin';
const password = process.env.GATESCOPE_PASSWORD || 'agentscan';

async function ensureDir(dir) {
  await fs.promises.mkdir(dir, { recursive: true });
}

async function screenshot(page, name) {
  const target = path.join(outputDir, name);
  await page.screenshot({ path: target, fullPage: true });
  console.log(`saved ${target}`);
}

async function main() {
  await ensureDir(outputDir);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1600, height: 1100 },
    ignoreHTTPSErrors: true,
  });
  const page = await context.newPage();

  await page.goto(`${baseUrl}/login`, { waitUntil: 'networkidle', timeout: 30000 });
  await screenshot(page, 'login-current-headless.png');

  await page.getByPlaceholder('用户名').fill(username);
  await page.getByPlaceholder('密码').fill(password);
  await page.getByRole('button', { name: '一键登录' }).click();
  await page.waitForURL(url => !url.pathname.endsWith('/login'), { timeout: 30000 });
  await page.waitForLoadState('networkidle');

  await page.goto(`${baseUrl}/vulnerabilities`, { waitUntil: 'networkidle', timeout: 30000 });
  await screenshot(page, 'vulnerability-center-current.png');

  await page.goto(`${baseUrl}/assets`, { waitUntil: 'networkidle', timeout: 30000 });
  await screenshot(page, 'assets-current.png');

  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
