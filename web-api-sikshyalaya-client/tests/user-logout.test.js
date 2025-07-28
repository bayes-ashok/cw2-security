import { test, expect } from '@playwright/test';

test('User should be able to logout successfully', async ({ page }) => {
  console.log("🔄 Navigating to Login Page...");
  await page.goto('http://localhost:5173/auth');

  // **Step 1: Login as User**
  console.log("🔄 Waiting for login form...");
  await page.waitForSelector('input[type="email"]');
  await page.waitForSelector('input[type="password"]');

  console.log("✅ Found email and password fields!");
  await page.fill('input[type="email"]', 'ashoksubsc46@gmail.com');
  await page.fill('input[type="password"]', '1');

  console.log("✅ Clicking login...");
  await page.click('button[type="submit"]');

  // **Step 2: Ensure Successful Login & Redirect**
  console.log("🔄 Waiting for redirect to Home Page...");
  await page.waitForURL('http://localhost:5173/home', { timeout: 10000 });
  console.log("✅ Successfully redirected to User Home Page!");

  // **Step 3: Click Logout Button**
  console.log("🔄 Clicking Logout button...");
  await page.click('button:has-text("Logout")');

  // **Step 4: Verify Redirect to Login Page**
  console.log("🔄 Waiting for redirect to Login Page...");
  await page.waitForURL('http://localhost:5173/auth', { timeout: 10000 });
  console.log("✅ Successfully logged out and redirected to Login Page!");

  // **Step 5: Ensure User is Logged Out (No Home Button)**
  await expect(page.locator('button:has-text("Logout")')).not.toBeVisible();
  console.log("✅ Logout button is no longer visible, user is logged out!");

  console.log("🎉 Test Passed: User successfully logged out!");
});
