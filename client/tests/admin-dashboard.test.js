import { test, expect } from '@playwright/test';

test('Admin should be able to access and navigate the Instructor Dashboard', async ({ page }) => {
  console.log("🔄 Navigating to Login Page...");
  await page.goto('http://localhost:5173/auth');

  // **Step 1: Login as Admin**
  console.log("🔄 Waiting for login form...");
  await page.waitForSelector('input[type="email"]');
  await page.waitForSelector('input[type="password"]');

  console.log("✅ Found email and password fields!");
  await page.fill('input[type="email"]', 'a@gmail.com');
  await page.fill('input[type="password"]', '1');

  console.log("✅ Clicking login...");
  await page.click('button[type="submit"]');

  // **Step 2: Ensure Successful Login & Redirect**
  console.log("🔄 Waiting for redirect to Instructor Dashboard...");
  await page.waitForURL('http://localhost:5173/instructor', { timeout: 10000 });
  console.log("✅ Successfully redirected to Instructor Dashboard!");

  // **Step 3: Verify UI Elements**
  console.log("🔍 Checking if Instructor Dashboard is loaded...");
  await expect(page.locator('text=Instructor Panel')).toBeVisible();
  console.log("✅ Instructor Panel header is visible!");

  // **Step 4: Verify Sidebar Menu Exists**
  console.log("🔍 Checking sidebar menu options...");
  await expect(page.locator('text=Dashboard')).toBeVisible();
  await expect(page.locator('text=Courses')).toBeVisible();
  await expect(page.locator('text=Quizzes')).toBeVisible();
  await expect(page.locator('text=Logout')).toBeVisible();
  console.log("✅ Sidebar menu options are present!");

  // **Step 5: Verify Logout Button Exists**
  console.log("🔍 Checking if Logout button is present...");
  await expect(page.locator('text=Logout')).toBeVisible();
  console.log("✅ Logout button is present!");

  console.log("✅ Admin Dashboard Test Passed!");
});
