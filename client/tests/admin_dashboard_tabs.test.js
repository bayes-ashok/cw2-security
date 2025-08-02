import { test, expect } from '@playwright/test';

test('Admin should be able to switch between tabs in the Instructor Dashboard', async ({ page }) => {
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

  // **Step 3: Verify Dashboard Tab is Active**
  console.log("🔍 Checking if Dashboard Tab is active...");
  await expect(page.locator('text=Instructor Panel')).toBeVisible();
  console.log("✅ Dashboard tab is active!");

  // **Step 4: Switch to Courses Tab (Fixed)**
  console.log("🔄 Switching to Courses tab...");
  await page.click('button:has-text("Courses")');

  // **Wait for API & UI to Load**
  console.log("🔄 Waiting for Courses tab content...");
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(2000); // Allow UI animations

  // **Check for a Reliable Element (Create Course Button)**
  if (await page.locator('text=Create New Course').isVisible()) {
    console.log("✅ Courses tab loaded successfully!");
  } else if (await page.locator('text=No courses found').isVisible()) {
    console.log("⚠️ No courses found, but tab switched successfully.");
  } else {
    throw new Error("❌ Courses tab did not load properly!");
  }


  // **Step 5: Switch Back to Dashboard Tab**
  console.log("🔄 Switching back to Dashboard tab...");
  await page.click('button:has-text("Dashboard")');
  await page.waitForTimeout(2000);
  await expect(page.locator('text=Instructor Panel')).toBeVisible();
  console.log("✅ Successfully switched back to Dashboard tab!");

  console.log("✅ Instructor Dashboard Tab Switching Test Passed!");
});
