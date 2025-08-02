import { test, expect } from '@playwright/test';

test('Admin should be able to access the Create New Course page and verify its elements', async ({ page }) => {
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

  // **Step 3: Switch to Courses Tab**
  console.log("🔄 Switching to Courses tab...");
  await page.click('button:has-text("Courses")');

  // **Wait for API & UI to Load**
  console.log("🔄 Waiting for Courses tab content...");
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(2000);

  // **Check if "Create New Course" Button Exists**
  const createCourseButton = page.locator('button:has-text("Create New Course")');
  await expect(createCourseButton).toBeVisible();
  console.log("✅ Create New Course button is visible!");

  // **Step 4: Click "Create New Course"**
  console.log("🔄 Clicking Create New Course...");
  await createCourseButton.click();

  // **Step 5: Verify Navigation to Create Course Page**
  console.log("🔄 Waiting for navigation to Create Course page...");
  await page.waitForURL('http://localhost:5173/instructor/create-new-course', { timeout: 10000 });
  console.log("✅ Successfully navigated to Create New Course page!");

  // **Step 6: Verify Page Elements**
  await expect(page.locator('h1:has-text("Create a New Course")')).toBeVisible();
  console.log("✅ 'Create a New Course' heading is visible!");

  await expect(page.locator('button:has-text("SUBMIT")')).toBeVisible();
  console.log("✅ Submit button is visible!");

  await expect(page.locator('button:has-text("SUBMIT")')).toBeDisabled();
  console.log("✅ Submit button is initially disabled!");

  // **Step 7: Verify Tabs Exist**
  await expect(page.locator('button:has-text("Curriculum")')).toBeVisible();
  await expect(page.locator('button:has-text("Course Landing Page")')).toBeVisible();
  await expect(page.locator('button:has-text("Settings")')).toBeVisible();
  console.log("✅ All required tabs are visible!");

  console.log("🎉 Test Passed: Admin can access and verify the Create New Course page!");
});
