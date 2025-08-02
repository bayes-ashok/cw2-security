import { test, expect } from '@playwright/test';

test('Student Courses Page should display purchased courses correctly', async ({ page }) => {
  console.log("🔄 Navigating to Login Page...");
  await page.goto('http://localhost:5173/auth');

  // Wait for login form
  console.log("🔄 Waiting for login form...");
  await page.waitForSelector('input[type="email"]', { timeout: 5000 });
  await page.waitForSelector('input[type="password"]', { timeout: 5000 });

  console.log("✅ Found email and password fields!");
  await page.fill('input[type="email"]', 'ashoksubsc46@gmail.com');
  await page.fill('input[type="password"]', '1');

  console.log("✅ Filled login credentials!");
  await page.click('button:has-text("Login")');

  // Ensure navigation to home page
  await page.waitForURL('http://localhost:5173/home', { timeout: 10000 });
  console.log("✅ Successfully logged in and redirected to Home Page!");

  // Navigate to Student Courses Page
  await page.goto('http://localhost:5173/student-courses');
  await expect(page).toHaveURL('http://localhost:5173/student-courses');
  console.log("✅ Navigated to Student Courses Page!");

  // Check if course cards exist
  const courseCards = page.locator('.rounded-xl.overflow-hidden.shadow-md.border-gray-300');
  const courseCount = await courseCards.count();
  console.log(`✅ Found ${courseCount} purchased courses.`);

  if (courseCount > 0) {
    console.log("🔍 Checking course details...");

    // Verify course title
    const courseTitle = courseCards.first().locator('h3');
    await expect(courseTitle).toBeVisible();
    console.log(`✅ Course Title: ${await courseTitle.innerText()}`);

    // Verify instructor name
    const instructorName = courseCards.first().locator('p.text-sm');
    await expect(instructorName).toBeVisible();
    console.log(`✅ Instructor Name: ${await instructorName.innerText()}`);

    // Verify course image
    const courseImage = courseCards.first().locator('img');
    await expect(courseImage).toBeVisible();
    console.log(`✅ Course Image is displayed!`);

    // Verify Start Watching Button
    const startWatchingBtn = courseCards.first().locator('button:has-text("Start Watching")');
    await expect(startWatchingBtn).toBeVisible();
    console.log(`✅ "Start Watching" Button Found!`);

    // Click Start Watching Button & Verify Navigation
    console.log("🔄 Clicking 'Start Watching'...");
    await startWatchingBtn.click();

    console.log("🔄 Waiting for URL to change...");
    await expect(page).toHaveURL(/\/course-progress\/\w+/, { timeout: 10000 });
    console.log("✅ Successfully navigated to course progress page!");

  } else {
    console.log("❌ No purchased courses found. Skipping further checks.");
  }
});
