import { test, expect } from '@playwright/test';

test('Course Details Page should display correct course information', async ({ page }) => {
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

  // Navigate to Courses Page
  await page.goto('http://localhost:5173/courses');
  await expect(page).toHaveURL('http://localhost:5173/courses');
  console.log("✅ Navigated to Courses Page!");

  // Check if course cards exist
  const courseCards = page.locator('.cursor-pointer.border-gray-300.rounded-lg');
  const courseCount = await courseCards.count();
  console.log(`✅ Found ${courseCount} courses.`);

  if (courseCount > 0) {
    console.log("✅ Clicking the first course...");
    
    // Click on the first course card
    await courseCards.first().click({ force: true });

    console.log("🔄 Waiting for URL to change...");
    await page.waitForTimeout(2000);

    // Verify navigation to either /course/details/:id OR /course-progress/:id
    await expect(page).toHaveURL(/\/course\/(details|progress)\/\w+/, { timeout: 10000 });
    console.log("✅ Successfully navigated to the correct course page!");

    // ✅ Check if essential course details are displayed
    console.log("🔍 Verifying course details...");
    
    // Course Title
    const courseTitle = page.locator('h1');
    await expect(courseTitle).toBeVisible();
    console.log(`✅ Course Title: ${await courseTitle.innerText()}`);

    // Instructor Name
    const instructorName = page.locator('span:has-text("Created By")');
    await expect(instructorName).toBeVisible();
    console.log(`✅ Instructor Name: ${await instructorName.innerText()}`);

    // Language
    const language = page.locator('.flex.items-center span:has-text("Created On") + span');
    await expect(language).toBeVisible();
    console.log(`✅ Course Language: ${await language.innerText()}`);

    // Pricing
    const price = page.locator('span.text-3xl.font-bold');
    await expect(price).toBeVisible();
    console.log(`✅ Course Price: ${await price.innerText()}`);

  } else {
    console.log("❌ No courses found. Skipping course details test.");
  }
});
