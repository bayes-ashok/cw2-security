import { test, expect } from '@playwright/test';

test('Courses page should display filters, sorting, and course list', async ({ page }) => {
  // Step 1: Login first
  await page.goto('http://localhost:5173/auth');

  // Wait for login fields
  await page.waitForSelector('input[type="email"]', { timeout: 5000 });
  await page.waitForSelector('input[type="password"]', { timeout: 5000 });

  // Fill in login details
  await page.fill('input[type="email"]', 'ashoksubsc46@gmail.com');
  await page.fill('input[type="password"]', '1');

  // Click login
  await page.click('button:has-text("Login")');

  // Wait for navigation to home page, then go to courses page
  await page.waitForURL('http://localhost:5173/home', { timeout: 5000 });
  await page.goto('http://localhost:5173/courses');

  // Ensure we are on the courses page
  await expect(page).toHaveURL('http://localhost:5173/courses');

  // Wait for filters section to load
  await page.waitForSelector('aside', { timeout: 5000 });

  // Ensure sorting dropdown is present
  await expect(page.locator('button:has-text("Sort By")')).toBeVisible();

  // Wait for course cards to load
  const courseCards = page.locator('.border-gray-300.rounded-lg');
  await courseCards.first().waitFor({ state: 'visible', timeout: 5000 });

  // Ensure courses are displayed
  const courseCount = await courseCards.count();
  console.log(`✅ Found ${courseCount} courses.`);
  expect(courseCount).toBeGreaterThan(0);

  // Ensure "No Courses Found" is NOT visible
  const noCourses = page.locator('h1:has-text("No Courses Found")');
  await expect(noCourses).not.toBeVisible();

  console.log("✅ Courses page UI test passed successfully!");
});
