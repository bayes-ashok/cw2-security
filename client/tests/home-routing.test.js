import { test, expect } from '@playwright/test';

test('Home page should have navigation for Course Categories and Featured Courses', async ({ page }) => {
  // Step 1: Login first
  await page.goto('http://localhost:5173/auth');

  // Wait for login fields
  await page.waitForSelector('input[type="email"]');
  await page.waitForSelector('input[type="password"]');

  // Fill in login details
  await page.fill('input[type="email"]', 'ashoksubsc46@gmail.com');
  await page.fill('input[type="password"]', '1');

  // Click login
  await page.click('button:has-text("Login")');

  // Wait for navigation to home page
  await page.waitForURL('http://localhost:5173/home');

  // Ensure we are on the home page
  await expect(page).toHaveURL('http://localhost:5173/home');

  // Step 2: Check if course categories exist and navigate correctly
  const categoryButton = page.locator('button[aria-label*="View courses in"]').first();
  await expect(categoryButton).toBeVisible();
  await categoryButton.click();
  await page.waitForTimeout(2000); // Wait for navigation
  await expect(page).not.toHaveURL('http://localhost:5173/home'); // Ensure the page changed

  // Go back to home page
  await page.goto('http://localhost:5173/home');

  // Step 3: Check if featured courses exist and navigate correctly
  const featuredCourse = page.locator('[role="button"][aria-label*="View details for"]').first();
  await expect(featuredCourse).toBeVisible();
  await featuredCourse.click();
  await page.waitForTimeout(2000); // Wait for navigation
  await expect(page).not.toHaveURL('http://localhost:5173/home'); // Ensure the page changed

  console.log("✅ Home page course categories & featured courses navigation test passed!");
});
