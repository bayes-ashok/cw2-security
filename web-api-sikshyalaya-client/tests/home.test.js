import { test, expect } from '@playwright/test';

test('User should be able to log in and verify home page content', async ({ page }) => {
  // Navigate to the auth page
  await page.goto('http://localhost:5173/auth');

  // Wait for the login form elements
  await page.waitForSelector('input[type="email"]');
  await page.waitForSelector('input[type="password"]');

  // Fill in login details
  await page.fill('input[type="email"]', 'ashoksubsc46@gmail.com');
  await page.fill('input[type="password"]', '1');

  // Click the login button
  await page.click('button:has-text("Login")');

  // Wait for navigation to the home page
  await page.waitForURL('http://localhost:5173/home');

  // Verify that we are on the home page
  await expect(page).toHaveURL('http://localhost:5173/home');

  // Verify the main heading exists
  await expect(page.getByRole('heading', { name: /Crack Loksewa Exams/i })).toBeVisible();

  // Verify that the "Course Categories" section is present
  await expect(page.getByRole('heading', { name: /Course Categories/i })).toBeVisible();

  // Verify that the "Featured Courses" section is present
  await expect(page.getByRole('heading', { name: /Featured Courses/i })).toBeVisible();

  // Verify "Explore Courses" button is present
  await expect(page.locator('button:has-text("Explore Courses")')).toBeVisible();

  console.log("✅ Home page test passed successfully!");
});
