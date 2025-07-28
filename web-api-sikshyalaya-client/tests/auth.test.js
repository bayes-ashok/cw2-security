import { test, expect } from '@playwright/test';

test('User should be able to log in and redirect to home page', async ({ page }) => {
  // Navigate to the auth page
  await page.goto('http://localhost:5173/auth');

  // Wait for email and password fields to be visible
  await page.waitForSelector('input[type="email"]');
  await page.waitForSelector('input[type="password"]');

  // Fill in login details
  await page.fill('input[type="email"]', 'ashoksubsc46@gmail.com');
  await page.fill('input[type="password"]', '1');

  // Click the login button
  await page.click('button:has-text("Login")');

  // Wait for navigation to home page
  await page.waitForURL('http://localhost:5173/home');

  // Verify that we have navigated to the home page
  await expect(page).toHaveURL('http://localhost:5173/home');

  // Use a more specific locator for the heading
  const mainHeading = page.locator('h1', { hasText: 'Crack Loksewa Exams' });
  await expect(mainHeading).toBeVisible();
});
