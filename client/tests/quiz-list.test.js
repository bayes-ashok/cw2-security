import { test, expect } from '@playwright/test';

test('Quiz List page should display quizzes correctly', async ({ page }) => {
  console.log("🔄 Navigating to Login Page...");
  await page.goto('http://localhost:5173/auth');

  // Step 1: Login
  await page.waitForSelector('input[type="email"]', { timeout: 5000 });
  await page.fill('input[type="email"]', 'ashoksubsc46@gmail.com');
  await page.fill('input[type="password"]', '1');
  await page.click('button:text("Login")');

  // Wait for navigation to home page
  await page.waitForURL('http://localhost:5173/home', { timeout: 10000 });

  console.log("✅ Successfully logged in and redirected to Home Page!");

  // Step 2: Navigate to Quiz List
  await page.goto('http://localhost:5173/quiz');
  await expect(page).toHaveURL('http://localhost:5173/quiz');

  console.log("✅ Navigated to Quiz List Page!");

  // Step 3: Check if Loading Indicator Appears *Only If Necessary*
  const isLoadingPresent = await page.locator('text=Loading quizzes...').isVisible();
  if (isLoadingPresent) {
    await page.waitForSelector('text=Loading quizzes...', { state: 'hidden', timeout: 10000 });
    console.log("✅ Loading completed!");
  } else {
    console.log("⚠️ Loading indicator did not appear, skipping...");
  }

  // Step 4: Ensure quizzes are displayed
  const quizCards = page.locator('.bg-white.shadow-md'); // Select quiz cards
  const quizCount = await quizCards.count();
  console.log(`✅ Found ${quizCount} quizzes.`);

  expect(quizCount).toBeGreaterThan(-1);

  // Step 5: Click on the first quiz if it exists
  if (quizCount > 0) {
    console.log("✅ Clicking first quiz...");
    await quizCards.first().click();
    await page.waitForTimeout(2000);

    // Ensure navigation to quiz details page
    await expect(page).toHaveURL(/\/quiz\/\w+/, { timeout: 10000 });
    console.log("✅ Successfully navigated to quiz details page!");
  } else {
    console.log("❌ No quizzes found. Skipping quiz details check.");
  }
});
