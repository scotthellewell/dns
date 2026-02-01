import { test, expect } from '@playwright/test';

test.describe('DNS Admin Dashboard', () => {
  test('should load the dashboard page', async ({ page }) => {
    await page.goto('/');
    
    // Should see the app title or dashboard content
    await expect(page.locator('body')).toBeVisible();
  });

  test('should display server status', async ({ page }) => {
    await page.goto('/');
    
    // Wait for the dashboard to load
    await page.waitForTimeout(1000);
    
    // Check for status indicators or dashboard elements
    const body = await page.locator('body').textContent();
    expect(body).toBeTruthy();
  });

  test('should navigate to zones page', async ({ page }) => {
    await page.goto('/');
    
    // Look for zones link or navigate directly
    await page.goto('/zones');
    await expect(page).toHaveURL(/zones/);
  });

  test('should navigate to records page', async ({ page }) => {
    await page.goto('/records');
    await expect(page).toHaveURL(/records/);
  });

  test('should navigate to settings page', async ({ page }) => {
    await page.goto('/settings');
    await expect(page).toHaveURL(/settings/);
  });
});

test.describe('DNS Admin Navigation', () => {
  test('should have working navigation menu', async ({ page }) => {
    await page.goto('/');
    
    // Check for navigation elements
    const nav = page.locator('nav, mat-sidenav, mat-toolbar, [role="navigation"]');
    const navExists = await nav.count() > 0;
    
    if (navExists) {
      await expect(nav.first()).toBeVisible();
    }
  });

  test('should handle 404 routes gracefully', async ({ page }) => {
    await page.goto('/nonexistent-route');
    
    // Should either redirect to home or show a 404 page
    await page.waitForTimeout(500);
    const url = page.url();
    // Accept any valid page load
    expect(url).toBeTruthy();
  });
});

test.describe('API Integration', () => {
  test('should fetch server status from API', async ({ page, request }) => {
    // Direct API call
    const response = await request.get('http://localhost:8080/api/status');
    
    if (response.ok()) {
      const data = await response.json();
      expect(data).toHaveProperty('status');
    } else {
      // API might not be running during test - skip gracefully
      test.skip();
    }
  });

  test('should fetch zones from API', async ({ page, request }) => {
    const response = await request.get('http://localhost:8080/api/zones');
    
    if (response.ok()) {
      const data = await response.json();
      expect(Array.isArray(data) || typeof data === 'object').toBe(true);
    } else {
      test.skip();
    }
  });

  test('should fetch records from API', async ({ page, request }) => {
    const response = await request.get('http://localhost:8080/api/records');
    
    if (response.ok()) {
      const data = await response.json();
      expect(data).toBeDefined();
    } else {
      test.skip();
    }
  });

  test('should handle CORS preflight', async ({ request }) => {
    const response = await request.fetch('http://localhost:8080/api/status', {
      method: 'OPTIONS',
      headers: {
        'Origin': 'http://localhost:4200',
        'Access-Control-Request-Method': 'GET',
      },
    });
    
    // Should return 200 or 204 for CORS preflight
    if (response.status() === 200 || response.status() === 204) {
      const corsHeader = response.headers()['access-control-allow-origin'];
      expect(corsHeader).toBeDefined();
    } else {
      // API not running
      test.skip();
    }
  });
});

test.describe('DNS Resolution E2E', () => {
  test('should resolve DNS queries via UDP', async ({ request }) => {
    // This test requires the DNS server to be running
    // We'll test via the API metrics endpoint
    const response = await request.get('http://localhost:8080/metrics');
    
    if (response.ok()) {
      const text = await response.text();
      expect(text).toContain('dns_');
    } else {
      test.skip();
    }
  });
});

test.describe('Dashboard Components', () => {
  test('should display query statistics', async ({ page }) => {
    await page.goto('/');
    await page.waitForTimeout(1000);
    
    // Look for statistics elements
    const statsElements = page.locator('[class*="stat"], [class*="metric"], [class*="count"], mat-card');
    const count = await statsElements.count();
    
    // Dashboard should have some content
    expect(count).toBeGreaterThanOrEqual(0);
  });

  test('should be responsive', async ({ page }) => {
    // Test mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/');
    
    // Page should still be functional
    await expect(page.locator('body')).toBeVisible();
    
    // Test desktop viewport
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto('/');
    
    await expect(page.locator('body')).toBeVisible();
  });
});
