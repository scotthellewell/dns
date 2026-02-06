import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class VersionService {
  readonly updateAvailable = signal(false);
  
  private currentVersion: string | null = null;
  private checkInterval: any = null;
  private readonly CHECK_INTERVAL_MS = 60000; // Check every 60 seconds

  constructor(private http: HttpClient) {}

  /**
   * Start checking for updates periodically
   */
  startChecking(): void {
    // Get initial version from the main.js hash in the page
    this.currentVersion = this.getAppVersion();
    
    // Start periodic checks
    this.checkInterval = setInterval(() => {
      this.checkForUpdate();
    }, this.CHECK_INTERVAL_MS);
  }

  /**
   * Stop checking for updates
   */
  stopChecking(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
  }

  /**
   * Get the current app version from script tags
   */
  private getAppVersion(): string {
    // Look for the main-*.js script which has a hash in its filename
    const scripts = document.querySelectorAll('script[src*="main-"]');
    if (scripts.length > 0) {
      const src = scripts[0].getAttribute('src');
      if (src) {
        // Extract hash from filename like "main-ABC123.js"
        const match = src.match(/main-([A-Z0-9]+)\.js/i);
        if (match) {
          return match[1];
        }
      }
    }
    return 'unknown';
  }

  /**
   * Check if a new version is available by fetching index.html
   */
  private checkForUpdate(): void {
    // Fetch index.html with cache-busting
    this.http.get('/index.html', { 
      responseType: 'text',
      headers: { 'Cache-Control': 'no-cache' }
    }).subscribe({
      next: (html) => {
        // Look for main-*.js in the fetched HTML
        const match = html.match(/main-([A-Z0-9]+)\.js/i);
        if (match) {
          const newVersion = match[1];
          if (this.currentVersion && this.currentVersion !== 'unknown' && newVersion !== this.currentVersion) {
            console.log(`New version available: ${newVersion} (current: ${this.currentVersion})`);
            this.updateAvailable.set(true);
            this.stopChecking(); // Stop checking once we know there's an update
          }
        }
      },
      error: () => {
        // Silently ignore errors
      }
    });
  }

  /**
   * Reload the page to get the new version
   */
  reload(): void {
    window.location.reload();
  }
}
