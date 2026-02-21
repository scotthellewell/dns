import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { ApiService, RecursionConfig } from '../services/api.service';

@Component({
  selector: 'app-recursion',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule,
    MatSlideToggleModule,
    MatSelectModule,
    MatSnackBarModule
  ],
  templateUrl: './recursion.component.html',
  styleUrl: './recursion.component.scss'
})
export class RecursionComponent implements OnInit {
  config: RecursionConfig = {
    enabled: false,
    mode: 'partial',
    upstream: [],
    timeout: 5,
    max_depth: 10,
    prefetch: [],
    prefetch_threshold: 2,
    prefetch_window: 0.2,
    stale_enabled: true,
    stale_max_age: 30
  };
  
  modes = [
    { value: 'disabled', label: 'Disabled - No recursion' },
    { value: 'partial', label: 'Partial - Only for local records (CNAME, ALIAS)' },
    { value: 'full', label: 'Full - Open resolver (use with caution)' }
  ];
  
  defaultPrefetchDomains = [
    'google.com', 'www.google.com', 'googleapis.com', 'youtube.com',
    'microsoft.com', 'login.microsoftonline.com', 'azure.com',
    'amazon.com', 'amazonaws.com', 'apple.com', 'icloud.com',
    'facebook.com', 'instagram.com', 'cloudflare.com', 'github.com'
  ];
  
  newUpstream = '';
  newPrefetchDomain = '';
  
  loading = false;
  saving = false;

  constructor(
    private api: ApiService,
    private snackBar: MatSnackBar,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.loadConfig();
  }

  loadConfig() {
    this.loading = true;
    this.api.getRecursionConfig().subscribe({
      next: (config) => {
        this.config = config || {
          enabled: false,
          mode: 'partial',
          upstream: [],
          timeout: 5,
          max_depth: 10,
          prefetch: [],
          prefetch_threshold: 2,
          prefetch_window: 0.2,
          stale_enabled: true,
          stale_max_age: 30
        };
        // Ensure arrays are always defined
        if (!this.config.upstream) {
          this.config.upstream = [];
        }
        if (!this.config.prefetch) {
          this.config.prefetch = [];
        }
        // Set defaults for new fields if not present
        if (this.config.prefetch_threshold === undefined) {
          this.config.prefetch_threshold = 2;
        }
        if (this.config.prefetch_window === undefined) {
          this.config.prefetch_window = 0.2;
        }
        if (this.config.stale_enabled === undefined) {
          this.config.stale_enabled = true;
        }
        if (this.config.stale_max_age === undefined) {
          this.config.stale_max_age = 30;
        }
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to load recursion config', 'Close', { duration: 3000 });
        console.error(err);
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  saveConfig() {
    this.saving = true;
    // Set enabled based on mode
    this.config.enabled = this.config.mode !== 'disabled';
    this.api.updateRecursionConfig(this.config).subscribe({
      next: () => {
        this.snackBar.open('Recursion settings saved', 'Close', { duration: 3000 });
        this.saving = false;
      },
      error: (err) => {
        this.snackBar.open('Failed to save settings', 'Close', { duration: 3000 });
        console.error(err);
        this.saving = false;
      }
    });
  }

  addUpstream() {
    if (this.newUpstream && !this.config.upstream!.includes(this.newUpstream)) {
      this.config.upstream!.push(this.newUpstream);
      this.newUpstream = '';
    }
  }

  removeUpstream(server: string) {
    this.config.upstream = this.config.upstream!.filter(s => s !== server);
  }

  addPrefetchDomain() {
    if (this.newPrefetchDomain && !this.config.prefetch!.includes(this.newPrefetchDomain)) {
      this.config.prefetch!.push(this.newPrefetchDomain);
      this.newPrefetchDomain = '';
    }
  }

  removePrefetchDomain(domain: string) {
    this.config.prefetch = this.config.prefetch!.filter(d => d !== domain);
  }

  useDefaultPrefetch() {
    this.config.prefetch = [...this.defaultPrefetchDomains];
  }

  clearPrefetch() {
    this.config.prefetch = [];
  }
}
