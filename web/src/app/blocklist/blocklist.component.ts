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
import { MatTableModule } from '@angular/material/table';
import { MatChipsModule } from '@angular/material/chips';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatDividerModule } from '@angular/material/divider';
import { ApiService, BlocklistConfig, BlocklistSource, BlocklistStats } from '../services/api.service';

@Component({
  selector: 'app-blocklist',
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
    MatSnackBarModule,
    MatTableModule,
    MatChipsModule,
    MatProgressSpinnerModule,
    MatTooltipModule,
    MatExpansionModule,
    MatDividerModule
  ],
  templateUrl: './blocklist.component.html',
  styleUrl: './blocklist.component.scss'
})
export class BlocklistComponent implements OnInit {
  config: BlocklistConfig = {
    enabled: false,
    response: 'nxdomain',
    log_blocked: true
  };

  sources: BlocklistSource[] = [];
  whitelist: string[] = [];
  stats: BlocklistStats | null = null;

  responseTypes = [
    { value: 'nxdomain', label: 'NXDOMAIN - Domain does not exist', icon: 'block' },
    { value: 'zero', label: 'Zero IP - Return 0.0.0.0/::' , icon: 'not_interested' },
    { value: 'redirect', label: 'Redirect - Custom IP address', icon: 'directions' }
  ];

  // New source form
  newSource = {
    name: '',
    url: '',
    format: 'domains',
    update_minutes: 720
  };

  newWhitelistDomain = '';
  testDomain = '';
  testResult: { domain: string; blocked: boolean; source?: string } | null = null;

  loading = false;
  saving = false;
  refreshingSource: string | null = null;

  displayedColumns = ['enabled', 'name', 'format', 'entries', 'lastUpdate', 'status', 'actions'];

  constructor(
    private api: ApiService,
    private snackBar: MatSnackBar,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.loadAll();
  }

  loadAll() {
    this.loading = true;
    
    // Load config
    this.api.getBlocklistConfig().subscribe({
      next: (config) => {
        this.config = config || {
          enabled: false,
          response: 'nxdomain',
          log_blocked: true
        };
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error('Failed to load blocklist config', err);
      }
    });

    // Load sources
    this.api.getBlocklistSources().subscribe({
      next: (sources) => {
        this.sources = sources || [];
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error('Failed to load blocklist sources', err);
        this.loading = false;
        this.cdr.detectChanges();
      }
    });

    // Load whitelist
    this.api.getBlocklistWhitelist().subscribe({
      next: (whitelist) => {
        this.whitelist = whitelist || [];
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error('Failed to load whitelist', err);
      }
    });

    // Load stats
    this.api.getBlocklistStats().subscribe({
      next: (stats) => {
        this.stats = stats;
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error('Failed to load stats', err);
      }
    });
  }

  saveConfig() {
    this.saving = true;
    this.api.updateBlocklistConfig(this.config).subscribe({
      next: () => {
        this.snackBar.open('Blocklist settings saved', 'Close', { duration: 3000 });
        this.saving = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to save settings: ' + (err.error?.error || err.message), 'Close', { duration: 5000 });
        this.saving = false;
        this.cdr.detectChanges();
      }
    });
  }

  toggleSource(source: BlocklistSource) {
    this.api.updateBlocklistSource(source.id, { enabled: !source.enabled }).subscribe({
      next: () => {
        source.enabled = !source.enabled;
        this.snackBar.open(`Source ${source.enabled ? 'enabled' : 'disabled'}`, 'Close', { duration: 2000 });
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to update source', 'Close', { duration: 3000 });
      }
    });
  }

  refreshSource(source: BlocklistSource) {
    this.refreshingSource = source.id;
    this.api.refreshBlocklistSource(source.id).subscribe({
      next: () => {
        this.snackBar.open('Source refresh started', 'Close', { duration: 2000 });
        this.refreshingSource = null;
        // Reload sources after a short delay
        setTimeout(() => this.loadAll(), 2000);
      },
      error: (err) => {
        this.snackBar.open('Failed to refresh source: ' + (err.error?.error || err.message), 'Close', { duration: 5000 });
        this.refreshingSource = null;
        this.cdr.detectChanges();
      }
    });
  }

  deleteSource(source: BlocklistSource) {
    if (!confirm(`Delete source "${source.name}"?`)) return;
    
    this.api.deleteBlocklistSource(source.id).subscribe({
      next: () => {
        this.sources = this.sources.filter(s => s.id !== source.id);
        this.snackBar.open('Source deleted', 'Close', { duration: 2000 });
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to delete source', 'Close', { duration: 3000 });
      }
    });
  }

  addSource() {
    if (!this.newSource.name || !this.newSource.url) {
      this.snackBar.open('Name and URL are required', 'Close', { duration: 3000 });
      return;
    }

    this.api.addBlocklistSource(this.newSource).subscribe({
      next: (source) => {
        this.sources.push(source);
        this.snackBar.open('Source added', 'Close', { duration: 2000 });
        this.newSource = { name: '', url: '', format: 'domains', update_minutes: 720 };
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to add source: ' + (err.error?.error || err.message), 'Close', { duration: 5000 });
      }
    });
  }

  addWhitelist() {
    if (!this.newWhitelistDomain) return;
    
    this.api.addBlocklistWhitelist(this.newWhitelistDomain).subscribe({
      next: () => {
        this.whitelist.push(this.newWhitelistDomain);
        this.snackBar.open('Domain whitelisted', 'Close', { duration: 2000 });
        this.newWhitelistDomain = '';
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to add to whitelist', 'Close', { duration: 3000 });
      }
    });
  }

  removeWhitelist(domain: string) {
    this.api.removeBlocklistWhitelist(domain).subscribe({
      next: () => {
        this.whitelist = this.whitelist.filter(d => d !== domain);
        this.snackBar.open('Domain removed from whitelist', 'Close', { duration: 2000 });
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to remove from whitelist', 'Close', { duration: 3000 });
      }
    });
  }

  testBlocklist() {
    if (!this.testDomain) return;
    
    this.api.testBlocklistDomain(this.testDomain).subscribe({
      next: (result) => {
        this.testResult = result;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to test domain', 'Close', { duration: 3000 });
      }
    });
  }

  formatUpdateInterval(minutes: number): string {
    if (minutes < 60) return `${minutes} min`;
    if (minutes < 1440) return `${Math.round(minutes / 60)} hours`;
    return `${Math.round(minutes / 1440)} days`;
  }

  formatEntryCount(count: number): string {
    if (count >= 1000000) return `${(count / 1000000).toFixed(1)}M`;
    if (count >= 1000) return `${(count / 1000).toFixed(0)}K`;
    return count.toString();
  }

  getSourceStatusIcon(source: BlocklistSource): string {
    if (source.last_error) return 'error';
    if (source.entry_count > 0) return 'check_circle';
    return 'schedule';
  }

  getSourceStatusColor(source: BlocklistSource): string {
    if (source.last_error) return 'warn';
    if (source.entry_count > 0) return 'primary';
    return '';
  }
}
