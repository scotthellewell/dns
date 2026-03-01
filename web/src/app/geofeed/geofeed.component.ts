import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatDividerModule } from '@angular/material/divider';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatTableModule } from '@angular/material/table';
import { MatDialogModule } from '@angular/material/dialog';
import { ApiService, GeoEntry } from '../services/api.service';
import { Clipboard, ClipboardModule } from '@angular/cdk/clipboard';

@Component({
  selector: 'app-geofeed',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatSlideToggleModule,
    MatIconModule,
    MatSnackBarModule,
    MatProgressSpinnerModule,
    MatDividerModule,
    MatTooltipModule,
    MatTableModule,
    MatDialogModule,
    ClipboardModule
  ],
  templateUrl: './geofeed.component.html',
  styleUrls: ['./geofeed.component.scss']
})
export class GeofeedComponent implements OnInit {
  loading = true;
  entries: GeoEntry[] = [];
  displayedColumns = ['prefix', 'country', 'region', 'city', 'postal_code', 'enabled', 'actions'];

  // New entry form
  showAddForm = false;
  newEntry: Partial<GeoEntry> = {
    prefix: '',
    country: '',
    region: '',
    city: '',
    postal_code: '',
    enabled: true
  };

  // Edit state
  editingId: string | null = null;
  editEntry: Partial<GeoEntry> = {};

  // CSV URL
  csvUrl = '';

  constructor(
    private api: ApiService,
    private snackBar: MatSnackBar,
    private clipboard: Clipboard,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void {
    this.csvUrl = this.api.getGeofeedCSVUrl();
    this.loadEntries();
  }

  loadEntries(): void {
    this.loading = true;
    this.api.getGeofeedEntries().subscribe({
      next: (entries) => {
        this.entries = entries || [];
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to load geofeed entries: ' + (err.error?.error || err.message), 'Dismiss', { duration: 5000 });
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  addEntry(): void {
    if (!this.newEntry.prefix || !this.newEntry.country) {
      this.snackBar.open('Prefix and country code are required', 'Dismiss', { duration: 3000 });
      return;
    }

    this.api.createGeofeedEntry(this.newEntry).subscribe({
      next: () => {
        this.snackBar.open('Geofeed entry created', 'Dismiss', { duration: 3000 });
        this.showAddForm = false;
        this.resetNewEntry();
        this.loadEntries();
      },
      error: (err) => {
        this.snackBar.open('Failed to create entry: ' + (err.error?.error || err.message), 'Dismiss', { duration: 5000 });
      }
    });
  }

  startEdit(entry: GeoEntry): void {
    this.editingId = entry.id;
    this.editEntry = { ...entry };
  }

  cancelEdit(): void {
    this.editingId = null;
    this.editEntry = {};
  }

  saveEdit(): void {
    if (!this.editingId) return;

    this.api.updateGeofeedEntry(this.editingId, this.editEntry).subscribe({
      next: () => {
        this.snackBar.open('Geofeed entry updated', 'Dismiss', { duration: 3000 });
        this.editingId = null;
        this.editEntry = {};
        this.loadEntries();
      },
      error: (err) => {
        this.snackBar.open('Failed to update entry: ' + (err.error?.error || err.message), 'Dismiss', { duration: 5000 });
      }
    });
  }

  deleteEntry(entry: GeoEntry): void {
    if (!confirm(`Delete geofeed entry for ${entry.prefix}?`)) return;

    this.api.deleteGeofeedEntry(entry.id).subscribe({
      next: () => {
        this.snackBar.open('Geofeed entry deleted', 'Dismiss', { duration: 3000 });
        this.loadEntries();
      },
      error: (err) => {
        this.snackBar.open('Failed to delete entry: ' + (err.error?.error || err.message), 'Dismiss', { duration: 5000 });
      }
    });
  }

  toggleEnabled(entry: GeoEntry): void {
    const updated = { ...entry, enabled: !entry.enabled };
    this.api.updateGeofeedEntry(entry.id, updated).subscribe({
      next: () => {
        entry.enabled = !entry.enabled;
        this.snackBar.open(entry.enabled ? 'Entry enabled' : 'Entry disabled', 'Dismiss', { duration: 2000 });
      },
      error: (err) => {
        this.snackBar.open('Failed to update entry: ' + (err.error?.error || err.message), 'Dismiss', { duration: 5000 });
      }
    });
  }

  copyCSVUrl(): void {
    this.clipboard.copy(this.csvUrl);
    this.snackBar.open('Geofeed CSV URL copied to clipboard', 'Dismiss', { duration: 3000 });
  }

  resetNewEntry(): void {
    this.newEntry = {
      prefix: '',
      country: '',
      region: '',
      city: '',
      postal_code: '',
      enabled: true
    };
  }

  getEnabledCount(): number {
    return this.entries.filter(e => e.enabled).length;
  }
}
