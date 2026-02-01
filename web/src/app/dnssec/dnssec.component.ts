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
import { MatTableModule } from '@angular/material/table';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { forkJoin } from 'rxjs';
import { ApiService, DnssecZone } from '../services/api.service';

@Component({
  selector: 'app-dnssec',
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
    MatTableModule,
    MatSnackBarModule
  ],
  templateUrl: './dnssec.component.html',
  styleUrl: './dnssec.component.scss'
})
export class DnssecComponent implements OnInit {
  zones: DnssecZone[] = [];
  availableZones: string[] = []; // Zones that don't have DNSSEC yet
  allZones: string[] = []; // All zones in the system
  
  algorithms = [
    { value: 'RSASHA256', label: 'RSA/SHA-256 (Algorithm 8)' },
    { value: 'RSASHA512', label: 'RSA/SHA-512 (Algorithm 10)' },
    { value: 'ECDSAP256SHA256', label: 'ECDSA P-256/SHA-256 (Algorithm 13)' },
    { value: 'ECDSAP384SHA384', label: 'ECDSA P-384/SHA-384 (Algorithm 14)' },
    { value: 'ED25519', label: 'Ed25519 (Algorithm 15)' }
  ];
  
  displayedColumns = ['zone', 'algorithm', 'key_dir', 'auto_create', 'actions'];
  
  showModal = false;
  editingIndex: number = -1;
  formData: Partial<DnssecZone> = {};
  
  loading = false;
  saving = false;

  constructor(
    private api: ApiService,
    private snackBar: MatSnackBar,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.loadData();
  }

  loadData() {
    this.loading = true;
    forkJoin({
      zones: this.api.getZones(),
      dnssecConfig: this.api.getDnssecConfig()
    }).subscribe({
      next: ({ zones, dnssecConfig }) => {
        this.allZones = zones.map(z => z.name);
        this.zones = dnssecConfig || [];
        this.updateAvailableZones();
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to load DNSSEC config', 'Close', { duration: 3000 });
        console.error(err);
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  loadZones() {
    this.api.getZones().subscribe({
      next: (zones) => {
        this.allZones = zones.map(z => z.name);
        this.updateAvailableZones();
      },
      error: (err) => {
        console.error('Failed to load zones:', err);
      }
    });
  }

  updateAvailableZones() {
    const configuredZones = new Set(this.zones.map(z => z.zone));
    this.availableZones = this.allZones.filter(z => !configuredZones.has(z));
  }

  loadConfig() {
    this.loading = true;
    this.api.getDnssecConfig().subscribe({
      next: (zones) => {
        this.zones = zones || [];
        this.updateAvailableZones();
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to load DNSSEC config', 'Close', { duration: 3000 });
        console.error(err);
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  saveConfig() {
    // Note: This is a no-op since saveZone and deleteZone handle individual API calls
    this.saving = false;
  }

  openAddModal() {
    this.editingIndex = -1;
    this.formData = {
      zone: '',
      key_dir: 'keys',
      algorithm: 'ECDSAP256SHA256',
      auto_create: true
    };
    this.showModal = true;
  }

  openEditModal(zone: DnssecZone, index: number) {
    this.editingIndex = index;
    this.formData = { ...zone };
    this.showModal = true;
  }

  closeModal() {
    this.showModal = false;
    this.editingIndex = -1;
    this.formData = {};
  }

  saveZone() {
    const zone = this.formData as DnssecZone;
    
    if (this.editingIndex >= 0) {
      // Updating existing zone - use PUT
      this.saving = true;
      this.api.updateDnssec(zone.zone, zone.algorithm, zone.enabled !== false).subscribe({
        next: () => {
          this.zones[this.editingIndex] = zone;
          this.snackBar.open('DNSSEC settings updated', 'Close', { duration: 3000 });
          this.closeModal();
          this.saving = false;
        },
        error: (err: any) => {
          this.snackBar.open('Failed to update DNSSEC', 'Close', { duration: 3000 });
          console.error(err);
          this.saving = false;
        }
      });
    } else {
      // Adding new zone - use POST
      this.saving = true;
      this.api.enableDnssec(zone.zone, zone.algorithm).subscribe({
        next: (result) => {
          this.zones.push(result);
          this.snackBar.open('DNSSEC enabled', 'Close', { duration: 3000 });
          this.closeModal();
          this.updateAvailableZones();
          this.saving = false;
        },
        error: (err: any) => {
          this.snackBar.open('Failed to enable DNSSEC', 'Close', { duration: 3000 });
          console.error(err);
          this.saving = false;
        }
      });
    }
  }

  deleteZone(index: number) {
    const zone = this.zones[index];
    if (confirm(`Delete DNSSEC configuration for ${zone.zone}?`)) {
      this.api.deleteDnssec(zone.zone).subscribe({
        next: () => {
          this.zones.splice(index, 1);
          this.updateAvailableZones();
          this.snackBar.open('DNSSEC disabled', 'Close', { duration: 3000 });
        },
        error: (err: any) => {
          this.snackBar.open('Failed to delete DNSSEC', 'Close', { duration: 3000 });
          console.error(err);
        }
      });
    }
  }

  getAlgorithmLabel(value: string): string {
    return this.algorithms.find(a => a.value === value)?.label || value;
  }
}
