import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatDialogModule } from '@angular/material/dialog';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { ApiService, SecondaryZone } from '../services/api.service';

@Component({
  selector: 'app-secondary-zones',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatCardModule,
    MatTableModule,
    MatButtonModule,
    MatIconModule,
    MatFormFieldModule,
    MatInputModule,
    MatDialogModule,
    MatSnackBarModule
  ],
  templateUrl: './secondary-zones.component.html',
  styleUrl: './secondary-zones.component.scss'
})
export class SecondaryZonesComponent implements OnInit {
  secondaryZones: SecondaryZone[] = [];
  displayedColumns = ['zone', 'primary', 'refresh_interval', 'tsig_key', 'actions'];
  
  showModal = false;
  editingZone: SecondaryZone | null = null;
  formData: Partial<SecondaryZone> = {};

  constructor(
    private api: ApiService,
    private snackBar: MatSnackBar,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.loadZones();
  }

  loadZones() {
    this.api.getSecondaryZones().subscribe({
      next: (zones) => {
        this.secondaryZones = zones || [];
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to load secondary zones', 'Close', { duration: 3000 });
        console.error(err);
        this.cdr.detectChanges();
      }
    });
  }

  openAddModal() {
    this.editingZone = null;
    this.formData = {
      zone: '',
      primary: '',
      refresh_interval: 3600,
      tsig_key: '',
      dnssec_key_url: '',
      dnssec_key_token: ''
    };
    this.showModal = true;
  }

  openEditModal(zone: SecondaryZone) {
    this.editingZone = zone;
    this.formData = { ...zone };
    this.showModal = true;
  }

  closeModal() {
    this.showModal = false;
    this.editingZone = null;
    this.formData = {};
  }

  saveZone() {
    if (this.editingZone) {
      // Update existing
      this.api.updateSecondaryZone(this.editingZone.zone, this.formData as SecondaryZone).subscribe({
        next: () => {
          this.snackBar.open('Secondary zone updated', 'Close', { duration: 3000 });
          this.loadZones();
          this.closeModal();
        },
        error: (err) => {
          this.snackBar.open('Failed to update zone', 'Close', { duration: 3000 });
          console.error(err);
        }
      });
    } else {
      // Create new
      this.api.createSecondaryZone(this.formData as SecondaryZone).subscribe({
        next: () => {
          this.snackBar.open('Secondary zone added', 'Close', { duration: 3000 });
          this.loadZones();
          this.closeModal();
        },
        error: (err) => {
          this.snackBar.open('Failed to add zone', 'Close', { duration: 3000 });
          console.error(err);
        }
      });
    }
  }

  deleteZone(zone: SecondaryZone) {
    if (confirm(`Delete secondary zone ${zone.zone}?`)) {
      this.api.deleteSecondaryZone(zone.zone).subscribe({
        next: () => {
          this.snackBar.open('Secondary zone deleted', 'Close', { duration: 3000 });
          this.loadZones();
        },
        error: (err) => {
          this.snackBar.open('Failed to delete zone', 'Close', { duration: 3000 });
          console.error(err);
        }
      });
    }
  }

  convertToPrimary(zone: SecondaryZone) {
    const message = `Convert ${zone.zone} to a primary zone?\n\nThis will:\n• Create a new primary zone with all current records\n• Delete the secondary zone configuration\n• You will manage this zone directly instead of syncing from ${zone.primaries?.[0] || 'the primary server'}`;
    
    if (confirm(message)) {
      this.api.convertSecondaryToPrimary(zone.zone).subscribe({
        next: (result) => {
          this.snackBar.open(
            `Zone converted successfully! ${result.records_created} records created.`,
            'Close',
            { duration: 5000 }
          );
          this.loadZones();
        },
        error: (err) => {
          this.snackBar.open(
            'Failed to convert zone: ' + (err.error?.error || err.message),
            'Close',
            { duration: 5000 }
          );
          console.error(err);
        }
      });
    }
  }

  triggerTransfer(zone: SecondaryZone) {
    // TODO: Implement manual zone transfer trigger
    this.snackBar.open('Zone transfer triggered for ' + zone.zone, 'Close', { duration: 3000 });
  }
}
