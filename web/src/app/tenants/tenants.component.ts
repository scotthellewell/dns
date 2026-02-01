import { Component, inject, signal, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatTableModule } from '@angular/material/table';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatDialogModule, MatDialog } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatChipsModule } from '@angular/material/chips';
import { AuthService, Tenant, User } from '../services/auth.service';
import { TenantDialogComponent } from './tenant-dialog.component';
import { TenantUsersDialogComponent } from './tenant-users-dialog.component';

@Component({
  selector: 'app-tenants',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatCardModule,
    MatTableModule,
    MatButtonModule,
    MatIconModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatSnackBarModule,
    MatProgressSpinnerModule,
    MatTooltipModule,
    MatChipsModule
  ],
  templateUrl: './tenants.component.html',
  styleUrl: './tenants.component.scss'
})
export class TenantsComponent implements OnInit {
  private authService = inject(AuthService);
  private dialog = inject(MatDialog);
  private snackBar = inject(MatSnackBar);

  tenants = signal<Tenant[]>([]);
  loading = signal(false);
  displayedColumns = ['name', 'description', 'is_main', 'actions'];

  ngOnInit() {
    this.loadTenants();
  }

  loadTenants() {
    this.loading.set(true);
    this.authService.getTenants().subscribe({
      next: (tenants) => {
        this.tenants.set(tenants);
        this.loading.set(false);
      },
      error: (err) => {
        this.loading.set(false);
        this.snackBar.open('Failed to load tenants', 'Dismiss', { duration: 3000 });
      }
    });
  }

  openCreateDialog() {
    const dialogRef = this.dialog.open(TenantDialogComponent, {
      width: '400px',
      data: { mode: 'create' }
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.createTenant(result);
      }
    });
  }

  openEditDialog(tenant: Tenant) {
    const dialogRef = this.dialog.open(TenantDialogComponent, {
      width: '400px',
      data: { mode: 'edit', tenant }
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.updateTenant(tenant.id, result);
      }
    });
  }

  openUsersDialog(tenant: Tenant) {
    this.dialog.open(TenantUsersDialogComponent, {
      panelClass: 'custom-dialog-panel',
      data: { tenant }
    });
  }

  createTenant(data: { name: string; description?: string }) {
    this.authService.createTenant(data).subscribe({
      next: () => {
        this.snackBar.open('Tenant created successfully', 'Dismiss', { duration: 3000 });
        this.loadTenants();
      },
      error: (err) => {
        const message = err.error || 'Failed to create tenant';
        this.snackBar.open(message, 'Dismiss', { duration: 5000 });
      }
    });
  }

  updateTenant(id: string, data: { name?: string; description?: string }) {
    this.authService.updateTenant(id, data).subscribe({
      next: () => {
        this.snackBar.open('Tenant updated successfully', 'Dismiss', { duration: 3000 });
        this.loadTenants();
      },
      error: (err) => {
        const message = err.error || 'Failed to update tenant';
        this.snackBar.open(message, 'Dismiss', { duration: 5000 });
      }
    });
  }

  deleteTenant(tenant: Tenant) {
    if (tenant.is_main) {
      this.snackBar.open('Cannot delete the main tenant', 'Dismiss', { duration: 3000 });
      return;
    }

    if (confirm(`Are you sure you want to delete tenant "${tenant.name}"? This action cannot be undone.`)) {
      this.authService.deleteTenant(tenant.id).subscribe({
        next: () => {
          this.snackBar.open('Tenant deleted successfully', 'Dismiss', { duration: 3000 });
          this.loadTenants();
        },
        error: (err) => {
          const message = err.error || 'Failed to delete tenant';
          this.snackBar.open(message, 'Dismiss', { duration: 5000 });
        }
      });
    }
  }
}
