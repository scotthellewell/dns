import { Component, inject, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatSelectModule } from '@angular/material/select';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { AuthService, APIKeyRole, Tenant } from '../services/auth.service';

export interface ApiKeyDialogData {
  tenantId?: string; // Current tenant context
  tenants: Tenant[];
  isSuperAdmin: boolean;
}

export interface ApiKeyDialogResult {
  name: string;
  role: string;
}

@Component({
  selector: 'app-api-key-dialog',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatSelectModule,
    MatProgressSpinnerModule
  ],
  template: `
    <h2 mat-dialog-title>Create API Key</h2>
    <mat-dialog-content>
      <form #keyForm="ngForm">
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>API Key Name</mat-label>
          <input matInput
                 name="name"
                 [(ngModel)]="formData.name"
                 placeholder="e.g., CI/CD Pipeline"
                 required
                 #nameField="ngModel">
          <mat-hint>A descriptive name to identify this key</mat-hint>
          @if (nameField.invalid && nameField.touched) {
            <mat-error>Name is required</mat-error>
          }
        </mat-form-field>

        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Role</mat-label>
          <mat-select name="role" [(ngModel)]="formData.role" required>
            @for (role of availableRoles; track role.value) {
              <mat-option [value]="role.value">{{role.label}}</mat-option>
            }
          </mat-select>
          <mat-hint>Permissions for this API key</mat-hint>
        </mat-form-field>
      </form>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-raised-button
              color="primary"
              [disabled]="keyForm.invalid || loading"
              (click)="create()">
        @if (loading) {
          <mat-spinner diameter="18"></mat-spinner>
        } @else {
          Create
        }
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    mat-dialog-content {
      min-width: 350px;
    }
    .full-width {
      width: 100%;
      margin-bottom: 16px;
    }
    mat-dialog-actions {
      padding: 16px 0 0;
    }
    mat-spinner {
      display: inline-block;
    }
  `]
})
export class ApiKeyDialogComponent implements OnInit {
  private dialogRef = inject(MatDialogRef<ApiKeyDialogComponent>);
  private authService = inject(AuthService);
  data = inject<ApiKeyDialogData>(MAT_DIALOG_DATA);

  availableRoles: APIKeyRole[] = [];
  loading = false;

  formData = {
    name: '',
    role: 'admin'
  };

  ngOnInit() {
    this.loadRoles();
  }

  loadRoles() {
    this.authService.getAPIKeyRoles().subscribe({
      next: (roles) => {
        this.availableRoles = roles;
        // Default to first role if current selection is not available
        if (roles.length > 0 && !roles.find(r => r.value === this.formData.role)) {
          this.formData.role = roles[0].value;
        }
      },
      error: (err) => {
        console.error('Failed to load roles', err);
        // Fallback roles
        this.availableRoles = [
          { value: 'readonly', label: 'Read Only', description: 'Can only read data' },
          { value: 'admin', label: 'Admin', description: 'Full access to tenant resources' }
        ];
      }
    });
  }

  create() {
    this.dialogRef.close({
      name: this.formData.name,
      role: this.formData.role
    } as ApiKeyDialogResult);
  }
}
