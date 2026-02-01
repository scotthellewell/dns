import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { Tenant } from '../services/auth.service';

export interface TenantDialogData {
  mode: 'create' | 'edit';
  tenant?: Tenant;
}

@Component({
  selector: 'app-tenant-dialog',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule
  ],
  template: `
    <h2 mat-dialog-title>{{ data.mode === 'create' ? 'Create Tenant' : 'Edit Tenant' }}</h2>
    <mat-dialog-content>
      <form #tenantForm="ngForm">
        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Name</mat-label>
          <input matInput
                 name="name"
                 [(ngModel)]="formData.name"
                 required
                 #nameField="ngModel">
          @if (nameField.invalid && nameField.touched) {
            <mat-error>Name is required</mat-error>
          }
        </mat-form-field>

        <mat-form-field appearance="outline" class="full-width">
          <mat-label>Description</mat-label>
          <textarea matInput
                    name="description"
                    [(ngModel)]="formData.description"
                    rows="3"></textarea>
        </mat-form-field>
      </form>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button mat-button mat-dialog-close>Cancel</button>
      <button mat-raised-button
              color="primary"
              [disabled]="tenantForm.invalid"
              (click)="save()">
        {{ data.mode === 'create' ? 'Create' : 'Save' }}
      </button>
    </mat-dialog-actions>
  `,
  styles: [`
    mat-dialog-content {
      min-width: 300px;
    }
    .full-width {
      width: 100%;
      margin-bottom: 8px;
    }
    mat-dialog-actions {
      padding: 16px 0 0;
    }
  `]
})
export class TenantDialogComponent {
  private dialogRef = inject(MatDialogRef<TenantDialogComponent>);
  data = inject<TenantDialogData>(MAT_DIALOG_DATA);

  formData = {
    name: this.data.tenant?.name || '',
    description: this.data.tenant?.description || ''
  };

  save() {
    this.dialogRef.close({
      name: this.formData.name,
      description: this.formData.description
    });
  }
}
