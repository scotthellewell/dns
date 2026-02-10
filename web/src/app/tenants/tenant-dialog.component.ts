import { Component, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatDialogModule, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
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
    MatButtonModule,
    MatChipsModule,
    MatIconModule
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

        <div class="nameservers-section">
          <h4>Default Nameservers</h4>
          <p class="hint">Zones in this tenant will automatically use these NS records unless explicitly overridden</p>
          
          <mat-chip-set>
            @for (ns of formData.default_nameservers; track ns; let i = $index) {
              <mat-chip (removed)="removeNameserver(i)">
                {{ ns }}
                <button matChipRemove>
                  <mat-icon>cancel</mat-icon>
                </button>
              </mat-chip>
            }
          </mat-chip-set>

          <div class="add-ns-row">
            <mat-form-field appearance="outline" class="ns-input">
              <mat-label>Add nameserver</mat-label>
              <input matInput
                     name="newNameserver"
                     [(ngModel)]="newNameserver"
                     placeholder="ns1.example.com"
                     (keyup.enter)="addNameserver()">
            </mat-form-field>
            <button mat-raised-button 
                    color="accent" 
                    class="add-btn"
                    (click)="addNameserver()" 
                    [disabled]="!newNameserver">
              <mat-icon>add</mat-icon>
              Add
            </button>
          </div>

          <mat-form-field appearance="outline" class="ttl-field">
            <mat-label>NS Record TTL (seconds)</mat-label>
            <input matInput
                   type="number"
                   name="default_nameserver_ttl"
                   [(ngModel)]="formData.default_nameserver_ttl"
                   placeholder="0 = use zone default">
            <mat-hint>0 or empty uses zone default TTL</mat-hint>
          </mat-form-field>
        </div>
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
      min-width: 400px;
    }
    .full-width {
      width: 100%;
      margin-bottom: 8px;
    }
    mat-dialog-actions {
      padding: 16px 0 0;
    }
    .nameservers-section {
      margin-top: 16px;
      padding: 16px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
    }
    .nameservers-section h4 {
      margin: 0 0 4px 0;
      font-size: 14px;
      font-weight: 500;
      color: #e2e8f0;
    }
    .nameservers-section .hint {
      margin: 0 0 12px 0;
      font-size: 12px;
      color: #94a3b8;
    }
    .add-ns-row {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      margin-top: 12px;
    }
    .ns-input {
      flex: 1;
    }
    .add-btn {
      margin-top: 8px;
    }
    .ttl-field {
      width: 200px;
      margin-top: 12px;
    }
    mat-chip-set {
      margin-bottom: 8px;
    }
  `]
})
export class TenantDialogComponent {
  private dialogRef = inject(MatDialogRef<TenantDialogComponent>);
  data = inject<TenantDialogData>(MAT_DIALOG_DATA);

  newNameserver = '';
  
  formData = {
    name: this.data.tenant?.name || '',
    description: this.data.tenant?.description || '',
    default_nameservers: [...(this.data.tenant?.default_nameservers || [])],
    default_nameserver_ttl: this.data.tenant?.default_nameserver_ttl || 0
  };

  addNameserver() {
    if (this.newNameserver && !this.formData.default_nameservers.includes(this.newNameserver)) {
      this.formData.default_nameservers.push(this.newNameserver);
      this.newNameserver = '';
    }
  }

  removeNameserver(index: number) {
    this.formData.default_nameservers.splice(index, 1);
  }

  save() {
    this.dialogRef.close({
      name: this.formData.name,
      description: this.formData.description,
      default_nameservers: this.formData.default_nameservers.length > 0 ? this.formData.default_nameservers : undefined,
      default_nameserver_ttl: this.formData.default_nameserver_ttl || undefined
    });
  }
}
