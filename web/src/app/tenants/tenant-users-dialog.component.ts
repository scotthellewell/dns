import { Component, inject, signal, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { MatDialogModule, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { AuthService, Tenant, User } from '../services/auth.service';

export interface TenantUsersDialogData {
  tenant: Tenant;
}

@Component({
  selector: 'app-tenant-users-dialog',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatDialogModule,
    MatSnackBarModule
  ],
  template: `
    <div class="dialog-container">
      <div class="dialog-header">
        <h2>
          Users in {{ data.tenant.name }}
          <span *ngIf="data.tenant.is_main" class="main-badge">Main Tenant</span>
        </h2>
        <button class="close-btn" (click)="close()">×</button>
      </div>
      
      <div class="dialog-body">
        <div *ngIf="loading()" class="loading">
          <div class="spinner"></div>
          <span>Loading users...</span>
        </div>
        
        <ng-container *ngIf="!loading()">
          <div class="toolbar">
            <button class="btn btn-primary" (click)="showCreateForm = !showCreateForm">
              {{ showCreateForm ? '✕ Cancel' : '+ Add User' }}
            </button>
          </div>

          <div *ngIf="showCreateForm" class="create-form">
            <h3>Create New User</h3>
            <form #createForm="ngForm" (ngSubmit)="createUser()">
              <div class="form-row">
                <div class="form-group">
                  <label for="username">Username *</label>
                  <input type="text" id="username" name="username" 
                         [(ngModel)]="newUser.username" required
                         placeholder="Enter username">
                </div>
                <div class="form-group">
                  <label for="email">Email</label>
                  <input type="email" id="email" name="email" 
                         [(ngModel)]="newUser.email"
                         placeholder="user@example.com">
                </div>
              </div>

              <div class="form-row">
                <div class="form-group">
                  <label for="display_name">Display Name</label>
                  <input type="text" id="display_name" name="display_name" 
                         [(ngModel)]="newUser.display_name"
                         placeholder="John Doe">
                </div>
                <div class="form-group">
                  <label for="role">Role *</label>
                  <select id="role" name="role" [(ngModel)]="newUser.role" required>
                    <option *ngIf="data.tenant.is_main" value="super_admin">Super Admin</option>
                    <option value="admin">Tenant Admin</option>
                    <option value="user">User</option>
                    <option value="readonly">Read Only</option>
                  </select>
                </div>
              </div>

              <div class="form-row">
                <div class="form-group">
                  <label for="password">Password *</label>
                  <input type="password" id="password" name="password" 
                         [(ngModel)]="newUser.password" required minlength="8"
                         placeholder="Minimum 8 characters">
                </div>
                <div class="form-group">
                  <label for="confirm_password">Confirm Password *</label>
                  <input type="password" id="confirm_password" name="confirm_password" 
                         [(ngModel)]="newUser.confirm_password" required
                         placeholder="Re-enter password">
                </div>
              </div>

              <div class="form-actions">
                <button type="submit" class="btn btn-primary"
                        [disabled]="createForm.invalid || newUser.password !== newUser.confirm_password || creating()">Create User</button>
              </div>
            </form>
          </div>

          <div *ngIf="users().length === 0 && !showCreateForm" class="empty-state">
            <span class="empty-icon">👤</span>
            <p>No users in this tenant</p>
          </div>

          <div *ngIf="users().length > 0" class="users-table">
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Display Name</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr *ngFor="let user of users()">
                  <td>{{ user.username }}</td>
                  <td>{{ user.display_name || '-' }}</td>
                  <td>{{ user.email || '-' }}</td>
                  <td>
                    <span class="role-badge" [attr.data-role]="user.role">
                      {{ getRoleLabel(user.role) }}
                    </span>
                  </td>
                  <td class="actions">
                    <button class="btn btn-sm" (click)="resetPassword(user)" title="Reset Password">
                      🔑 Reset
                    </button>
                    <button class="btn btn-sm btn-danger" 
                            (click)="deleteUser(user)"
                            [disabled]="user.role === 'super_admin' && isSingleSuperAdmin()"
                            title="Delete User">
                      Delete
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </ng-container>
      </div>
      
      <div class="dialog-footer">
        <button class="btn" (click)="close()">Close</button>
      </div>
    </div>
  `,
  styles: [`
    .dialog-container {
      background: #1e293b;
      border-radius: 12px;
      width: 700px;
      max-width: calc(100vw - 48px);
      max-height: calc(100vh - 48px);
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }

    .dialog-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px 20px;
      border-bottom: 1px solid #334155;

      h2 {
        margin: 0;
        font-size: 1.125rem;
        font-weight: 500;
        color: #f1f5f9;
        display: flex;
        align-items: center;
        gap: 12px;
      }

      .main-badge {
        background: #2563eb;
        color: white;
        font-size: 0.75rem;
        padding: 2px 8px;
        border-radius: 4px;
        font-weight: 500;
      }

      .close-btn {
        background: none;
        border: none;
        font-size: 24px;
        cursor: pointer;
        color: #94a3b8;
        padding: 0;
        line-height: 1;

        &:hover {
          color: #f1f5f9;
        }
      }
    }

    .dialog-body {
      padding: 20px;
      overflow-y: auto;
      flex: 1;
    }

    .dialog-footer {
      display: flex;
      justify-content: flex-end;
      gap: 12px;
      padding: 16px 20px;
      border-top: 1px solid #334155;
    }

    .loading {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 48px;
      color: #94a3b8;

      .spinner {
        width: 32px;
        height: 32px;
        border: 3px solid #334155;
        border-top-color: #3b82f6;
        border-radius: 50%;
        animation: spin 1s linear infinite;
      }

      span {
        margin-top: 16px;
      }
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    .toolbar {
      margin-bottom: 16px;
    }

    .create-form {
      background: #0f172a;
      padding: 16px;
      border-radius: 8px;
      margin-bottom: 16px;
      border: 1px solid #334155;

      h3 {
        margin: 0 0 16px;
        font-size: 1rem;
        color: #f1f5f9;
        font-weight: 500;
      }
    }

    .form-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-bottom: 16px;
    }

    .form-group {
      label {
        display: block;
        font-weight: 500;
        margin-bottom: 4px;
        color: #94a3b8;
        font-size: 0.875rem;
      }

      input, select {
        width: 100%;
        padding: 8px 12px;
        border: 1px solid #475569;
        border-radius: 6px;
        font-size: 0.875rem;
        background: #1e293b;
        color: #e2e8f0;

        &:focus {
          outline: none;
          border-color: #3b82f6;
          box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }

        &::placeholder {
          color: #64748b;
        }
      }

      select {
        cursor: pointer;
      }
    }

    .form-actions {
      display: flex;
      justify-content: flex-end;
      margin-top: 8px;
    }

    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 48px;
      color: #94a3b8;

      .empty-icon {
        font-size: 48px;
        opacity: 0.5;
      }

      p {
        margin: 12px 0 0;
      }
    }

    .users-table {
      overflow-x: auto;

      table {
        width: 100%;
        border-collapse: collapse;
      }

      th, td {
        padding: 12px 16px;
        text-align: left;
        border-bottom: 1px solid #334155;
      }

      th {
        font-weight: 600;
        color: #94a3b8;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
      }

      td {
        color: #e2e8f0;
      }

      tr:hover td {
        background: rgba(255, 255, 255, 0.02);
      }
    }

    .role-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 500;

      &[data-role="super_admin"] {
        background: #7f1d1d;
        color: #fecaca;
      }
      &[data-role="admin"] {
        background: #1e40af;
        color: #bfdbfe;
      }
      &[data-role="user"] {
        background: #065f46;
        color: #a7f3d0;
      }
      &[data-role="readonly"] {
        background: #334155;
        color: #94a3b8;
      }
    }

    .actions {
      display: flex;
      gap: 8px;
    }

    .btn {
      padding: 8px 16px;
      border: 1px solid #475569;
      border-radius: 6px;
      background: #1e293b !important;
      color: #e2e8f0 !important;
      cursor: pointer;
      font-size: 0.875rem;
      transition: all 0.15s;

      &:hover:not(:disabled) {
        background: #334155 !important;
      }

      &:disabled {
        opacity: 0.5;
        cursor: not-allowed;
      }

      &.btn-primary {
        background: #2563eb !important;
        border-color: #2563eb;
        color: #fff !important;

        &:hover:not(:disabled) {
          background: #1d4ed8 !important;
        }
      }

      &.btn-danger {
        color: #f87171 !important;
        border-color: #7f1d1d;

        &:hover:not(:disabled) {
          background: #450a0a;
        }
      }

      &.btn-sm {
        padding: 4px 8px;
        font-size: 0.75rem;
      }
    }
  `]
})
export class TenantUsersDialogComponent implements OnInit {
  private dialogRef = inject(MatDialogRef<TenantUsersDialogComponent>);
  private authService = inject(AuthService);
  private http = inject(HttpClient);
  private snackBar = inject(MatSnackBar);
  data = inject<TenantUsersDialogData>(MAT_DIALOG_DATA);

  users = signal<User[]>([]);
  loading = signal(false);
  creating = signal(false);
  showCreateForm = false;

  newUser = {
    username: '',
    email: '',
    display_name: '',
    role: 'user',
    password: '',
    confirm_password: ''
  };

  ngOnInit() {
    this.loadUsers();
  }

  close() {
    this.dialogRef.close();
  }

  loadUsers() {
    this.loading.set(true);
    this.authService.getTenantUsers(this.data.tenant.id).subscribe({
      next: (users) => {
        this.users.set(users);
        this.loading.set(false);
      },
      error: (err) => {
        this.loading.set(false);
        this.snackBar.open('Failed to load users', 'Dismiss', { duration: 3000 });
      }
    });
  }

  createUser() {
    if (this.newUser.password !== this.newUser.confirm_password) {
      this.snackBar.open('Passwords do not match', 'Dismiss', { duration: 3000 });
      return;
    }

    this.creating.set(true);
    this.http.post('/api/auth/tenants/' + this.data.tenant.id + '/users', {
      username: this.newUser.username,
      email: this.newUser.email || undefined,
      display_name: this.newUser.display_name || undefined,
      role: this.newUser.role,
      password: this.newUser.password
    }).subscribe({
      next: () => {
        this.snackBar.open('User created successfully', 'Dismiss', { duration: 3000 });
        this.creating.set(false);
        this.showCreateForm = false;
        this.resetNewUser();
        this.loadUsers();
      },
      error: (err: { error?: string }) => {
        this.creating.set(false);
        const message = err.error || 'Failed to create user';
        this.snackBar.open(message, 'Dismiss', { duration: 5000 });
      }
    });
  }

  resetNewUser() {
    this.newUser = {
      username: '',
      email: '',
      display_name: '',
      role: 'user',
      password: '',
      confirm_password: ''
    };
  }

  resetPassword(user: User) {
    const newPassword = prompt(`Enter new password for ${user.username} (minimum 8 characters):`);
    if (!newPassword) return;
    if (newPassword.length < 8) {
      this.snackBar.open('Password must be at least 8 characters', 'Dismiss', { duration: 3000 });
      return;
    }

    this.http.put('/api/auth/users/' + user.id, { password: newPassword }).subscribe({
      next: () => {
        this.snackBar.open('Password reset successfully', 'Dismiss', { duration: 3000 });
      },
      error: (err: { error?: string }) => {
        const message = err.error || 'Failed to reset password';
        this.snackBar.open(message, 'Dismiss', { duration: 5000 });
      }
    });
  }

  deleteUser(user: User) {
    if (confirm(`Are you sure you want to delete user "${user.username}"?`)) {
      this.http.delete('/api/auth/users/' + user.id).subscribe({
        next: () => {
          this.snackBar.open('User deleted successfully', 'Dismiss', { duration: 3000 });
          this.loadUsers();
        },
        error: (err: { error?: string }) => {
          const message = err.error || 'Failed to delete user';
          this.snackBar.open(message, 'Dismiss', { duration: 5000 });
        }
      });
    }
  }

  getRoleLabel(role: string): string {
    switch (role) {
      case 'super_admin': return 'Super Admin';
      case 'admin': return 'Tenant Admin';
      case 'user': return 'User';
      case 'readonly': return 'Read Only';
      default: return role;
    }
  }

  isSingleSuperAdmin(): boolean {
    return this.users().filter(u => u.role === 'super_admin').length <= 1;
  }
}
