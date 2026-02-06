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
            <div class="form-row">
              <div class="form-group">
                <label for="new_username">Username *</label>
                <input type="text" id="new_username" #usernameInput
                       placeholder="Enter username">
              </div>
              <div class="form-group">
                <label for="new_email">Email</label>
                <input type="email" id="new_email" #emailInput
                       placeholder="user@example.com">
              </div>
            </div>

            <div class="form-row">
              <div class="form-group">
                <label for="new_display_name">Display Name</label>
                <input type="text" id="new_display_name" #displayNameInput
                       placeholder="John Doe">
              </div>
              <div class="form-group">
                <label for="new_role">Role *</label>
                <select id="new_role" #roleSelect>
                  <option *ngIf="data.tenant.is_main" value="super_admin">Super Admin</option>
                  <option value="admin">Tenant Admin</option>
                  <option value="user" selected>User</option>
                  <option value="readonly">Read Only</option>
                </select>
              </div>
            </div>

            <div class="form-row">
              <div class="form-group">
                <label for="new_password">Password *</label>
                <input type="password" id="new_password" #passwordInput
                       placeholder="Minimum 8 characters">
              </div>
              <div class="form-group">
                <label for="new_confirm_password">Confirm Password *</label>
                <input type="password" id="new_confirm_password" #confirmPasswordInput
                       placeholder="Re-enter password">
              </div>
            </div>

            <div class="form-actions">
              <button type="button" class="btn btn-primary" 
                      (click)="createUserFromInputs(usernameInput.value, emailInput.value, displayNameInput.value, roleSelect.value, passwordInput.value, confirmPasswordInput.value)"
                      [disabled]="creating()">Create User</button>
            </div>
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
                    <button class="btn btn-sm" (click)="startEditUser(user)" title="Edit User">
                      ✏️ Edit
                    </button>
                    <button class="btn btn-sm" (click)="resetPassword(user)" title="Reset Password">
                      🔑 Reset
                    </button>
                    <button class="btn btn-sm btn-danger" 
                            (click)="deleteUser(user)"
                            [disabled]="isCurrentUser(user) || (user.role === 'super_admin' && isSingleSuperAdmin())"
                            [title]="isCurrentUser(user) ? 'Cannot delete yourself' : 'Delete User'">
                      Delete
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- Edit User Form -->
          <div *ngIf="editingUser" class="edit-form">
            <h3>Edit User: {{ editingUser.username }}</h3>
            <div class="form-row">
              <div class="form-group">
                <label for="edit_display_name">Display Name</label>
                <input type="text" id="edit_display_name" #editDisplayNameInput
                       [value]="editingUser.display_name || ''"
                       placeholder="John Doe">
              </div>
              <div class="form-group">
                <label for="edit_email">Email</label>
                <input type="email" id="edit_email" #editEmailInput
                       [value]="editingUser.email || ''"
                       placeholder="user@example.com">
              </div>
            </div>

            <div class="form-row">
              <div class="form-group">
                <label for="edit_role">Role *</label>
                <select id="edit_role" #editRoleSelect [value]="editingUser.role">
                  <option *ngIf="data.tenant.is_main" value="super_admin" [selected]="editingUser.role === 'super_admin'">Super Admin</option>
                  <option value="admin" [selected]="editingUser.role === 'admin'">Tenant Admin</option>
                  <option value="user" [selected]="editingUser.role === 'user'">User</option>
                  <option value="readonly" [selected]="editingUser.role === 'readonly'">Read Only</option>
                </select>
              </div>
            </div>

            <div class="form-actions">
              <button type="button" class="btn" (click)="cancelEdit()">Cancel</button>
              <button type="button" class="btn btn-primary" 
                      (click)="saveUser(editDisplayNameInput.value, editEmailInput.value, editRoleSelect.value)"
                      [disabled]="saving()">Save Changes</button>
            </div>
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

    .create-form, .edit-form {
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

    .edit-form {
      margin-top: 16px;
      border-color: #3b82f6;
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
      gap: 8px;
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
  saving = signal(false);
  showCreateForm = false;
  editingUser: User | null = null;

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

  isCurrentUser(user: User): boolean {
    const currentUser = this.authService.currentUser();
    return currentUser?.id === user.id;
  }

  startEditUser(user: User) {
    this.editingUser = { ...user };
    this.showCreateForm = false;
  }

  cancelEdit() {
    this.editingUser = null;
  }

  saveUser(displayName: string, email: string, role: string) {
    if (!this.editingUser) return;

    this.saving.set(true);
    const payload = {
      display_name: displayName,
      email: email,
      role: role
    };

    this.http.put('/api/auth/users/' + this.editingUser.id, payload).subscribe({
      next: () => {
        this.snackBar.open('User updated successfully', 'Dismiss', { duration: 3000 });
        this.saving.set(false);
        this.editingUser = null;
        this.loadUsers();
      },
      error: (err: any) => {
        this.saving.set(false);
        let message = 'Failed to update user';
        if (typeof err.error === 'string') {
          message = err.error;
        } else if (err.error?.message) {
          message = err.error.message;
        }
        this.snackBar.open(message, 'Dismiss', { duration: 5000 });
      }
    });
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

  createUserFromInputs(username: string, email: string, displayName: string, role: string, password: string, confirmPassword: string) {
    if (password !== confirmPassword) {
      this.snackBar.open('Passwords do not match', 'Dismiss', { duration: 3000 });
      return;
    }

    if (!username || !password) {
      this.snackBar.open('Username and password are required', 'Dismiss', { duration: 3000 });
      return;
    }

    this.creating.set(true);
    const payload = {
      username: username,
      email: email || undefined,
      display_name: displayName || undefined,
      role: role,
      password: password
    };
    console.log('Creating user with payload:', payload);
    
    this.http.post('/api/auth/tenants/' + this.data.tenant.id + '/users', payload).subscribe({
      next: () => {
        this.snackBar.open('User created successfully', 'Dismiss', { duration: 3000 });
        this.creating.set(false);
        this.showCreateForm = false;
        this.loadUsers();
      },
      error: (err: any) => {
        this.creating.set(false);
        let message = 'Failed to create user';
        if (typeof err.error === 'string') {
          message = err.error;
        } else if (err.error?.message) {
          message = err.error.message;
        } else if (err.message) {
          message = err.message;
        }
        this.snackBar.open(message, 'Dismiss', { duration: 5000 });
      }
    });
  }

  createUser() {
    if (this.newUser.password !== this.newUser.confirm_password) {
      this.snackBar.open('Passwords do not match', 'Dismiss', { duration: 3000 });
      return;
    }

    if (!this.newUser.username || !this.newUser.password) {
      this.snackBar.open('Username and password are required', 'Dismiss', { duration: 3000 });
      return;
    }

    this.creating.set(true);
    const payload = {
      username: this.newUser.username,
      email: this.newUser.email || undefined,
      display_name: this.newUser.display_name || undefined,
      role: this.newUser.role,
      password: this.newUser.password
    };
    console.log('Creating user with payload:', payload);
    
    this.http.post('/api/auth/tenants/' + this.data.tenant.id + '/users', payload).subscribe({
      next: () => {
        this.snackBar.open('User created successfully', 'Dismiss', { duration: 3000 });
        this.creating.set(false);
        this.showCreateForm = false;
        this.resetNewUser();
        this.loadUsers();
      },
      error: (err: any) => {
        this.creating.set(false);
        let message = 'Failed to create user';
        if (typeof err.error === 'string') {
          message = err.error;
        } else if (err.error?.message) {
          message = err.error.message;
        } else if (err.message) {
          message = err.message;
        }
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
