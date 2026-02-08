import { Component, inject, signal, OnInit, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { AuthService, User } from '../services/auth.service';
import { TenantContextService } from '../services/tenant-context.service';

@Component({
  selector: 'app-users',
  standalone: true,
  imports: [CommonModule, FormsModule, MatSnackBarModule],
  templateUrl: './users.component.html',
  styleUrl: './users.component.scss'
})
export class UsersComponent implements OnInit {
  private http = inject(HttpClient);
  private snackBar = inject(MatSnackBar);
  readonly auth = inject(AuthService);
  private tenantContext = inject(TenantContextService);

  users = signal<User[]>([]);
  loading = signal(false);
  creating = signal(false);
  saving = signal(false);
  
  showCreateForm = false;
  editingUser: User | null = null;

  constructor() {
    // React to tenant context changes
    effect(() => {
      const tenantId = this.tenantContext.currentTenantId();
      this.loadUsers();
    });
  }

  ngOnInit() {
    this.loadUsers();
  }

  loadUsers() {
    this.loading.set(true);
    const tenantId = this.tenantContext.currentTenantId();
    
    this.http.get<User[]>(`/api/auth/tenants/${tenantId}/users`).subscribe({
      next: (users) => {
        this.users.set(users);
        this.loading.set(false);
      },
      error: (err) => {
        this.snackBar.open('Failed to load users', 'Dismiss', { duration: 3000 });
        console.error(err);
        this.loading.set(false);
      }
    });
  }

  createUserFromInputs(
    username: string,
    email: string,
    displayName: string,
    role: string,
    password: string,
    confirmPassword: string
  ) {
    if (!username?.trim()) {
      this.snackBar.open('Username is required', 'Dismiss', { duration: 3000 });
      return;
    }
    if (!password || password.length < 8) {
      this.snackBar.open('Password must be at least 8 characters', 'Dismiss', { duration: 3000 });
      return;
    }
    if (password !== confirmPassword) {
      this.snackBar.open('Passwords do not match', 'Dismiss', { duration: 3000 });
      return;
    }

    this.creating.set(true);
    const tenantId = this.tenantContext.currentTenantId();

    this.http.post(`/api/auth/tenants/${tenantId}/users`, {
      username: username.trim(),
      email: email?.trim() || undefined,
      display_name: displayName?.trim() || undefined,
      role: role || 'user',
      password
    }).subscribe({
      next: () => {
        this.snackBar.open('User created successfully', 'Dismiss', { duration: 3000 });
        this.showCreateForm = false;
        this.loadUsers();
        this.creating.set(false);
      },
      error: (err) => {
        this.snackBar.open(err.error?.message || 'Failed to create user', 'Dismiss', { duration: 3000 });
        this.creating.set(false);
      }
    });
  }

  startEditUser(user: User) {
    this.editingUser = { ...user };
  }

  cancelEdit() {
    this.editingUser = null;
  }

  saveUser(displayName: string, email: string, role: string) {
    if (!this.editingUser) return;

    this.saving.set(true);
    const tenantId = this.tenantContext.currentTenantId();

    this.http.put(`/api/auth/tenants/${tenantId}/users/${this.editingUser.id}`, {
      display_name: displayName?.trim() || undefined,
      email: email?.trim() || undefined,
      role
    }).subscribe({
      next: () => {
        this.snackBar.open('User updated successfully', 'Dismiss', { duration: 3000 });
        this.editingUser = null;
        this.loadUsers();
        this.saving.set(false);
      },
      error: (err) => {
        this.snackBar.open(err.error?.message || 'Failed to update user', 'Dismiss', { duration: 3000 });
        this.saving.set(false);
      }
    });
  }

  resetPassword(user: User) {
    const newPassword = prompt('Enter new password (minimum 8 characters):');
    if (!newPassword || newPassword.length < 8) {
      if (newPassword !== null) {
        this.snackBar.open('Password must be at least 8 characters', 'Dismiss', { duration: 3000 });
      }
      return;
    }

    const tenantId = this.tenantContext.currentTenantId();
    this.http.put(`/api/auth/tenants/${tenantId}/users/${user.id}`, {
      password: newPassword
    }).subscribe({
      next: () => {
        this.snackBar.open('Password reset successfully', 'Dismiss', { duration: 3000 });
      },
      error: (err) => {
        this.snackBar.open(err.error?.message || 'Failed to reset password', 'Dismiss', { duration: 3000 });
      }
    });
  }

  deleteUser(user: User) {
    if (!confirm(`Delete user "${user.username}"? This action cannot be undone.`)) {
      return;
    }

    const tenantId = this.tenantContext.currentTenantId();
    this.http.delete(`/api/auth/tenants/${tenantId}/users/${user.id}`).subscribe({
      next: () => {
        this.snackBar.open('User deleted', 'Dismiss', { duration: 3000 });
        this.loadUsers();
      },
      error: (err) => {
        this.snackBar.open(err.error?.message || 'Failed to delete user', 'Dismiss', { duration: 3000 });
      }
    });
  }

  isCurrentUser(user: User): boolean {
    return user.id === this.auth.currentUser()?.id;
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
}
