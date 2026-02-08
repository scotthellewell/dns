import { Component, OnInit, inject, signal, computed, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTableModule } from '@angular/material/table';
import { MatDialogModule, MatDialog } from '@angular/material/dialog';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatChipsModule } from '@angular/material/chips';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatSelectModule } from '@angular/material/select';
import { Clipboard, ClipboardModule } from '@angular/cdk/clipboard';
import { AuthService, APIKey, APIKeyRole, Tenant } from '../services/auth.service';
import { TenantContextService } from '../services/tenant-context.service';
import { ApiKeyDialogComponent, ApiKeyDialogResult } from './api-key-dialog.component';

@Component({
  selector: 'app-api-keys',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule,
    MatTableModule,
    MatDialogModule,
    MatSnackBarModule,
    MatProgressSpinnerModule,
    MatChipsModule,
    MatTooltipModule,
    MatSelectModule,
    ClipboardModule
  ],
  templateUrl: './api-keys.component.html',
  styleUrl: './api-keys.component.scss'
})
export class ApiKeysComponent implements OnInit {
  private authService = inject(AuthService);
  private tenantContext = inject(TenantContextService);
  private dialog = inject(MatDialog);
  private snackBar = inject(MatSnackBar);
  private clipboard = inject(Clipboard);

  apiKeys = signal<APIKey[]>([]);
  availableRoles = signal<APIKeyRole[]>([]);
  loading = signal(false);
  creating = signal(false);
  newKeyValue = signal<string | null>(null);

  // Filtered API keys based on tenant context
  filteredApiKeys = computed(() => {
    const keys = this.apiKeys();
    const currentTenant = this.tenantContext.currentTenantId();
    return keys.filter(k => k.tenant_id === currentTenant);
  });

  displayedColumns = ['name', 'prefix', 'role', 'created_at', 'last_used', 'actions'];

  // Check if user is super admin
  isSuperAdmin = computed(() => this.authService.isSuperAdmin());

  constructor() {
    // React to tenant context changes
    effect(() => {
      const tenantId = this.tenantContext.currentTenantId();
      // Reload keys when tenant changes
      this.loadApiKeys();
    });
  }

  ngOnInit() {
    this.loadApiKeys();
  }

  loadApiKeys() {
    this.loading.set(true);
    this.authService.getAPIKeys().subscribe({
      next: (keys) => {
        this.apiKeys.set(keys);
        this.loading.set(false);
      },
      error: (err) => {
        this.snackBar.open('Failed to load API keys', 'Dismiss', { duration: 3000 });
        console.error(err);
        this.loading.set(false);
      }
    });
  }

  openCreateDialog() {
    // Use the current tenant context
    const currentTenant = this.tenantContext.currentTenantId();
    
    const dialogRef = this.dialog.open(ApiKeyDialogComponent, {
      data: {
        tenantId: currentTenant,
        tenants: this.tenantContext.tenants(),
        isSuperAdmin: this.isSuperAdmin()
      }
    });

    dialogRef.afterClosed().subscribe((result: ApiKeyDialogResult | undefined) => {
      if (result) {
        this.createApiKey(result);
      }
    });
  }

  createApiKey(data: ApiKeyDialogResult) {
    this.creating.set(true);
    // Always create in the current tenant context (no tenant selection in dialog)
    const tenantId = this.tenantContext.currentTenantId();
    this.authService.createAPIKey(data.name, data.role, tenantId).subscribe({
      next: (response) => {
        this.newKeyValue.set(response.key);
        this.loadApiKeys();
        this.creating.set(false);
      },
      error: (err) => {
        const errorMsg = err.error || 'Failed to create API key';
        this.snackBar.open(errorMsg, 'Dismiss', { duration: 5000 });
        console.error(err);
        this.creating.set(false);
      }
    });
  }

  copyKey(key: string) {
    this.clipboard.copy(key);
    this.snackBar.open('API key copied to clipboard', 'Dismiss', { duration: 2000 });
  }

  dismissNewKey() {
    this.newKeyValue.set(null);
  }

  revokeKey(keyId: string) {
    if (!confirm('Are you sure you want to revoke this API key? This action cannot be undone.')) {
      return;
    }

    this.authService.revokeAPIKey(keyId).subscribe({
      next: () => {
        this.snackBar.open('API key revoked', 'Dismiss', { duration: 3000 });
        this.loadApiKeys();
      },
      error: (err) => {
        this.snackBar.open('Failed to revoke API key', 'Dismiss', { duration: 3000 });
        console.error(err);
      }
    });
  }

  formatDate(dateStr: string): string {
    if (!dateStr) return 'Never';
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  getRoleName(permissions: string[]): string {
    if (!permissions || permissions.length === 0) return 'Unknown';
    if (permissions.includes('*')) return 'Super Admin';
    if (permissions.includes('admin')) return 'Admin';
    if (permissions.includes('write')) return 'User';
    if (permissions.includes('read')) return 'Read Only';
    return 'Unknown';
  }
}
