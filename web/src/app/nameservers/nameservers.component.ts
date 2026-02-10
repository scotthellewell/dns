import { Component, OnInit, inject, signal, computed, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatChipsModule } from '@angular/material/chips';
import { MatTooltipModule } from '@angular/material/tooltip';
import { AuthService, Tenant } from '../services/auth.service';
import { TenantContextService } from '../services/tenant-context.service';

@Component({
  selector: 'app-nameservers',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule,
    MatSnackBarModule,
    MatProgressSpinnerModule,
    MatChipsModule,
    MatTooltipModule
  ],
  templateUrl: './nameservers.component.html',
  styleUrl: './nameservers.component.scss'
})
export class NameserversComponent implements OnInit {
  private authService = inject(AuthService);
  private snackBar = inject(MatSnackBar);
  readonly tenantContext = inject(TenantContextService);

  tenant = signal<Tenant | null>(null);
  loading = signal(false);
  saving = signal(false);

  // Form data
  nameservers = signal<string[]>([]);
  nameserverTTL = signal<number>(0);
  newNameserver = '';

  // Computed
  isSuperAdmin = computed(() => this.authService.isSuperAdmin());
  tenantName = computed(() => this.tenant()?.name || 'Unknown');
  hasChanges = computed(() => {
    const tenant = this.tenant();
    if (!tenant) return false;
    const currentNS = tenant.default_nameservers || [];
    const newNS = this.nameservers();
    const currentTTL = tenant.default_nameserver_ttl || 0;
    const newTTL = this.nameserverTTL();
    
    if (currentNS.length !== newNS.length) return true;
    if (currentTTL !== newTTL) return true;
    return !currentNS.every((ns, i) => ns === newNS[i]);
  });

  constructor() {
    // React to tenant context changes
    effect(() => {
      const tenantId = this.tenantContext.currentTenantId();
      if (tenantId) {
        this.loadTenant();
      }
    });
  }

  ngOnInit() {
    this.loadTenant();
  }

  loadTenant() {
    this.loading.set(true);
    const tenantId = this.tenantContext.currentTenantId();
    
    this.authService.getTenant(tenantId).subscribe({
      next: (tenant) => {
        this.tenant.set(tenant);
        this.nameservers.set([...(tenant.default_nameservers || [])]);
        this.nameserverTTL.set(tenant.default_nameserver_ttl || 0);
        this.loading.set(false);
      },
      error: (err) => {
        console.error('Failed to load tenant:', err);
        this.snackBar.open('Failed to load nameserver settings', 'Dismiss', { duration: 3000 });
        this.loading.set(false);
      }
    });
  }

  addNameserver() {
    const ns = this.newNameserver.trim();
    if (ns && !this.nameservers().includes(ns)) {
      this.nameservers.update(arr => [...arr, ns]);
      this.newNameserver = '';
    }
  }

  removeNameserver(index: number) {
    this.nameservers.update(arr => {
      const newArr = [...arr];
      newArr.splice(index, 1);
      return newArr;
    });
  }

  save() {
    const tenant = this.tenant();
    if (!tenant) return;

    this.saving.set(true);
    
    this.authService.updateTenant(tenant.id, {
      name: tenant.name,
      description: tenant.description,
      default_nameservers: this.nameservers().length > 0 ? this.nameservers() : undefined,
      default_nameserver_ttl: this.nameserverTTL() || undefined
    }).subscribe({
      next: (updatedTenant) => {
        this.tenant.set(updatedTenant);
        this.nameservers.set([...(updatedTenant.default_nameservers || [])]);
        this.nameserverTTL.set(updatedTenant.default_nameserver_ttl || 0);
        this.snackBar.open('Nameserver settings saved', 'Dismiss', { duration: 3000 });
        this.saving.set(false);
      },
      error: (err) => {
        console.error('Failed to save:', err);
        this.snackBar.open('Failed to save nameserver settings', 'Dismiss', { duration: 3000 });
        this.saving.set(false);
      }
    });
  }

  reset() {
    const tenant = this.tenant();
    if (tenant) {
      this.nameservers.set([...(tenant.default_nameservers || [])]);
      this.nameserverTTL.set(tenant.default_nameserver_ttl || 0);
    }
  }
}
