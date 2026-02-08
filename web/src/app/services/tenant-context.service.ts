import { Injectable, signal, computed, inject, effect } from '@angular/core';
import { AuthService, Tenant } from './auth.service';

/**
 * TenantContextService manages the currently selected tenant context for super admins.
 * Regular users always operate in their own tenant context.
 * Super admins can switch between tenants using the tenant selector.
 */
@Injectable({
  providedIn: 'root'
})
export class TenantContextService {
  private authService = inject(AuthService);
  
  // The currently selected tenant ID (for super admins) or user's tenant
  private _selectedTenantId = signal<string>('');
  
  // All available tenants
  readonly tenants = signal<Tenant[]>([]);
  
  // Loading state
  readonly loading = signal(false);
  
  // The effective tenant ID (selected for super admins, user's tenant for others)
  readonly currentTenantId = computed(() => {
    if (this.authService.isSuperAdmin()) {
      return this._selectedTenantId() || this.authService.tenantId() || 'main';
    }
    return this.authService.tenantId() || 'main';
  });
  
  // The current tenant object
  readonly currentTenant = computed(() => {
    const tenantId = this.currentTenantId();
    return this.tenants().find(t => t.id === tenantId) || null;
  });
  
  // Whether the main tenant is currently selected
  readonly isMainTenantSelected = computed(() => {
    return this.currentTenantId() === 'main';
  });
  
  // Get the current tenant name
  readonly currentTenantName = computed(() => {
    return this.currentTenant()?.name || this.currentTenantId();
  });

  constructor() {
    // Load tenants when auth state changes
    effect(() => {
      if (this.authService.isAuthenticated()) {
        this.loadTenants();
      }
    });
  }

  /**
   * Load available tenants
   */
  loadTenants(): void {
    if (!this.authService.isAuthenticated()) return;
    
    this.loading.set(true);
    this.authService.getTenants().subscribe({
      next: (tenants) => {
        // Sort tenants: Main first, then alphabetically by name
        const sortedTenants = [...tenants].sort((a, b) => {
          // Main tenant always first
          if (a.is_main) return -1;
          if (b.is_main) return 1;
          // Then alphabetically by name
          return (a.name || a.id).localeCompare(b.name || b.id);
        });
        
        this.tenants.set(sortedTenants);
        
        // Initialize selected tenant if not set
        if (!this._selectedTenantId()) {
          const userTenant = this.authService.tenantId();
          const mainTenant = sortedTenants.find(t => t.is_main);
          this._selectedTenantId.set(userTenant || mainTenant?.id || 'main');
        }
        
        this.loading.set(false);
      },
      error: (err) => {
        console.error('Failed to load tenants', err);
        this.loading.set(false);
      }
    });
  }

  /**
   * Set the current tenant context (super admins only)
   */
  setTenant(tenantId: string): void {
    if (this.authService.isSuperAdmin()) {
      this._selectedTenantId.set(tenantId);
      // Store in localStorage for persistence
      localStorage.setItem('selected_tenant', tenantId);
    }
  }

  /**
   * Initialize from localStorage
   */
  initFromStorage(): void {
    const stored = localStorage.getItem('selected_tenant');
    if (stored && this.authService.isSuperAdmin()) {
      this._selectedTenantId.set(stored);
    }
  }

  /**
   * Get the selected tenant ID (for super admins)
   */
  getSelectedTenantId(): string {
    return this._selectedTenantId();
  }
}
