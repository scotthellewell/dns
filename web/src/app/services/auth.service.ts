import { Injectable, signal, computed } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, tap, catchError, of, BehaviorSubject } from 'rxjs';
import { Router } from '@angular/router';

export interface User {
  id: string;
  username: string;
  role: string;
  email?: string;
  display_name?: string;
  tenant_id?: string;
  tenant_name?: string;
  is_super_admin?: boolean;
}

export interface Tenant {
  id: string;
  name: string;
  description?: string;
  is_main?: boolean;
  created_at?: string;
  created_by?: string;
}

export interface AuthStatus {
  auth_enabled: boolean;
  authenticated: boolean;
  needs_setup?: boolean;
  user?: User;
  auth_method?: string;
  auth_methods?: string[];
  expires_at?: string;
}

export interface LoginResponse {
  success: boolean;
  token: string;
  user: User;
  expires_at: string;
}

export interface APIKey {
  id: string;
  name: string;
  key?: string; // Only returned on creation
  prefix: string;
  permissions: string[];
  created_at: string;
  expires_at?: string;
  last_used?: string;
  created_by: string;
}

export interface WebAuthnCredential {
  id: string;
  name: string;
  created_at: string;
  last_used?: string;
}

export interface OIDCProvider {
  id: string;
  name: string;
  icon?: string;
}

export interface AuthUser {
  id: string;
  username: string;
  role: string;
  email?: string;
  display_name?: string;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private baseUrl = '/api/auth';
  private authStatus = new BehaviorSubject<AuthStatus | null>(null);

  // Signals for reactive state
  readonly isAuthenticated = signal(false);
  readonly currentUser = signal<User | null>(null);
  readonly authEnabled = signal(false);
  readonly authMethods = signal<string[]>(['password']);
  readonly needsSetup = signal(false);

  readonly isAdmin = computed(() => {
    const user = this.currentUser();
    return user?.role === 'admin' || user?.role === 'super_admin' || user?.is_super_admin === true;
  });

  readonly isSuperAdmin = computed(() => {
    const user = this.currentUser();
    return user?.is_super_admin === true || user?.role === 'super_admin';
  });

  readonly tenantId = computed(() => this.currentUser()?.tenant_id || 'main');
  readonly tenantName = computed(() => this.currentUser()?.tenant_name || 'Main');

  constructor(
    private http: HttpClient,
    private router: Router
  ) {
    this.checkAuthStatus();
  }

  /**
   * Check current authentication status
   */
  checkAuthStatus(): Observable<AuthStatus> {
    return this.http.get<AuthStatus>(`${this.baseUrl}/status`).pipe(
      tap(status => {
        this.authStatus.next(status);
        this.authEnabled.set(status.auth_enabled);
        this.isAuthenticated.set(status.authenticated);
        this.currentUser.set(status.user || null);
        this.authMethods.set(status.auth_methods || ['password']);
        this.needsSetup.set(status.needs_setup || false);
      }),
      catchError(err => {
        console.error('Failed to check auth status', err);
        return of({
          auth_enabled: false,
          authenticated: false,
          auth_methods: ['password']
        } as AuthStatus);
      })
    );
  }

  /**
   * Login with username and password
   */
  login(username: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.baseUrl}/login`, { username, password }).pipe(
      tap(response => {
        if (response.success) {
          this.storeToken(response.token);
          this.isAuthenticated.set(true);
          this.currentUser.set(response.user);
        }
      })
    );
  }

  /**
   * Logout
   */
  logout(): Observable<any> {
    return this.http.post(`${this.baseUrl}/logout`, {}).pipe(
      tap(() => {
        this.clearToken();
        this.isAuthenticated.set(false);
        this.currentUser.set(null);
        this.router.navigate(['/login']);
      }),
      catchError(() => {
        this.clearToken();
        this.isAuthenticated.set(false);
        this.currentUser.set(null);
        this.router.navigate(['/login']);
        return of({ success: true });
      })
    );
  }

  /**
   * Get current user info
   */
  getMe(): Observable<User> {
    return this.http.get<User>(`${this.baseUrl}/me`);
  }

  /**
   * Change password
   */
  changePassword(currentPassword: string, newPassword: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/change-password`, {
      current_password: currentPassword,
      new_password: newPassword
    });
  }

  // ============ User Management (Admin) ============

  /**
   * List all users
   */
  getUsers(): Observable<User[]> {
    return this.http.get<User[]>(`${this.baseUrl}/users`);
  }

  /**
   * Create a new user
   */
  createUser(user: { username: string; password: string; email?: string; display_name?: string; role: string; tenant_id?: string }): Observable<User> {
    return this.http.post<User>(`${this.baseUrl}/users`, user);
  }

  /**
   * Update a user
   */
  updateUser(userId: string, updates: Partial<User & { password?: string }>): Observable<any> {
    return this.http.put(`${this.baseUrl}/users/${userId}`, updates);
  }

  /**
   * Delete a user
   */
  deleteUser(userId: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/users/${userId}`);
  }

  // ============ API Keys ============

  /**
   * List API keys
   */
  getAPIKeys(): Observable<APIKey[]> {
    return this.http.get<APIKey[]>(`${this.baseUrl}/apikeys`);
  }

  /**
   * Create a new API key
   */
  createAPIKey(name: string, permissions: string[], expiresAt?: Date): Observable<APIKey & { key: string }> {
    return this.http.post<APIKey & { key: string }>(`${this.baseUrl}/apikeys`, {
      name,
      permissions,
      expires_at: expiresAt?.toISOString()
    });
  }

  /**
   * Delete an API key
   */
  deleteAPIKey(keyId: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/apikeys/${keyId}`);
  }

  /**
   * Revoke an API key (alias for delete)
   */
  revokeAPIKey(keyId: string): Observable<any> {
    return this.deleteAPIKey(keyId);
  }

  // ============ WebAuthn/Passkeys ============

  /**
   * List WebAuthn credentials
   */
  getWebAuthnCredentials(): Observable<WebAuthnCredential[]> {
    return this.http.get<WebAuthnCredential[]>(`${this.baseUrl}/webauthn/credentials`);
  }

  /**
   * Remove a WebAuthn credential
   */
  removeWebAuthnCredential(credentialId: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/webauthn/credentials/${credentialId}`);
  }

  /**
   * Begin WebAuthn registration
   */
  beginWebAuthnRegistration(): Observable<any> {
    return this.http.post<any>(`${this.baseUrl}/webauthn/register/begin`, {});
  }

  /**
   * Finish WebAuthn registration
   */
  finishWebAuthnRegistration(credential: any): Observable<any> {
    const name = encodeURIComponent(credential.name || 'Passkey');
    return this.http.post(`${this.baseUrl}/webauthn/register/finish?name=${name}`, credential);
  }

  /**
   * Begin WebAuthn login
   */
  beginWebAuthnLogin(username?: string): Observable<any> {
    return this.http.post<any>(`${this.baseUrl}/webauthn/login/begin`, { username });
  }

  /**
   * Finish WebAuthn login
   */
  finishWebAuthnLogin(credential: any): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.baseUrl}/webauthn/login/finish`, credential).pipe(
      tap(response => {
        if (response.success) {
          this.storeToken(response.token);
          this.isAuthenticated.set(true);
          this.currentUser.set(response.user);
        }
      })
    );
  }

  /**
   * Begin passkey registration (alias)
   */
  beginPasskeyRegistration(): Observable<PublicKeyCredentialCreationOptions> {
    return this.beginWebAuthnRegistration();
  }

  /**
   * Finish passkey registration (alias)
   */
  finishPasskeyRegistration(credential: any, name: string): Observable<any> {
    credential.name = name;
    return this.finishWebAuthnRegistration(credential);
  }

  /**
   * Begin passkey login (alias)
   */
  beginPasskeyLogin(username?: string): Observable<PublicKeyCredentialRequestOptions> {
    return this.beginWebAuthnLogin(username);
  }

  /**
   * Finish passkey login (alias)
   */
  finishPasskeyLogin(credential: any): Observable<LoginResponse> {
    return this.finishWebAuthnLogin(credential);
  }

  /**
   * Delete a WebAuthn credential (alias)
   */
  deleteWebAuthnCredential(credentialId: string): Observable<any> {
    return this.removeWebAuthnCredential(credentialId);
  }

  // ============ OIDC ============

  /**
   * Get available OIDC providers
   */
  getOIDCProviders(): Observable<OIDCProvider[]> {
    return this.http.get<OIDCProvider[]>(`${this.baseUrl}/oidc/providers`);
  }

  /**
   * Login with OIDC provider
   */
  loginWithOIDC(providerId: string): Observable<{ redirect_url: string }> {
    return this.http.post<{ redirect_url: string }>(`${this.baseUrl}/oidc/login`, { provider_id: providerId });
  }

  /**
   * Initiate OIDC login (redirects to provider)
   */
  initiateOIDCLogin(returnUrl?: string): void {
    let url = `${this.baseUrl}/oidc/login`;
    if (returnUrl) {
      url += `?return_url=${encodeURIComponent(returnUrl)}`;
    }
    window.location.href = url;
  }

  /**
   * Get current authenticated user
   */
  getCurrentUser(): Observable<AuthUser> {
    return this.http.get<AuthUser>(`${this.baseUrl}/me`);
  }

  /**
   * Handle OIDC callback (called from callback route)
   */
  handleOIDCCallback(token: string): void {
    this.storeToken(token);
    this.checkAuthStatus().subscribe();
  }

  // ============ Token Management ============

  private storeToken(token: string): void {
    localStorage.setItem('auth_token', token);
  }

  private clearToken(): void {
    localStorage.removeItem('auth_token');
  }

  getToken(): string | null {
    return localStorage.getItem('auth_token');
  }

  /**
   * Get headers with auth token
   */
  getAuthHeaders(): HttpHeaders {
    const token = this.getToken();
    if (token) {
      return new HttpHeaders().set('Authorization', `Bearer ${token}`);
    }
    return new HttpHeaders();
  }

  // ============ Initial Setup ============

  /**
   * Check if setup is needed
   */
  checkSetupStatus(): Observable<{ needs_setup: boolean }> {
    return this.http.get<{ needs_setup: boolean }>(`${this.baseUrl}/setup-status`);
  }

  /**
   * Complete initial setup (creates super admin and main tenant)
   */
  setup(data: { username: string; password: string; email?: string; display_name?: string }): Observable<{ success: boolean; user: User; token: string }> {
    return this.http.post<{ success: boolean; user: User; token: string }>(`${this.baseUrl}/setup`, data).pipe(
      tap(response => {
        if (response.success) {
          this.storeToken(response.token);
          this.isAuthenticated.set(true);
          this.currentUser.set(response.user);
          this.needsSetup.set(false);
        }
      })
    );
  }

  // ============ Tenant Management (Super Admin) ============

  /**
   * List all tenants
   */
  getTenants(): Observable<Tenant[]> {
    return this.http.get<Tenant[]>(`${this.baseUrl}/tenants`);
  }

  /**
   * Get a single tenant
   */
  getTenant(tenantId: string): Observable<Tenant> {
    return this.http.get<Tenant>(`${this.baseUrl}/tenants/${tenantId}`);
  }

  /**
   * Create a new tenant
   */
  createTenant(tenant: { name: string; description?: string }): Observable<Tenant> {
    return this.http.post<Tenant>(`${this.baseUrl}/tenants`, tenant);
  }

  /**
   * Update a tenant
   */
  updateTenant(tenantId: string, updates: { name?: string; description?: string }): Observable<Tenant> {
    return this.http.put<Tenant>(`${this.baseUrl}/tenants/${tenantId}`, updates);
  }

  /**
   * Delete a tenant
   */
  deleteTenant(tenantId: string): Observable<{ success: boolean }> {
    return this.http.delete<{ success: boolean }>(`${this.baseUrl}/tenants/${tenantId}`);
  }

  /**
   * Get users for a specific tenant
   */
  getTenantUsers(tenantId: string): Observable<User[]> {
    return this.http.get<User[]>(`${this.baseUrl}/tenants/${tenantId}/users`);
  }
}
