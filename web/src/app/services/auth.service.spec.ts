import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { TestBed, fakeAsync, tick, flush } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { Router } from '@angular/router';
import { AuthService, AuthStatus, User, LoginResponse } from './auth.service';

describe('AuthService', () => {
  let service: AuthService;
  let httpMock: HttpTestingController;
  let routerSpy: { navigate: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    routerSpy = { navigate: vi.fn() };

    TestBed.configureTestingModule({
      providers: [
        AuthService,
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: Router, useValue: routerSpy },
      ],
    });

    service = TestBed.inject(AuthService);
    httpMock = TestBed.inject(HttpTestingController);

    // Handle the initial checkAuthStatus call if it happens
    const reqs = httpMock.match('/api/auth/status');
    reqs.forEach(req => {
      req.flush({
        auth_enabled: true,
        authenticated: false,
        auth_methods: ['password'],
      } as AuthStatus);
    });
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should have initial state as not authenticated', () => {
    expect(service.isAuthenticated()).toBe(false);
    expect(service.currentUser()).toBeNull();
  });

  it('should set authEnabled from status after checking', () => {
    // Trigger a fresh status check
    service.checkAuthStatus().subscribe();
    const req = httpMock.expectOne('/api/auth/status');
    req.flush({ auth_enabled: true, authenticated: false } as AuthStatus);
    expect(service.authEnabled()).toBe(true);
  });

  describe('login', () => {
    it('should authenticate user on successful login', () => {
      const mockUser: User = {
        id: 'user-1',
        username: 'testuser',
        role: 'admin',
      };
      const mockResponse: LoginResponse = {
        success: true,
        token: 'test-token',
        user: mockUser,
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      };

      service.login('testuser', 'password123').subscribe(response => {
        expect(response.success).toBe(true);
        expect(response.user.username).toBe('testuser');
      });

      const req = httpMock.expectOne('/api/auth/login');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual({ username: 'testuser', password: 'password123' });
      req.flush(mockResponse);

      expect(service.isAuthenticated()).toBe(true);
      expect(service.currentUser()?.username).toBe('testuser');
    });

    it('should handle login failure', () => {
      service.login('baduser', 'wrongpassword').subscribe({
        error: err => {
          expect(err.status).toBe(401);
        },
      });

      const req = httpMock.expectOne('/api/auth/login');
      req.flush({ error: 'Invalid credentials' }, { status: 401, statusText: 'Unauthorized' });

      expect(service.isAuthenticated()).toBe(false);
    });
  });

  describe('logout', () => {
    it('should clear authentication state on logout', () => {
      // First set authenticated state
      service.isAuthenticated.set(true);
      service.currentUser.set({ id: '1', username: 'test', role: 'user' });

      service.logout().subscribe();

      const req = httpMock.expectOne('/api/auth/logout');
      req.flush({ success: true });

      expect(service.isAuthenticated()).toBe(false);
      expect(service.currentUser()).toBeNull();
      expect(routerSpy.navigate).toHaveBeenCalledWith(['/login']);
    });
  });

  describe('isAdmin computed', () => {
    it('should return true for admin role', () => {
      service.currentUser.set({ id: '1', username: 'admin', role: 'admin' });
      expect(service.isAdmin()).toBe(true);
    });

    it('should return true for super_admin role', () => {
      service.currentUser.set({ id: '1', username: 'superadmin', role: 'super_admin' });
      expect(service.isAdmin()).toBe(true);
    });

    it('should return true for is_super_admin flag', () => {
      service.currentUser.set({ id: '1', username: 'user', role: 'user', is_super_admin: true });
      expect(service.isAdmin()).toBe(true);
    });

    it('should return false for regular user', () => {
      service.currentUser.set({ id: '1', username: 'user', role: 'user' });
      expect(service.isAdmin()).toBe(false);
    });

    it('should return false when no user', () => {
      service.currentUser.set(null);
      expect(service.isAdmin()).toBe(false);
    });
  });

  describe('isSuperAdmin computed', () => {
    it('should return true for super_admin role', () => {
      service.currentUser.set({ id: '1', username: 'superadmin', role: 'super_admin' });
      expect(service.isSuperAdmin()).toBe(true);
    });

    it('should return true for is_super_admin flag', () => {
      service.currentUser.set({ id: '1', username: 'user', role: 'user', is_super_admin: true });
      expect(service.isSuperAdmin()).toBe(true);
    });

    it('should return false for admin (not super)', () => {
      service.currentUser.set({ id: '1', username: 'admin', role: 'admin' });
      expect(service.isSuperAdmin()).toBe(false);
    });
  });

  describe('tenantId computed', () => {
    it('should return tenant_id when user has one', () => {
      service.currentUser.set({ id: '1', username: 'user', role: 'user', tenant_id: 'tenant-123' });
      expect(service.tenantId()).toBe('tenant-123');
    });

    it('should return main when no tenant_id', () => {
      service.currentUser.set({ id: '1', username: 'user', role: 'user' });
      expect(service.tenantId()).toBe('main');
    });
  });
});
