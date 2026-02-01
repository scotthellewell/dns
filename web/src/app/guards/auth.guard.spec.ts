import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TestBed } from '@angular/core/testing';
import { Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { of, firstValueFrom, isObservable } from 'rxjs';
import { authGuard, adminGuard } from './auth.guard';
import { AuthService, AuthStatus } from '../services/auth.service';

describe('Auth Guards', () => {
  let authServiceMock: { checkAuthStatus: ReturnType<typeof vi.fn> };
  let routerMock: { navigate: ReturnType<typeof vi.fn> };
  let mockRoute: ActivatedRouteSnapshot;
  let mockState: RouterStateSnapshot;

  beforeEach(() => {
    authServiceMock = {
      checkAuthStatus: vi.fn(),
    };
    routerMock = {
      navigate: vi.fn(),
    };
    mockRoute = {} as ActivatedRouteSnapshot;
    mockState = { url: '/protected' } as RouterStateSnapshot;

    TestBed.configureTestingModule({
      providers: [
        { provide: AuthService, useValue: authServiceMock },
        { provide: Router, useValue: routerMock },
      ],
    });
  });

  async function runGuard(guard: typeof authGuard | typeof adminGuard): Promise<boolean | import('@angular/router').UrlTree> {
    return TestBed.runInInjectionContext(async () => {
      const result = guard(mockRoute, mockState);
      if (typeof result === 'boolean') {
        return result;
      }
      if (isObservable(result)) {
        return firstValueFrom(result);
      }
      return result;
    }) as Promise<boolean | import('@angular/router').UrlTree>;
  }

  describe('authGuard', () => {
    it('should allow access when auth is disabled', async () => {
      const status: AuthStatus = {
        auth_enabled: false,
        authenticated: false,
      };
      authServiceMock.checkAuthStatus.mockReturnValue(of(status));

      const result = await runGuard(authGuard);
      expect(result).toBe(true);
    });

    it('should allow access when authenticated', async () => {
      const status: AuthStatus = {
        auth_enabled: true,
        authenticated: true,
        user: { id: '1', username: 'test', role: 'user' },
      };
      authServiceMock.checkAuthStatus.mockReturnValue(of(status));

      const result = await runGuard(authGuard);
      expect(result).toBe(true);
    });

    it('should redirect to login when not authenticated', async () => {
      const status: AuthStatus = {
        auth_enabled: true,
        authenticated: false,
      };
      authServiceMock.checkAuthStatus.mockReturnValue(of(status));

      const result = await runGuard(authGuard);
      expect(result).toBe(false);
      expect(routerMock.navigate).toHaveBeenCalledWith(['/login'], {
        queryParams: { returnUrl: '/protected' },
      });
    });

    it('should redirect to setup when setup is needed', async () => {
      const status: AuthStatus = {
        auth_enabled: true,
        authenticated: false,
        needs_setup: true,
      };
      authServiceMock.checkAuthStatus.mockReturnValue(of(status));

      const result = await runGuard(authGuard);
      expect(result).toBe(false);
      expect(routerMock.navigate).toHaveBeenCalledWith(['/setup']);
    });
  });

  describe('adminGuard', () => {
    it('should allow access for admin users', async () => {
      const status: AuthStatus = {
        auth_enabled: true,
        authenticated: true,
        user: { id: '1', username: 'admin', role: 'admin' },
      };
      authServiceMock.checkAuthStatus.mockReturnValue(of(status));

      const result = await runGuard(adminGuard);
      expect(result).toBe(true);
    });

    it('should allow access for super_admin users', async () => {
      const status: AuthStatus = {
        auth_enabled: true,
        authenticated: true,
        user: { id: '1', username: 'superadmin', role: 'super_admin', is_super_admin: true },
      };
      authServiceMock.checkAuthStatus.mockReturnValue(of(status));

      const result = await runGuard(adminGuard);
      expect(result).toBe(true);
    });

    it('should deny access for regular users', async () => {
      const status: AuthStatus = {
        auth_enabled: true,
        authenticated: true,
        user: { id: '1', username: 'user', role: 'user' },
      };
      authServiceMock.checkAuthStatus.mockReturnValue(of(status));

      const result = await runGuard(adminGuard);
      expect(result).toBe(false);
    });
  });
});
