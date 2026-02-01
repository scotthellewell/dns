import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from '../services/auth.service';
import { map, take } from 'rxjs/operators';

export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return authService.checkAuthStatus().pipe(
    take(1),
    map(status => {
      // If setup is needed, redirect to setup
      if (status.needs_setup) {
        router.navigate(['/setup']);
        return false;
      }

      // If auth is not enabled, allow access
      if (!status.auth_enabled) {
        return true;
      }

      // If authenticated, allow access
      if (status.authenticated) {
        return true;
      }

      // Redirect to login
      router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
      return false;
    })
  );
};

export const adminGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return authService.checkAuthStatus().pipe(
    take(1),
    map(status => {
      // If setup is needed, redirect to setup
      if (status.needs_setup) {
        router.navigate(['/setup']);
        return false;
      }

      // If auth is not enabled, allow access
      if (!status.auth_enabled) {
        return true;
      }

      // Check if authenticated and admin (including super_admin)
      const isAdmin = status.user?.role === 'admin' || 
                      status.user?.role === 'super_admin' || 
                      status.user?.is_super_admin === true;
      if (status.authenticated && isAdmin) {
        return true;
      }

      // If authenticated but not admin, show forbidden or redirect to dashboard
      if (status.authenticated) {
        router.navigate(['/dashboard']);
        return false;
      }

      // Redirect to login
      router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
      return false;
    })
  );
};

export const superAdminGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return authService.checkAuthStatus().pipe(
    take(1),
    map(status => {
      // If setup is needed, redirect to setup
      if (status.needs_setup) {
        router.navigate(['/setup']);
        return false;
      }

      // If auth is not enabled, allow access
      if (!status.auth_enabled) {
        return true;
      }

      // Check if authenticated and super admin
      const isSuperAdmin = status.user?.role === 'super_admin' || status.user?.is_super_admin === true;
      if (status.authenticated && isSuperAdmin) {
        return true;
      }

      // If authenticated but not super admin, redirect to dashboard
      if (status.authenticated) {
        router.navigate(['/dashboard']);
        return false;
      }

      // Redirect to login
      router.navigate(['/login'], { queryParams: { returnUrl: state.url } });
      return false;
    })
  );
};

export const loginGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return authService.checkAuthStatus().pipe(
    take(1),
    map(status => {
      // If setup is needed, redirect to setup
      if (status.needs_setup) {
        router.navigate(['/setup']);
        return false;
      }

      // If auth is not enabled, redirect to dashboard
      if (!status.auth_enabled) {
        router.navigate(['/dashboard']);
        return false;
      }

      // If already authenticated, redirect to dashboard
      if (status.authenticated) {
        router.navigate(['/dashboard']);
        return false;
      }

      return true;
    })
  );
};

export const setupGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  return authService.checkAuthStatus().pipe(
    take(1),
    map(status => {
      // Only allow access to setup if setup is needed
      if (status.needs_setup) {
        return true;
      }

      // If setup not needed, redirect to login or dashboard
      if (status.authenticated) {
        router.navigate(['/dashboard']);
      } else {
        router.navigate(['/login']);
      }
      return false;
    })
  );
};
