import { HttpInterceptorFn, HttpRequest, HttpHandlerFn, HttpEvent, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { Router } from '@angular/router';
import { AuthService } from './auth.service';

export const authInterceptor: HttpInterceptorFn = (
  request: HttpRequest<any>,
  next: HttpHandlerFn
): Observable<HttpEvent<any>> => {
  const authService = inject(AuthService);
  const router = inject(Router);

  // Skip auth header for auth status and login endpoints
  const skipAuth = ['/api/auth/status', '/api/auth/login', '/api/auth/logout', '/api/auth/oidc/providers'];
  if (skipAuth.some(url => request.url.includes(url))) {
    return next(request);
  }

  // Add auth token to request
  const token = authService.getToken();
  if (token) {
    request = request.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  return next(request).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status === 401) {
        // Only redirect to login if auth is enabled
        if (authService.authEnabled()) {
          router.navigate(['/login']);
        }
      }
      return throwError(() => error);
    })
  );
};
