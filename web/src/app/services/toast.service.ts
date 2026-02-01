import { Injectable, inject } from '@angular/core';
import { MatSnackBar, MatSnackBarConfig } from '@angular/material/snack-bar';

export type ToastType = 'success' | 'error' | 'info' | 'warning';

@Injectable({
  providedIn: 'root'
})
export class ToastService {
  private snackBar = inject(MatSnackBar);

  private readonly defaultConfig: MatSnackBarConfig = {
    horizontalPosition: 'right',
    verticalPosition: 'top',
  };

  /**
   * Show a success toast (auto-dismisses after 3 seconds)
   */
  success(message: string, action: string = 'OK'): void {
    this.snackBar.open(message, action, {
      ...this.defaultConfig,
      duration: 3000,
      panelClass: ['toast-success']
    });
  }

  /**
   * Show an info toast (auto-dismisses after 4 seconds)
   */
  info(message: string, action: string = 'OK'): void {
    this.snackBar.open(message, action, {
      ...this.defaultConfig,
      duration: 4000,
      panelClass: ['toast-info']
    });
  }

  /**
   * Show a warning toast (auto-dismisses after 5 seconds)
   */
  warning(message: string, action: string = 'OK'): void {
    this.snackBar.open(message, action, {
      ...this.defaultConfig,
      duration: 5000,
      panelClass: ['toast-warning']
    });
  }

  /**
   * Show an error toast (does NOT auto-dismiss - must be manually closed)
   */
  error(message: string, action: string = 'Dismiss'): void {
    this.snackBar.open(message, action, {
      ...this.defaultConfig,
      duration: 0, // 0 means it won't auto-dismiss
      panelClass: ['toast-error']
    });
  }

  /**
   * Dismiss the current toast
   */
  dismiss(): void {
    this.snackBar.dismiss();
  }
}
