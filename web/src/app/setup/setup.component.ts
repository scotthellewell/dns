import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { AuthService } from '../services/auth.service';

@Component({
  selector: 'app-setup',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule,
    MatProgressSpinnerModule,
    MatSnackBarModule
  ],
  templateUrl: './setup.component.html',
  styleUrl: './setup.component.scss'
})
export class SetupComponent {
  private authService = inject(AuthService);
  private router = inject(Router);
  private snackBar = inject(MatSnackBar);

  username = '';
  password = '';
  confirmPassword = '';
  email = '';
  displayName = '';
  loading = signal(false);
  hidePassword = signal(true);
  hideConfirmPassword = signal(true);

  ngOnInit() {
    // Check if setup is already complete
    this.authService.checkSetupStatus().subscribe({
      next: (status) => {
        if (!status.needs_setup) {
          this.router.navigate(['/login']);
        }
      },
      error: () => {
        // If we can't check, allow setup attempt
      }
    });
  }

  setup() {
    if (!this.username || !this.password) {
      this.snackBar.open('Username and password are required', 'Dismiss', { duration: 3000 });
      return;
    }

    if (this.password !== this.confirmPassword) {
      this.snackBar.open('Passwords do not match', 'Dismiss', { duration: 3000 });
      return;
    }

    if (this.password.length < 8) {
      this.snackBar.open('Password must be at least 8 characters', 'Dismiss', { duration: 3000 });
      return;
    }

    this.loading.set(true);

    this.authService.setup({
      username: this.username,
      password: this.password,
      email: this.email || undefined,
      display_name: this.displayName || undefined
    }).subscribe({
      next: () => {
        this.snackBar.open('Setup complete! Welcome to DNS Server Admin.', 'Dismiss', { duration: 3000 });
        this.router.navigate(['/dashboard']);
      },
      error: (err) => {
        this.loading.set(false);
        const message = err.error?.message || err.message || 'Setup failed';
        this.snackBar.open(message, 'Dismiss', { duration: 5000 });
      }
    });
  }
}
