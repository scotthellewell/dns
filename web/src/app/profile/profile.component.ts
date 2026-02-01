import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTableModule } from '@angular/material/table';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatDividerModule } from '@angular/material/divider';
import { Router } from '@angular/router';
import { AuthService, AuthUser, WebAuthnCredential } from '../services/auth.service';

@Component({
  selector: 'app-profile',
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
    MatSnackBarModule,
    MatProgressSpinnerModule,
    MatTooltipModule,
    MatDividerModule
  ],
  templateUrl: './profile.component.html',
  styleUrl: './profile.component.scss'
})
export class ProfileComponent implements OnInit {
  private authService = inject(AuthService);
  private snackBar = inject(MatSnackBar);
  private router = inject(Router);

  user = signal<AuthUser | null>(null);
  loading = signal(false);
  credentials = signal<WebAuthnCredential[]>([]);
  
  // Password change
  currentPassword = '';
  newPassword = '';
  confirmPassword = '';
  changingPassword = signal(false);

  // Passkey registration
  registeringPasskey = signal(false);
  newPasskeyName = '';

  credentialColumns = ['name', 'created_at', 'last_used', 'actions'];

  ngOnInit() {
    this.loadProfile();
    this.loadCredentials();
  }

  loadProfile() {
    this.loading.set(true);
    this.authService.getCurrentUser().subscribe({
      next: (user) => {
        this.user.set(user);
        this.loading.set(false);
      },
      error: () => {
        this.snackBar.open('Failed to load profile', 'Dismiss', { duration: 3000 });
        this.loading.set(false);
      }
    });
  }

  loadCredentials() {
    this.authService.getWebAuthnCredentials().subscribe({
      next: (creds) => {
        this.credentials.set(creds);
      },
      error: () => {
        // WebAuthn might not be available
      }
    });
  }

  async changePassword() {
    if (!this.currentPassword || !this.newPassword) {
      this.snackBar.open('Please fill in all password fields', 'Dismiss', { duration: 3000 });
      return;
    }

    if (this.newPassword !== this.confirmPassword) {
      this.snackBar.open('New passwords do not match', 'Dismiss', { duration: 3000 });
      return;
    }

    if (this.newPassword.length < 8) {
      this.snackBar.open('Password must be at least 8 characters', 'Dismiss', { duration: 3000 });
      return;
    }

    this.changingPassword.set(true);
    this.authService.changePassword(this.currentPassword, this.newPassword).subscribe({
      next: () => {
        this.snackBar.open('Password changed successfully', 'Dismiss', { duration: 3000 });
        this.currentPassword = '';
        this.newPassword = '';
        this.confirmPassword = '';
        this.changingPassword.set(false);
      },
      error: (err) => {
        this.snackBar.open(err?.error?.error || 'Failed to change password', 'Dismiss', { duration: 3000 });
        this.changingPassword.set(false);
      }
    });
  }

  async registerPasskey() {
    if (!this.newPasskeyName.trim()) {
      this.snackBar.open('Please enter a name for the passkey', 'Dismiss', { duration: 3000 });
      return;
    }

    this.registeringPasskey.set(true);
    try {
      // Start registration
      const beginResp = await this.authService.beginWebAuthnRegistration().toPromise();
      
      // Prepare options for browser - go-webauthn returns { publicKey: {...} }
      const options = this.prepareCredentialCreationOptions(beginResp.publicKey);
      
      // Create credential in browser
      const credential = await navigator.credentials.create({ publicKey: options }) as PublicKeyCredential;
      
      // Serialize and send to server
      const credentialData = this.serializeCreatedCredential(credential);
      credentialData.name = this.newPasskeyName;
      
      await this.authService.finishWebAuthnRegistration(credentialData).toPromise();
      
      this.snackBar.open('Passkey registered successfully', 'Dismiss', { duration: 3000 });
      this.newPasskeyName = '';
      this.loadCredentials();
    } catch (error: any) {
      if (error.name === 'NotAllowedError') {
        this.snackBar.open('Passkey registration cancelled', 'Dismiss', { duration: 3000 });
      } else {
        this.snackBar.open(error?.error?.error || 'Failed to register passkey', 'Dismiss', { duration: 3000 });
      }
    } finally {
      this.registeringPasskey.set(false);
    }
  }

  removeCredential(credId: string) {
    if (!confirm('Are you sure you want to remove this passkey?')) {
      return;
    }

    this.authService.removeWebAuthnCredential(credId).subscribe({
      next: () => {
        this.snackBar.open('Passkey removed', 'Dismiss', { duration: 3000 });
        this.loadCredentials();
      },
      error: () => {
        this.snackBar.open('Failed to remove passkey', 'Dismiss', { duration: 3000 });
      }
    });
  }

  logout() {
    this.authService.logout().subscribe({
      next: () => {
        this.router.navigate(['/login']);
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

  private prepareCredentialCreationOptions(options: any): PublicKeyCredentialCreationOptions {
    return {
      ...options,
      challenge: this.base64UrlToBuffer(options.challenge),
      user: {
        ...options.user,
        id: this.base64UrlToBuffer(options.user.id)
      },
      excludeCredentials: options.excludeCredentials?.map((cred: any) => ({
        ...cred,
        id: this.base64UrlToBuffer(cred.id)
      }))
    };
  }

  private serializeCreatedCredential(credential: PublicKeyCredential): any {
    const response = credential.response as AuthenticatorAttestationResponse;
    return {
      id: credential.id,
      rawId: this.bufferToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: this.bufferToBase64Url(response.attestationObject),
        clientDataJSON: this.bufferToBase64Url(response.clientDataJSON)
      }
    };
  }

  private base64UrlToBuffer(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - base64.length % 4) % 4;
    const padded = base64 + '='.repeat(padLen);
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
  }

  private bufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
}
