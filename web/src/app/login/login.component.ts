import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatDividerModule } from '@angular/material/divider';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { AuthService, OIDCProvider } from '../services/auth.service';

@Component({
  selector: 'app-login',
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
    MatDividerModule,
    MatSnackBarModule
  ],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss'
})
export class LoginComponent {
  private authService = inject(AuthService);
  private router = inject(Router);
  private route = inject(ActivatedRoute);
  private snackBar = inject(MatSnackBar);

  username = '';
  password = '';
  loading = signal(false);
  hidePassword = signal(true);
  oidcProviders = signal<OIDCProvider[]>([]);
  passkeyAvailable = signal(false);

  private returnUrl = '/dashboard';

  ngOnInit() {
    this.returnUrl = this.route.snapshot.queryParams['returnUrl'] || '/dashboard';
    this.loadOIDCProviders();
    this.checkPasskeySupport();
  }

  private loadOIDCProviders() {
    this.authService.getOIDCProviders().subscribe({
      next: (providers) => {
        this.oidcProviders.set(providers);
      },
      error: () => {
        // OIDC might not be configured
      }
    });
  }

  private checkPasskeySupport() {
    // Check if WebAuthn is supported
    if (window.PublicKeyCredential) {
      // Check if user has a passkey registered by trying conditional UI
      PublicKeyCredential.isConditionalMediationAvailable?.().then(available => {
        this.passkeyAvailable.set(available || true); // Show button if WebAuthn is available
      });
    }
  }

  async login() {
    if (!this.username || !this.password) {
      this.snackBar.open('Please enter username and password', 'Dismiss', { duration: 3000 });
      return;
    }

    this.loading.set(true);
    try {
      await this.authService.login(this.username, this.password).toPromise();
      this.router.navigateByUrl(this.returnUrl);
    } catch (error: any) {
      this.snackBar.open(error?.error?.error || 'Login failed', 'Dismiss', { duration: 5000 });
    } finally {
      this.loading.set(false);
    }
  }

  async loginWithPasskey() {
    this.loading.set(true);
    try {
      // Start WebAuthn authentication
      const beginResp = await this.authService.beginWebAuthnLogin().toPromise();
      
      // Convert options for the browser - go-webauthn returns { publicKey: {...} }
      const options = this.prepareCredentialRequestOptions(beginResp.publicKey);
      
      // Get credential from browser
      const credential = await navigator.credentials.get({ publicKey: options }) as PublicKeyCredential;
      
      // Send to server
      const credentialData = this.serializeCredential(credential);
      await this.authService.finishWebAuthnLogin(credentialData).toPromise();
      
      this.router.navigateByUrl(this.returnUrl);
    } catch (error: any) {
      if (error.name === 'NotAllowedError') {
        this.snackBar.open('Passkey authentication cancelled', 'Dismiss', { duration: 3000 });
      } else {
        this.snackBar.open(error?.error?.error || 'Passkey login failed', 'Dismiss', { duration: 5000 });
      }
    } finally {
      this.loading.set(false);
    }
  }

  loginWithOIDC(provider: OIDCProvider) {
    this.loading.set(true);
    this.authService.loginWithOIDC(provider.id).subscribe({
      next: (response) => {
        // Redirect to OIDC provider
        window.location.href = response.redirect_url;
      },
      error: (error) => {
        this.loading.set(false);
        this.snackBar.open(error?.error?.error || 'Failed to start OIDC login', 'Dismiss', { duration: 5000 });
      }
    });
  }

  private prepareCredentialRequestOptions(options: any): PublicKeyCredentialRequestOptions {
    return {
      ...options,
      challenge: this.base64UrlToBuffer(options.challenge),
      allowCredentials: options.allowCredentials?.map((cred: any) => ({
        ...cred,
        id: this.base64UrlToBuffer(cred.id)
      }))
    };
  }

  private serializeCredential(credential: PublicKeyCredential): any {
    const response = credential.response as AuthenticatorAssertionResponse;
    return {
      id: credential.id,
      rawId: this.bufferToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: this.bufferToBase64Url(response.authenticatorData),
        clientDataJSON: this.bufferToBase64Url(response.clientDataJSON),
        signature: this.bufferToBase64Url(response.signature),
        userHandle: response.userHandle ? this.bufferToBase64Url(response.userHandle) : null
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
