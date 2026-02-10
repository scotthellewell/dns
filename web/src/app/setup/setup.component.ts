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
import { MatTabsModule } from '@angular/material/tabs';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSelectModule } from '@angular/material/select';
import { AuthService } from '../services/auth.service';
import { ToastService } from '../services/toast.service';

// ACME Provider definitions
interface ACMEProvider {
  id: string;
  name: string;
  requiresEAB: boolean;
  eabInstructions?: string;
}

const ACME_PROVIDERS: ACMEProvider[] = [
  { id: 'letsencrypt', name: "Let's Encrypt", requiresEAB: false },
  { id: 'zerossl', name: 'ZeroSSL', requiresEAB: true, eabInstructions: 'Get EAB credentials from https://zerossl.com/documentation/acme/' },
  { id: 'buypass', name: 'Buypass (180-day certs)', requiresEAB: false },
  { id: 'google', name: 'Google Trust Services', requiresEAB: true, eabInstructions: 'Get EAB credentials from Google Cloud Certificate Manager' }
];

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
    MatTabsModule,
    MatSlideToggleModule,
    MatSelectModule
  ],
  templateUrl: './setup.component.html',
  styleUrl: './setup.component.scss'
})
export class SetupComponent {
  private authService = inject(AuthService);
  private router = inject(Router);
  private toast = inject(ToastService);

  // New server setup fields
  username = '';
  password = '';
  confirmPassword = '';
  email = '';
  displayName = '';
  
  // Cluster join fields
  clusterUrl = '';
  clusterUsername = '';
  clusterPassword = '';
  serverUrl = '';
  serverName = '';
  
  // ACME certificate fields for cluster join
  acmeEmail = '';
  acmeDomain = '';
  acmeProvider = 'letsencrypt';
  acmeEABKeyID = '';
  acmeEABHMACKey = '';
  useStaging = false;
  
  // Available ACME providers
  acmeProviders = ACME_PROVIDERS;
  
  loading = signal(false);
  hidePassword = signal(true);
  hideConfirmPassword = signal(true);
  hideClusterPassword = signal(true);
  
  selectedTab = 0;

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
    
    // Try to auto-detect server URL and ACME domain
    this.serverUrl = window.location.origin;
    
    // Extract hostname for ACME domain (remove port if present)
    const hostname = window.location.hostname;
    // Only use as ACME domain if it's not localhost or an IP address
    if (hostname && hostname !== 'localhost' && !hostname.match(/^\d+\.\d+\.\d+\.\d+$/)) {
      this.acmeDomain = hostname;
    }
  }

  setup() {
    if (!this.username || !this.password) {
      this.toast.warning('Username and password are required');
      return;
    }

    if (this.password !== this.confirmPassword) {
      this.toast.warning('Passwords do not match');
      return;
    }

    if (this.password.length < 8) {
      this.toast.warning('Password must be at least 8 characters');
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
        this.toast.success('Setup complete! Welcome to DNS Server Admin.');
        this.router.navigate(['/dashboard']);
      },
      error: (err) => {
        this.loading.set(false);
        const message = err.error?.message || err.message || 'Setup failed';
        this.toast.error(message);
      }
    });
  }
  
  joinCluster() {
    if (!this.clusterUrl || !this.clusterUsername || !this.clusterPassword) {
      this.toast.warning('Cluster URL, username, and password are required');
      return;
    }
    
    if (!this.serverUrl) {
      this.toast.warning('Server URL is required (for other servers to connect back)');
      return;
    }
    
    if (!this.acmeEmail || !this.acmeDomain) {
      this.toast.warning('ACME email and domain are required for TLS certificate');
      return;
    }
    
    // Check if EAB credentials are required for the selected provider
    const selectedProvider = this.acmeProviders.find(p => p.id === this.acmeProvider);
    if (selectedProvider?.requiresEAB && (!this.acmeEABKeyID || !this.acmeEABHMACKey)) {
      this.toast.warning(`${selectedProvider.name} requires EAB credentials (Key ID and HMAC Key)`);
      return;
    }
    
    this.loading.set(true);
    
    this.authService.joinCluster({
      cluster_url: this.clusterUrl,
      username: this.clusterUsername,
      password: this.clusterPassword,
      server_url: this.serverUrl,
      server_name: this.serverName || undefined,
      acme_email: this.acmeEmail,
      acme_domain: this.acmeDomain,
      acme_staging: this.useStaging,
      acme_provider: this.acmeProvider,
      acme_eab_key_id: this.acmeEABKeyID || undefined,
      acme_eab_hmac_key: this.acmeEABHMACKey || undefined
    }).subscribe({
      next: (result) => {
        this.loading.set(false);
        this.toast.success('Successfully joined cluster! Redirecting...');
        // Force a hard navigation to ensure auth state is fully refreshed
        setTimeout(() => {
          window.location.href = '/dashboard';
        }, 1000);
      },
      error: (err) => {
        this.loading.set(false);
        const message = err.error?.message || err.error || err.message || 'Failed to join cluster';
        this.toast.error(message);
      }
    });
  }
  
  // Get the selected ACME provider
  getSelectedProvider(): ACMEProvider | undefined {
    return this.acmeProviders.find(p => p.id === this.acmeProvider);
  }
}
