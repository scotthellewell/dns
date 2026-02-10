import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatDividerModule } from '@angular/material/divider';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatChipsModule } from '@angular/material/chips';
import { MatSelectModule } from '@angular/material/select';
import { MatTableModule } from '@angular/material/table';
import { ApiService, PortsConfig, DNSPortConfig, DoTPortConfig, DoHPortConfig, WebPortConfig, CertificateInfo, CertificateListItem, GenerateCertRequest, ACMEConfig } from '../services/api.service';

@Component({
  selector: 'app-network',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatSlideToggleModule,
    MatIconModule,
    MatSnackBarModule,
    MatProgressSpinnerModule,
    MatDividerModule,
    MatTooltipModule,
    MatExpansionModule,
    MatChipsModule,
    MatSelectModule,
    MatTableModule
  ],
  templateUrl: './network.component.html',
  styleUrls: ['./network.component.scss']
})
export class NetworkComponent implements OnInit {
  loading = true;
  saving: { [key: string]: boolean } = {};

  portsConfig: PortsConfig = {
    dns: { enabled: true, port: 53, address: '' },
    dot: { enabled: false, port: 853, address: '' },
    doh: { enabled: false, port: 8443, address: '', path: '/dns-query', standalone: false },
    web: { enabled: true, port: 8080, address: '', tls: false }
  };

  // Certificate management
  certInfo: CertificateInfo | null = null;
  certificates: CertificateListItem[] = [];
  loadingCert = false;
  loadingCertificates = false;
  generatingCert = false;
  uploadingCert = false;
  requestingCertDomain: string | null = null;
  deletingCertDomain: string | null = null;
  generateRequest: GenerateCertRequest = {
    common_name: 'localhost',
    dns_names: ['localhost'],
    ip_addresses: ['127.0.0.1', '::1']
  };
  dnsNamesInput = 'localhost';
  ipAddressesInput = '127.0.0.1, ::1';

  // File upload
  certFileContent = '';
  keyFileContent = '';

  // ACME / Let's Encrypt
  acmeConfig: ACMEConfig = {
    enabled: false,
    email: '',
    domains: [],
    use_staging: true,
    challenge_type: 'dns-01',
    auto_renew: true,
    renew_before: 30
  };
  acmeDomainsInput = '';
  loadingAcme = false;
  requestingAcme = false;
  renewingAcme = false;
  savingAcme = false;

  constructor(
    private apiService: ApiService,
    private snackBar: MatSnackBar,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void {
    this.loadConfig();
    this.loadCertificate();
    this.loadCertificates();
    this.loadACMEConfig();
  }

  loadConfig(): void {
    this.loading = true;
    this.apiService.getPorts().subscribe({
      next: (config) => {
        this.portsConfig = config;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loading = false;
        this.cdr.detectChanges();
        this.snackBar.open('Failed to load port configuration', 'Close', { duration: 5000 });
        console.error('Failed to load ports config:', err);
      }
    });
  }

  loadCertificate(): void {
    this.loadingCert = true;
    this.apiService.getCertificate().subscribe({
      next: (cert) => {
        this.certInfo = cert;
        this.loadingCert = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loadingCert = false;
        this.cdr.detectChanges();
        console.error('Failed to load certificate info:', err);
      }
    });
  }

  loadCertificates(): void {
    this.loadingCertificates = true;
    this.apiService.listCertificates().subscribe({
      next: (certs) => {
        this.certificates = certs || [];
        this.loadingCertificates = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loadingCertificates = false;
        this.cdr.detectChanges();
        console.error('Failed to load certificates:', err);
      }
    });
  }

  requestCertificateForDomain(domain: string): void {
    this.requestingCertDomain = domain;
    this.apiService.requestCertificate(domain).subscribe({
      next: () => {
        this.requestingCertDomain = null;
        this.snackBar.open(`Certificate requested for ${domain}`, 'Close', { duration: 3000 });
        this.loadCertificates();
      },
      error: (err) => {
        this.requestingCertDomain = null;
        this.cdr.detectChanges();
        this.snackBar.open('Failed to request certificate: ' + (err.error?.error || err.message), 'Close', { duration: 5000 });
      }
    });
  }

  deleteCertificate(domain: string): void {
    if (!confirm(`Are you sure you want to delete the certificate for "${domain}"?`)) {
      return;
    }
    this.deletingCertDomain = domain;
    this.apiService.deleteCertificate(domain).subscribe({
      next: () => {
        this.deletingCertDomain = null;
        this.snackBar.open(`Certificate deleted for ${domain}`, 'Close', { duration: 3000 });
        this.loadCertificates();
      },
      error: (err) => {
        this.deletingCertDomain = null;
        this.cdr.detectChanges();
        this.snackBar.open('Failed to delete certificate: ' + (err.error?.error || err.message), 'Close', { duration: 5000 });
      }
    });
  }

  getCertStatusClass(cert: CertificateListItem): string {
    if (cert.is_expired) return 'status-expired';
    if (cert.is_expiring_soon) return 'status-expiring';
    return 'status-valid';
  }

  getCertStatusText(cert: CertificateListItem): string {
    if (cert.is_expired) return 'Expired';
    if (cert.is_expiring_soon) return `Expires in ${cert.days_until_expiry} days`;
    return `Valid (${cert.days_until_expiry} days)`;
  }

  generateCertificate(): void {
    // Parse the comma-separated inputs
    this.generateRequest.dns_names = this.dnsNamesInput.split(',').map(s => s.trim()).filter(s => s);
    this.generateRequest.ip_addresses = this.ipAddressesInput.split(',').map(s => s.trim()).filter(s => s);

    this.generatingCert = true;
    this.apiService.generateCertificate(this.generateRequest).subscribe({
      next: () => {
        this.generatingCert = false;
        this.snackBar.open('Self-signed certificate generated successfully', 'Close', { duration: 3000 });
        this.loadCertificate();
      },
      error: (err) => {
        this.generatingCert = false;
        this.cdr.detectChanges();
        this.snackBar.open('Failed to generate certificate: ' + (err.error || err.message), 'Close', { duration: 5000 });
      }
    });
  }

  onCertFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files[0]) {
      const reader = new FileReader();
      reader.onload = (e) => {
        this.certFileContent = e.target?.result as string;
        this.cdr.detectChanges();
      };
      reader.readAsText(input.files[0]);
    }
  }

  onKeyFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files[0]) {
      const reader = new FileReader();
      reader.onload = (e) => {
        this.keyFileContent = e.target?.result as string;
        this.cdr.detectChanges();
      };
      reader.readAsText(input.files[0]);
    }
  }

  uploadCertificate(): void {
    if (!this.certFileContent || !this.keyFileContent) {
      this.snackBar.open('Please select both certificate and private key files', 'Close', { duration: 3000 });
      return;
    }

    this.uploadingCert = true;
    this.apiService.uploadCertificate(this.certFileContent, this.keyFileContent).subscribe({
      next: () => {
        this.uploadingCert = false;
        this.certFileContent = '';
        this.keyFileContent = '';
        this.snackBar.open('Certificate uploaded successfully', 'Close', { duration: 3000 });
        this.loadCertificate();
      },
      error: (err) => {
        this.uploadingCert = false;
        this.cdr.detectChanges();
        this.snackBar.open('Failed to upload certificate: ' + (err.error || err.message), 'Close', { duration: 5000 });
      }
    });
  }

  getCertExpiryClass(): string {
    if (!this.certInfo) return '';
    if (this.certInfo.is_expired) return 'expired';
    if (this.certInfo.is_expiring_soon) return 'expiring-soon';
    return 'valid';
  }

  formatDate(dateStr: string): string {
    if (!dateStr) return '';
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  saveDNS(): void {
    this.saving['dns'] = true;
    this.apiService.updateDNSPort(this.portsConfig.dns).subscribe({
      next: () => {
        this.saving['dns'] = false;
        this.cdr.detectChanges();
        this.snackBar.open('DNS configuration saved', 'Close', { duration: 3000 });
      },
      error: (err) => {
        this.saving['dns'] = false;
        this.cdr.detectChanges();
        this.snackBar.open('Failed to save DNS configuration: ' + err.error, 'Close', { duration: 5000 });
      }
    });
  }

  saveDoT(): void {
    this.saving['dot'] = true;
    this.apiService.updateDoTPort(this.portsConfig.dot).subscribe({
      next: () => {
        this.saving['dot'] = false;
        this.cdr.detectChanges();
        this.snackBar.open('DoT configuration saved', 'Close', { duration: 3000 });
      },
      error: (err) => {
        this.saving['dot'] = false;
        this.cdr.detectChanges();
        this.snackBar.open('Failed to save DoT configuration: ' + err.error, 'Close', { duration: 5000 });
      }
    });
  }

  saveDoH(): void {
    this.saving['doh'] = true;
    this.apiService.updateDoHPort(this.portsConfig.doh).subscribe({
      next: () => {
        this.saving['doh'] = false;
        this.cdr.detectChanges();
        this.snackBar.open('DoH configuration saved', 'Close', { duration: 3000 });
      },
      error: (err) => {
        this.saving['doh'] = false;
        this.cdr.detectChanges();
        this.snackBar.open('Failed to save DoH configuration: ' + err.error, 'Close', { duration: 5000 });
      }
    });
  }

  saveWeb(): void {
    this.saving['web'] = true;
    this.apiService.updateWebPort(this.portsConfig.web).subscribe({
      next: () => {
        this.saving['web'] = false;
        this.cdr.detectChanges();
        this.snackBar.open('Web UI configuration saved. Note: Changes may require page refresh.', 'Close', { duration: 5000 });
      },
      error: (err) => {
        this.saving['web'] = false;
        this.cdr.detectChanges();
        this.snackBar.open('Failed to save Web UI configuration: ' + err.error, 'Close', { duration: 5000 });
      }
    });
  }

  // ACME / Let's Encrypt methods
  loadACMEConfig(): void {
    this.loadingAcme = true;
    this.apiService.getACMEConfig().subscribe({
      next: (config) => {
        this.acmeConfig = config;
        this.acmeDomainsInput = config.domains?.join(', ') || '';
        this.loadingAcme = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.loadingAcme = false;
        this.cdr.detectChanges();
        console.error('Failed to load ACME config:', err);
      }
    });
  }

  saveACMEConfig(): void {
    // Parse domains from input
    this.acmeConfig.domains = this.acmeDomainsInput
      .split(',')
      .map(s => s.trim())
      .filter(s => s);

    this.savingAcme = true;
    this.apiService.updateACMEConfig(this.acmeConfig).subscribe({
      next: () => {
        this.savingAcme = false;
        this.cdr.detectChanges();
        this.snackBar.open('ACME configuration saved', 'Close', { duration: 3000 });
      },
      error: (err) => {
        this.savingAcme = false;
        this.cdr.detectChanges();
        this.snackBar.open('Failed to save ACME configuration: ' + (err.error || err.message), 'Close', { duration: 5000 });
      }
    });
  }

  requestACMECertificate(): void {
    const domains = this.acmeDomainsInput
      .split(',')
      .map(s => s.trim())
      .filter(s => s);

    if (!this.acmeConfig.email) {
      this.snackBar.open('Email is required for ACME certificate request', 'Close', { duration: 3000 });
      return;
    }
    if (domains.length === 0) {
      this.snackBar.open('At least one domain is required', 'Close', { duration: 3000 });
      return;
    }

    // Update domains in config
    this.acmeConfig.domains = domains;

    this.requestingAcme = true;
    this.snackBar.open('Saving configuration and requesting certificate...', 'Close', { duration: 60000 });

    // Save config first, then request certificate
    this.apiService.updateACMEConfig(this.acmeConfig).subscribe({
      next: () => {
        // Now request the certificate
        this.apiService.requestACMECertificate(this.acmeConfig.email, domains).subscribe({
          next: () => {
            this.requestingAcme = false;
            this.cdr.detectChanges();
            this.snackBar.open('Certificate obtained successfully!', 'Close', { duration: 5000 });
            this.loadCertificate();
            this.loadACMEConfig();
          },
          error: (err) => {
            this.requestingAcme = false;
            this.cdr.detectChanges();
            this.snackBar.open('Failed to obtain certificate: ' + (err.error || err.message), 'Close', { duration: 10000 });
          }
        });
      },
      error: (err) => {
        this.requestingAcme = false;
        this.cdr.detectChanges();
        this.snackBar.open('Failed to save config: ' + (err.error || err.message), 'Close', { duration: 5000 });
      }
    });
  }

  renewACMECertificate(): void {
    this.renewingAcme = true;
    this.snackBar.open('Renewing certificate... This may take a minute.', 'Close', { duration: 60000 });

    this.apiService.renewACMECertificate().subscribe({
      next: () => {
        this.renewingAcme = false;
        this.cdr.detectChanges();
        this.snackBar.open('Certificate renewed successfully!', 'Close', { duration: 5000 });
        this.loadCertificate();
        this.loadACMEConfig();
      },
      error: (err) => {
        this.renewingAcme = false;
        this.cdr.detectChanges();
        this.snackBar.open('Failed to renew certificate: ' + (err.error || err.message), 'Close', { duration: 10000 });
      }
    });
  }
}
