import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatSelectModule } from '@angular/material/select';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatChipsModule } from '@angular/material/chips';
import { MatTooltipModule } from '@angular/material/tooltip';
import { ApiService, DynamicUpdateConfig, TsigKey } from '../services/api.service';

@Component({
  selector: 'app-dynamic-updates',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatIconModule,
    MatSlideToggleModule,
    MatSelectModule,
    MatSnackBarModule,
    MatChipsModule,
    MatTooltipModule
  ],
  templateUrl: './dynamic-updates.component.html',
  styleUrl: './dynamic-updates.component.scss'
})
export class DynamicUpdatesComponent implements OnInit {
  config: DynamicUpdateConfig = {
    enabled: false,
    allowed_nets: [],
    allowed_zones: [],
    tsig_keys: [],
    auto_ptr: true,
    allowed_types: ['A', 'AAAA', 'PTR', 'TXT'],
    logging: true
  };
  
  allRecordTypes = ['A', 'AAAA', 'PTR', 'TXT', 'CNAME', 'MX', 'SRV'];
  tsigAlgorithms = [
    { value: 'hmac-sha256.', label: 'HMAC-SHA256 (recommended)' },
    { value: 'hmac-sha512.', label: 'HMAC-SHA512' },
    { value: 'hmac-md5.sig-alg.reg.int.', label: 'HMAC-MD5 (legacy)' }
  ];
  
  newNetwork = '';
  newZone = '';
  newKey: TsigKey = { name: '', algorithm: 'hmac-sha256.', secret: '' };
  showKeySecret = false;
  
  loading = false;
  saving = false;

  constructor(
    private api: ApiService,
    private snackBar: MatSnackBar
  ) {}

  ngOnInit() {
    this.loadConfig();
  }

  loadConfig() {
    this.loading = true;
    this.api.getDynamicUpdateConfig().subscribe({
      next: (config) => {
        this.config = config || {
          enabled: false,
          allowed_nets: [],
          allowed_zones: [],
          tsig_keys: [],
          auto_ptr: true,
          allowed_types: ['A', 'AAAA', 'PTR', 'TXT'],
          logging: true
        };
        // Ensure arrays are always defined
        if (!this.config.allowed_nets) this.config.allowed_nets = [];
        if (!this.config.allowed_zones) this.config.allowed_zones = [];
        if (!this.config.tsig_keys) this.config.tsig_keys = [];
        if (!this.config.allowed_types) this.config.allowed_types = ['A', 'AAAA', 'PTR', 'TXT'];
        this.loading = false;
      },
      error: (err) => {
        console.error('Error loading config:', err);
        this.snackBar.open('Failed to load configuration', 'Dismiss', { duration: 5000 });
        this.loading = false;
      }
    });
  }

  saveConfig() {
    this.saving = true;
    this.api.updateDynamicUpdateConfig(this.config).subscribe({
      next: () => {
        this.snackBar.open('Configuration saved successfully', 'Dismiss', { duration: 3000 });
        this.saving = false;
      },
      error: (err) => {
        console.error('Error saving config:', err);
        this.snackBar.open('Failed to save configuration: ' + (err.error?.error || err.message), 'Dismiss', { duration: 5000 });
        this.saving = false;
      }
    });
  }

  // Network management
  addNetwork() {
    if (this.newNetwork && !this.config.allowed_nets.includes(this.newNetwork)) {
      // Basic CIDR validation
      if (this.validateCIDR(this.newNetwork)) {
        this.config.allowed_nets.push(this.newNetwork);
        this.newNetwork = '';
      } else {
        this.snackBar.open('Invalid CIDR format (e.g., 10.0.0.0/8 or 192.168.1.0/24)', 'Dismiss', { duration: 3000 });
      }
    }
  }

  removeNetwork(network: string) {
    const idx = this.config.allowed_nets.indexOf(network);
    if (idx >= 0) {
      this.config.allowed_nets.splice(idx, 1);
    }
  }

  validateCIDR(cidr: string): boolean {
    // Basic CIDR validation for IPv4 and IPv6
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    const ipv6Regex = /^([0-9a-fA-F:]+)\/\d{1,3}$/;
    return ipv4Regex.test(cidr) || ipv6Regex.test(cidr);
  }

  // Zone management
  addZone() {
    if (this.newZone && !this.config.allowed_zones?.includes(this.newZone)) {
      if (!this.config.allowed_zones) this.config.allowed_zones = [];
      this.config.allowed_zones.push(this.newZone);
      this.newZone = '';
    }
  }

  removeZone(zone: string) {
    if (!this.config.allowed_zones) return;
    const idx = this.config.allowed_zones.indexOf(zone);
    if (idx >= 0) {
      this.config.allowed_zones.splice(idx, 1);
    }
  }

  // TSIG Key management
  addKey() {
    if (this.newKey.name && this.newKey.secret) {
      const keyExists = this.config.tsig_keys.some(k => k.name === this.newKey.name);
      if (keyExists) {
        this.snackBar.open('A key with this name already exists', 'Dismiss', { duration: 3000 });
        return;
      }
      this.config.tsig_keys.push({ ...this.newKey });
      this.newKey = { name: '', algorithm: 'hmac-sha256.', secret: '' };
      this.showKeySecret = false;
    }
  }

  removeKey(keyName: string) {
    const idx = this.config.tsig_keys.findIndex(k => k.name === keyName);
    if (idx >= 0) {
      this.config.tsig_keys.splice(idx, 1);
    }
  }

  generateSecret() {
    // Generate a random 256-bit key, base64 encoded
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    this.newKey.secret = btoa(String.fromCharCode.apply(null, Array.from(array)));
  }

  toggleRecordType(type: string) {
    if (!this.config.allowed_types) this.config.allowed_types = [];
    const idx = this.config.allowed_types.indexOf(type);
    if (idx >= 0) {
      this.config.allowed_types.splice(idx, 1);
    } else {
      this.config.allowed_types.push(type);
    }
  }

  isTypeAllowed(type: string): boolean {
    return this.config.allowed_types?.includes(type) ?? false;
  }

  // Common network presets
  addPrivateNetworks() {
    const privateNets = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];
    for (const net of privateNets) {
      if (!this.config.allowed_nets.includes(net)) {
        this.config.allowed_nets.push(net);
      }
    }
  }

  addLocalhost() {
    const localhost = ['127.0.0.0/8', '::1/128'];
    for (const net of localhost) {
      if (!this.config.allowed_nets.includes(net)) {
        this.config.allowed_nets.push(net);
      }
    }
  }
}
