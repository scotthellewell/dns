import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatChipsModule } from '@angular/material/chips';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatSelectModule } from '@angular/material/select';
import { MatExpansionModule } from '@angular/material/expansion';
import { ApiService, TransferConfig, TsigKey, TransferAcl, NotifyTarget } from '../services/api.service';

@Component({
  selector: 'app-transfer',
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
    MatChipsModule,
    MatSnackBarModule,
    MatSelectModule,
    MatExpansionModule
  ],
  templateUrl: './transfer.component.html',
  styleUrl: './transfer.component.scss'
})
export class TransferComponent implements OnInit {
  config: TransferConfig = {
    enabled: false,
    tsig_keys: [],
    acls: [],
    notify_targets: []
  };
  
  // New TSIG Key form
  newTsigKey: TsigKey = { name: '', algorithm: 'hmac-sha256', secret: '' };
  
  // New ACL form
  newAcl: TransferAcl = { zone: '', allow_transfer: [], allow_notify: [], tsig_key: '' };
  newAclTransferIp = '';
  newAclNotifyIp = '';
  
  // New Notify Target form
  newNotify: NotifyTarget = { zone: '', targets: [], tsig_key: '' };
  newNotifyTarget = '';
  
  // Algorithm options
  algorithms = ['hmac-md5', 'hmac-sha1', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512'];
  
  loading = false;
  saving = false;

  constructor(
    private api: ApiService,
    private snackBar: MatSnackBar,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.loadConfig();
  }

  loadConfig() {
    this.loading = true;
    this.api.getTransferConfig().subscribe({
      next: (config) => {
        this.config = config || {
          enabled: false,
          tsig_keys: [],
          acls: [],
          notify_targets: []
        };
        // Ensure arrays exist
        if (!this.config.tsig_keys) this.config.tsig_keys = [];
        if (!this.config.acls) this.config.acls = [];
        if (!this.config.notify_targets) this.config.notify_targets = [];
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to load transfer config', 'Close', { duration: 3000 });
        console.error(err);
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  saveConfig() {
    this.saving = true;
    this.api.updateTransferConfig(this.config).subscribe({
      next: () => {
        this.snackBar.open('Transfer settings saved', 'Close', { duration: 3000 });
        this.saving = false;
      },
      error: (err) => {
        this.snackBar.open('Failed to save settings', 'Close', { duration: 3000 });
        console.error(err);
        this.saving = false;
      }
    });
  }

  // TSIG Key methods
  addTsigKey() {
    if (this.newTsigKey.name && this.newTsigKey.secret) {
      this.config.tsig_keys.push({ ...this.newTsigKey });
      this.newTsigKey = { name: '', algorithm: 'hmac-sha256', secret: '' };
    }
  }

  removeTsigKey(index: number) {
    this.config.tsig_keys.splice(index, 1);
  }

  // ACL methods
  addAclTransferIp() {
    if (this.newAclTransferIp && !this.newAcl.allow_transfer?.includes(this.newAclTransferIp)) {
      if (!this.newAcl.allow_transfer) this.newAcl.allow_transfer = [];
      this.newAcl.allow_transfer.push(this.newAclTransferIp);
      this.newAclTransferIp = '';
    }
  }

  removeAclTransferIp(ip: string) {
    if (this.newAcl.allow_transfer) {
      this.newAcl.allow_transfer = this.newAcl.allow_transfer.filter(i => i !== ip);
    }
  }

  addAclNotifyIp() {
    if (this.newAclNotifyIp && !this.newAcl.allow_notify?.includes(this.newAclNotifyIp)) {
      if (!this.newAcl.allow_notify) this.newAcl.allow_notify = [];
      this.newAcl.allow_notify.push(this.newAclNotifyIp);
      this.newAclNotifyIp = '';
    }
  }

  removeAclNotifyIp(ip: string) {
    if (this.newAcl.allow_notify) {
      this.newAcl.allow_notify = this.newAcl.allow_notify.filter(i => i !== ip);
    }
  }

  addAcl() {
    if (this.newAcl.zone) {
      this.config.acls.push({ ...this.newAcl });
      this.newAcl = { zone: '', allow_transfer: [], allow_notify: [], tsig_key: '' };
    }
  }

  removeAcl(index: number) {
    this.config.acls.splice(index, 1);
  }

  // Notify Target methods
  addNotifyTargetAddress() {
    if (this.newNotifyTarget && !this.newNotify.targets.includes(this.newNotifyTarget)) {
      this.newNotify.targets.push(this.newNotifyTarget);
      this.newNotifyTarget = '';
    }
  }

  removeNotifyTargetAddress(target: string) {
    this.newNotify.targets = this.newNotify.targets.filter(t => t !== target);
  }

  addNotifyEntry() {
    if (this.newNotify.zone && this.newNotify.targets.length > 0) {
      if (!this.config.notify_targets) this.config.notify_targets = [];
      this.config.notify_targets.push({ ...this.newNotify });
      this.newNotify = { zone: '', targets: [], tsig_key: '' };
    }
  }

  removeNotifyEntry(index: number) {
    if (this.config.notify_targets) {
      this.config.notify_targets.splice(index, 1);
    }
  }

  getTsigKeyNames(): string[] {
    return this.config.tsig_keys.map(k => k.name);
  }
}
