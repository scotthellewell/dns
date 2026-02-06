import { Component, OnInit, ChangeDetectorRef, inject, ViewChild, ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService, Zone, ZoneType, DnssecZone, DnssecKeyImport } from '../services/api.service';
import { ToastService } from '../services/toast.service';
import { AuthService, Tenant } from '../services/auth.service';

@Component({
  selector: 'app-zones',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './zones.component.html',
  styleUrls: ['./zones.component.scss']
})
export class ZonesComponent implements OnInit {
  private toast = inject(ToastService);
  readonly auth = inject(AuthService);
  
  @ViewChild('keyFileInput') keyFileInput!: ElementRef<HTMLInputElement>;
  
  zones: Zone[] = [];
  filteredZones: Zone[] = [];
  tenants: Tenant[] = [];
  selectedTenant = '';
  dnssecZones: Map<string, DnssecZone> = new Map();
  showForm = false;
  saving = false;
  editingZone: Zone | null = null;
  
  // DNSSEC form state
  dnssecEnabled = false;
  dnssecAlgorithm = 'ECDSAP256SHA256';
  dnssecLoading = false;
  currentDnssec: DnssecZone | null = null;
  keyToken: string | null = null;      // Current key token (full or masked)
  showKeyToken = false;                 // Whether token was just generated (show full)
  
  algorithms = [
    { value: 'ECDSAP256SHA256', label: 'ECDSA P-256 (Recommended)' },
    { value: 'ECDSAP384SHA384', label: 'ECDSA P-384' },
    { value: 'ED25519', label: 'Ed25519' }
  ];
  
  formData: Zone = {
    name: '',
    type: 'forward',
    subnet: '',
    strip_prefix: false,
    ttl: 3600
  };

  constructor(private api: ApiService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.loadTenants();
    this.loadZones();
    this.loadDnssecConfig();
  }

  loadTenants(): void {
    if (!this.auth.isSuperAdmin()) return;
    
    this.auth.getTenants().subscribe({
      next: (tenants) => {
        this.tenants = tenants;
        // Default to main tenant
        const mainTenant = tenants.find(t => t.is_main);
        if (mainTenant && !this.selectedTenant) {
          this.selectedTenant = mainTenant.id;
          this.filterZones();
        }
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error('Failed to load tenants', err);
      }
    });
  }

  onTenantFilterChange(): void {
    this.filterZones();
  }

  filterZones(): void {
    if (!this.selectedTenant || !this.auth.isSuperAdmin()) {
      this.filteredZones = this.zones;
    } else {
      this.filteredZones = this.zones.filter(z => z.tenant_id === this.selectedTenant);
    }
    this.cdr.detectChanges();
  }

  loadZones(): void {
    this.api.getZones().subscribe({
      next: (zones) => {
        this.zones = zones;
        this.filterZones();
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.toast.error('Failed to load zones');
        this.cdr.detectChanges();
      }
    });
  }

  loadDnssecConfig(): void {
    this.api.getDnssecConfig().subscribe({
      next: (dnssecZones) => {
        this.dnssecZones.clear();
        for (const z of dnssecZones) {
          this.dnssecZones.set(z.zone, z);
        }
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error('Failed to load DNSSEC config:', err);
      }
    });
  }

  hasDnssec(zoneName: string): boolean {
    const dnssec = this.dnssecZones.get(zoneName);
    return dnssec?.enabled ?? false;
  }

  get forwardZones(): Zone[] {
    return this.filteredZones.filter(z => z.type === 'forward');
  }

  get reverseZones(): Zone[] {
    return this.filteredZones.filter(z => z.type === 'reverse');
  }

  openAddForm(type: ZoneType = 'forward'): void {
    this.formData = {
      name: '',
      type: type,
      subnet: '',
      strip_prefix: false,
      ttl: 3600
    };
    this.editingZone = null;
    this.showForm = true;
  }

  openEditForm(zone: Zone): void {
    this.formData = { ...zone };
    this.editingZone = zone;
    this.showForm = true;
    this.keyToken = null;
    this.showKeyToken = false;
    
    // Load DNSSEC state for this zone
    const dnssec = this.dnssecZones.get(zone.name);
    if (dnssec) {
      this.dnssecEnabled = dnssec.enabled;
      this.dnssecAlgorithm = dnssec.algorithm || 'ECDSAP256SHA256';
      this.currentDnssec = dnssec;
      
      // Load key token info if DNSSEC is enabled
      if (dnssec.enabled) {
        this.loadKeyToken(zone.name);
      }
    } else {
      this.dnssecEnabled = false;
      this.dnssecAlgorithm = 'ECDSAP256SHA256';
      this.currentDnssec = null;
    }
  }

  closeForm(): void {
    this.showForm = false;
    this.editingZone = null;
    this.dnssecEnabled = false;
    this.dnssecAlgorithm = 'ECDSAP256SHA256';
    this.currentDnssec = null;
    this.keyToken = null;
    this.showKeyToken = false;
  }

  saveZone(): void {
    if (this.saving) return; // Prevent double-submit
    this.saving = true;

    const zoneId = this.editingZone?.zone_id || this.editingZone?.id;
    if (this.editingZone !== null && zoneId !== undefined) {
      this.api.updateZone(zoneId, this.formData).subscribe({
        next: () => {
          // Handle DNSSEC changes
          this.saveDnssecIfNeeded();
        },
        error: (err) => {
          this.saving = false;
          this.toast.error(err.error?.error || 'Failed to update zone');
          this.cdr.detectChanges();
        }
      });
    } else {
      this.api.addZone(this.formData).subscribe({
        next: () => {
          // For new zones, handle DNSSEC if enabled
          if (this.dnssecEnabled && this.formData.name) {
            this.api.enableDnssec(this.formData.name, this.dnssecAlgorithm).subscribe({
              next: () => {
                this.saving = false;
                this.toast.success('Zone created with DNSSEC enabled');
                this.loadZones();
                this.loadDnssecConfig();
                this.closeForm();
              },
              error: (err) => {
                this.saving = false;
                this.toast.success('Zone created, but DNSSEC failed to enable');
                this.loadZones();
                this.closeForm();
              }
            });
          } else {
            this.saving = false;
            this.toast.success('Zone created successfully');
            this.loadZones();
            this.closeForm();
          }
        },
        error: (err) => {
          this.saving = false;
          this.toast.error(err.error?.error || 'Failed to add zone');
          this.cdr.detectChanges();
        }
      });
    }
  }

  saveDnssecIfNeeded(): void {
    const zoneName = this.formData.name;
    const hadDnssec = this.currentDnssec?.enabled ?? false;
    
    if (this.dnssecEnabled && !hadDnssec) {
      // Enable DNSSEC
      this.api.enableDnssec(zoneName, this.dnssecAlgorithm).subscribe({
        next: (result) => {
          this.saving = false;
          this.toast.success('Zone updated with DNSSEC enabled');
          this.loadZones();
          this.loadDnssecConfig();
          // Update currentDnssec to show DS record immediately
          this.currentDnssec = result;
          this.cdr.detectChanges();
        },
        error: (err) => {
          this.saving = false;
          this.toast.error('Zone updated, but DNSSEC failed');
          this.loadZones();
          this.closeForm();
        }
      });
    } else if (!this.dnssecEnabled && hadDnssec) {
      // Disable DNSSEC
      this.api.deleteDnssec(zoneName).subscribe({
        next: () => {
          this.saving = false;
          this.toast.success('Zone updated, DNSSEC disabled');
          this.loadZones();
          this.loadDnssecConfig();
          this.closeForm();
        },
        error: (err) => {
          this.saving = false;
          this.toast.error('Zone updated, but failed to disable DNSSEC');
          this.loadZones();
          this.closeForm();
        }
      });
    } else {
      this.saving = false;
      this.toast.success('Zone updated successfully');
      this.loadZones();
      this.closeForm();
    }
  }

  // View DS record from table
  showDsRecord: DnssecZone | null = null;
  
  viewDsRecord(zoneName: string): void {
    const dnssec = this.dnssecZones.get(zoneName);
    if (dnssec) {
      this.showDsRecord = dnssec;
    }
  }

  closeDsModal(): void {
    this.showDsRecord = null;
  }

  copyDsRecordFromModal(): void {
    if (this.showDsRecord?.ds_record) {
      navigator.clipboard.writeText(this.showDsRecord.ds_record).then(() => {
        this.toast.success('DS record copied to clipboard');
      });
    }
  }

  copyDsRecord(): void {
    if (this.currentDnssec?.ds_record) {
      navigator.clipboard.writeText(this.currentDnssec.ds_record).then(() => {
        this.toast.success('DS record copied to clipboard');
      });
    }
  }

  // Key Download/Upload for Secondary Servers
  downloadKeys(): void {
    const zoneName = this.formData.name;
    if (!zoneName) return;

    this.api.exportDnssecKeys(zoneName).subscribe({
      next: (keys) => {
        const blob = new Blob([JSON.stringify(keys, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `dnssec-keys-${zoneName.replace(/\./g, '-')}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        this.toast.success('Keys downloaded successfully');
      },
      error: (err) => {
        this.toast.error(err.error?.error || 'Failed to download keys');
      }
    });
  }

  triggerKeyUpload(): void {
    this.keyFileInput.nativeElement.click();
  }

  uploadKeys(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (!input.files?.length) return;

    const file = input.files[0];
    const zoneName = this.formData.name;
    if (!zoneName) return;

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const keys = JSON.parse(reader.result as string) as DnssecKeyImport;
        this.api.importDnssecKeys(zoneName, keys).subscribe({
          next: () => {
            this.toast.success('Keys imported successfully');
            this.loadDnssecConfig();
            // Update current DNSSEC state
            const dnssec = this.dnssecZones.get(zoneName);
            if (dnssec) {
              this.currentDnssec = dnssec;
              this.dnssecEnabled = true;
            }
            this.cdr.detectChanges();
          },
          error: (err) => {
            this.toast.error(err.error?.error || 'Failed to import keys');
          }
        });
      } catch (e) {
        this.toast.error('Invalid key file format');
      }
      input.value = ''; // Reset file input
    };
    reader.readAsText(file);
  }

  deleteZone(zone: Zone): void {
    const zoneId = zone.zone_id || zone.id;
    if (zoneId === undefined) return;
    if (!confirm(`Delete zone ${zone.name}?`)) return;

    this.api.deleteZone(zoneId).subscribe({
      next: () => {
        this.toast.success('Zone deleted successfully');
        this.loadZones();
      },
      error: (err) => {
        this.toast.error('Failed to delete zone');
      }
    });
  }

  // Key Token Management
  loadKeyToken(zoneName: string): void {
    this.api.getKeyToken(zoneName).subscribe({
      next: (info) => {
        if (info.has_token) {
          this.keyToken = info.token;
          this.showKeyToken = false;
        } else {
          this.keyToken = null;
        }
        this.cdr.detectChanges();
      },
      error: () => {
        this.keyToken = null;
      }
    });
  }

  generateKeyToken(): void {
    const zoneName = this.formData.name;
    if (!zoneName) return;

    this.api.generateKeyToken(zoneName).subscribe({
      next: (response) => {
        this.keyToken = response.token;
        this.showKeyToken = true;  // Show full token once
        this.toast.success('Key sharing token generated');
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.toast.error(err.error?.error || 'Failed to generate token');
      }
    });
  }

  revokeKeyToken(): void {
    const zoneName = this.formData.name;
    if (!zoneName) return;

    if (!confirm('Revoke this token? Secondary servers using it will no longer be able to fetch keys.')) return;

    this.api.revokeKeyToken(zoneName).subscribe({
      next: () => {
        this.keyToken = null;
        this.showKeyToken = false;
        this.toast.success('Key sharing token revoked');
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.toast.error(err.error?.error || 'Failed to revoke token');
      }
    });
  }

  copyKeyToken(): void {
    if (this.keyToken && this.showKeyToken) {
      navigator.clipboard.writeText(this.keyToken).then(() => {
        this.toast.success('Token copied to clipboard');
      });
    }
  }

  getKeyFetchUrl(): string {
    const zoneName = this.formData.name;
    if (!zoneName || !this.keyToken || !this.showKeyToken) return '';
    // Build the URL for secondary servers to fetch keys
    const baseUrl = window.location.origin;
    return `${baseUrl}/api/dnssec/keys/${encodeURIComponent(zoneName)}?token=${this.keyToken}`;
  }

  copyKeyFetchUrl(): void {
    const url = this.getKeyFetchUrl();
    if (url) {
      navigator.clipboard.writeText(url).then(() => {
        this.toast.success('Key fetch URL copied to clipboard');
      });
    }
  }
}
