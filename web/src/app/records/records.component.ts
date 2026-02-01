import { Component, OnInit, ChangeDetectorRef, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService, DnsRecord, Zone, Delegation, GlueRecord, DsRecordData } from '../services/api.service';
import { ToastService } from '../services/toast.service';

@Component({
  selector: 'app-records',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './records.component.html',
  styleUrls: ['./records.component.scss']
})
export class RecordsComponent implements OnInit {
  private toast = inject(ToastService);
  
  records: DnsRecord[] = [];
  filteredRecords: DnsRecord[] = [];
  zones: Zone[] = [];
  showForm = false;
  editingRecord: { record: DnsRecord; index: number } | null = null;
  
  recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA', 'PTR', 'ALIAS', 'SSHFP', 'TLSA', 'NAPTR', 'SVCB', 'HTTPS', 'LOC', 'Delegation'];
  selectedType = '';
  selectedZone = '';
  
  formData: DnsRecord = this.getEmptyRecord('A');
  
  // Delegation form data
  delegationData: Delegation = {
    parent_zone: '',
    child_zone: '',
    nameservers: [''],
    glue_records: [],
    ds_records: []
  };
  showDelegationForm = false;
  delegations: Delegation[] = [];

  constructor(private api: ApiService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.loadZones();
    this.loadRecords();
    this.loadDelegations();
  }

  loadZones(): void {
    this.api.getZones().subscribe({
      next: (zones) => {
        this.zones = zones;
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error('Failed to load zones', err);
      }
    });
  }

  loadDelegations(): void {
    this.api.getDelegations(this.selectedZone || undefined).subscribe({
      next: (delegations) => {
        this.delegations = delegations || [];
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error('Failed to load delegations', err);
      }
    });
  }

  loadRecords(): void {
    // Use zone filter if selected
    this.api.getRecords(undefined, this.selectedZone || undefined).subscribe({
      next: (records) => {
        this.records = records;
        this.filterRecords();
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.toast.error('Failed to load records');
        this.cdr.detectChanges();
      }
    });
  }

  filterRecords(): void {
    let filtered = this.records;
    
    // Filter by type (client-side since we get all records)
    if (this.selectedType) {
      filtered = filtered.filter(r => r.type === this.selectedType);
    }
    
    this.filteredRecords = filtered;
  }

  onTypeFilterChange(): void {
    // If Delegation is selected, open the delegation form
    if (this.selectedType === 'Delegation') {
      this.openAddForm('Delegation');
      this.selectedType = ''; // Reset filter
      return;
    }
    this.filterRecords();
  }

  onZoneFilterChange(): void {
    this.loadRecords(); // Reload with zone filter
    this.loadDelegations(); // Reload delegations too
  }

  get forwardZones(): Zone[] {
    return this.zones.filter(z => z.type === 'forward');
  }

  // Record types for the form (without Delegation which has its own form)
  get formRecordTypes(): string[] {
    return this.recordTypes.filter(t => t !== 'Delegation');
  }

  getEmptyRecord(type: string): DnsRecord {
    const record: DnsRecord = { type, ttl: 3600, zone: this.selectedZone || undefined };
    switch (type) {
      case 'A':
      case 'AAAA':
        record.name = '';
        record.ip = '';
        break;
      case 'MX':
        record.name = '';
        record.priority = 10;
        record.target = '';
        break;
      case 'TXT':
        record.name = '';
        record.values = [''];
        break;
      case 'NS':
      case 'CNAME':
      case 'ALIAS':
        record.name = '';
        record.target = '';
        break;
      case 'SOA':
        record.name = '';
        record.mname = '';
        record.rname = '';
        record.serial = Math.floor(Date.now() / 1000);
        record.refresh = 3600;
        record.retry = 900;
        record.expire = 1209600;
        record.minimum = 3600;
        break;
      case 'SRV':
        record.name = '';
        record.priority = 10;
        record.weight = 0;
        record.port = 0;
        record.target = '';
        break;
      case 'CAA':
        record.name = '';
        record.flag = 0;
        record.tag = 'issue';
        record.value = '';
        break;
      case 'PTR':
        record.ip = '';
        record.hostname = '';
        break;
      case 'SSHFP':
        record.name = '';
        record.algorithm = 1;
        record.fp_type = 2;
        record.fingerprint = '';
        break;
      case 'TLSA':
        record.name = '';
        record.usage = 3;
        record.selector = 1;
        record.matching_type = 1;
        record.certificate = '';
        break;
      case 'NAPTR':
        record.name = '';
        record.order = 100;
        record.preference = 10;
        record.flags = '';
        record.service = '';
        record.regexp = '';
        record.replacement = '';
        break;
      case 'SVCB':
      case 'HTTPS':
        record.name = '';
        record.priority = 1;
        record.target = '.';
        record.params = {};
        break;
      case 'LOC':
        record.name = '';
        record.latitude = 0;
        record.longitude = 0;
        record.altitude = 0;
        record.size = 1;
        record.horiz_pre = 10000;
        record.vert_pre = 10;
        break;
    }
    return record;
  }

  openAddForm(type: string = 'A'): void {
    if (type === 'Delegation') {
      this.delegationData = {
        parent_zone: this.selectedZone || '',
        child_zone: '',
        nameservers: [''],
        glue_records: [],
        ds_records: []
      };
      this.showDelegationForm = true;
      this.showForm = false;
    } else {
      this.formData = this.getEmptyRecord(type);
      this.editingRecord = null;
      this.showForm = true;
      this.showDelegationForm = false;
    }
  }

  openEditForm(record: DnsRecord): void {
    // Find the index within the same type
    const sameTypeRecords = this.records.filter(r => r.type === record.type);
    const index = sameTypeRecords.indexOf(record);
    
    this.formData = { ...record, values: record.values ? [...record.values] : undefined };
    this.editingRecord = { record, index };
    this.showForm = true;
  }

  closeForm(): void {
    this.showForm = false;
    this.editingRecord = null;
  }

  onFormTypeChange(): void {
    const type = this.formData.type;
    this.formData = { ...this.getEmptyRecord(type), type };
  }

  saveRecord(): void {
    if (this.editingRecord !== null) {
      this.api.updateRecord(
        this.formData.type,
        this.editingRecord.index,
        this.formData
      ).subscribe({
        next: () => {
          this.toast.success('Record updated successfully');
          this.loadRecords();
          this.closeForm();
        },
        error: (err) => {
          this.toast.error('Failed to update record');
        }
      });
    } else {
      this.api.addRecord(this.formData).subscribe({
        next: () => {
          this.toast.success('Record created successfully');
          this.loadRecords();
          this.closeForm();
        },
        error: (err) => {
          this.toast.error('Failed to add record');
        }
      });
    }
  }

  deleteRecord(record: DnsRecord): void {
    const sameTypeRecords = this.records.filter(r => r.type === record.type);
    const index = sameTypeRecords.indexOf(record);
    
    if (!confirm(`Delete ${record.type} record for ${record.name || record.ip}?`)) return;

    this.api.deleteRecord(record.type, index).subscribe({
      next: () => {
        this.toast.success('Record deleted successfully');
        this.loadRecords();
      },
      error: (err) => {
        this.toast.error('Failed to delete record');
      }
    });
  }

  addTxtValue(): void {
    if (!this.formData.values) {
      this.formData.values = [];
    }
    this.formData.values.push('');
  }

  removeTxtValue(index: number): void {
    this.formData.values?.splice(index, 1);
  }

  trackByIndex(index: number): number {
    return index;
  }

  getRecordSummary(record: DnsRecord): string {
    switch (record.type) {
      case 'A':
      case 'AAAA':
        return `${record.name} → ${record.ip}`;
      case 'MX':
        return `${record.name} → ${record.priority} ${record.target}`;
      case 'TXT':
        return `${record.name} → "${record.values?.join(', ')}"`;
      case 'NS':
      case 'CNAME':
      case 'ALIAS':
        return `${record.name} → ${record.target}`;
      case 'SOA':
        return `${record.name} (serial: ${record.serial})`;
      case 'SRV':
        return `${record.name} → ${record.target}:${record.port}`;
      case 'CAA':
        return `${record.name} ${record.tag} ${record.value}`;
      case 'PTR':
        return `${record.ip} → ${record.hostname}`;
      case 'SSHFP':
        return `${record.name} (alg: ${record.algorithm}, type: ${record.fp_type})`;
      case 'TLSA':
        return `${record.name} (usage: ${record.usage})`;
      case 'NAPTR':
        return `${record.name} → ${record.replacement || record.regexp}`;
      case 'SVCB':
      case 'HTTPS':
        return `${record.name} → ${record.target} (pri: ${record.priority})`;
      case 'LOC':
        return `${record.name} (${record.latitude}, ${record.longitude})`;
      default:
        return record.name || '';
    }
  }

  // Delegation Methods
  closeDelegationForm(): void {
    this.showDelegationForm = false;
  }

  addNameserver(): void {
    this.delegationData.nameservers.push('');
  }

  removeNameserver(index: number): void {
    this.delegationData.nameservers.splice(index, 1);
  }

  addGlueRecord(): void {
    if (!this.delegationData.glue_records) {
      this.delegationData.glue_records = [];
    }
    this.delegationData.glue_records.push({ hostname: '', ip: '', ip_type: 'A' });
  }

  removeGlueRecord(index: number): void {
    this.delegationData.glue_records?.splice(index, 1);
  }

  addDsRecord(): void {
    if (!this.delegationData.ds_records) {
      this.delegationData.ds_records = [];
    }
    this.delegationData.ds_records.push({ key_tag: 0, algorithm: 13, digest_type: 2, digest: '' });
  }

  removeDsRecord(index: number): void {
    this.delegationData.ds_records?.splice(index, 1);
  }

  saveDelegation(): void {
    // Validate
    if (!this.delegationData.parent_zone) {
      this.toast.error('Parent zone is required');
      return;
    }
    if (!this.delegationData.child_zone) {
      this.toast.error('Child zone name is required');
      return;
    }
    if (this.delegationData.nameservers.filter(ns => ns.trim()).length === 0) {
      this.toast.error('At least one nameserver is required');
      return;
    }

    // Clean up empty entries
    this.delegationData.nameservers = this.delegationData.nameservers.filter(ns => ns.trim());
    
    this.api.createDelegation(this.delegationData).subscribe({
      next: () => {
        this.toast.success('Delegation created successfully');
        this.closeDelegationForm();
        this.loadRecords();
        this.loadDelegations();
      },
      error: (err) => {
        this.toast.error(err.error?.error || 'Failed to create delegation');
      }
    });
  }

  deleteDelegation(delegation: Delegation): void {
    if (!confirm(`Delete delegation for ${delegation.child_zone}.${delegation.parent_zone}?`)) return;

    this.api.deleteDelegation(delegation.parent_zone, delegation.child_zone).subscribe({
      next: () => {
        this.toast.success('Delegation deleted successfully');
        this.loadDelegations();
        this.loadRecords();
      },
      error: (err) => {
        this.toast.error(err.error?.error || 'Failed to delete delegation');
      }
    });
  }

  getDelegationSummary(delegation: Delegation): string {
    const child = `${delegation.child_zone}.${delegation.parent_zone}`;
    const ns = delegation.nameservers.join(', ');
    const hasDnssec = delegation.ds_records && delegation.ds_records.length > 0;
    return `${child} → ${ns}${hasDnssec ? ' 🔒' : ''}`;
  }
}
