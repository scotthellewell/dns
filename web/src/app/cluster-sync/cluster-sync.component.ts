import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatTableModule } from '@angular/material/table';
import { MatChipsModule } from '@angular/material/chips';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatDialogModule, MatDialog } from '@angular/material/dialog';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatDividerModule } from '@angular/material/divider';
import { ApiService, ClusterStatus, PeerState, SyncPeer, SyncConfig } from '../services/api.service';
import { Subject, interval } from 'rxjs';
import { takeUntil } from 'rxjs/operators';

@Component({
  selector: 'app-cluster-sync',
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
    MatChipsModule,
    MatProgressSpinnerModule,
    MatTooltipModule,
    MatCheckboxModule,
    MatSnackBarModule,
    MatDialogModule,
    MatSlideToggleModule,
    MatExpansionModule,
    MatDividerModule
  ],
  templateUrl: './cluster-sync.component.html',
  styleUrl: './cluster-sync.component.scss'
})
export class ClusterSyncComponent implements OnInit, OnDestroy {
  status: ClusterStatus | null = null;
  config: SyncConfig | null = null;
  loading = false;
  saving = false;
  addingPeer = false;
  
  // Config form
  configForm: SyncConfig = {
    enabled: false,
    server_id: '',
    server_name: '',
    listen_addr: ':9443',
    shared_secret: '',
    peers: [],
    tombstone_retention_days: 7
  };

  // New peer form
  showAddPeer = false;
  newPeerUrl = '';
  newPeerInsecure = false;

  displayedColumns = ['server_name', 'server_id', 'status', 'last_sync', 'pending_ops', 'actions'];
  peerColumns = ['url', 'actions'];

  private destroy$ = new Subject<void>();

  constructor(
    private api: ApiService,
    private snackBar: MatSnackBar,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit() {
    this.loadData();
    
    // Auto-refresh status every 10 seconds
    interval(10000)
      .pipe(takeUntil(this.destroy$))
      .subscribe(() => this.loadStatus());
  }

  ngOnDestroy() {
    this.destroy$.next();
    this.destroy$.complete();
  }

  loadData() {
    this.loading = true;
    // Load both config and status
    this.api.getSyncConfig().subscribe({
      next: (config) => {
        this.config = config;
        this.configForm = { ...config };
        this.loadStatus();
      },
      error: (err) => {
        console.error('Failed to load sync config:', err);
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  loadStatus() {
    this.api.getSyncStatus().subscribe({
      next: (status) => {
        this.status = status;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        console.error('Failed to load sync status:', err);
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  saveConfig() {
    this.saving = true;
    this.api.updateSyncConfig(this.configForm).subscribe({
      next: (res) => {
        this.snackBar.open(res.message || 'Configuration saved', 'Close', { duration: 3000 });
        this.saving = false;
        this.loadData();
      },
      error: (err) => {
        this.snackBar.open('Failed to save: ' + (err.error || err.message), 'Close', { duration: 5000 });
        this.saving = false;
        this.cdr.detectChanges();
      }
    });
  }

  generateSecret() {
    this.api.generateSyncSecret().subscribe({
      next: (res) => {
        this.configForm.shared_secret = res.secret;
        this.snackBar.open('New secret generated', 'Close', { duration: 2000 });
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.snackBar.open('Failed to generate secret', 'Close', { duration: 3000 });
      }
    });
  }

  addPeerToConfig() {
    if (!this.newPeerUrl) return;
    
    if (!this.configForm.peers) {
      this.configForm.peers = [];
    }
    
    this.configForm.peers.push({
      url: this.newPeerUrl,
      insecure_skip_verify: this.newPeerInsecure
    });
    
    this.newPeerUrl = '';
    this.newPeerInsecure = false;
    this.showAddPeer = false;
    this.cdr.detectChanges();
  }

  removePeerFromConfig(index: number) {
    this.configForm.peers.splice(index, 1);
    this.cdr.detectChanges();
  }

  toggleAddPeer() {
    this.showAddPeer = !this.showAddPeer;
    if (!this.showAddPeer) {
      this.newPeerUrl = '';
      this.newPeerInsecure = false;
    }
  }

  forceSync(peer: PeerState) {
    this.api.forceSync(peer.server_id).subscribe({
      next: () => {
        this.snackBar.open('Sync triggered for ' + peer.server_name, 'Close', { duration: 3000 });
      },
      error: (err) => {
        this.snackBar.open('Failed to trigger sync: ' + (err.error || err.message), 'Close', { duration: 5000 });
      }
    });
  }

  formatHLC(hlc: any): string {
    if (!hlc) return 'N/A';
    return `${hlc.pt}.${hlc.lc}`;
  }

  formatTime(timeStr: string): string {
    if (!timeStr) return 'Never';
    const date = new Date(timeStr);
    if (isNaN(date.getTime())) return 'Never';
    return date.toLocaleString();
  }

  getStatusClass(peer: PeerState): string {
    if (peer.connected) return 'connected';
    if (peer.last_error) return 'error';
    return 'disconnected';
  }

  getStatusText(peer: PeerState): string {
    if (peer.connected) return 'Connected';
    if (peer.last_error) return 'Error';
    return 'Disconnected';
  }
}
