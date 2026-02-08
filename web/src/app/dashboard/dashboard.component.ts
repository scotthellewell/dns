import { Component, OnInit, OnDestroy, ChangeDetectorRef, inject, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService, ServerStatus, PortsConfig, ClusterStatus } from '../services/api.service';
import { ToastService } from '../services/toast.service';
import { AuthService } from '../services/auth.service';
import { TenantContextService } from '../services/tenant-context.service';
import { interval, Subscription, forkJoin, of } from 'rxjs';
import { switchMap, catchError } from 'rxjs/operators';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit, OnDestroy {
  private toast = inject(ToastService);
  private authService = inject(AuthService);
  readonly tenantContext = inject(TenantContextService);
  
  status: ServerStatus | null = null;
  portsConfig: PortsConfig | null = null;
  clusterStatus: ClusterStatus | null = null;
  private subscription?: Subscription;
  private hasShownError = false;

  constructor(private api: ApiService, private cdr: ChangeDetectorRef) {
    // React to tenant context changes
    effect(() => {
      const tenantId = this.tenantContext.currentTenantId();
      this.loadStatus();
    });
  }

  ngOnInit(): void {
    this.loadStatus();
    // Refresh every 5 seconds
    this.subscription = interval(5000).pipe(
      switchMap(() => {
        const tenantId = this.authService.isSuperAdmin() ? this.tenantContext.currentTenantId() : undefined;
        const shouldLoadCluster = this.authService.isSuperAdmin() && this.tenantContext.isMainTenantSelected();
        
        return forkJoin({
          status: this.api.getStatus(tenantId),
          cluster: shouldLoadCluster ? this.api.getSyncStatus().pipe(catchError(() => of(null))) : of(null)
        });
      })
    ).subscribe({
      next: (result) => {
        this.status = result.status;
        this.clusterStatus = result.cluster;
        this.hasShownError = false;
        this.cdr.detectChanges();
      },
      error: (err) => {
        // Only show error toast once to avoid spam
        if (!this.hasShownError) {
          this.toast.error('Failed to load status');
          this.hasShownError = true;
        }
        this.cdr.detectChanges();
      }
    });
  }

  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
  }

  loadStatus(): void {
    const tenantId = this.authService.isSuperAdmin() ? this.tenantContext.currentTenantId() : undefined;
    const shouldLoadCluster = this.authService.isSuperAdmin() && this.tenantContext.isMainTenantSelected();
    
    forkJoin({
      status: this.api.getStatus(tenantId),
      ports: this.api.getPorts(),
      cluster: shouldLoadCluster ? this.api.getSyncStatus().pipe(catchError(() => of(null))) : of(null)
    }).subscribe({
      next: (result) => {
        this.status = result.status;
        this.portsConfig = result.ports;
        this.clusterStatus = result.cluster;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.toast.error('Failed to connect to server');
        this.cdr.detectChanges();
      }
    });
  }

  get showClusterStats(): boolean {
    return this.authService.isSuperAdmin() && this.tenantContext.isMainTenantSelected() && !!this.clusterStatus;
  }

  getConnectedPeers(): number {
    if (!this.clusterStatus?.peers) return 0;
    return this.clusterStatus.peers.filter(p => p.connected).length;
  }

  getTotalPeers(): number {
    return this.clusterStatus?.peers?.length || 0;
  }

  getDnsAddress(): string {
    if (!this.portsConfig?.dns) return 'N/A';
    const dns = this.portsConfig.dns;
    const addr = dns.address || '0.0.0.0';
    return `${addr}:${dns.port}`;
  }

  getQueryTypes(): { type: string; count: number }[] {
    if (!this.status?.queries_by_type) return [];
    return Object.entries(this.status.queries_by_type)
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count);
  }
}
