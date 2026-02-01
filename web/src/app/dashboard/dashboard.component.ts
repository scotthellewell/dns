import { Component, OnInit, OnDestroy, ChangeDetectorRef, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ApiService, ServerStatus, PortsConfig } from '../services/api.service';
import { ToastService } from '../services/toast.service';
import { interval, Subscription, forkJoin } from 'rxjs';
import { switchMap } from 'rxjs/operators';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.scss']
})
export class DashboardComponent implements OnInit, OnDestroy {
  private toast = inject(ToastService);
  
  status: ServerStatus | null = null;
  portsConfig: PortsConfig | null = null;
  private subscription?: Subscription;
  private hasShownError = false;

  constructor(private api: ApiService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.loadStatus();
    // Refresh every 5 seconds
    this.subscription = interval(5000).pipe(
      switchMap(() => this.api.getStatus())
    ).subscribe({
      next: (status) => {
        this.status = status;
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
    forkJoin({
      status: this.api.getStatus(),
      ports: this.api.getPorts()
    }).subscribe({
      next: (result) => {
        this.status = result.status;
        this.portsConfig = result.ports;
        this.cdr.detectChanges();
      },
      error: (err) => {
        this.toast.error('Failed to connect to server');
        this.cdr.detectChanges();
      }
    });
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
