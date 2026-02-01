import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { of, throwError } from 'rxjs';
import { DashboardComponent } from './dashboard.component';
import { ApiService, ServerStatus, PortsConfig } from '../services/api.service';
import { ChangeDetectorRef } from '@angular/core';

describe('DashboardComponent', () => {
  let component: DashboardComponent;
  let apiServiceSpy: {
    getStatus: ReturnType<typeof vi.fn>;
    getPorts: ReturnType<typeof vi.fn>;
  };
  let cdrSpy: { detectChanges: ReturnType<typeof vi.fn> };

  const mockStatus: ServerStatus = {
    status: 'running',
    uptime: '2h 30m',
    uptime_seconds: 9000,
    total_queries: 2500,
    queries_by_type: { A: 1500, AAAA: 800, MX: 200 },
    listen: ':53',
    zone_count: 10,
    record_count: 100,
    secondary_zones: 3,
  };

  const mockPorts: PortsConfig = {
    dns: { enabled: true, port: 53, address: '0.0.0.0' },
    dot: { enabled: false, port: 853, address: '0.0.0.0' },
    doh: { enabled: false, port: 443, address: '0.0.0.0', path: '/dns-query', standalone: false },
    web: { enabled: true, port: 8080, address: '0.0.0.0', tls: false },
  };

  beforeEach(() => {
    apiServiceSpy = {
      getStatus: vi.fn().mockReturnValue(of(mockStatus)),
      getPorts: vi.fn().mockReturnValue(of(mockPorts)),
    };
    cdrSpy = { detectChanges: vi.fn() };

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ApiService, useValue: apiServiceSpy },
        { provide: ChangeDetectorRef, useValue: cdrSpy },
      ],
    });

    // Inject the component directly without template resolution
    component = new DashboardComponent(
      TestBed.inject(ApiService),
      TestBed.inject(ChangeDetectorRef)
    );
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should load status on init', async () => {
    component.ngOnInit();
    // Wait for async operations
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(apiServiceSpy.getStatus).toHaveBeenCalled();
    expect(apiServiceSpy.getPorts).toHaveBeenCalled();
    expect(component.status).toEqual(mockStatus);
    expect(component.portsConfig).toEqual(mockPorts);
    expect(component.error).toBeNull();
  });

  it('should display error on load failure', async () => {
    apiServiceSpy.getStatus.mockReturnValue(throwError(() => new Error('Network error')));

    component.ngOnInit();
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(component.error).toBe('Failed to connect to server');
  });

  it('should return DNS address from ports config', async () => {
    component.ngOnInit();
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(component.getDnsAddress()).toBe('0.0.0.0:53');
  });

  it('should return N/A when no ports config', () => {
    component.portsConfig = null;
    expect(component.getDnsAddress()).toBe('N/A');
  });

  it('should get query types sorted by count', async () => {
    component.ngOnInit();
    await new Promise(resolve => setTimeout(resolve, 10));

    const queryTypes = component.getQueryTypes();
    expect(queryTypes.length).toBe(3);
    expect(queryTypes[0].type).toBe('A');
    expect(queryTypes[0].count).toBe(1500);
    expect(queryTypes[1].type).toBe('AAAA');
    expect(queryTypes[2].type).toBe('MX');
  });

  it('should return empty array when no status', () => {
    component.status = null;
    expect(component.getQueryTypes()).toEqual([]);
  });

  it('should cleanup subscription on destroy', async () => {
    component.ngOnInit();
    await new Promise(resolve => setTimeout(resolve, 10));

    const subscription = (component as any)['subscription'];
    expect(subscription).toBeDefined();

    const unsubscribeSpy = vi.spyOn(subscription, 'unsubscribe');
    component.ngOnDestroy();

    expect(unsubscribeSpy).toHaveBeenCalled();
  });
});
