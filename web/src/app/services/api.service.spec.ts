import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { ApiService, ServerStatus, Zone, DnsRecord, RecursionConfig, PortsConfig } from './api.service';

describe('ApiService', () => {
  let service: ApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        ApiService,
        provideHttpClient(),
        provideHttpClientTesting(),
      ],
    });

    service = TestBed.inject(ApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  describe('getStatus', () => {
    it('should return server status', () => {
      const mockStatus: ServerStatus = {
        status: 'running',
        uptime: '1h 30m',
        uptime_seconds: 5400,
        total_queries: 1500,
        queries_by_type: { A: 1000, AAAA: 500 },
        listen: ':53',
        zone_count: 5,
        record_count: 50,
        secondary_zones: 2,
      };

      service.getStatus().subscribe(status => {
        expect(status.status).toBe('running');
        expect(status.total_queries).toBe(1500);
        expect(status.zone_count).toBe(5);
      });

      const req = httpMock.expectOne('/api/status');
      expect(req.request.method).toBe('GET');
      req.flush(mockStatus);
    });
  });

  describe('Zones', () => {
    it('should get zones', () => {
      const mockZones: Zone[] = [
        { name: 'example.com', type: 'forward', strip_prefix: false, ttl: 3600 },
        { name: '168.192.in-addr.arpa', type: 'reverse', subnet: '192.168.0.0/16', strip_prefix: false, ttl: 3600 },
      ];

      service.getZones().subscribe(zones => {
        expect(zones.length).toBe(2);
        expect(zones[0].name).toBe('example.com');
      });

      const req = httpMock.expectOne('/api/zones');
      expect(req.request.method).toBe('GET');
      req.flush(mockZones);
    });

    it('should add zone', () => {
      const newZone: Zone = { name: 'newzone.com', type: 'forward', strip_prefix: false, ttl: 3600 };

      service.addZone(newZone).subscribe(response => {
        expect(response).toBeTruthy();
      });

      const req = httpMock.expectOne('/api/zones');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual(newZone);
      req.flush({ success: true });
    });

    it('should delete zone', () => {
      service.deleteZone(1).subscribe();

      const req = httpMock.expectOne('/api/zones/1');
      expect(req.request.method).toBe('DELETE');
      req.flush({ success: true });
    });
  });

  describe('Records', () => {
    it('should get all records', () => {
      const mockRecords: DnsRecord[] = [
        { type: 'A', name: 'www', ip: '192.168.1.1', ttl: 300 },
        { type: 'CNAME', name: 'mail', target: 'smtp.example.com', ttl: 300 },
      ];

      service.getRecords().subscribe(records => {
        expect(records.length).toBe(2);
      });

      const req = httpMock.expectOne('/api/records');
      expect(req.request.method).toBe('GET');
      req.flush(mockRecords);
    });

    it('should get records with type filter', () => {
      service.getRecords('A').subscribe();

      const req = httpMock.expectOne('/api/records?type=A');
      expect(req.request.method).toBe('GET');
      req.flush([]);
    });

    it('should get records with zone filter', () => {
      service.getRecords(undefined, 'example.com').subscribe();

      const req = httpMock.expectOne('/api/records?zone=example.com');
      expect(req.request.method).toBe('GET');
      req.flush([]);
    });

    it('should get records with both filters', () => {
      service.getRecords('A', 'example.com').subscribe();

      const req = httpMock.expectOne('/api/records?type=A&zone=example.com');
      expect(req.request.method).toBe('GET');
      req.flush([]);
    });

    it('should add record', () => {
      const newRecord: DnsRecord = { type: 'A', name: 'test', ip: '10.0.0.1', ttl: 300 };

      service.addRecord(newRecord).subscribe();

      const req = httpMock.expectOne('/api/records');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual(newRecord);
      req.flush({ success: true });
    });

    it('should delete record', () => {
      service.deleteRecord('A', 0).subscribe();

      const req = httpMock.expectOne('/api/records/A/0');
      expect(req.request.method).toBe('DELETE');
      req.flush({ success: true });
    });
  });

  describe('Recursion Config', () => {
    it('should get recursion config', () => {
      const mockConfig: RecursionConfig = {
        enabled: true,
        mode: 'fallback',
        upstream: ['8.8.8.8', '1.1.1.1'],
        timeout: 5,
        max_depth: 10,
      };

      service.getRecursionConfig().subscribe(config => {
        expect(config.enabled).toBe(true);
        expect(config.mode).toBe('fallback');
      });

      const req = httpMock.expectOne('/api/recursion');
      expect(req.request.method).toBe('GET');
      req.flush(mockConfig);
    });

    it('should update recursion config', () => {
      const config: RecursionConfig = {
        enabled: true,
        mode: 'always',
        upstream: ['8.8.8.8'],
        timeout: 10,
        max_depth: 5,
      };

      service.updateRecursionConfig(config).subscribe();

      const req = httpMock.expectOne('/api/recursion');
      expect(req.request.method).toBe('PUT');
      expect(req.request.body).toEqual(config);
      req.flush({ success: true });
    });
  });

  describe('Ports Config', () => {
    it('should get ports config', () => {
      const mockConfig: PortsConfig = {
        dns: { enabled: true, port: 53, address: '0.0.0.0' },
        dot: { enabled: false, port: 853, address: '0.0.0.0' },
        doh: { enabled: false, port: 443, address: '0.0.0.0', path: '/dns-query', standalone: false },
        web: { enabled: true, port: 8080, address: '0.0.0.0', tls: false },
      };

      service.getPorts().subscribe(config => {
        expect(config.dns.enabled).toBe(true);
        expect(config.dns.port).toBe(53);
      });

      const req = httpMock.expectOne('/api/ports');
      expect(req.request.method).toBe('GET');
      req.flush(mockConfig);
    });

    it('should update DNS port config', () => {
      const config = { enabled: true, port: 5353, address: '127.0.0.1' };

      service.updateDNSPort(config).subscribe();

      const req = httpMock.expectOne('/api/ports/dns');
      expect(req.request.method).toBe('PUT');
      expect(req.request.body).toEqual(config);
      req.flush({ success: true });
    });
  });

  describe('Secondary Zones', () => {
    it('should get secondary zones', () => {
      service.getSecondaryZones().subscribe();

      const req = httpMock.expectOne('/api/secondary-zones');
      expect(req.request.method).toBe('GET');
      req.flush([]);
    });

    it('should add secondary zone', () => {
      const zone = { zone: 'example.com', primary: '192.168.1.1', notify: true, refresh_interval: 3600 };
      service.addSecondaryZone(zone).subscribe();

      const req = httpMock.expectOne('/api/secondary-zones');
      expect(req.request.method).toBe('POST');
      expect(req.request.body).toEqual(zone);
      req.flush({ success: true });
    });
  });
});
