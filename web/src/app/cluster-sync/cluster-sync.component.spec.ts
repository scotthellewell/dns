import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { of, throwError } from 'rxjs';
import { ClusterSyncComponent } from './cluster-sync.component';
import { ApiService, ClusterStatus, PeerState, SyncPeer } from '../services/api.service';
import { ChangeDetectorRef } from '@angular/core';
import { MatSnackBar } from '@angular/material/snack-bar';

describe('ClusterSyncComponent', () => {
  let component: ClusterSyncComponent;
  let apiServiceSpy: {
    getSyncStatus: ReturnType<typeof vi.fn>;
    getSyncPeers: ReturnType<typeof vi.fn>;
    addSyncPeer: ReturnType<typeof vi.fn>;
    forceSync: ReturnType<typeof vi.fn>;
  };
  let snackBarSpy: { open: ReturnType<typeof vi.fn> };
  let cdrSpy: { detectChanges: ReturnType<typeof vi.fn> };

  const mockStatus: ClusterStatus = {
    server_id: 'test-server-id-12345',
    server_name: 'Test Server',
    enabled: true,
    current_hlc: { pt: 1234567890, lc: 5, sid: 'test-server-id' },
    oplog_entries: 150,
    peers: [
      {
        server_id: 'peer-1-id',
        server_name: 'Peer 1',
        url: 'wss://peer1.example.com:9443/sync',
        connected: true,
        last_hlc: { pt: 1234567880, lc: 3, sid: 'peer-1-id' },
        last_sync_time: '2024-01-15T10:30:00Z',
        pending_ops: 0
      },
      {
        server_id: 'peer-2-id',
        server_name: 'Peer 2',
        url: 'wss://peer2.example.com:9443/sync',
        connected: false,
        last_hlc: { pt: 1234567800, lc: 1, sid: 'peer-2-id' },
        last_sync_time: '2024-01-15T09:00:00Z',
        pending_ops: 25,
        last_error: 'Connection refused',
        last_error_time: '2024-01-15T10:00:00Z'
      }
    ]
  };

  beforeEach(() => {
    apiServiceSpy = {
      getSyncStatus: vi.fn().mockReturnValue(of(mockStatus)),
      getSyncPeers: vi.fn().mockReturnValue(of([])),
      addSyncPeer: vi.fn().mockReturnValue(of({ status: 'ok' })),
      forceSync: vi.fn().mockReturnValue(of({ status: 'sync_triggered' })),
    };
    snackBarSpy = { open: vi.fn() };
    cdrSpy = { detectChanges: vi.fn() };

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ApiService, useValue: apiServiceSpy },
        { provide: MatSnackBar, useValue: snackBarSpy },
        { provide: ChangeDetectorRef, useValue: cdrSpy },
      ],
    });

    component = new ClusterSyncComponent(
      TestBed.inject(ApiService),
      TestBed.inject(MatSnackBar),
      TestBed.inject(ChangeDetectorRef)
    );
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should load status on init', async () => {
    component.ngOnInit();
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(apiServiceSpy.getSyncStatus).toHaveBeenCalled();
    expect(component.status).toEqual(mockStatus);
    expect(component.loading).toBe(false);
  });

  it('should handle load status error', async () => {
    apiServiceSpy.getSyncStatus.mockReturnValue(throwError(() => new Error('Network error')));

    component.ngOnInit();
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(component.loading).toBe(false);
    expect(component.status).toBeNull();
  });

  it('should toggle add peer form', () => {
    expect(component.showAddPeer).toBe(false);
    
    component.toggleAddPeer();
    expect(component.showAddPeer).toBe(true);
    
    component.toggleAddPeer();
    expect(component.showAddPeer).toBe(false);
  });

  it('should clear form when closing add peer', () => {
    component.newPeerUrl = 'wss://test.com/sync';
    component.newPeerInsecure = true;
    component.showAddPeer = true;

    component.toggleAddPeer();

    expect(component.newPeerUrl).toBe('');
    expect(component.newPeerInsecure).toBe(false);
  });

  it('should show error when adding peer without URL', () => {
    component.newPeerUrl = '';
    component.addPeer();

    expect(snackBarSpy.open).toHaveBeenCalledWith(
      'Please enter a peer URL',
      'Close',
      { duration: 3000 }
    );
  });

  it('should add peer successfully', async () => {
    component.showAddPeer = true;
    component.newPeerUrl = 'wss://newpeer.example.com:9443/sync';
    component.newPeerInsecure = false;

    component.addPeer();
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(apiServiceSpy.addSyncPeer).toHaveBeenCalledWith({
      url: 'wss://newpeer.example.com:9443/sync',
      insecure_skip_verify: false
    });
    expect(snackBarSpy.open).toHaveBeenCalledWith(
      'Peer added successfully',
      'Close',
      { duration: 3000 }
    );
    expect(component.showAddPeer).toBe(false);
  });

  it('should handle add peer error', async () => {
    apiServiceSpy.addSyncPeer.mockReturnValue(throwError(() => ({ error: 'Connection failed' })));
    
    component.showAddPeer = true;
    component.newPeerUrl = 'wss://bad.example.com/sync';
    
    component.addPeer();
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(snackBarSpy.open).toHaveBeenCalled();
    expect(component.addingPeer).toBe(false);
  });

  it('should force sync with peer', async () => {
    const peer = mockStatus.peers[0];
    component.forceSync(peer);
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(apiServiceSpy.forceSync).toHaveBeenCalledWith('peer-1-id');
    expect(snackBarSpy.open).toHaveBeenCalledWith(
      'Sync triggered for Peer 1',
      'Close',
      { duration: 3000 }
    );
  });

  it('should format HLC correctly', () => {
    const hlc = { pt: 123456, lc: 5, sid: 'server-1' };
    expect(component.formatHLC(hlc)).toBe('123456.5');
  });

  it('should handle null HLC', () => {
    expect(component.formatHLC(null)).toBe('N/A');
    expect(component.formatHLC(undefined)).toBe('N/A');
  });

  it('should format time correctly', () => {
    const timeStr = '2024-01-15T10:30:00Z';
    const result = component.formatTime(timeStr);
    expect(result).not.toBe('Never');
    expect(result.length).toBeGreaterThan(0);
  });

  it('should handle empty time string', () => {
    expect(component.formatTime('')).toBe('Never');
    expect(component.formatTime(null as any)).toBe('Never');
  });

  describe('PeerState status helpers', () => {
    it('should return connected for connected peer', () => {
      const peer: PeerState = {
        server_id: 'test',
        server_name: 'Test',
        url: 'wss://test.com/sync',
        connected: true,
        last_hlc: { pt: 0, lc: 0, sid: 'test' },
        last_sync_time: '',
        pending_ops: 0
      };
      
      expect(component.getStatusClass(peer)).toBe('connected');
      expect(component.getStatusText(peer)).toBe('Connected');
    });

    it('should return error for peer with error', () => {
      const peer: PeerState = {
        server_id: 'test',
        server_name: 'Test',
        url: 'wss://test.com/sync',
        connected: false,
        last_hlc: { pt: 0, lc: 0, sid: 'test' },
        last_sync_time: '',
        pending_ops: 0,
        last_error: 'Connection refused'
      };
      
      expect(component.getStatusClass(peer)).toBe('error');
      expect(component.getStatusText(peer)).toBe('Error');
    });

    it('should return disconnected for disconnected peer without error', () => {
      const peer: PeerState = {
        server_id: 'test',
        server_name: 'Test',
        url: 'wss://test.com/sync',
        connected: false,
        last_hlc: { pt: 0, lc: 0, sid: 'test' },
        last_sync_time: '',
        pending_ops: 0
      };
      
      expect(component.getStatusClass(peer)).toBe('disconnected');
      expect(component.getStatusText(peer)).toBe('Disconnected');
    });
  });

  it('should have correct display columns', () => {
    expect(component.displayedColumns).toEqual([
      'server_name',
      'server_id',
      'status',
      'last_sync',
      'pending_ops',
      'actions'
    ]);
  });

  it('should refresh status when loadStatus is called', async () => {
    // Initial load
    component.ngOnInit();
    await new Promise(resolve => setTimeout(resolve, 10));
    
    apiServiceSpy.getSyncStatus.mockClear();
    
    // Refresh
    component.loadStatus();
    await new Promise(resolve => setTimeout(resolve, 10));

    expect(apiServiceSpy.getSyncStatus).toHaveBeenCalled();
  });

  it('should cleanup on destroy', () => {
    component.ngOnInit();
    
    // Should not throw
    expect(() => component.ngOnDestroy()).not.toThrow();
  });
});
