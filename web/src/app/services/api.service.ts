import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface ServerStatus {
  status: string;
  uptime: string;
  uptime_seconds: number;
  total_queries: number;
  queries_by_type: { [key: string]: number };
  listen: string;
  zone_count: number;
  record_count: number;
  secondary_zones: number;
}

export type ZoneType = 'forward' | 'reverse';

export interface Zone {
  id?: number;
  zone_id?: string;         // Storage-based ID (zone name)
  name: string;             // Zone name (e.g., "example.com" or "168.192.in-addr.arpa")
  type: ZoneType;           // "forward" or "reverse"
  subnet?: string;          // For reverse zones
  domain?: string;          // For reverse zones (legacy)
  strip_prefix: boolean;
  ttl: number;
  // DNSSEC fields (populated when fetching zone details)
  dnssec_enabled?: boolean;
  dnssec_algorithm?: string;
  dnssec_ds_record?: string;
  dnssec_ksk_key_tag?: number;
}

export interface DnsRecord {
  type: string;
  zone?: string;            // Zone this record belongs to
  name?: string;
  ip?: string;
  ttl: number;
  priority?: number;
  target?: string;
  values?: string[];
  mname?: string;
  rname?: string;
  serial?: number;
  refresh?: number;
  retry?: number;
  expire?: number;
  minimum?: number;
  weight?: number;
  port?: number;
  flag?: number;
  tag?: string;
  value?: string;
  hostname?: string;
  // SSHFP
  algorithm?: number;
  fp_type?: number;
  fingerprint?: string;
  // TLSA
  usage?: number;
  selector?: number;
  matching_type?: number;
  certificate?: string;
  // NAPTR
  order?: number;
  preference?: number;
  flags?: string;
  service?: string;
  regexp?: string;
  replacement?: string;
  // SVCB/HTTPS
  params?: { [key: string]: string };
  // LOC
  latitude?: number;
  longitude?: number;
  altitude?: number;
  size?: number;
  horiz_pre?: number;
  vert_pre?: number;
}

export interface SecondaryZone {
  zone: string;
  primary: string;
  primaries?: string[];
  refresh_interval: number;
  retry_interval?: number;
  tsig_key?: string;
  // DNSSEC key sharing for secondary signing
  dnssec_key_url?: string;   // URL to fetch keys from primary
  dnssec_key_token?: string; // Token for authentication
}

export interface TransferConfig {
  enabled: boolean;
  tsig_keys: TsigKey[];
  acls: TransferAcl[];
  notify_targets?: NotifyTarget[];
}

export interface TsigKey {
  name: string;
  algorithm: string;
  secret: string;
}

export interface TransferAcl {
  zone: string;
  allow_transfer?: string[];
  allow_notify?: string[];
  tsig_key?: string;
}

export interface NotifyTarget {
  zone: string;
  targets: string[];
  tsig_key?: string;
}

export interface RecursionConfig {
  enabled: boolean;
  mode: string;
  upstream?: string[];
  timeout: number;
  max_depth: number;
}

export interface DnssecZone {
  zone: string;
  algorithm: string;
  enabled: boolean;
  key_dir?: string;
  auto_create?: boolean;
  ksk_key_tag?: number;
  zsk_key_tag?: number;
  ds_record?: string;
  ksk_public?: string;
  ksk_created?: string;
  ksk_rotation_due?: boolean;  // Advisory flag when KSK should be rotated
  has_key_token?: boolean;     // Whether a key sharing token exists
  created_at?: string;
  updated_at?: string;
}

// Port configuration types
export interface DNSPortConfig {
  enabled: boolean;
  port: number;
  address: string;
}

export interface DoTPortConfig {
  enabled: boolean;
  port: number;
  address: string;
}

export interface DoHPortConfig {
  enabled: boolean;
  port: number;
  address: string;
  path: string;
  standalone: boolean; // If false, shares port with Web UI
}

export interface WebPortConfig {
  enabled: boolean;
  port: number;
  address: string;
  tls: boolean; // Enable HTTPS
}

export interface PortsConfig {
  dns: DNSPortConfig;
  dot: DoTPortConfig;
  doh: DoHPortConfig;
  web: WebPortConfig;
}

// Certificate types
export interface CertificateInfo {
  auto_generated: boolean;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  dns_names: string[];
  ip_addresses: string[];
  is_expired: boolean;
  is_expiring_soon: boolean;
}

export interface GenerateCertRequest {
  common_name: string;
  dns_names: string[];
  ip_addresses: string[];
}

export interface UploadCertRequest {
  certificate: string;
  private_key: string;
}

// DNSSEC Key Export/Import
export interface DnssecKeyExport {
  zone: string;
  algorithm: string;
  ksk_private: string;  // PEM-encoded private key
  ksk_public: string;   // DNSKEY record
  ksk_key_tag: number;
  ksk_created?: string;
  zsk_private: string;  // PEM-encoded private key
  zsk_public: string;   // DNSKEY record
  zsk_key_tag: number;
  zsk_created?: string;
  ds_record: string;
  ksk_rotation_due?: boolean;  // Advisory flag when KSK should be rotated
}

export interface DnssecKeyImport {
  algorithm: string;
  ksk_private: string;
  ksk_public: string;
  ksk_key_tag: number;
  zsk_private: string;
  zsk_public: string;
  zsk_key_tag: number;
  ds_record?: string;
}

// DNSSEC Key Token for Secondary Server Key Sharing
export interface KeyTokenInfo {
  zone: string;
  has_token: boolean;
  token: string;  // Masked token (e.g., "abcd...wxyz")
}

export interface KeyTokenResponse {
  zone: string;
  token: string;  // Full token (only shown on generation)
}

// Zone Delegation
export interface GlueRecord {
  hostname: string;
  ip: string;
  ip_type: string;  // "A" or "AAAA"
}

export interface DsRecordData {
  key_tag: number;
  algorithm: number;
  digest_type: number;
  digest: string;
}

export interface Delegation {
  parent_zone: string;
  child_zone: string;
  nameservers: string[];
  glue_records?: GlueRecord[];
  ds_records?: DsRecordData[];
}

@Injectable({
  providedIn: 'root'
})
export class ApiService {
  private baseUrl = '/api';

  constructor(private http: HttpClient) {}

  // Status
  getStatus(): Observable<ServerStatus> {
    return this.http.get<ServerStatus>(`${this.baseUrl}/status`);
  }

  // Zones
  getZones(): Observable<Zone[]> {
    return this.http.get<Zone[]>(`${this.baseUrl}/zones`);
  }

  addZone(zone: Zone): Observable<any> {
    return this.http.post(`${this.baseUrl}/zones`, zone);
  }

  updateZone(id: number | string, zone: Zone): Observable<any> {
    return this.http.put(`${this.baseUrl}/zones/${id}`, zone);
  }

  deleteZone(id: number | string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/zones/${id}`);
  }

  // Records
  getRecords(type?: string, zone?: string): Observable<DnsRecord[]> {
    const params: string[] = [];
    if (type) params.push(`type=${type}`);
    if (zone) params.push(`zone=${encodeURIComponent(zone)}`);
    const queryString = params.length ? `?${params.join('&')}` : '';
    return this.http.get<DnsRecord[]>(`${this.baseUrl}/records${queryString}`);
  }

  addRecord(record: DnsRecord): Observable<any> {
    return this.http.post(`${this.baseUrl}/records`, record);
  }

  updateRecord(type: string, index: number, record: DnsRecord): Observable<any> {
    return this.http.put(`${this.baseUrl}/records/${type}/${index}`, record);
  }

  deleteRecord(type: string, index: number): Observable<any> {
    return this.http.delete(`${this.baseUrl}/records/${type}/${index}`);
  }

  // Secondary Zones
  getSecondaryZones(): Observable<SecondaryZone[]> {
    return this.http.get<SecondaryZone[]>(`${this.baseUrl}/secondary-zones`);
  }

  addSecondaryZone(zone: SecondaryZone): Observable<any> {
    return this.http.post(`${this.baseUrl}/secondary-zones`, zone);
  }

  updateSecondaryZone(zone: string, data: SecondaryZone): Observable<any> {
    return this.http.put(`${this.baseUrl}/secondary-zones/${encodeURIComponent(zone)}`, data);
  }

  deleteSecondaryZone(zone: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/secondary-zones/${encodeURIComponent(zone)}`);
  }

  createSecondaryZone(zone: SecondaryZone): Observable<any> {
    return this.http.post(`${this.baseUrl}/secondary-zones`, zone);
  }

  // Transfer Settings
  getTransferConfig(): Observable<TransferConfig> {
    return this.http.get<TransferConfig>(`${this.baseUrl}/transfer`);
  }

  updateTransferConfig(config: TransferConfig): Observable<any> {
    return this.http.put(`${this.baseUrl}/transfer`, config);
  }

  // Recursion Settings
  getRecursionConfig(): Observable<RecursionConfig> {
    return this.http.get<RecursionConfig>(`${this.baseUrl}/recursion`);
  }

  updateRecursionConfig(config: RecursionConfig): Observable<any> {
    return this.http.put(`${this.baseUrl}/recursion`, config);
  }

  // DNSSEC Settings
  getDnssecConfig(): Observable<DnssecZone[]> {
    return this.http.get<DnssecZone[]>(`${this.baseUrl}/dnssec`);
  }

  enableDnssec(zone: string, algorithm: string): Observable<DnssecZone> {
    return this.http.post<DnssecZone>(`${this.baseUrl}/dnssec`, { zone, algorithm });
  }

  updateDnssec(zone: string, algorithm: string, enabled: boolean): Observable<any> {
    return this.http.put(`${this.baseUrl}/dnssec`, { zone, algorithm, enabled });
  }

  deleteDnssec(zone: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/dnssec?zone=${encodeURIComponent(zone)}`);
  }

  // DNSSEC Key Export/Import
  exportDnssecKeys(zone: string): Observable<DnssecKeyExport> {
    return this.http.get<DnssecKeyExport>(`${this.baseUrl}/dnssec/keys/${encodeURIComponent(zone)}`);
  }

  importDnssecKeys(zone: string, keys: DnssecKeyImport): Observable<any> {
    return this.http.put(`${this.baseUrl}/dnssec/keys/${encodeURIComponent(zone)}`, keys);
  }

  // DNSSEC Key Token Management
  getKeyToken(zone: string): Observable<KeyTokenInfo> {
    return this.http.get<KeyTokenInfo>(`${this.baseUrl}/dnssec/token/${encodeURIComponent(zone)}`);
  }

  generateKeyToken(zone: string): Observable<KeyTokenResponse> {
    return this.http.post<KeyTokenResponse>(`${this.baseUrl}/dnssec/token/${encodeURIComponent(zone)}`, {});
  }

  revokeKeyToken(zone: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/dnssec/token/${encodeURIComponent(zone)}`);
  }

  // Delegations
  getDelegations(parentZone?: string): Observable<Delegation[]> {
    const params = parentZone ? `?parent=${encodeURIComponent(parentZone)}` : '';
    return this.http.get<Delegation[]>(`${this.baseUrl}/delegations${params}`);
  }

  createDelegation(delegation: Delegation): Observable<Delegation> {
    return this.http.post<Delegation>(`${this.baseUrl}/delegations`, delegation);
  }

  updateDelegation(parentZone: string, childZone: string, delegation: Delegation): Observable<Delegation> {
    return this.http.put<Delegation>(`${this.baseUrl}/delegations/${encodeURIComponent(parentZone)}/${encodeURIComponent(childZone)}`, delegation);
  }

  deleteDelegation(parentZone: string, childZone: string): Observable<any> {
    return this.http.delete(`${this.baseUrl}/delegations/${encodeURIComponent(parentZone)}/${encodeURIComponent(childZone)}`);
  }

  // Server Settings
  getSettings(): Observable<ServerSettings> {
    return this.http.get<ServerSettings>(`${this.baseUrl}/settings`);
  }

  updateSettings(settings: ServerSettings): Observable<any> {
    return this.http.put(`${this.baseUrl}/settings`, settings);
  }

  // Port Configuration
  getPorts(): Observable<PortsConfig> {
    return this.http.get<PortsConfig>(`${this.baseUrl}/ports`);
  }

  updateDNSPort(config: DNSPortConfig): Observable<any> {
    return this.http.put(`${this.baseUrl}/ports/dns`, config);
  }

  updateDoTPort(config: DoTPortConfig): Observable<any> {
    return this.http.put(`${this.baseUrl}/ports/dot`, config);
  }

  updateDoHPort(config: DoHPortConfig): Observable<any> {
    return this.http.put(`${this.baseUrl}/ports/doh`, config);
  }

  updateWebPort(config: WebPortConfig): Observable<any> {
    return this.http.put(`${this.baseUrl}/ports/web`, config);
  }

  // Certificate Management
  getCertificate(): Observable<CertificateInfo> {
    return this.http.get<CertificateInfo>(`${this.baseUrl}/certs`);
  }

  generateCertificate(request: GenerateCertRequest): Observable<any> {
    return this.http.post(`${this.baseUrl}/certs/generate`, request);
  }

  uploadCertificate(certificate: string, privateKey: string): Observable<any> {
    const request: UploadCertRequest = {
      certificate: certificate,
      private_key: privateKey
    };
    return this.http.post(`${this.baseUrl}/certs/upload`, request);
  }

  uploadCertificateFiles(certFile: File, keyFile: File): Observable<any> {
    const formData = new FormData();
    formData.append('certificate', certFile);
    formData.append('private_key', keyFile);
    return this.http.post(`${this.baseUrl}/certs/upload`, formData);
  }

  // ACME / Let's Encrypt
  getACMEConfig(): Observable<ACMEConfig> {
    return this.http.get<ACMEConfig>(`${this.baseUrl}/certs/acme`);
  }

  updateACMEConfig(config: ACMEConfig): Observable<any> {
    return this.http.put(`${this.baseUrl}/certs/acme`, config);
  }

  requestACMECertificate(email: string, domains: string[]): Observable<any> {
    return this.http.post(`${this.baseUrl}/certs/acme/request`, { email, domains });
  }

  renewACMECertificate(): Observable<any> {
    return this.http.post(`${this.baseUrl}/certs/acme/renew`, {});
  }

  // Cluster Sync API
  getSyncStatus(): Observable<ClusterStatus> {
    return this.http.get<ClusterStatus>(`${this.baseUrl}/sync/status`);
  }

  getSyncPeers(): Observable<SyncPeer[]> {
    return this.http.get<SyncPeer[]>(`${this.baseUrl}/sync/peers`);
  }

  addSyncPeer(peer: SyncPeer): Observable<any> {
    return this.http.post(`${this.baseUrl}/sync/peers`, peer);
  }

  forceSync(serverId: string): Observable<any> {
    return this.http.post(`${this.baseUrl}/sync/force`, { server_id: serverId });
  }

  getSyncConfig(): Observable<SyncConfig> {
    return this.http.get<SyncConfig>(`${this.baseUrl}/sync/config`);
  }

  updateSyncConfig(config: SyncConfig): Observable<any> {
    return this.http.put(`${this.baseUrl}/sync/config`, config);
  }

  generateSyncSecret(): Observable<{ secret: string }> {
    return this.http.post<{ secret: string }>(`${this.baseUrl}/sync/config/generate-secret`, {});
  }
}

// Cluster Sync types
export interface HybridLogicalClock {
  pt: number;   // Physical time (milliseconds)
  lc: number;   // Logical counter
  sid: string;  // Server ID
}

export interface PeerState {
  server_id: string;
  server_name: string;
  url: string;
  connected: boolean;
  last_hlc: HybridLogicalClock;
  last_sync_time: string;
  pending_ops: number;
  last_error?: string;
  last_error_time?: string;
}

export interface ClusterStatus {
  server_id: string;
  server_name: string;
  enabled: boolean;
  current_hlc: HybridLogicalClock;
  oplog_entries: number;
  peers: PeerState[];
}

export interface SyncPeer {
  url: string;
  insecure_skip_verify?: boolean;
}

export interface SyncConfig {
  enabled: boolean;
  server_id: string;
  server_name: string;
  listen_addr: string;
  shared_secret: string;
  peers: SyncPeer[];
  tombstone_retention_days: number;
}

// ACME configuration
export interface ACMEConfig {
  enabled: boolean;
  email: string;
  domains: string[];
  use_staging: boolean;
  challenge_type: string;
  auto_renew: boolean;
  renew_before: number;
  last_renewal?: string;
  next_renewal?: string;
}

export interface ServerSettings {
  listen: string;
}
