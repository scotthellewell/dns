package storage

import (
	"log"

	dnssync "github.com/scott/dns/sync"
)

// SyncHook is called when data changes to record the change for synchronization
type SyncHook func(entityType, entityID, tenantID, operation string, data interface{}) error

var (
	// Global sync hook - set by main when sync is enabled
	syncHook SyncHook
)

// SetSyncHook sets the global sync hook function
func SetSyncHook(hook SyncHook) {
	syncHook = hook
}

// recordChange records a change for synchronization if sync is enabled
func recordChange(entityType, entityID, tenantID, operation string, data interface{}) {
	if syncHook == nil {
		return
	}

	if err := syncHook(entityType, entityID, tenantID, operation, data); err != nil {
		log.Printf("[storage] sync hook error: %v", err)
	}
}

// Entity type constants that map to sync entity types
const (
	EntityTypeZone          = dnssync.EntityZone
	EntityTypeRecord        = dnssync.EntityRecord
	EntityTypeUser          = dnssync.EntityUser
	EntityTypeTenant        = dnssync.EntityTenant
	EntityTypeDNSSECKeys    = dnssync.EntityDNSSECKeys
	EntityTypeDelegation    = dnssync.EntityDelegation
	EntityTypeSecondaryZone = dnssync.EntitySecondaryZone
	EntityTypeTransfer      = dnssync.EntityTransfer
	EntityTypeRecursion     = dnssync.EntityRecursion
	EntityTypeAPIKey        = dnssync.EntityAPIKey
	EntityTypeSettings      = dnssync.EntitySettings
)

// Operation constants
const (
	OpCreate = dnssync.OpCreate
	OpUpdate = dnssync.OpUpdate
	OpDelete = dnssync.OpDelete
)

// =============================================================================
// TODO: Future Sync Enhancements
// =============================================================================
//
// CERTIFICATES (EntityTypeCertificate - to be added):
// - Need to plan for multiple certificates per host for load-balanced scenarios
// - Consider certificate identity (common name + SANs) as the sync key
// - Handle private key synchronization securely
// - May need certificate-specific conflict resolution (prefer newer expiry)
//
// SESSIONS (EntityTypeSession - to be added):
// - Required for round-robin DNS scenarios where users may authenticate
//   on one server and then be routed to another for subsequent requests
// - Security considerations: session tokens should be synced securely
// - May want to sync only active sessions, not expired ones
// - Consider session affinity vs full sync trade-offs
//
// =============================================================================
