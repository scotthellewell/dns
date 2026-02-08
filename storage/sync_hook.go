package storage

import (
	"log"
	"sync/atomic"

	dnssync "github.com/scott/dns/sync"
)

// SyncHook is called when data changes to record the change for synchronization
type SyncHook func(entityType, entityID, tenantID, operation string, data interface{}) error

var (
	// Global sync hook - set by main when sync is enabled
	syncHook SyncHook

	// skipSyncHook is used to disable the sync hook when applying remote changes
	// to prevent changes from being broadcast back to the source
	skipSyncHook atomic.Bool
)

// SetSyncHook sets the global sync hook function
func SetSyncHook(hook SyncHook) {
	syncHook = hook
}

// WithSyncHookDisabled runs the given function with the sync hook disabled.
// This is used when applying remote changes to prevent re-broadcasting.
func WithSyncHookDisabled(fn func() error) error {
	skipSyncHook.Store(true)
	defer skipSyncHook.Store(false)
	return fn()
}

// recordChange records a change for synchronization if sync is enabled
func recordChange(entityType, entityID, tenantID, operation string, data interface{}) {
	if syncHook == nil {
		log.Printf("[storage] sync hook not set, skipping change: %s %s %s", entityType, entityID, operation)
		return
	}

	// Skip if we're in the middle of applying a remote change
	if skipSyncHook.Load() {
		log.Printf("[storage] sync hook disabled (applying remote), skipping: %s %s %s", entityType, entityID, operation)
		return
	}

	log.Printf("[storage] recording change for sync: %s %s %s", entityType, entityID, operation)
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
	EntityTypeSession       = dnssync.EntitySession
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
