// Package sync provides multi-master synchronization between DNS server instances.
package sync

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// HybridLogicalClock provides a Hybrid Logical Clock for ordering events across servers.
// It combines physical time with logical counters to ensure total ordering.
type HybridLogicalClock struct {
	// Physical timestamp (milliseconds since epoch)
	Physical int64 `json:"pt"`
	// Logical counter for events at same physical time
	Logical uint32 `json:"lc"`
	// Server ID that last updated this clock
	ServerID string `json:"sid"`
}

// Compare compares two HLCs. Returns:
//
//	-1 if h < other
//	 0 if h == other
//	 1 if h > other
func (h HybridLogicalClock) Compare(other HybridLogicalClock) int {
	if h.Physical < other.Physical {
		return -1
	}
	if h.Physical > other.Physical {
		return 1
	}
	// Physical times are equal, compare logical
	if h.Logical < other.Logical {
		return -1
	}
	if h.Logical > other.Logical {
		return 1
	}
	// Both equal, use server ID as tiebreaker (deterministic)
	if h.ServerID < other.ServerID {
		return -1
	}
	if h.ServerID > other.ServerID {
		return 1
	}
	return 0
}

// IsZero returns true if the clock has not been initialized
func (h HybridLogicalClock) IsZero() bool {
	return h.Physical == 0 && h.Logical == 0
}

// String returns a string representation of the HLC
func (h HybridLogicalClock) String() string {
	return fmt.Sprintf("%d.%d@%s", h.Physical, h.Logical, h.ServerID)
}

// Clock manages a Hybrid Logical Clock for this server
type Clock struct {
	mu       sync.Mutex
	serverID string
	physical int64
	logical  uint32
}

// NewClock creates a new HLC clock for the given server ID
func NewClock(serverID string) *Clock {
	return &Clock{
		serverID: serverID,
		physical: time.Now().UnixMilli(),
		logical:  0,
	}
}

// Now returns the current HLC timestamp, advancing the clock
func (c *Clock) Now() HybridLogicalClock {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UnixMilli()
	if now > c.physical {
		c.physical = now
		c.logical = 0
	} else {
		c.logical++
	}

	return HybridLogicalClock{
		Physical: c.physical,
		Logical:  c.logical,
		ServerID: c.serverID,
	}
}

// Update updates the local clock based on a received HLC from another server.
// This ensures the clock advances past any received timestamps.
func (c *Clock) Update(received HybridLogicalClock) HybridLogicalClock {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UnixMilli()

	// Find the maximum of local physical, received physical, and current time
	maxPhysical := now
	if c.physical > maxPhysical {
		maxPhysical = c.physical
	}
	if received.Physical > maxPhysical {
		maxPhysical = received.Physical
	}

	if maxPhysical == c.physical && maxPhysical == received.Physical {
		// All equal, increment logical past both
		if c.logical > received.Logical {
			c.logical++
		} else {
			c.logical = received.Logical + 1
		}
	} else if maxPhysical == c.physical {
		// Local physical is max, increment logical
		c.logical++
	} else if maxPhysical == received.Physical {
		// Received physical is max, use received logical + 1
		c.physical = received.Physical
		c.logical = received.Logical + 1
	} else {
		// Current time is max, reset logical
		c.physical = maxPhysical
		c.logical = 0
	}

	return HybridLogicalClock{
		Physical: c.physical,
		Logical:  c.logical,
		ServerID: c.serverID,
	}
}

// Current returns the current HLC without advancing it
func (c *Clock) Current() HybridLogicalClock {
	c.mu.Lock()
	defer c.mu.Unlock()
	return HybridLogicalClock{
		Physical: c.physical,
		Logical:  c.logical,
		ServerID: c.serverID,
	}
}

// Operation types
const (
	OpCreate = "create"
	OpUpdate = "update"
	OpDelete = "delete"
)

// Entity types that can be synchronized
const (
	EntityZone          = "zone"
	EntityRecord        = "record"
	EntityUser          = "user"
	EntityTenant        = "tenant"
	EntityDNSSECKeys    = "dnssec_keys"
	EntityDelegation    = "delegation"
	EntitySecondaryZone = "secondary_zone"
	EntityTransfer      = "transfer"
	EntityRecursion     = "recursion"
	EntityAPIKey        = "api_key"
	EntitySettings      = "settings"
	EntitySession       = "session"
)

// OpLogEntry represents a single operation in the operation log
type OpLogEntry struct {
	// Unique identifier for this operation
	ID string `json:"id"`

	// Server that originated this change
	ServerID string `json:"server_id"`

	// Hybrid logical clock timestamp for ordering
	HLC HybridLogicalClock `json:"hlc"`

	// Wall clock time (for debugging and tombstone expiration)
	Timestamp time.Time `json:"timestamp"`

	// Type of entity: zone, record, user, tenant, dnssec_keys, settings, etc.
	EntityType string `json:"entity_type"`

	// Unique identifier for the entity (zone name, record ID, user ID, etc.)
	EntityID string `json:"entity_id"`

	// Tenant ID (empty for main tenant)
	TenantID string `json:"tenant_id,omitempty"`

	// Operation type: create, update, delete
	Operation string `json:"operation"`

	// The actual data (JSON encoded) - nil for deletes
	Data json.RawMessage `json:"data,omitempty"`

	// Checksum of data for integrity verification (SHA256)
	Checksum string `json:"checksum,omitempty"`
}

// GenerateID generates a unique operation ID
func GenerateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateServerID generates a unique server ID
func GenerateServerID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
