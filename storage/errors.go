package storage

import "errors"

// Common errors
var (
	ErrNotFound           = errors.New("not found")
	ErrAlreadyExists      = errors.New("already exists")
	ErrInvalidData        = errors.New("invalid data")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrZoneInUse          = errors.New("zone is in use by delegation")
	ErrDelegationRequired = errors.New("delegation required to create subzone")
)
