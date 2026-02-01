package auth

import (
	"context"
)

type contextKey string

const sessionKey contextKey = "session"

// withSession adds a session to the context
func withSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, sessionKey, session)
}

// GetSession retrieves the session from the context
func GetSession(ctx context.Context) *Session {
	session, ok := ctx.Value(sessionKey).(*Session)
	if !ok {
		return nil
	}
	return session
}

// GetUserID retrieves the user ID from the context
func GetUserID(ctx context.Context) string {
	session := GetSession(ctx)
	if session == nil {
		return ""
	}
	return session.UserID
}

// GetUsername retrieves the username from the context
func GetUsername(ctx context.Context) string {
	session := GetSession(ctx)
	if session == nil {
		return ""
	}
	return session.Username
}

// GetRole retrieves the role from the context
func GetRole(ctx context.Context) string {
	session := GetSession(ctx)
	if session == nil {
		return ""
	}
	return session.Role
}

// IsAdmin checks if the current user is an admin
func IsAdmin(ctx context.Context) bool {
	return GetRole(ctx) == "admin"
}
