package storage

import (
	"sync"
	"time"
)

// User represents a user with authentication credentials
type User struct {
	ARN          string
	Username     string
	Password     string
	ExpiresAt    time.Time
	PrimaryGroup string
}

// UserStore provides thread-safe user storage with automatic cleanup
type UserStore struct {
	mu              sync.RWMutex
	users           map[string]*User
	cleanupInterval time.Duration
}

// NewUserStore creates a new thread-safe user store
func NewUserStore(cleanupInterval time.Duration) *UserStore {
	store := &UserStore{
		users:           make(map[string]*User),
		cleanupInterval: cleanupInterval,
	}

	// Start cleanup goroutine
	go store.cleanupExpiredUsers()

	return store
}

// Set stores a user with multiple bind DN variations
func (s *UserStore) Set(bindDNs []string, user *User) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, bindDN := range bindDNs {
		s.users[bindDN] = user
	}
}

// Get retrieves a user by bind DN
func (s *UserStore) Get(bindDN string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[bindDN]
	if !exists || user.ExpiresAt.Before(time.Now()) {
		return nil, false
	}

	return user, true
}

// cleanupExpiredUsers removes expired users at configured interval
func (s *UserStore) cleanupExpiredUsers() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for bindDN, user := range s.users {
			if user.ExpiresAt.Before(now) {
				delete(s.users, bindDN)
			}
		}
		s.mu.Unlock()
	}
}
