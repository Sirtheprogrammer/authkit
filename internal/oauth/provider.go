package oauth

import (
	"context"
	"fmt"
	"sync"

	"authkit/internal/domain"
)

// Provider abstracts external OAuth/OIDC identity providers
type Provider interface {
	Name() domain.OAuthProvider
	GetAuthURL(state, redirectURI string) string
	Exchange(ctx context.Context, code, redirectURI string) (*domain.OAuthUserInfo, error)
}

// Manager orchestrates configured OAuth providers
type Manager struct {
	mu        sync.RWMutex
	providers map[domain.OAuthProvider]Provider
}

// NewManager creates a new OAuth provider manager
func NewManager() *Manager {
	return &Manager{
		providers: make(map[domain.OAuthProvider]Provider),
	}
}

// Register adds an OAuth provider to the registry
func (m *Manager) Register(provider Provider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers[provider.Name()] = provider
}

// Unregister removes an OAuth provider from the registry
func (m *Manager) Unregister(name domain.OAuthProvider) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.providers, name)
}

// Clear removes all registered providers
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.providers = make(map[domain.OAuthProvider]Provider)
}

// Get retrieves a provider by its name
func (m *Manager) Get(name domain.OAuthProvider) (Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, exists := m.providers[name]
	if !exists {
		return nil, fmt.Errorf("oauth provider '%s' is not configured or enabled", name)
	}
	return p, nil
}

// EnabledProviders returns list of active provider names
func (m *Manager) EnabledProviders() []domain.OAuthProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]domain.OAuthProvider, 0, len(m.providers))
	for name := range m.providers {
		names = append(names, name)
	}
	return names
}
