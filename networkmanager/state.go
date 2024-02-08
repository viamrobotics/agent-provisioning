package networkmanager

import (
	"sync"
	"time"
)

type connectionState struct {
	mu sync.Mutex

	online     bool
	lastOnline time.Time

	configured bool

	provisioningMode   bool
	provisioningChange time.Time
}

func (c *connectionState) setOnline(online bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.online = online
	if online {
		c.lastOnline = time.Now()
	}
}

// getOnline returns true if online, last online time.
func (c *connectionState) getOnline() (bool, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.online, c.lastOnline
}

func (c *connectionState) setConfigured(configured bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.configured = configured
}

func (c *connectionState) getConfigured() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.configured
}

func (c *connectionState) setProvisioning(mode bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.provisioningMode = mode
	c.provisioningChange = time.Now()
}

// getProvisioning returns true if in provisioning mode, and the time of the last state change.
func (c *connectionState) getProvisioning() (bool, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.provisioningMode, c.provisioningChange
}
