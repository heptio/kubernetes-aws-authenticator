package regions

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	stsServiceID = "sts"
)

// Discoverer returns a list of valid STS service hostsnames
type Discoverer interface {
	Find(context.Context) (map[string]bool, error)
}

// EndpointVerifier reports if a given hostname is valid
type EndpointVerifier interface {
	Verify(string) bool // Verify if a given hostname is valid
	Stop() error        // Stop the verifier from updating
}

// NewEndpointVerifier returns a populated Verifier that updates based a given
// Discoverer every 24 hours. The EndpointVerifier is thread-safe and locks for
// updates.
//
// If the Discoverer returns an error on a future update, the error is logged
// and previous Discoverer values are used. Invocations can call v.Stop() to
// end future updates.
func NewEndpointVerifier(d Discoverer) (EndpointVerifier, error) {
	resp := &endpointVerifier{
		d:      d,
		mu:     sync.RWMutex{},
		done:   make(chan bool),
		period: time.Hour * 24,
	}
	hosts, err := d.Find(context.Background())
	if err != nil {
		return nil, err
	}
	resp.hosts = hosts

	go resp.run()

	return resp, nil
}

type endpointVerifier struct {
	d     Discoverer
	hosts map[string]bool
	mu    sync.RWMutex
	done  chan bool

	period time.Duration
}

func (v *endpointVerifier) Verify(host string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	_, ok := v.hosts[host]
	return ok
}

func (v *endpointVerifier) Stop() error {
	v.done <- true
	return nil
}

func (v *endpointVerifier) run() {
	ticker := time.NewTicker(v.period)
	defer ticker.Stop()
	for {
		select {
		case <-v.done:
			logrus.Info("stopping Verifier updates")
			return
		case <-ticker.C:
			v.mu.Lock()
			if hosts, err := v.d.Find(context.Background()); err == nil {
				v.hosts = hosts
			} else {
				logrus.Errorf("failed to discover sts hosts: %v", err)
			}
			v.mu.Unlock()
		}
	}
}
