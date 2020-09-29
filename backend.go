package vaultpkcs11

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	//"github.com/hashicorp/vault/sdk/logical"
	//"google.golang.org/api/option"
	"github.com/miekg/pkcs11"
)

var (
	defaultClientLifetime = 30 * time.Minute
)

type pkcs11Client struct {
	p                *pkcs11.Ctx
	sess             pkcs11.SessionHandle
	objID            int
	ClientCreateTime time.Time
	ClientLifetime   time.Duration
	ClientLock       sync.RWMutex
	// Device data
	device *Device
}

type backend struct {
	*framework.Backend

	//maps devices to pkcs11 clients
	clients map[string]*pkcs11Client
	// ctx and ctxCancel are used to control overall plugin shutdown. These
	// contexts are given to any client libraries or requests that should be
	// terminated during plugin termination.
	ctx            context.Context
	ctxCancel      context.CancelFunc
	ctxLock        sync.Mutex
	generateLeases bool
}

// Factory returns a configured instance of the backend.
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend returns a configured instance of the backend.
func Backend() *backend {
	var b backend

	b.generateLeases = false
	b.clients = make(map[string]*pkcs11Client)
	b.ctx, b.ctxCancel = context.WithCancel(context.Background())

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        "The PKCS#11 secrets engine provides object management on supported devices",

		Paths: []*framework.Path{
			b.pathDevicesData(),
			b.pathDevicesDataCRUD(),
			b.pathDevices(),
			b.pathDevicesCRUD(),
		},
		Invalidate: b.invalidate,
		Clean:      b.clean,
		Secrets: []*framework.Secret{
			&framework.Secret{
				Type: "pkcs11",

				Renew: b.pathDevicesDataRead,
				Revoke: func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
					// This is a no-op
					return nil, nil
				},
			},
		},
	}

	return &b
}

// clean cancels the shared contexts. This is called just before unmounting
// the plugin.
func (b *backend) clean(_ context.Context) {
	b.ctxLock.Lock()
	b.ctxCancel()
	b.ctxLock.Unlock()
}

// invalidate resets the plugin. This is called when a key is updated via
// replication.
func (b *backend) invalidate(ctx context.Context, key string) {
	switch {
	case strings.HasPrefix(key, "devices/"):
		// Check that the invalidation was made on device/<name>
		parts := strings.Split(key, "/")
		b.Logger().Debug("invalidate:", "found %#v", parts)
		if len(parts) == 2 {
			b.ResetClient(parts[1])
		}
	}
}

// ResetClient closes any connected clients.
func (b *backend) ResetClient(deviceName string) {
	cHandler := b.clients[deviceName]
	cHandler.ClientLock.Lock()
	b.resetClient(cHandler)
	cHandler.ClientLock.Unlock()
}

// resetClient rests the underlying client. The caller is responsible for
// acquiring and releasing locks. This method is not safe to call concurrently.
func (b *backend) resetClient(cHandler *pkcs11Client) {
	if cHandler.ClientCreateTime.IsZero() {
		return
	}
	b.Logger().Debug("resetClient:", "destroying PKCS11 client for Device: %s", cHandler.device.Name)
	cHandler.p.Destroy()
	cHandler.p.Finalize()
	cHandler.ClientCreateTime = time.Unix(0, 0).UTC()
}
