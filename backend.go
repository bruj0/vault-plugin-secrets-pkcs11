package vaultpkcs11

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
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
	Device
	p    *pkcs11.Ctx
	sess pkcs11.SessionHandle
}
type backend struct {
	*framework.Backend

	// kmsClient is the actual client for connecting to KMS. It is cached on
	// the backend for efficiency.
	Client           *pkcs11Client
	ClientCreateTime time.Time
	ClientLifetime   time.Duration
	ClientLock       sync.RWMutex

	// ctx and ctxCancel are used to control overall plugin shutdown. These
	// contexts are given to any client libraries or requests that should be
	// terminated during plugin termination.
	ctx       context.Context
	ctxCancel context.CancelFunc
	ctxLock   sync.Mutex

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

	b.generateLeases = true
	b.ClientLifetime = defaultClientLifetime
	b.ctx, b.ctxCancel = context.WithCancel(context.Background())

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        "The PKCS#11 secrets engine provides object management on supported devices",

		Paths: []*framework.Path{

			b.pathDevices(),
			b.pathDevicesDataCRUD(),
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
	switch key {
	case "config":
		b.ResetClient()
	}
}

// ResetClient closes any connected clients.
func (b *backend) ResetClient() {
	b.ClientLock.Lock()
	b.resetClient()
	b.ClientLock.Unlock()
}

// resetClient rests the underlying client. The caller is responsible for
// acquiring and releasing locks. This method is not safe to call concurrently.
func (b *backend) resetClient() {
	if b.Client != nil {
		b.Client.p.Destroy()
		b.Client.p.Finalize()
		b.Client = nil
	}

	b.ClientCreateTime = time.Unix(0, 0).UTC()
}

func (b *backend) Pkcs11Client(s logical.Storage, deviceName string) (*pkcs11Client, func(), error) {
	// If the client already exists and is valid, return it
	b.ClientLock.RLock()
	if b.Client != nil && time.Now().UTC().Sub(b.ClientCreateTime) < b.ClientLifetime {
		closer := func() {
			b.Client.p.Destroy()
			b.Client.p.Finalize()
			b.ClientLock.RUnlock()
		}
		return b.Client, closer, nil
	}
	b.ClientLock.RUnlock()

	// Acquire a full lock. Since all invocations acquire a read lock and defer
	// the release of that lock, this will block until all clients are no longer
	// in use. At that point, we can acquire a globally exclusive lock to close
	// any connections and create a new client.
	b.ClientLock.Lock()

	b.Logger().Debug("creating new PKCS11 session for Device %s", deviceName)

	// Attempt to close an existing client if we have one.
	b.resetClient()

	//Get device configuration
	config, err := b.GetDevice(b.ctx, s, deviceName)
	if err != nil {
		b.ClientLock.Unlock()
		return nil, nil, err
	}
	b.Logger().Debug("Config for device aquierd: %v", config)
	client := &pkcs11Client{}

	client.p = pkcs11.New(config.LibPath)
	err = client.p.Initialize()
	if err != nil {
		return nil, nil, errwrap.Wrapf(fmt.Sprintf("failed to initialize device %s with library %s: {{err}}", deviceName, config.LibPath), err)
	}

	slots, err := client.p.GetSlotList(true)
	if err != nil {
		return nil, nil, errwrap.Wrapf(fmt.Sprintf("failed to GetSlotList from device %s : {{err}}", deviceName), err)
	}
	b.Logger().Debug("Pkcs11Client:", "GetSlotList", "%#v", slots)
	// Cache the client
	b.Client = client
	b.ClientCreateTime = time.Now().UTC()
	b.ClientLock.Unlock()

	b.ClientLock.RLock()
	closer := func() {
		b.Client.p.Destroy()
		b.Client.p.Finalize()
		b.ClientLock.RUnlock()
	}
	return client, closer, nil
}
