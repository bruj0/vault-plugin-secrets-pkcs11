package vaultpkcs11

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"

	hclog "github.com/hashicorp/go-hclog"
)

// testBackend creates a new isolated instance of the backend for testing.
func testBackend(tb testing.TB) (*backend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}
	return b.(*backend), config.StorageView
}
