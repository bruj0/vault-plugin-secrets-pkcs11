package vaultpkcs11

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestPathKeys_List(t *testing.T) {
	t.Parallel()

	b, storage := testBackend(t)

	ctx := context.Background()
	if err := storage.Put(ctx, &logical.StorageEntry{
		Key:   "devices/my-device",
		Value: []byte(`{"name":"my-device", "lib_path":"/usr/lib/pkcs11/libsofthsm2.so", "slot": "229915468", "pint":"1234"}`),
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Storage:   storage,
		Operation: logical.ListOperation,
		Path:      "devices",
	})
	if err != nil {
		t.Fatal(err)
	}
	if v, exp := resp.Data["keys"].([]string), []string{"my-device"}; !reflect.DeepEqual(v, exp) {
		t.Errorf("expected %q to be %q", v, exp)
	}
}
