package vaultpkcs11

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	ErrdeviceNotFound = errors.New("encryption device not found")
)

// Device represents a device configuration from the storage backend.
type Device struct {
	// Name is the name of the device in Vault.
	Name string `json:"name"`

	LibPath     string `json:"lib_path"`
	GenerateKey bool   `json:"generate_key`
	Slot        uint   `json:slot`
	Pin         string `json:pin`
}

// Device retrieves the named device from the storage backend, or an error if one does
// not exist.
func (b *backend) GetDevice(ctx context.Context, s logical.Storage, device string) (*Device, error) {
	entry, err := s.Get(ctx, "devices/"+device)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to retrieve device %q: {{err}}", device), err)
	}
	if entry == nil {
		return nil, ErrdeviceNotFound
	}

	var result Device
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to decode entry for %q: {{err}}", device), err)
	}
	return &result, nil
}

// Devices returns the list of devices
func (b *backend) ListDevices(ctx context.Context, s logical.Storage) ([]string, error) {
	entries, err := s.List(ctx, "devices/")
	if err != nil {
		return nil, errwrap.Wrapf("failed to list devices: {{err}}", err)
	}
	return entries, nil
}
