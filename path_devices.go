package vaultpkcs11

import (
	"context"
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	//"github.com/miekg/pkcs11"
)

func (b *backend) pathDevices() *framework.Path {
	return &framework.Path{
		Pattern: "devices/?$",

		HelpSynopsis:    "List configured PKCS11 devices",
		HelpDescription: "List the configured PKCS11 devices available for use.",
		Fields: map[string]*framework.FieldSchema{
			"library_path": &framework.FieldSchema{
				Type:     framework.TypeString,
				Required: true,
				Description: `
	Path to the device pkcs11 library implementation.`,
			},
			"slot": &framework.FieldSchema{
				Type:     framework.TypeString,
				Required: true,
				Description: `
	Slot to use in the device.`,
			},
			"pin": &framework.FieldSchema{
				Type:     framework.TypeString,
				Required: true,
				Description: `
	Pin to login to the Slot.`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathDevicesList,
		},
	}
}
func (b *backend) pathDevicesCRUD() *framework.Path {
	return &framework.Path{
		Pattern: "devices/" + framework.GenericNameRegex("name"),

		HelpSynopsis:    "Interact with pkcs11 objects stored in a device",
		HelpDescription: ``,
		ExistenceCheck:  b.pathDevicesExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathDevicesRead,
			logical.CreateOperation: b.pathDevicesWrite,
			logical.UpdateOperation: b.pathDevicesWrite,
			logical.DeleteOperation: b.pathDevicesDelete,
		},
	}
}

// pathDevicesExistenceCheck is used to check if a given device exists.
func (b *backend) pathDevicesExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	if k, err := b.GetDevice(ctx, req.Storage, name); err != nil || k == nil {
		return false, nil
	}
	return true, nil
}

// pathDevicesRead corresponds to GET devices/:name and is used to show
// information about the device.
func (b *backend) pathDevicesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	k, err := b.GetDevice(ctx, req.Storage, name)
	if err != nil {
		if err == ErrdeviceNotFound {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		return nil, err
	}
	data := map[string]interface{}{
		"name":         k.Name,
		"lib_path":     k.LibPath,
		"generate_key": k.GenerateKey,
		"slot":         k.Slot,
		"pin":          k.Pin,
	}

	return &logical.Response{
		Data: data,
	}, nil
}

// pathDevicesList corresponds to LIST devices/ and is used to list all Devices
// in the system.
func (b *backend) pathDevicesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	devices, err := b.ListDevices(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(devices), nil
}

// pathKeysWrite corresponds to PUT/POST devices/create/:name and creates a
// new GCP KMS key and registers it for use in Vault.
func (b *backend) pathDevicesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//TODO: Check that the configuration works
	/*Client, closer, err := b.Client(req.Storage)
	if err != nil {
		return nil, err
	}
	defer closer()
	*/

	name := d.Get("name").(string)
	libPath := d.Get("lib_path").(string)
	generateKey := d.Get("generate_key").(bool)
	slot := d.Get("slot").(uint)
	pin := d.Get("pin").(string)

	//Check if name is defined on a update operation and deny it
	if name != "" && req.Operation == logical.UpdateOperation {
		return nil, errImmutable("name")
	}
	// Save it
	entry, err := logical.StorageEntryJSON("devices/"+name, &Device{
		Name:        name,
		LibPath:     libPath,
		GenerateKey: generateKey,
		Slot:        slot,
		Pin:         pin,
	})
	if err != nil {
		return nil, errwrap.Wrapf("failed to create storage entry: {{err}}", err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, errwrap.Wrapf("failed to write to storage: {{err}}", err)
	}

	return nil, nil
}

// pathKeysDelete corresponds to PUT/POST devices/delete/:key and deletes an
// existing device
func (b *backend) pathDevicesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	_, err := b.GetDevice(ctx, req.Storage, name)
	if err != nil {
		if err == ErrdeviceNotFound {
			return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
		}
		return nil, err
	}
	// Delete the device from our storage
	if err := req.Storage.Delete(ctx, "devices/"+name); err != nil {
		return nil, errwrap.Wrapf("failed to delete from storage: {{err}}", err)
	}
	return nil, nil
}

// errImmutable is a logical coded error that is returned when the user tries to
// modfiy an immutable field.
func errImmutable(s string) error {
	return logical.CodedError(400, fmt.Sprintf("cannot change %s after key creation", s))
}
