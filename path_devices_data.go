package vaultpkcs11

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/helper/wrapping"
	"github.com/hashicorp/vault/sdk/logical"
	//"github.com/miekg/pkcs11"
)

func (b *backend) pathDevicesData() *framework.Path {
	return &framework.Path{
		Pattern: "devices/" + framework.GenericNameRegex("device_name") + "/$",
		Fields: map[string]*framework.FieldSchema{
			"device_name": &framework.FieldSchema{
				Type:     framework.TypeString,
				Required: true,
				Description: `
	Path to the stored object.`,
			},
		},
		HelpSynopsis:    "List data objects stored in the device root",
		HelpDescription: "List data objects stored in the device root",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathDevicesDataRootList,
		},
	}
}
func (b *backend) pathDevicesDataCRUD() *framework.Path {
	return &framework.Path{
		Pattern: "devices/" + framework.GenericNameRegex("device_name") + "/" + framework.MatchAllRegex("path"),

		HelpSynopsis:    "Interact with pkcs11 objects stored in a device",
		HelpDescription: ``,
		Fields: map[string]*framework.FieldSchema{
			"path": &framework.FieldSchema{
				Type:     framework.TypeString,
				Required: true,
				Description: `
	Path to the stored object.`,
			},
			"device_name": &framework.FieldSchema{
				Type:     framework.TypeString,
				Required: true,
				Description: `
	Name of the device this object belongs to.`,
			},
		},
		ExistenceCheck: b.pathDevicesExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathDevicesDataRead,
			logical.CreateOperation: b.pathDevicesDataWrite,
			logical.UpdateOperation: b.pathDevicesDataWrite,
			logical.DeleteOperation: b.pathDevicesDataDelete,
			logical.ListOperation:   b.pathDevicesDataList,
		},
	}
}

// pathDevicesExistenceCheck is used to check if a given device exists.
func (b *backend) pathDevicesDataExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	nameRaw, ok := d.GetOk("device_name")
	if !ok {
		return true, errMissingFields("device_name")
	}
	name := nameRaw.(string)

	pathRaw, ok := d.GetOk("path")
	if !ok {
		return true, errMissingFields("path")
	}
	path := pathRaw.(string)

	key := "devices/" + name + "/" + path

	if k, err := b.GetDevice(ctx, req.Storage, key); err != nil || k == nil {
		return false, nil
	}
	return true, nil
}

// pathDevicesRead corresponds to GET devices/:name and is used to show
// information about the device.
func (b *backend) pathDevicesDataRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("device_name")
	if !ok {
		return nil, errMissingFields("device_name")
	}
	name := nameRaw.(string)

	pathRaw, ok := d.GetOk("path")
	if !ok {
		return nil, errMissingFields("path")
	}
	path := pathRaw.(string)

	key := "devices/" + name + "/" + path

	// Read the path
	out, err := req.Storage.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}

	// Fast-path the no data case
	if out == nil {
		return nil, nil
	}

	// Decode the data
	var rawData map[string]interface{}

	if err := jsonutil.DecodeJSON(out.Value, &rawData); err != nil {
		return nil, fmt.Errorf("json decoding failed: %v", err)
	}

	var resp *logical.Response
	if b.generateLeases {
		// Generate the response
		resp = b.Secret("pkcs11").Response(rawData, nil)
		resp.Secret.Renewable = false
	} else {
		resp = &logical.Response{
			Secret: &logical.Secret{},
			Data:   rawData,
		}
	}

	// Ensure seal wrapping is carried through if the response is
	// response-wrapped
	if out.SealWrap {
		if resp.WrapInfo == nil {
			resp.WrapInfo = &wrapping.ResponseWrapInfo{}
		}
		resp.WrapInfo.SealWrap = out.SealWrap
	}

	// Check if there is a ttl key
	ttlDuration := b.System().DefaultLeaseTTL()
	ttlRaw, ok := rawData["ttl"]
	if !ok {
		ttlRaw, ok = rawData["lease"]
	}
	if ok {
		dur, err := parseutil.ParseDurationSecond(ttlRaw)
		if err == nil {
			ttlDuration = dur
		}

		if b.generateLeases {
			resp.Secret.Renewable = true
		}
	}

	resp.Secret.TTL = ttlDuration

	return resp, nil

}

// pathDevicesList corresponds to LIST devices/ and is used to list all Devices
// in the system.
func (b *backend) pathDevicesDataRootList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathDevicesDataRootList", "FieldData", spew.Sdump(d))
	nameRaw, ok := d.GetOk("device_name")
	if !ok {
		return nil, errMissingFields("device_name")
	}
	name := nameRaw.(string)

	path := "devices/" + name

	if path != "" && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	// List the keys at the prefix given by the request
	keys, err := req.Storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	// Generate the response
	return logical.ListResponse(keys), nil

}

// pathDevicesList corresponds to LIST devices/ and is used to list all Devices
// in the system.
func (b *backend) pathDevicesDataList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("pathDevicesDataList", "FieldData", spew.Sdump(d))
	nameRaw, ok := d.GetOk("device_name")
	if !ok {
		return nil, errMissingFields("device_name")
	}
	name := nameRaw.(string)

	pathRaw, ok := d.GetOk("path")
	if !ok {
		return nil, errMissingFields("path")
	}
	path := "devices/" + name + "/" + pathRaw.(string)

	if path != "" && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	// List the keys at the prefix given by the request
	keys, err := req.Storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	// Generate the response
	return logical.ListResponse(keys), nil

}

// pathKeysWrite corresponds to PUT/POST devices/:name and creates a
// new data object in the HSM
func (b *backend) pathDevicesDataWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	nameRaw, ok := d.GetOk("device_name")
	if !ok {
		return nil, errMissingFields("device_name")
	}
	name := nameRaw.(string)

	pathRaw, ok := d.GetOk("path")
	if !ok {
		return nil, errMissingFields("path")
	}
	path := pathRaw.(string)
	// Check that some fields are given
	if len(req.Data) == 0 {
		return logical.ErrorResponse("missing data fields"), nil
	}
	// JSON encode the data
	buf, err := json.Marshal(req.Data)
	if err != nil {
		return nil, fmt.Errorf("json encoding failed: %v", err)
	}
	//if buf, ok := req.Data["secret"]; ok {
	err = b.storeData(name, path, buf)
	if err != nil {
		return nil, fmt.Errorf("pathDevicesDataWrite: failed to write: %v", err)
	}
	//}

	/*


		// Write out a new key
		entry := &logical.StorageEntry{
			Key:   "devices/" + name + "/" + path,
			Value: buf,
		}
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("failed to write: %v", err)
		}*/

	return nil, nil

}

// pathKeysDelete corresponds to PUT/POST devices/delete/:key and deletes an
// existing device
func (b *backend) pathDevicesDataDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("device_name")
	if !ok {
		return nil, errMissingFields("device_name")
	}
	name := nameRaw.(string)

	pathRaw, ok := d.GetOk("path")
	if !ok {
		return nil, errMissingFields("path")
	}
	path := pathRaw.(string)

	key := "devices/" + name + "/" + path

	// Delete the key at the request path
	if err := req.Storage.Delete(ctx, key); err != nil {
		return nil, err
	}
	return nil, nil
}
