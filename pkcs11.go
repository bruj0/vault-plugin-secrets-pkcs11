package vaultpkcs11

import (
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/logical"

	//"github.com/hashicorp/vault/sdk/logical"
	//"google.golang.org/api/option"
	"github.com/miekg/pkcs11"
)

//TODO: Handle multiple devices sessions
func (b *backend) NewPkcs11Client(s logical.Storage, deviceName string) (*pkcs11Client, func(), error) {
	// If the client already exists and is valid, return it
	var cHandler *pkcs11Client
	if val, ok := b.clients[deviceName]; ok { //client exists
		cHandler = val
		cHandler.ClientLock.RLock()
		if cHandler != nil && time.Now().UTC().Sub(cHandler.ClientCreateTime) < cHandler.ClientLifetime { //client NOT expired
			closer := func() {
				cHandler.ClientLock.RUnlock()
			}
			return cHandler, closer, nil
		}

		cHandler.ClientLock.RUnlock()
	} else {
		b.ctxLock.Lock()
		b.Logger().Debug("Pkcs11Client:", "creating new PKCS11 client for Device", deviceName)
		b.clients[deviceName] = &pkcs11Client{
			ClientLifetime: defaultClientLifetime,
		}
		b.ctxLock.Unlock()
		cHandler = b.clients[deviceName]
	}
	// Acquire a full lock. Since all invocations acquire a read lock and defer
	// the release of that lock, this will block until all clients are no longer
	// in use. At that point, we can acquire a globally exclusive lock to close
	// any connections and create a new client.
	cHandler.ClientLock.Lock()

	b.Logger().Debug("Pkcs11Client:", "creating new PKCS11 session for Device", deviceName)

	// Attempt to close an existing client if we have one.
	b.resetClient(cHandler)

	//Get device configuration
	config, err := b.GetDevice(b.ctx, s, deviceName)
	if err != nil {
		cHandler.ClientLock.Unlock()
		return nil, nil, err
	}
	b.Logger().Debug("Pkcs11Client:", "Config for device aquired", config)

	cHandler.p = pkcs11.New(config.LibPath)
	err = cHandler.p.Initialize()
	if err != nil {
		return nil, nil, errwrap.Wrapf(fmt.Sprintf("failed to initialize device %s with library %s: {{err}}", deviceName, config.LibPath), err)
	}

	slots, err := cHandler.p.GetSlotList(true)
	if err != nil {
		return nil, nil, errwrap.Wrapf(fmt.Sprintf("failed to GetSlotList from device %s : {{err}}", deviceName), err)
	}
	b.Logger().Debug("Pkcs11Client:", "GetSlotList", slots)

	deviceConfig, err := b.GetDevice(b.ctx, s, deviceName)
	if err != nil {
		return nil, nil, err
	}
	found := false
	for k, slot := range slots {
		switch {
		case deviceConfig.Slot != 0:
			//log.Debugf("Checking slot:%08d==%08d,id:%d", slot, *config.Slot, k)
			if slot == uint(deviceConfig.Slot) {
				b.Logger().Debug("Pkcs11Client:", "Found slot", slot, "id", k)
				found = true
				break
			}
		}
	}
	if !found {
		b.Logger().Error("Pkcs11Client", "slot not found; available slots are:", slots)
		return nil, nil, fmt.Errorf("Slot not found")
	}
	//GetTokenInfo from the Slot and show debug
	token, err := cHandler.p.GetTokenInfo(uint(deviceConfig.Slot))
	if err != nil {
		b.Logger().Error("Pkcs11Client", "GetTokenInfo:", err)
		return nil, nil, err
	}

	b.Logger().Debug("Pkcs11Client", "GetTokenInfo", spew.Sdump(token))

	cHandler.sess, err = cHandler.p.OpenSession(uint(deviceConfig.Slot), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		b.Logger().Error("Pkcs11Client", "OpenSession:", err)
		return nil, nil, err
	}

	err = cHandler.p.Login(cHandler.sess, pkcs11.CKU_USER, deviceConfig.Pin)
	if err != nil {
		b.Logger().Error("Pkcs11Client", "Login:", err)
		return nil, nil, err
	}

	cHandler.p.DigestInit(cHandler.sess, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	hash, err := cHandler.p.Digest(cHandler.sess, []byte("this is a string"))
	if err != nil {
		b.Logger().Error("Pkcs11Client", "DigestInit:", err)
	}
	b.Logger().Debug("Pkcs11Client", "Digest:", hash)

	// Cache the client
	cHandler.device = deviceConfig
	cHandler.ClientCreateTime = time.Now().UTC()

	cHandler.ClientLock.Unlock()

	cHandler.ClientLock.RLock()
	closer := func() {
		cHandler.ClientLock.RUnlock()
	}
	return cHandler, closer, nil
}
func (b *backend) readData(deviceName, path string) (buf []byte, err error) {
	cHandler := b.clients[deviceName]
	//b.Logger().Debug(spew.Sdump(cHandler))
	//search for the object by label
	label := fmt.Sprintf("vault_path=%s/%s", deviceName, path)
	objHandle, err := b.findObject(pkcs11.CKO_DATA, label, deviceName)
	if err != nil {
		return nil, fmt.Errorf("storeData:error while searching for data object by label: %w", err)
	}

	//object found
	if objHandle == 0 {
		b.Logger().Debug("storeData: data object NOT found", label)
		return nil, fmt.Errorf("object not found")
	}
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	//b.Logger().Debug(spew.Sdump(cHandler))
	//b.Logger().Debug(spew.Sdump(attributes))
	attr, err := cHandler.p.GetAttributeValue(cHandler.sess, objHandle, attributes)

	b.Logger().Debug(spew.Sdump("readData: GetAttributeValue", attr))

	for i, a := range attr {
		b.Logger().Debug("readData: attr ", i, "type", a.Type, "valuelen", len(a.Value))
		if a.Type == pkcs11.CKA_VALUE {
			return []byte(a.Value), nil
		}
	}

	if err != nil {
		return nil, fmt.Errorf("storeData: failed to write data to hsm: %w", err)
	}

	return []byte("test"), nil

}
func (b *backend) storeData(deviceName, path string, buf []byte) (err error) {
	/*
			CK_OBJECT_CLASS class = CKO_DATA;
			CK_UTF8CHAR label[] = “A data object”;
			CK_UTF8CHAR application[] = “An application”;
			CK_BYTE data[] = “Sample data”;
			CK_BBOOL true = CK_TRUE;
			CK_ATTRIBUTE template[] = {
			  {CKA_CLASS, &class, sizeof(class)},
			  {CKA_TOKEN, &true, sizeof(true)}, //to false if not persistent
			  {CKA_LABEL, label, sizeof(label)-1},
			  {CKA_APPLICATION, application, sizeof(application)-1},
			  {CKA_VALUE, data, sizeof(data)},
			  {CKA_PRIVATE}

			};
		idInt, err := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
		if err != nil {
			return fmt.Errorf("storeData: error generating random id: %w", err)
		}
		id := idInt.String()
	*/

	cHandler := b.clients[deviceName]
	//b.Logger().Debug(spew.Sdump(cHandler))
	//search for the object by label
	label := fmt.Sprintf("vault_path=%s/%s", deviceName, path)
	objHandle, err := b.findObject(pkcs11.CKO_DATA, label, deviceName)
	if err != nil {
		return fmt.Errorf("storeData:error while searching for data object by label: %w", err)
	}

	//update operation started
	if objHandle != 0 {
		b.Logger().Debug("storeData: data object found, destroying it and recreating", label)
		err = cHandler.p.DestroyObject(cHandler.sess, objHandle)
		if err != nil {
			return fmt.Errorf("storeData: failed to destroy data object: %w", err)
		}
	}
	//update opration ended

	//create operation started
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_DATA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODIFIABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_APPLICATION, fmt.Sprintf("HashiCorp Vault pkcs11 secret")),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte(buf)),
	}
	//b.Logger().Debug(spew.Sdump(cHandler))
	//b.Logger().Debug(spew.Sdump(attributes))
	_, err = cHandler.p.CreateObject(cHandler.sess, attributes)
	if err != nil {
		return fmt.Errorf("storeData: failed to write data to hsm: %w", err)
	}

	return nil
}

func (b *backend) findObject(class uint, label string, deviceName string) (pkcs11.ObjectHandle, error) {
	cHandler := b.clients[deviceName]
	session := cHandler.sess
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	b.Logger().Debug("findObject", spew.Sdump("Searching for:%s", attributes))
	err := cHandler.p.FindObjectsInit(session, attributes)
	if err != nil {
		return 0, fmt.Errorf("findObject: could not initialize object lookup: %w", err)
	}
	defer cHandler.p.FindObjectsFinal(session)

	objs, moreFound, err := cHandler.p.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("findObject: could not look up object with id %v: %w", label, err)
	}
	if len(objs) == 0 {
		b.Logger().Debug("findObject: found 0 objects")
		return 0, nil
	}
	if moreFound {
		return 0, fmt.Errorf("findObject: expected to find one object with id %v, found %d", label, len(objs))
	}
	b.Logger().Debug(spew.Sdump("findObject:", objs))
	return objs[0], nil
}
