# What this is

This is a plugin for HashiCorp Vault that implements storing data objects into HSM devices using PKCS#11 

It support multiple devices and uses a tree like structure to store objects.

At this stage its considered a MVP for storing data objects on a HSM.

# Installation

1. Download the plugin binary or compile it by using the Makefile
2. Copy the binary to your `plugins` directory.
3. Enable the plugin globaly

```
$ vault write sys/plugins/catalog/database/pkcs11 \
    sha256=<expected SHA256 Hex value of the plugin binary> \
    command="myplugin"
```
4. Mount the secrent engine
```
$ vault secrets enable pkcs11
Success! Enabled the pkcs11 secrets engine at: pkcs11/
```
5. Configure the HSM device
```
$ vault write pkcs11/devices/my-device lib_path="/usr/lib/pkcs11/libsofthsm2.so" slot=229915468 pin="1234"   
$ vault read pkcs11/devices/my-device
Key         Value
---         -----
lib_path    /usr/lib/pkcs11/libsofthsm2.so
pin         1234
slot        229915468

```
6. Read/Write data to your HSM device
```
$ vault write pkcs11/devices/my-device/foo3 bar=foo
Success! Data written to: pkcs11/devices/my-device/foo3
$vault read  pkcs11/devices/my-device/foo3 -format=json
{
  "request_id": "3f2371a1-a0e5-b137-2edc-5cab18ee59c6",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "data": {
      "bar": "foo"
    }
  },
  "warnings": null
}
```

# TODO

- [ ] Add Leases to data objects
- [ ] Add other types of objects
- [ ] Add full testing coverage


# License

Mozilla Public License Version 2.0