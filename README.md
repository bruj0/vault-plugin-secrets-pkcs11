# vault-plugin-secrets-pkcs11

$ export SOFTHSM2_CONF=softhsm2.conf
$ vault server -dev -dev-root-token-id=root -dev-plugin-dir=./plugins -log-level=trace
$ vault secrets enable pkcs11
Success! Enabled the pkcs11 secrets engine at: pkcs11/
$ vault write pkcs11/devices/my-device lib_path=/usr/lib/pkcs11/libsofthsm2.so slot=229915468 pin=1234
vault read pkcs11/devices/my-device
Key         Value
---         -----
lib_path    /usr/lib/pkcs11/libsofthsm2.so
pin         1234
slot        229915468

$ vault list pkcs11/devices/
Keys
----
my-device


