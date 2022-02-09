# SRP6a-sha512 library

## About

This library is based on Stanford's Secure Remote Password (SRP) protocol
implementation, or more precise on the `libsrp` part thereof.
The entire source code for the SRP project can be obtained from [here](https://github.com/secure-remote-password/stanford-srp).

It has been adapted to the needs of the libimobiledevice project, and
contains just a part of the original code; it only supports the SRP6a
client method which has been modified to use SHA512 instead of SHA1.
The only supported SRP method is `SRP6a_sha512_client_method()`.
Besides that, support for MbedTLS has been added.

Also, all server-side code has been removed, and the client-side code
has been reduced to a minimum, so that basically only the following
functions remain operational:

- `SRP_initialize_library`
- `SRP_new`
- `SRP_free`
- `SRP_set_user_raw`
- `SRP_set_params`
- `SRP_set_auth_password`
- `SRP_gen_pub`
- `SRP_compute_key`
- `SRP_respond`
- `SRP_verify`

Anything else has not been tested and must be considered non-functional.

## License

The license of the original work does still apply and can be found in the
LICENSE file that comes with the code.
