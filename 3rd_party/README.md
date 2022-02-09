# Third party components/libraries

This folder contains  third party components or libraries  that are used
within the  libimobiledevice project.  They have been bundled since they
are either not readily available on the intended target platforms and/or
have been modified.

Their respective licenses are provided in each corresponding folder in a
file called LICENSE.


## ed25519

Source: https://github.com/orlp/ed25519
Based on commit 7fa6712ef5d581a6981ec2b08ee623314cd1d1c4.
[LICENCE](ed25519/LICENSE)

The original source has not been modified, except that the file `test.c`
and the contained DLL files have been removed. To allow building within
libimobiledevice, a `Makefile.am` has been added.


## libsrp6a-sha512

Source: https://github.com/secure-remote-password/stanford-srp
Based on commit 587900d32777348f98477cb25123d5761fbe3725.
[LICENCE](libsrp6a-sha512/LICENSE)

For the usage within libimobiledevice, only [libsrp](https://github.com/secure-remote-password/stanford-srp/tree/master/libsrp)
has been used as a basis.
It has been adapted to the needs of the libimobiledevice project, and
contains just a part of the original code; it only supports the SRP6a
client method which has been modified to use SHA512 instead of SHA1,
hence the name was changed to `libsrp6a-sha512`.
More details about the modifications can be found in [libsrp6a-sha512/README.md](libsrp6a-sha512/README.md).

