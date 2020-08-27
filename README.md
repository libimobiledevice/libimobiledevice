# libimobiledevice

*A library to communicate with services on iOS devices using native protocols.*

## Features

libimobiledevice is a cross-platform software library that talks the protocols
to interact with iOS devices.

Unlike other projects, it does not depend on using any existing proprietary
libraries and does not require jailbreaking.

Some key features are:

- **Interface**: Implements many high-level interfaces for device services
- **Implementation**: Object oriented architecture and service abstraction layer
- **Cross-Platform:** Tested on Linux, macOS, Windows and Android platforms
- **Utilities**: Provides various command-line utilities for device services
- **SSL**: Allows choosing between OpenSSL or GnuTLS to handle SSL communication
- **Network**: Supports network connections with "WiFi sync" enabled devices
- **Python:** Provides Cython based bindings for Python

The implemented interfaces of many device service protocols allow applications
to:

* Access filesystem of a device
* Access documents of file sharing apps
* Retrieve information about a device and modify various settings
* Backup and restore the device in a native way compatible with iTunes
* Manage app icons arrangement on the device
* Install, remove, list and basically manage apps
* Activate a device using official serviers
* Manage contacts, calendars, notes and bookmarks
* Retrieve and remove crashreports
* Retrieve various diagnostics information
* Establish a debug connection for app debugging
* Mount filesystem images
* Forward device notifications
* Manage device provisioning
* Take screenshots from the device screen (requires mounted developer image)
* Simulate changed geolocation of the device (requires mounted developer image)
* Relay the syslog of the device
* Expose a connection for WebKit remote debugging

... and much more.

The library is in development since August 2007 with the goal to bring support
for these devices to the Linux Desktop.

## Installation / Getting started

### Debian / Ubuntu Linux

First install all required dependencies and build tools:
```shell
sudo apt-get install \
	build-essential \
	checkinstall \
	git \
	autoconf \
	automake \
	libtool-bin \
	libplist-dev \
	libusbmuxd-dev \
	libssl-dev \
	usbmuxd
```

If you want to optionally build the documentation or Python bindings use:
```shell
sudo apt-get install \
	doxygen \
	cython
```

Then clone the actual project repository:
```shell
git clone https://github.com/libimobiledevice/libimobiledevice.git
cd libimobiledevice
```

Now you can build and install it:
```shell
./autogen.sh
make
sudo make install
```

If you require a custom prefix or other option being passed to `./configure`
you can pass them directly to `./autogen.sh` like this:
```bash
./autogen.sh --prefix=/opt/local --enable-debug
make
sudo make install
```

By default, OpenSSL will be used. If you prefer GnuTLS, configure with
`--disable-openssl` like this:
```bash
./autogen.sh --disable-openssl
```

## Usage

Documentation about using the library in your application is not available yet.
The "hacker way" for now is to look at the implementation of the included
utilities.

### Utilities

The library bundles the following command-line utilities in the tools directory:

| Utility                    | Description                                                        |
| -------------------------- | ------------------------------------------------------------------ |
| `idevice_id`               | List attached devices or print device name of given device         |
| `idevicebackup`            | Create or restore backup for devices (legacy)                      |
| `idevicebackup2`           | Create or restore backups for devices running iOS 4 or later       |
| `idevicecrashreport`       | Retrieve crash reports from a device                               |
| `idevicedate`              | Display the current date or set it on a device                     |
| `idevicedebug`             | Interact with the debugserver service of a device                  |
| `idevicedebugserverproxy`  | Proxy a debugserver connection from a device for remote debugging  |
| `idevicediagnostics`       | Interact with the diagnostics interface of a device                |
| `ideviceenterrecovery`     | Make a device enter recovery mode                                  |
| `ideviceimagemounter`      | Mount disk images on the device                                    |
| `ideviceinfo`              | Show information about a connected device                          |
| `idevicename`              | Display or set the device name                                     |
| `idevicenotificationproxy` | Post or observe notifications on a device                          |
| `idevicepair`              | Manage host pairings with devices and usbmuxd                      |
| `ideviceprovision`         | Manage provisioning profiles on a device                           |
| `idevicescreenshot`        | Gets a screenshot from the connected device                        |
| `idevicesetlocation`       | Simulate location on device                                        |
| `idevicesyslog`            | Relay syslog of a connected device                                 |

Please consult the usage information or manual pages of each utility for a
documentation of available command line options and usage examples like this:
```shell
ideviceinfo --help
man ideviceinfo
```

## Contributing

We welcome contributions from anyone and are grateful for every pull request!

If you'd like to contribute, please fork the `master` branch, change, commit and
send a pull request for review. Once approved it can be merged into the main
code base.

If you plan to contribute larger changes or a major refactoring, please create a
ticket first to discuss the idea upfront to ensure less effort for everyone.

Please make sure your contribution adheres to:
* Try to follow the code style of the project
* Commit messages should describe the change well without being to short
* Try to split larger changes into individual commits of a common domain
* Use your real name and a valid email address for your commits

We are still working on the guidelines so bear with us!

## Links

* Homepage: https://libimobiledevice.org/
* Repository: https://git.libimobiledevice.org/libimobiledevice.git
* Repository (Mirror): https://github.com/libimobiledevice/libimobiledevice.git
* Issue Tracker: https://github.com/libimobiledevice/libimobiledevice/issues
* Mailing List: https://lists.libimobiledevice.org/mailman/listinfo/libimobiledevice-devel
* Twitter: https://twitter.com/libimobiledev

## License

This library and utilities are licensed under the [GNU Lesser General Public License v2.1](https://www.gnu.org/licenses/lgpl-2.1.en.html),
also included in the repository in the `COPYING` file.

## Credits

Apple, iPhone, iPad, iPod, iPod Touch, Apple TV, Apple Watch, Mac, iOS,
iPadOS, tvOS, watchOS, and macOS are trademarks of Apple Inc.

This project is an independent software and has not been authorized, sponsored,
or otherwise approved by Apple Inc.

README Updated on: 2020-06-12
