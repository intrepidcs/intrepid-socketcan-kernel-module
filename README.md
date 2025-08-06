Version 3.1.2

This is the kernel object portion of the Intrepid Control Systems SocketCAN support. For SocketCAN to work with Intrepid devices you will need to have this kernel object loaded on your system. Once the module is built and loaded run [icsscand](https://github.com/intrepidcs/icsscand) to turn on SocketCAN support.

First, install the necessary dependencies for building kernel modules:
- Ubuntu: `sudo apt install linux-headers-generic build-essential gcc git`
- Fedora: `sudo dnf install git kernel-devel-matched`

Clone this repository by running `git clone https://github.com/intrepidcs/intrepid-socketcan-kernel-module.git`

Change into the resulting clone, `cd intrepid-socketcan-kernel-module`

Then, build the KO, `make`

The resulting file will be ```intrepid.ko```. This module depends on ```can```, ```can_dev```, and ```can_raw``` (which should already be a part of your system). Before you can load the module, make sure these modules are loaded, then ```insmod``` can be used to load it.

A script is provided to help within the makefile, `make reload`.

If you prefer to run it yourself, you can run

```
$ sudo modprobe can
$ sudo modprobe can_raw
$ sudo modprobe can_dev
$ sudo insmod intrepid.ko
```

```lsmod``` can confirm the module is loaded. At this point, you can refer to the [icsscand](https://github.com/intrepidcs/icsscand) instructions.

If you wish you have the module auto-load on boot run ```make install``` once the module is built.

```
$ sudo make install
```

Follow your distro-specific method to auto-load modules. For example, on Ubuntu, edit your ```/etc/modules``` file to look something like this:

```
# /etc/modules: kernel modules to load at boot time.
#
# This file contains the names of kernel modules that should be loaded
# at boot time, one per line. Lines beginning with "#" are ignored.
can
can_raw
can_dev
intrepid
```

## Dynamic Debug Support

The module includes debug messages that can be enabled at runtime using the kernel's dynamic debug framework. This requires your kernel to be built with `CONFIG_DYNAMIC_DEBUG=y` (most modern distributions include this).

### Enabling Debug Messages

After building and loading the module with the standard `make` and `make install`, you can enable debug output:

**Enable all debug messages for the intrepid module:**
```bash
$ echo "module intrepid +p" | sudo tee /sys/kernel/debug/dynamic_debug/control
```

**Disable debug messages:**
```bash
$ echo "module intrepid -p" | sudo tee /sys/kernel/debug/dynamic_debug/control
```

**Enable debug messages for specific functions:**
```bash
$ echo "file intrepid.c func function_name +p" | sudo tee /sys/kernel/debug/dynamic_debug/control
```

**View current debug settings:**
```bash
$ sudo cat /sys/kernel/debug/dynamic_debug/control | grep intrepid
```

**View debug output:**
```bash
$ sudo dmesg | grep intrepid
$ sudo dmesg -w  # Follow live output
```

### Available Debug Messages

The debug messages provide information about:
- CAN bittiming configuration
- Frame validation and processing
- Message dropping conditions
- Error handling

Debug messages are primarily triggered during:
- CAN interface configuration
- Frame transmission/reception
- Error conditions and message drops
