Version 2.0.5

This is the kernel object portion of the Intrepid Control Systems SocketCAN support. For SocketCAN to work with Intrepid devices you will need to have this kernel object loaded on your system. Once the module is built and loaded run [icsscand](https://github.com/intrepidcs/icsscand) to turn on SocketCAN support.

First, install the necessary dependencies for building kernel modules.

On Ubuntu, this is accomplished by running `sudo apt install linux-headers-generic build-essential gcc git`

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
