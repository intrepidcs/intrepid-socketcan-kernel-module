#!/bin/sh

sudo rmmod intrepid
sudo modprobe can
sudo modprobe can_raw
sudo modprobe can_dev
sudo insmod intrepid.ko

