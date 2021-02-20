#!/bin/sh
clear;
make clean;
make;
rmmod myfw;
insmod myfw.ko;
dmesg -c;
