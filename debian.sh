#!/bin/sh

rm -rf build/*
rm -rf debian/tmp
fakeroot debian/rules clean
fakeroot debian/rules build
fakeroot debian/rules binary
