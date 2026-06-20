#!/bin/sh

fakeroot debian/rules clean
fakeroot debian/rules build
fakeroot debian/rules binary

