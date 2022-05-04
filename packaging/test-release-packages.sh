#!/bin/bash
set -eux
# Verify package install for a latest release version
docker run --rm -it ubuntu:22.04 sh -c "apt-get update && apt-get install -y sudo gpg curl;curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh"
docker run --rm -it ubuntu:20.04 sh -c "apt-get update && apt-get install -y sudo gpg curl;curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh"
docker run --rm -it ubuntu:18.04 sh -c "apt-get update && apt-get install -y sudo gpg curl;curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh"
docker run --rm -it debian:10 sh -c "apt-get update && apt-get install -y sudo gpg curl;curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh"
docker run --rm -it debian:11 sh -c "apt-get update && apt-get install -y sudo gpg curl;curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh"
docker run --rm -it centos:7 sh -c "yum install -y curl sudo;curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh"
docker run --rm -it rockylinux:8 sh -c "yum install -y curl sudo;curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh"
docker run --rm -it amazonlinux:2 sh -c "yum install -y curl sudo;curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh"
