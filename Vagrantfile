# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # config.vm.box = "ubuntu/focal64"     # Ubuntu 20.04 Focal Fossa (non CO-RE)
  # config.vm.box = "ubuntu/hirsute64"   # Ubuntu 21.04 Hirsute Hippo (CO-RE)
  # config.vm.box = "ubuntu/impish64"    #  Ubuntu 21.10 Impish Indri (CO-RE)
  config.vm.box = "ubuntu/jammy64"       #  Ubuntu 22.04 Jammy Jellyfish (CO-RE)

  config.ssh.extra_args = ["-t", "cd /vagrant; bash --login"]

  # Use rsync rather than mounting into the VM as triggers a few issues with permissions during build
  config.vm.synced_folder ".", "/vagrant", type: "rsync"

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "2048"
  end

  config.vm.provision "shell", inline: <<-SHELL
    VAGRANT_HOME="/home/vagrant"

    apt-get update
    apt-get install --yes apt-transport-https ca-certificates curl

    # https://github.com/fluent/fluent-bit/tree/master/packaging/distros/ubuntu

    # Main build
    apt-get install --yes build-essential cmake dh-make git make openssl pkg-config tar
    # Dependencies
    apt-get install --yes libssl3 libssl-dev libsasl2-dev pkg-config libsystemd-dev zlib1g-dev libpq-dev postgresql-server-dev-all flex bison libyaml-dev libpq5 libbpf-dev

    # Debug
    apt-get install --yes gdb valgrind

    # From Unit Tests:
    apt-get install --yes gcc-7 g++-7 clang-6.0 gcovr

    # For packaging potentially
    apt-get install --yes docker.io
    usermod -aG docker vagrant
  SHELL
end
