#!/usr/bin/env bash
set -e

# Provided primarily to simplify testing for staging, etc.
RELEASE_URL=${FLUENT_BIT_PACKAGES_URL:-https://packages.fluentbit.io}
RELEASE_KEY=${FLUENT_BIT_PACKAGES_KEY:-$RELEASE_URL/fluentbit.key}

# Optionally specify the version to install
RELEASE_VERSION=${FLUENT_BIT_RELEASE_VERSION:-}
# Optionally prefix install commands, e.g. use 'echo ' here to prevent installation after repo set up.
INSTALL_CMD_PREFIX=${FLUENT_BIT_INSTALL_COMMAND_PREFIX:-}
# Optionally set the name of th package to install, e.g. for legacy td-agent-bit.
INSTALL_PACKAGE_NAME=${FLUENT_BIT_INSTALL_PACKAGE_NAME:-fluent-bit}
# Optional Apt/Yum additional parameters (e.g. releasever for AL2022/AL2023)
APT_PARAMETERS=${FLUENT_BIT_INSTALL_APT_PARAMETERS:-}
YUM_PARAMETERS=${FLUENT_BIT_INSTALL_YUM_PARAMETERS:-}
ZYPPER_PARAMETERS=${FLUENT_BIT_INSTALL_ZYPPER_PARAMETERS:-}

echo "================================"
echo " Fluent Bit Installation Script "
echo "================================"
echo "This script requires superuser access to install packages."
echo "You will be prompted for your password by sudo."

# Determine package type to install: https://unix.stackexchange.com/a/6348
# OS used by all - for Debs it must be Ubuntu or Debian
# CODENAME only used for Debs
if [ -f /etc/os-release ]; then
    # Debian uses Dash which does not support source
    # shellcheck source=/dev/null
    . /etc/os-release
    OS=$( echo "${ID}" | tr '[:upper:]' '[:lower:]')
    CODENAME=$( echo "${VERSION_CODENAME}" | tr '[:upper:]' '[:lower:]')
elif lsb_release &>/dev/null; then
    OS=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
    CODENAME=$(lsb_release -cs)
else
    OS=$(uname -s)
fi

SUDO=sudo
if [ "$(id -u)" -eq 0 ]; then
    SUDO=''
else
    # Clear any previous sudo permission
    sudo -k
fi

# Set up version pinning
APT_VERSION=''
YUM_VERSION=''
ZYPPER_VERSION=''
if [ -n "${RELEASE_VERSION}" ]; then
    APT_VERSION="=$RELEASE_VERSION"
    YUM_VERSION="-$RELEASE_VERSION"
    ZYPPER_VERSION="=$RELEASE_VERSION"
fi

# Now set up repos and install dependent on OS, version, etc.
# Will require sudo
case ${OS} in
    amzn|amazonlinux)
        $SUDO sh <<SCRIPT
rpm --import $RELEASE_KEY
cat << EOF > /etc/yum.repos.d/fluent-bit.repo
[fluent-bit]
name = Fluent Bit
# Legacy server style
baseurl = $RELEASE_URL/amazonlinux/$VERSION
gpgcheck=1
repo_gpgcheck=1
gpgkey=$RELEASE_KEY
enabled=1
EOF
cat /etc/yum.repos.d/fluent-bit.repo
$INSTALL_CMD_PREFIX yum -y $YUM_PARAMETERS install $INSTALL_PACKAGE_NAME$YUM_VERSION
SCRIPT
    ;;
    centos|centoslinux|rhel|redhatenterpriselinuxserver|fedora)
        # We need variable expansion and non-expansion on the URL line to pick up the base URL.
        # Therefore we combine things with sed to handle it.
        $SUDO sh <<SCRIPT
rpm --import $RELEASE_KEY
cat << EOF > /etc/yum.repos.d/fluent-bit.repo
[fluent-bit]
name = Fluent Bit
# Legacy server style
baseurl = $RELEASE_URL/centos/VERSION_SUBSTR
gpgcheck=1
repo_gpgcheck=1
gpgkey=$RELEASE_KEY
enabled=1
EOF
sed -i 's|VERSION_SUBSTR|\$releasever/|g' /etc/yum.repos.d/fluent-bit.repo
cat /etc/yum.repos.d/fluent-bit.repo
$INSTALL_CMD_PREFIX yum -y $YUM_PARAMETERS install $INSTALL_PACKAGE_NAME$YUM_VERSION
SCRIPT
    ;;
    # For Rocky and AlmaLinux, we provide new repos now CentOS no longer tracks downstream.
    almalinux)
        $SUDO sh <<SCRIPT
rpm --import $RELEASE_KEY
cat << EOF > /etc/yum.repos.d/fluent-bit.repo
[fluent-bit]
name = Fluent Bit
# Legacy server style
baseurl = $RELEASE_URL/$OS/VERSION_SUBSTR
gpgcheck=1
repo_gpgcheck=1
gpgkey=$RELEASE_KEY
enabled=1
EOF
sed -i 's|VERSION_SUBSTR|\$releasever/|g' /etc/yum.repos.d/fluent-bit.repo
cat /etc/yum.repos.d/fluent-bit.repo
$INSTALL_CMD_PREFIX yum -y $YUM_PARAMETERS install $INSTALL_PACKAGE_NAME$YUM_VERSION
SCRIPT
    ;;
    rocky|rockylinux)
        $SUDO sh <<SCRIPT
rpm --import $RELEASE_KEY
cat << EOF > /etc/yum.repos.d/fluent-bit.repo
[fluent-bit]
name = Fluent Bit
# Legacy server style
baseurl = $RELEASE_URL/rockylinux/VERSION_SUBSTR
gpgcheck=1
repo_gpgcheck=1
gpgkey=$RELEASE_KEY
enabled=1
EOF
sed -i 's|VERSION_SUBSTR|\$releasever/|g' /etc/yum.repos.d/fluent-bit.repo
cat /etc/yum.repos.d/fluent-bit.repo
$INSTALL_CMD_PREFIX yum -y $YUM_PARAMETERS install $INSTALL_PACKAGE_NAME$YUM_VERSION
SCRIPT
    ;;
    ubuntu|debian)
        # Remember apt-key add is deprecated
        # https://wiki.debian.org/DebianRepository/UseThirdParty#OpenPGP_Key_distribution
        $SUDO sh <<SCRIPT
export DEBIAN_FRONTEND=noninteractive
mkdir -p /usr/share/keyrings/
curl $RELEASE_KEY | gpg --dearmor > /usr/share/keyrings/fluentbit-keyring.gpg
cat > /etc/apt/sources.list.d/fluent-bit.list <<EOF
deb [signed-by=/usr/share/keyrings/fluentbit-keyring.gpg] $RELEASE_URL/${OS}/${CODENAME} ${CODENAME} main
EOF
cat /etc/apt/sources.list.d/fluent-bit.list
apt-get -y update
$INSTALL_CMD_PREFIX apt-get -y $APT_PARAMETERS install $INSTALL_PACKAGE_NAME$APT_VERSION
SCRIPT
    ;;
    opensuse-leap)
        $SUDO sh <<SCRIPT
rpm --import $RELEASE_KEY
cat << EOF > /etc/zypp/repos.d/fluent-bit.repo
[fluent-bit]
name = Fluent Bit
baseurl = $RELEASE_URL/opensuse/leap/\$releaserver
gpgcheck=1
repo_gpgcheck=1
gpgkey=$RELEASE_KEY
enabled=1
type=rpm-md
autorefresh=1
EOF
cat /etc/zypp/repos.d/fluent-bit.repo
zypper --non-interactive --gpg-auto-import-keys refresh
$INSTALL_CMD_PREFIX zypper --non-interactive --gpg-auto-import-keys $ZYPPER_PARAMETERS install $INSTALL_PACKAGE_NAME$ZYPPER_VERSION
SCRIPT
    ;;
    sles)
        $SUDO sh <<SCRIPT
rpm --import $RELEASE_KEY
cat << EOF > /etc/zypp/repos.d/fluent-bit.repo
[fluent-bit]
name = Fluent Bit
baseurl = $RELEASE_URL/sles/\$releasever
gpgcheck=1
repo_gpgcheck=1
gpgkey=$RELEASE_KEY
enabled=1
type=rpm-md
autorefresh=1
EOF
cat /etc/zypp/repos.d/fluent-bit.repo
zypper --non-interactive --gpg-auto-import-keys refresh
$INSTALL_CMD_PREFIX zypper --non-interactive --gpg-auto-import-keys $ZYPPER_PARAMETERS install $INSTALL_PACKAGE_NAME$ZYPPER_VERSION
SCRIPT
    ;;
    *)
        echo "${OS} not supported."
        exit 1
    ;;
esac

echo ""
echo "Installation completed. Happy Logging!"
echo ""
