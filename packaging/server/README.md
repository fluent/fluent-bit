This directory contains the necessary files to support publishing release packages.

The [publish-all.sh](./publish-all.sh) script is intended to cover everything required to push a new (1.9+) version.

An Aptly [config file](./aptly.conf) is also provided, intended to be installed at `/etc/aptly.conf`.

## Process

Assuming some variables like so:
- GPG_KEY - the GPG signing key to use, e.g. "a@b.com".
- VERSION - the new version you want to publish.

For YUM repos, it is:
1. Copy RPMs to the destination dir, e.g. `/var/www/apt.fluentbit.io/amazonlinux/2/aarch64`: `find "$SOURCE_DIR/amazonlinux/" -iname "*-bit-$VERSION-*aarch64*.rpm" -exec cp -fv {} "/var/www/apt.fluentbit.io/amazonlinux/2/aarch64" \;`
2. Sign the RPMs if they have not been (CI for 1.9 signs them): `rpm --define "_gpg_name $GPG_KEY" --addsign "*-bit-$VERSION-*aarch64*.rpm"`
3. Update the repo meta data: `createrepo -dvp "/var/www/apt.fluentbit.io/amazonlinux/2/aarch64"`
4. Sign the repo meta data: `find "/var/www/apt.fluentbit.io/" -name repomd.xml -exec gpg --detach-sign --batch --armor --yes -u "$GPG_KEY" {} \;`

For APT repos, it is:
1. Add Debs to the repo: `aptly repo add flb-debian-buster "*-bit_$VERSION*.deb"`
2. Create a snapshot for the version: `aptly snapshot create "fluent-bit-debian-buster-${VERSION}" from repo flb-debian-buster`
3. Publish the snapshot: `aptly publish switch -gpg-key="$GPG_KEY" buster filesystem:debian/buster: "fluent-bit-debian-buster-${VERSION}"`

The [publish-all.sh](./publish-all.sh) script just does this so refer to that.

For signing, the [update-repos.sh](../update-repos.sh) script carries this out during build so also refer to that.
For RPMs they are explicitly signed but for DEBs Aptly handles this in its [configuration](https://www.aptly.info/doc/aptly/publish/switch/), ensure the GPG key is [set appropriately](https://www.aptly.info/doc/aptly/publish/).

## New distributions

The process above only covers existing repositories.
For new targets then a new repository has to be created so follow the RPM or Aptly documentation for that.
