# Install on Raspberry Pi (Raspbian)

We distribute binary versions of [Fluent Bit](http://fluentbit.io) for the Raspberry, specifically for [Raspbian](http://raspbian.org). Note that binary versions are built with all options enabled, for a more custom version consider recompile from sources.

## Server GPG key

The first step is to add our server GPG key to your keyring, on that way you can get our signed packages:

```shell
$ wget -qO - http://apt.fluentbit.io/fluentbit.key | sudo apt-key add -
```

## Update your sources lists

On Debian and derivated systems such as Raspbian, you need to add our APT server entry to your sources lists, please add the following content at bottom of your __/etc/apt/sources.list__ file:

```
deb http://apt.fluentbit.io/raspbian wheezy main
```

### Update your repositories database

Now let your system update the _apt_ database:

```bash
$ sudo apt-get update
```

## Install Fluent Bit

Using the _apt-get_ command you are able now to install the latest version of [Fluent Bit](http://fluentbit.io):

```shell
$ sudo apt-get install fluentbit
```
