#!/usr/bin/env python3
#
# Create self-contained static-library tar-ball package
#

import os
import tempfile
import shutil
import subprocess
from packaging import Package, Mapping


class StaticPackage (Package):
    """ Create a tar-ball with self-contained static libraries.
        These are later imported into confluent-kafka-go. """

    # Make sure gssapi (cyrus-sasl) is not linked, since that is a
    # dynamic linkage, by specifying negative match '!extra': 'gssapi'.
    # Except for on OSX where cyrus-sasl is always available, and
    # Windows where it is never linked.
    #
    # Match statically linked artifacts (which are included in 'all' builds)
    mappings = [
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'dist': 'centos6',
                 '!extra': 'gssapi'},
                'librdkafka.tgz',
                './usr/local/include/librdkafka/rdkafka.h',
                'rdkafka.h'),
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'dist': 'centos6',
                 '!extra': 'gssapi'},
                'librdkafka.tgz',
                './usr/local/share/doc/librdkafka/LICENSES.txt',
                'LICENSES.txt'),

        # glibc linux static lib and pkg-config file
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'dist': 'centos6',
                 'lnk': 'all',
                 '!extra': 'gssapi'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka-static.a',
                'librdkafka_glibc_linux_amd64.a'),
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'dist': 'centos6',
                 'lnk': 'all',
                 '!extra': 'gssapi'},
                'librdkafka.tgz',
                './usr/local/lib/pkgconfig/rdkafka-static.pc',
                'librdkafka_glibc_linux_amd64.pc'),

        # glibc linux arm64 static lib and pkg-config file
        Mapping({'arch': 'arm64',
                 'plat': 'linux',
                 'dist': 'centos7',
                 'lnk': 'all',
                 '!extra': 'gssapi'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka-static.a',
                'librdkafka_glibc_linux_arm64.a'),
        Mapping({'arch': 'arm64',
                 'plat': 'linux',
                 'dist': 'centos7',
                 'lnk': 'all',
                 '!extra': 'gssapi'},
                'librdkafka.tgz',
                './usr/local/lib/pkgconfig/rdkafka-static.pc',
                'librdkafka_glibc_linux_arm64.pc'),

        # musl linux static lib and pkg-config file
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'dist': 'alpine',
                 'lnk': 'all',
                 '!extra': 'gssapi'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka-static.a',
                'librdkafka_musl_linux_amd64.a'),
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'dist': 'alpine',
                 'lnk': 'all',
                 '!extra': 'gssapi'},
                'librdkafka.tgz',
                './usr/local/lib/pkgconfig/rdkafka-static.pc',
                'librdkafka_musl_linux_amd64.pc'),

        # musl linux arm64 static lib and pkg-config file
        Mapping({'arch': 'arm64',
                 'plat': 'linux',
                 'dist': 'alpine',
                 'lnk': 'all',
                 '!extra': 'gssapi'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka-static.a',
                'librdkafka_musl_linux_arm64.a'),
        Mapping({'arch': 'arm64',
                 'plat': 'linux',
                 'dist': 'alpine',
                 'lnk': 'all',
                 '!extra': 'gssapi'},
                'librdkafka.tgz',
                './usr/local/lib/pkgconfig/rdkafka-static.pc',
                'librdkafka_musl_linux_arm64.pc'),

        # osx x64 static lib and pkg-config file
        Mapping({'arch': 'x64',
                 'plat': 'osx',
                 'lnk': 'all'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka-static.a',
                'librdkafka_darwin_amd64.a'),
        Mapping({'arch': 'x64',
                 'plat': 'osx',
                 'lnk': 'all'},
                'librdkafka.tgz',
                './usr/local/lib/pkgconfig/rdkafka-static.pc',
                'librdkafka_darwin_amd64.pc'),

        # osx arm64 static lib and pkg-config file
        Mapping({'arch': 'arm64',
                 'plat': 'osx',
                 'lnk': 'all'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka-static.a',
                'librdkafka_darwin_arm64.a'),
        Mapping({'arch': 'arm64',
                 'plat': 'osx',
                 'lnk': 'all'},
                'librdkafka.tgz',
                './usr/local/lib/pkgconfig/rdkafka-static.pc',
                'librdkafka_darwin_arm64.pc'),

        # win static lib and pkg-config file (mingw)
        Mapping({'arch': 'x64',
                 'plat': 'win',
                 'dist': 'mingw',
                 'lnk': 'static'},
                'librdkafka.tgz',
                './lib/librdkafka-static.a', 'librdkafka_windows.a'),
        Mapping({'arch': 'x64',
                 'plat': 'win',
                 'dist': 'mingw',
                 'lnk': 'static'},
                'librdkafka.tgz',
                './lib/pkgconfig/rdkafka-static.pc',
                'librdkafka_windows.pc'),
    ]

    def __init__(self, version, arts):
        super(StaticPackage, self).__init__(version, arts)

    def cleanup(self):
        if os.path.isdir(self.stpath):
            shutil.rmtree(self.stpath)

    def build(self, buildtype):
        """ Build single package for all artifacts. """

        self.stpath = tempfile.mkdtemp(prefix="out-", dir=".")

        self.apply_mappings()

        print('Tree extracted to %s' % self.stpath)

        # After creating a bare-bone layout, create a tarball.
        outname = "librdkafka-static-bundle-%s.tgz" % self.version
        print('Writing to %s in %s' % (outname, self.stpath))
        subprocess.check_call("(cd %s && tar cvzf ../%s .)" %
                              (self.stpath, outname),
                              shell=True)

        return outname
