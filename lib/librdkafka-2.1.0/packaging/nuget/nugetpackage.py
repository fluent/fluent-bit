#!/usr/bin/env python3
#
# Create NuGet package
#

import os
import tempfile
import shutil
import subprocess
from packaging import Package, Mapping


class NugetPackage (Package):
    """ All platforms, archs, et.al, are bundled into one set of
        NuGet output packages: "main", redist and symbols """

    # See .semamphore/semaphore.yml for where these are built.
    mappings = [
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'lnk': 'std'},
                'librdkafka.tgz',
                './usr/local/include/librdkafka/rdkafka.h',
                'build/native/include/librdkafka/rdkafka.h'),
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'lnk': 'std'},
                'librdkafka.tgz',
                './usr/local/include/librdkafka/rdkafkacpp.h',
                'build/native/include/librdkafka/rdkafkacpp.h'),
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'lnk': 'std'},
                'librdkafka.tgz',
                './usr/local/include/librdkafka/rdkafka_mock.h',
                'build/native/include/librdkafka/rdkafka_mock.h'),

        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'lnk': 'std'},
                'librdkafka.tgz',
                './usr/local/share/doc/librdkafka/README.md',
                'README.md'),
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'lnk': 'std'},
                'librdkafka.tgz',
                './usr/local/share/doc/librdkafka/CONFIGURATION.md',
                'CONFIGURATION.md'),
        Mapping({'arch': 'x64',
                 'plat': 'osx',
                 'lnk': 'all'},
                'librdkafka.tgz',
                './usr/local/share/doc/librdkafka/LICENSES.txt',
                'LICENSES.txt'),

        # OSX x64
        Mapping({'arch': 'x64',
                 'plat': 'osx'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka.dylib',
                'runtimes/osx-x64/native/librdkafka.dylib'),
        # OSX arm64
        Mapping({'arch': 'arm64',
                 'plat': 'osx'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka.1.dylib',
                'runtimes/osx-arm64/native/librdkafka.dylib'),

        # Linux glibc centos6 x64 with GSSAPI
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'dist': 'centos6',
                 'lnk': 'std'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka.so.1',
                'runtimes/linux-x64/native/librdkafka.so'),
        # Linux glibc centos6 x64 without GSSAPI (no external deps)
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'dist': 'centos6',
                 'lnk': 'all'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka.so.1',
                'runtimes/linux-x64/native/centos6-librdkafka.so'),
        # Linux glibc centos7 x64 with GSSAPI
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'dist': 'centos7',
                 'lnk': 'std'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka.so.1',
                'runtimes/linux-x64/native/centos7-librdkafka.so'),
        # Linux glibc centos7 arm64 without GSSAPI (no external deps)
        Mapping({'arch': 'arm64',
                 'plat': 'linux',
                 'dist': 'centos7',
                 'lnk': 'all'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka.so.1',
                'runtimes/linux-arm64/native/librdkafka.so'),

        # Linux musl alpine x64 without GSSAPI (no external deps)
        Mapping({'arch': 'x64',
                 'plat': 'linux',
                 'dist': 'alpine',
                 'lnk': 'all'},
                'librdkafka.tgz',
                './usr/local/lib/librdkafka.so.1',
                'runtimes/linux-x64/native/alpine-librdkafka.so'),

        # Common Win runtime
        Mapping({'arch': 'x64',
                 'plat': 'win'},
                'msvcr140.zip',
                'vcruntime140.dll',
                'runtimes/win-x64/native/vcruntime140.dll'),
        Mapping({'arch': 'x64',
                 'plat': 'win'},
                'msvcr140.zip',
                'msvcp140.dll', 'runtimes/win-x64/native/msvcp140.dll'),

        # matches x64 librdkafka.redist.zip
        Mapping({'arch': 'x64',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/x64/Release/librdkafka.dll',
                'runtimes/win-x64/native/librdkafka.dll'),
        Mapping({'arch': 'x64',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/x64/Release/librdkafkacpp.dll',
                'runtimes/win-x64/native/librdkafkacpp.dll'),
        Mapping({'arch': 'x64',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/x64/Release/libcrypto-3-x64.dll',
                'runtimes/win-x64/native/libcrypto-3-x64.dll'),
        Mapping({'arch': 'x64',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/x64/Release/libssl-3-x64.dll',
                'runtimes/win-x64/native/libssl-3-x64.dll'),
        Mapping({'arch': 'x64',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/x64/Release/zlib1.dll',
                'runtimes/win-x64/native/zlib1.dll'),
        Mapping({'arch': 'x64',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/x64/Release/zstd.dll',
                'runtimes/win-x64/native/zstd.dll'),
        Mapping({'arch': 'x64',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/x64/Release/libcurl.dll',
                'runtimes/win-x64/native/libcurl.dll'),
        # matches x64 librdkafka.redist.zip, lib files
        Mapping({'arch': 'x64',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/lib/v142/x64/Release/librdkafka.lib',
                'build/native/lib/win/x64/win-x64-Release/v142/librdkafka.lib'  # noqa: E501
                ),
        Mapping({'arch': 'x64',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/lib/v142/x64/Release/librdkafkacpp.lib',
                'build/native/lib/win/x64/win-x64-Release/v142/librdkafkacpp.lib'  # noqa: E501
                ),

        Mapping({'arch': 'x86',
                 'plat': 'win'},
                'msvcr140.zip',
                'vcruntime140.dll',
                'runtimes/win-x86/native/vcruntime140.dll'),
        Mapping({'arch': 'x86',
                 'plat': 'win'},
                'msvcr140.zip',
                'msvcp140.dll', 'runtimes/win-x86/native/msvcp140.dll'),

        # matches Win32 librdkafka.redist.zip
        Mapping({'arch': 'x86',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/Win32/Release/librdkafka.dll',
                'runtimes/win-x86/native/librdkafka.dll'),
        Mapping({'arch': 'x86',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/Win32/Release/librdkafkacpp.dll',
                'runtimes/win-x86/native/librdkafkacpp.dll'),
        Mapping({'arch': 'x86',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/Win32/Release/libcrypto-3.dll',
                'runtimes/win-x86/native/libcrypto-3.dll'),
        Mapping({'arch': 'x86',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/Win32/Release/libssl-3.dll',
                'runtimes/win-x86/native/libssl-3.dll'),

        Mapping({'arch': 'x86',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/Win32/Release/zlib1.dll',
                'runtimes/win-x86/native/zlib1.dll'),
        Mapping({'arch': 'x86',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/Win32/Release/zstd.dll',
                'runtimes/win-x86/native/zstd.dll'),
        Mapping({'arch': 'x86',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/bin/v142/Win32/Release/libcurl.dll',
                'runtimes/win-x86/native/libcurl.dll'),

        # matches Win32 librdkafka.redist.zip, lib files
        Mapping({'arch': 'x86',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/lib/v142/Win32/Release/librdkafka.lib',
                'build/native/lib/win/x86/win-x86-Release/v142/librdkafka.lib'  # noqa: E501
                ),
        Mapping({'arch': 'x86',
                 'plat': 'win'},
                'librdkafka.redist*',
                'build/native/lib/v142/Win32/Release/librdkafkacpp.lib',
                'build/native/lib/win/x86/win-x86-Release/v142/librdkafkacpp.lib'  # noqa: E501
                )
    ]

    def __init__(self, version, arts):
        if version.startswith('v'):
            version = version[1:]  # Strip v prefix
        super(NugetPackage, self).__init__(version, arts)

    def cleanup(self):
        if os.path.isdir(self.stpath):
            shutil.rmtree(self.stpath)

    def build(self, buildtype):
        """ Build single NuGet package for all its artifacts. """

        # NuGet removes the prefixing v from the version.
        vless_version = self.kv['version']
        if vless_version[0] == 'v':
            vless_version = vless_version[1:]

        self.stpath = tempfile.mkdtemp(prefix="out-", suffix="-%s" % buildtype,
                                       dir=".")

        self.render('librdkafka.redist.nuspec')
        self.copy_template('librdkafka.redist.targets',
                           destpath=os.path.join('build', 'native'))
        self.copy_template('librdkafka.redist.props',
                           destpath='build')

        # Generate template tokens for artifacts
        for a in self.arts.artifacts:
            if 'bldtype' not in a.info:
                a.info['bldtype'] = 'release'

            a.info['variant'] = '%s-%s-%s' % (a.info.get('plat'),
                                              a.info.get('arch'),
                                              a.info.get('bldtype'))
            if 'toolset' not in a.info:
                a.info['toolset'] = 'v142'

        # Apply mappings and extract files
        self.apply_mappings()

        print('Tree extracted to %s' % self.stpath)

        # After creating a bare-bone nupkg layout containing the artifacts
        # and some spec and props files, call the 'nuget' utility to
        # make a proper nupkg of it (with all the metadata files).
        subprocess.check_call("./nuget.sh pack %s -BasePath '%s' -NonInteractive" %  # noqa: E501
                              (os.path.join(self.stpath,
                                            'librdkafka.redist.nuspec'),
                               self.stpath), shell=True)

        return 'librdkafka.redist.%s.nupkg' % vless_version
