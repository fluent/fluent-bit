#!/usr/bin/env python3
#
# NuGet packaging script.
# Assembles a NuGet package using CI artifacts in S3
# and calls nuget (in docker) to finalize the package.
#

import sys
import re
import os
import tempfile
import shutil
import subprocess
import urllib
from fnmatch import fnmatch
from string import Template
from collections import defaultdict
import boto3
from zfile import zfile

if sys.version_info[0] < 3:
    from urllib import unquote
else:
    from urllib.parse import unquote


# Rename token values
rename_vals = {'plat': {'windows': 'win'},
               'arch': {'x86_64': 'x64',
                        'i386': 'x86',
                        'win32': 'x86'}}

# Collects CI artifacts from S3 storage, downloading them
# to a local directory, or collecting already downloaded artifacts from
# local directory.
#
# The artifacts' folder in the S3 bucket must have the following token
# format:
#  <token>-[<value>]__   (repeat)
#
# Recognized tokens (unrecognized tokens are ignored):
#  p       - project (e.g., "confluent-kafka-python")
#  bld     - builder (e.g., "travis")
#  plat    - platform ("osx", "linux", ..)
#  arch    - arch ("x64", ..)
#  tag     - git tag
#  sha     - git sha
#  bid     - builder's build-id
#  bldtype - Release, Debug (appveyor)
#  lnk     - std, static
#
# Example:
#   librdkafka/p-librdkafka__bld-travis__plat-linux__arch-x64__tag-v0.0.62__sha-d051b2c19eb0c118991cd8bc5cf86d8e5e446cde__bid-1562.1/librdkafka.tar.gz


s3_bucket = 'librdkafka-ci-packages'
dry_run = False

class Artifact (object):
    def __init__(self, arts, path, info=None):
        self.path = path
        # Remove unexpanded AppVeyor $(..) tokens from filename
        self.fname = re.sub(r'\$\([^\)]+\)', '', os.path.basename(path))
        slpath = os.path.join(os.path.dirname(path), self.fname)
        if os.path.isfile(slpath):
            # Already points to local file in correct location
            self.lpath = slpath
        else:
            # Prepare download location in dlpath
            self.lpath = os.path.join(arts.dlpath, slpath)

        if info is None:
            self.info = dict()
        else:
            # Assign the map and convert all keys to lower case
            self.info = {k.lower(): v for k, v in info.items()}
            # Rename values, e.g., 'plat':'linux' to 'plat':'debian'
            for k,v in self.info.items():
                rdict = rename_vals.get(k, None)
                if rdict is not None:
                    self.info[k] = rdict.get(v, v)

        # Score value for sorting
        self.score = 0

        # AppVeyor symbol builds are of less value
        if self.fname.find('.symbols.') != -1:
            self.score -= 10

        self.arts = arts
        arts.artifacts.append(self)


    def __repr__(self):
        return self.path

    def __lt__ (self, other):
        return self.score < other.score

    def download(self):
        """ Download artifact from S3 and store in local directory .lpath.
            If the artifact is already downloaded nothing is done. """
        if os.path.isfile(self.lpath) and os.path.getsize(self.lpath) > 0:
            return
        print('Downloading %s' % self.path)
        if dry_run:
            return
        ldir = os.path.dirname(self.lpath)
        if not os.path.isdir(ldir):
            os.makedirs(ldir, 0o755)
        self.arts.s3_bucket.download_file(self.path, self.lpath)


class Artifacts (object):
    def __init__(self, match, dlpath):
        super(Artifacts, self).__init__()
        self.match = match
        self.artifacts = list()
        # Download directory (make sure it ends with a path separator)
        if not dlpath.endswith(os.path.sep):
            dlpath = os.path.join(dlpath, '')
        self.dlpath = dlpath
        if not os.path.isdir(self.dlpath):
            if not dry_run:
                os.makedirs(self.dlpath, 0o755)


    def collect_single(self, path, req_tag=True):
        """ Collect single artifact, be it in S3 or locally.
        :param: path string: S3 or local (relative) path
        :param: req_tag bool: Require tag to match.
        """

        #print('?  %s' % path)

        # For local files, strip download path.
        # Also ignore any parent directories.
        if path.startswith(self.dlpath):
            folder = os.path.basename(os.path.dirname(path[len(self.dlpath):]))
        else:
            folder = os.path.basename(os.path.dirname(path))

        # The folder contains the tokens needed to perform
        # matching of project, gitref, etc.
        rinfo = re.findall(r'(?P<tag>[^-]+)-(?P<val>.*?)(?:__|$)', folder)
        if rinfo is None or len(rinfo) == 0:
            print('Incorrect folder/file name format for %s' % folder)
            return None

        info = dict(rinfo)

        # Ignore AppVeyor Debug builds
        if info.get('bldtype', '').lower() == 'debug':
            print('Ignoring debug artifact %s' % folder)
            return None

        tag = info.get('tag', None)
        if tag is not None and (len(tag) == 0 or tag.startswith('$(')):
            # AppVeyor doesn't substite $(APPVEYOR_REPO_TAG_NAME)
            # with an empty value when not set, it leaves that token
            # in the string - so translate that to no tag.
            del info['tag']

        # Perform matching
        unmatched = list()
        for m,v in self.match.items():
            if m not in info or info[m] != v:
                unmatched.append(m)

        # Make sure all matches were satisfied, unless this is a
        # common artifact.
        if info.get('p', '') != 'common' and len(unmatched) > 0:
            # print('%s: %s did not match %s' % (info.get('p', None), folder, unmatched))
            return None

        return Artifact(self, path, info)


    def collect_s3(self):
        """ Collect and download build-artifacts from S3 based on git reference """
        print('Collecting artifacts matching %s from S3 bucket %s' % (self.match, s3_bucket))
        self.s3 = boto3.resource('s3')
        self.s3_bucket = self.s3.Bucket(s3_bucket)
        self.s3_client = boto3.client('s3')

        # note: list_objects will return at most 1000 objects per call,
        #       use continuation token to read full list.
        cont_token = None
        more = True
        while more:
            if cont_token is not None:
                res = self.s3_client.list_objects_v2(Bucket=s3_bucket,
                                                     Prefix='librdkafka/',
                                                     ContinuationToken=cont_token)
            else:
                res = self.s3_client.list_objects_v2(Bucket=s3_bucket,
                                                     Prefix='librdkafka/')

            if res.get('IsTruncated') == True:
                cont_token = res.get('NextContinuationToken')
            else:
                more = False

            for item in res.get('Contents'):
                self.collect_single(item.get('Key'))

        for a in self.artifacts:
            a.download()

    def collect_local(self, path, req_tag=True):
        """ Collect artifacts from a local directory possibly previously
        collected from s3 """
        for f in [os.path.join(dp, f) for dp, dn, filenames in os.walk(path) for f in filenames]:
            if not os.path.isfile(f):
                continue
            self.collect_single(f, req_tag)


class Package (object):
    """ Generic Package class
        A Package is a working container for one or more output
        packages for a specific package type (e.g., nuget) """

    def __init__ (self, version, arts, ptype):
        super(Package, self).__init__()
        self.version = version
        self.arts = arts
        self.ptype = ptype
        # These may be overwritten by specific sub-classes:
        self.artifacts = arts.artifacts
        # Staging path, filled in later.
        self.stpath = None
        self.kv = {'version': version}
        self.files = dict()

    def add_file (self, file):
        self.files[file] = True

    def build (self):
        """ Build package output(s), return a list of paths to built packages """
        raise NotImplementedError

    def cleanup (self):
        """ Optional cleanup routine for removing temporary files, etc. """
        pass

    def verify (self, path):
        """ Optional post-build package verifier """
        pass

    def render (self, fname, destpath='.'):
        """ Render template in file fname and save to destpath/fname,
        where destpath is relative to stpath """

        outf = os.path.join(self.stpath, destpath, fname)

        if not os.path.isdir(os.path.dirname(outf)):
            os.makedirs(os.path.dirname(outf), 0o0755)

        with open(os.path.join('templates', fname), 'r') as tf:
            tmpl = Template(tf.read())
        with open(outf, 'w') as of:
            of.write(tmpl.substitute(self.kv))

        self.add_file(outf)


    def copy_template (self, fname, target_fname=None, destpath='.'):
        """ Copy template file to destpath/fname
        where destpath is relative to stpath """

        if target_fname is None:
            target_fname = fname
        outf = os.path.join(self.stpath, destpath, target_fname)

        if not os.path.isdir(os.path.dirname(outf)):
            os.makedirs(os.path.dirname(outf), 0o0755)

        shutil.copy(os.path.join('templates', fname), outf)

        self.add_file(outf)


class NugetPackage (Package):
    """ All platforms, archs, et.al, are bundled into one set of
        NuGet output packages: "main", redist and symbols """
    def __init__ (self, version, arts):
        if version.startswith('v'):
            version = version[1:] # Strip v prefix
        super(NugetPackage, self).__init__(version, arts, "nuget")

    def cleanup(self):
        if os.path.isdir(self.stpath):
            shutil.rmtree(self.stpath)

    def build (self, buildtype):
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
        for f in ['../../README.md', '../../CONFIGURATION.md', '../../LICENSES.txt']:
            shutil.copy(f, self.stpath)

        # Generate template tokens for artifacts
        for a in self.arts.artifacts:
            if 'bldtype' not in a.info:
                a.info['bldtype'] = 'release'

            a.info['variant'] = '%s-%s-%s' % (a.info.get('plat'),
                                              a.info.get('arch'),
                                              a.info.get('bldtype'))
            if 'toolset' not in a.info:
                a.info['toolset'] = 'v120'

        mappings = [
            [{'arch': 'x64', 'plat': 'linux', 'fname_glob': 'librdkafka-gcc.tar.gz'}, './include/librdkafka/rdkafka.h', 'build/native/include/librdkafka/rdkafka.h'],
            [{'arch': 'x64', 'plat': 'linux', 'fname_glob': 'librdkafka-gcc.tar.gz'}, './include/librdkafka/rdkafkacpp.h', 'build/native/include/librdkafka/rdkafkacpp.h'],
            [{'arch': 'x64', 'plat': 'linux', 'fname_glob': 'librdkafka-gcc.tar.gz'}, './include/librdkafka/rdkafka_mock.h', 'build/native/include/librdkafka/rdkafka_mock.h'],

            # Travis OSX build
            [{'arch': 'x64', 'plat': 'osx', 'fname_glob': 'librdkafka-clang.tar.gz'}, './lib/librdkafka.dylib', 'runtimes/osx-x64/native/librdkafka.dylib'],
            # Travis Debian 9 / Ubuntu 16.04 build
            [{'arch': 'x64', 'plat': 'linux', 'fname_glob': 'librdkafka-debian9.tgz'}, './lib/librdkafka.so.1', 'runtimes/linux-x64/native/debian9-librdkafka.so'],
            # Travis Ubuntu 14.04 build
            [{'arch': 'x64', 'plat': 'linux', 'fname_glob': 'librdkafka-gcc.tar.gz'}, './lib/librdkafka.so.1', 'runtimes/linux-x64/native/librdkafka.so'],
            # Travis CentOS 7 RPM build
            [{'arch': 'x64', 'plat': 'linux', 'fname_glob': 'librdkafka1*el7.x86_64.rpm'}, './usr/lib64/librdkafka.so.1', 'runtimes/linux-x64/native/centos7-librdkafka.so'],
            # Alpine build
            [{'arch': 'x64', 'plat': 'linux', 'fname_glob': 'alpine-librdkafka.tgz'}, 'librdkafka.so.1', 'runtimes/linux-x64/native/alpine-librdkafka.so'],

            # Common Win runtime
            [{'arch': 'x64', 'plat': 'win', 'fname_glob': 'msvcr120.zip'}, 'msvcr120.dll', 'runtimes/win-x64/native/msvcr120.dll'],
            [{'arch': 'x64', 'plat': 'win', 'fname_glob': 'msvcr120.zip'}, 'msvcp120.dll', 'runtimes/win-x64/native/msvcp120.dll'],
            # matches librdkafka.redist.{VER}.nupkg
            [{'arch': 'x64', 'plat': 'win', 'fname_glob': 'librdkafka.redist*'}, 'build/native/bin/v120/x64/Release/librdkafka.dll', 'runtimes/win-x64/native/librdkafka.dll'],
            [{'arch': 'x64', 'plat': 'win', 'fname_glob': 'librdkafka.redist*'}, 'build/native/bin/v120/x64/Release/librdkafkacpp.dll', 'runtimes/win-x64/native/librdkafkacpp.dll'],
            [{'arch': 'x64', 'plat': 'win', 'fname_glob': 'librdkafka.redist*'}, 'build/native/bin/v120/x64/Release/zlib.dll', 'runtimes/win-x64/native/zlib.dll'],
            [{'arch': 'x64', 'plat': 'win', 'fname_glob': 'librdkafka.redist*'}, 'build/native/bin/v120/x64/Release/libzstd.dll', 'runtimes/win-x64/native/libzstd.dll'],
            # matches librdkafka.{VER}.nupkg
            [{'arch': 'x64', 'plat': 'win', 'fname_glob': 'librdkafka*', 'fname_excludes': ['redist', 'symbols']},
             'build/native/lib/v120/x64/Release/librdkafka.lib', 'build/native/lib/win/x64/win-x64-Release/v120/librdkafka.lib'],
            [{'arch': 'x64', 'plat': 'win', 'fname_glob': 'librdkafka*', 'fname_excludes': ['redist', 'symbols']},
             'build/native/lib/v120/x64/Release/librdkafkacpp.lib', 'build/native/lib/win/x64/win-x64-Release/v120/librdkafkacpp.lib'],

            [{'arch': 'x86', 'plat': 'win', 'fname_glob': 'msvcr120.zip'}, 'msvcr120.dll', 'runtimes/win-x86/native/msvcr120.dll'],
            [{'arch': 'x86', 'plat': 'win', 'fname_glob': 'msvcr120.zip'}, 'msvcp120.dll', 'runtimes/win-x86/native/msvcp120.dll'],
            # matches librdkafka.redist.{VER}.nupkg
            [{'arch': 'x86', 'plat': 'win', 'fname_glob': 'librdkafka.redist*'}, 'build/native/bin/v120/Win32/Release/librdkafka.dll', 'runtimes/win-x86/native/librdkafka.dll'],
            [{'arch': 'x86', 'plat': 'win', 'fname_glob': 'librdkafka.redist*'}, 'build/native/bin/v120/Win32/Release/librdkafkacpp.dll', 'runtimes/win-x86/native/librdkafkacpp.dll'],
            [{'arch': 'x86', 'plat': 'win', 'fname_glob': 'librdkafka.redist*'}, 'build/native/bin/v120/Win32/Release/zlib.dll', 'runtimes/win-x86/native/zlib.dll'],
            [{'arch': 'x86', 'plat': 'win', 'fname_glob': 'librdkafka.redist*'}, 'build/native/bin/v120/Win32/Release/libzstd.dll', 'runtimes/win-x86/native/libzstd.dll'],

            # matches librdkafka.{VER}.nupkg
            [{'arch': 'x86', 'plat': 'win', 'fname_glob': 'librdkafka*', 'fname_excludes': ['redist', 'symbols']},
            'build/native/lib/v120/Win32/Release/librdkafka.lib', 'build/native/lib/win/x86/win-x86-Release/v120/librdkafka.lib'],
            [{'arch': 'x86', 'plat': 'win', 'fname_glob': 'librdkafka*', 'fname_excludes': ['redist', 'symbols']},
            'build/native/lib/v120/Win32/Release/librdkafkacpp.lib', 'build/native/lib/win/x86/win-x86-Release/v120/librdkafkacpp.lib']
        ]

        for m in mappings:
            attributes = m[0]
            fname_glob = attributes['fname_glob']
            del attributes['fname_glob']
            fname_excludes = []
            if 'fname_excludes' in attributes:
                fname_excludes = attributes['fname_excludes']
                del attributes['fname_excludes']

            artifact = None
            for a in self.arts.artifacts:
                found = True

                for attr in attributes:
                    if a.info[attr] != attributes[attr]:
                        found = False
                        break

                if not fnmatch(a.fname, fname_glob):
                    found = False

                for exclude in fname_excludes:
                    if exclude in a.fname:
                        found = False
                        break

                if found:
                    artifact = a
                    break

            if artifact is None:
                raise Exception('unable to find artifact with tags %s matching "%s"' % (str(attributes), fname_glob))

            outf = os.path.join(self.stpath, m[2])
            member = m[1]
            try:
                zfile.ZFile.extract(artifact.lpath, member, outf)
            except KeyError as e:
                raise Exception('file not found in archive %s: %s. Files in archive are: %s' % (artifact.lpath, e, zfile.ZFile(artifact.lpath).getnames()))

        print('Tree extracted to %s' % self.stpath)

        # After creating a bare-bone nupkg layout containing the artifacts
        # and some spec and props files, call the 'nuget' utility to
        # make a proper nupkg of it (with all the metadata files).
        subprocess.check_call("./nuget.sh pack %s -BasePath '%s' -NonInteractive" %  \
                              (os.path.join(self.stpath, 'librdkafka.redist.nuspec'),
                               self.stpath), shell=True)

        return 'librdkafka.redist.%s.nupkg' % vless_version

    def verify (self, path):
        """ Verify package """
        expect = [
            "librdkafka.redist.nuspec",
            "LICENSES.txt",
            "build/librdkafka.redist.props",
            "build/native/librdkafka.redist.targets",
            "build/native/include/librdkafka/rdkafka.h",
            "build/native/include/librdkafka/rdkafkacpp.h",
            "build/native/include/librdkafka/rdkafka_mock.h",
            "build/native/lib/win/x64/win-x64-Release/v120/librdkafka.lib",
            "build/native/lib/win/x64/win-x64-Release/v120/librdkafkacpp.lib",
            "build/native/lib/win/x86/win-x86-Release/v120/librdkafka.lib",
            "build/native/lib/win/x86/win-x86-Release/v120/librdkafkacpp.lib",
            "runtimes/linux-x64/native/centos7-librdkafka.so",
            "runtimes/linux-x64/native/debian9-librdkafka.so",
            "runtimes/linux-x64/native/alpine-librdkafka.so",
            "runtimes/linux-x64/native/librdkafka.so",
            "runtimes/osx-x64/native/librdkafka.dylib",
            "runtimes/win-x64/native/librdkafka.dll",
            "runtimes/win-x64/native/librdkafkacpp.dll",
            "runtimes/win-x64/native/msvcr120.dll",
            "runtimes/win-x64/native/msvcp120.dll",
            "runtimes/win-x64/native/zlib.dll",
            "runtimes/win-x64/native/libzstd.dll",
            "runtimes/win-x86/native/librdkafka.dll",
            "runtimes/win-x86/native/librdkafkacpp.dll",
            "runtimes/win-x86/native/msvcr120.dll",
            "runtimes/win-x86/native/msvcp120.dll",
            "runtimes/win-x86/native/zlib.dll",
            "runtimes/win-x86/native/libzstd.dll"]

        missing = list()
        with zfile.ZFile(path, 'r') as zf:
            print('Verifying %s:' % path)

            # Zipfiles may url-encode filenames, unquote them before matching.
            pkgd = [unquote(x) for x in zf.getnames()]
            missing = [x for x in expect if x not in pkgd]

        if len(missing) > 0:
            print('Missing files in package %s:\n%s' % (path, '\n'.join(missing)))
            return False
        else:
            print('OK - %d expected files found' % len(expect))
            return True


class StaticPackage (Package):
    """ Create a package with all static libraries """

    # Only match statically linked artifacts
    match = {'lnk': 'static'}

    def __init__ (self, version, arts):
        super(StaticPackage, self).__init__(version, arts, "static")

    def cleanup(self):
        if os.path.isdir(self.stpath):
            shutil.rmtree(self.stpath)

    def build (self, buildtype):
        """ Build single package for all artifacts. """

        self.stpath = tempfile.mkdtemp(prefix="out-", dir=".")

        mappings = [
            # rdkafka.h
            [{'arch': 'x64', 'plat': 'linux', 'fname_glob': 'librdkafka-clang.tar.gz'}, './include/librdkafka/rdkafka.h', 'rdkafka.h'],

            # LICENSES.txt
            [{'arch': 'x64', 'plat': 'osx', 'fname_glob': 'librdkafka-clang.tar.gz'}, './share/doc/librdkafka/LICENSES.txt', 'LICENSES.txt'],

            # glibc linux static lib and pkg-config file
            [{'arch': 'x64', 'plat': 'linux', 'fname_glob': 'librdkafka-clang.tar.gz'}, './lib/librdkafka-static.a', 'librdkafka_glibc_linux.a'],
            [{'arch': 'x64', 'plat': 'linux', 'fname_glob': 'librdkafka-clang.tar.gz'}, './lib/pkgconfig/rdkafka-static.pc', 'librdkafka_glibc_linux.pc'],

            # musl linux static lib and pkg-config file
            [{'arch': 'x64', 'plat': 'linux', 'fname_glob': 'alpine-librdkafka.tgz'}, 'librdkafka-static.a', 'librdkafka_musl_linux.a'],
            [{'arch': 'x64', 'plat': 'linux', 'fname_glob': 'alpine-librdkafka.tgz'}, 'rdkafka-static.pc', 'librdkafka_musl_linux.pc'],

            # osx static lib and pkg-config file
            [{'arch': 'x64', 'plat': 'osx', 'fname_glob': 'librdkafka-clang.tar.gz'}, './lib/librdkafka-static.a', 'librdkafka_darwin.a'],
            [{'arch': 'x64', 'plat': 'osx', 'fname_glob': 'librdkafka-clang.tar.gz'}, './lib/pkgconfig/rdkafka-static.pc', 'librdkafka_darwin.pc'],
        ]

        for m in mappings:
            attributes = m[0].copy()
            attributes.update(self.match)
            fname_glob = attributes['fname_glob']
            del attributes['fname_glob']
            fname_excludes = []
            if 'fname_excludes' in attributes:
                fname_excludes = attributes['fname_excludes']
                del attributes['fname_excludes']

            artifact = None
            for a in self.arts.artifacts:
                found = True

                for attr in attributes:
                    if attr not in a.info or a.info[attr] != attributes[attr]:
                        found = False
                        break

                if not fnmatch(a.fname, fname_glob):
                    found = False

                for exclude in fname_excludes:
                    if exclude in a.fname:
                        found = False
                        break

                if found:
                    artifact = a
                    break

            if artifact is None:
                raise Exception('unable to find artifact with tags %s matching "%s"' % (str(attributes), fname_glob))

            outf = os.path.join(self.stpath, m[2])
            member = m[1]
            try:
                zfile.ZFile.extract(artifact.lpath, member, outf)
            except KeyError as e:
                raise Exception('file not found in archive %s: %s. Files in archive are: %s' % (artifact.lpath, e, zfile.ZFile(artifact.lpath).getnames()))

        print('Tree extracted to %s' % self.stpath)

        # After creating a bare-bone layout, create a tarball.
        outname = "librdkafka-static-bundle-%s.tgz" % self.version
        print('Writing to %s' % outname)
        subprocess.check_call("(cd %s && tar cvzf ../%s .)" % \
                              (self.stpath, outname),
                              shell=True)

        return outname


    def verify (self, path):
        """ Verify package """
        expect = [
            "./rdkafka.h",
            "./LICENSES.txt",
            "./librdkafka_glibc_linux.a",
            "./librdkafka_glibc_linux.pc",
            "./librdkafka_musl_linux.a",
            "./librdkafka_musl_linux.pc",
            "./librdkafka_darwin.a",
            "./librdkafka_darwin.pc"]

        missing = list()
        with zfile.ZFile(path, 'r') as zf:
            print('Verifying %s:' % path)

            # Zipfiles may url-encode filenames, unquote them before matching.
            pkgd = [unquote(x) for x in zf.getnames()]
            missing = [x for x in expect if x not in pkgd]

        if len(missing) > 0:
            print('Missing files in package %s:\n%s' % (path, '\n'.join(missing)))
            return False
        else:
            print('OK - %d expected files found' % len(expect))
            return True
