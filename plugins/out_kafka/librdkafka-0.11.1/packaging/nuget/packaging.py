#!/usr/bin/env python
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
from string import Template
from collections import defaultdict
import boto3
from zfile import zfile

# File categories
categories = ['dynamic', # dynamic libraries
              'static',  # static libraries
              'pc',      # pkg-config
              'include'] # include files / headers

win_ver = 'win7'
# Maps platform and category to expected files, or vice versa.
wanted_files = {
    win_ver: {
        'dynamic': ['librdkafka.dll', 'librdkafkacpp.dll',
                    'librdkafka.lib', 'librdkafkacpp.lib',
                    'msvcr120.dll', 'zlib.dll'],
        'static': ['librdkafka.lib', 'librdkafkacpp.lib'],
        'include': ['rdkafka.h', 'rdkafkacpp.h'],
    },

    'osx': {
        'dynamic': ['librdkafka.dylib', 'librdkafka++.dylib'],
        'static': ['librdkafka.a', 'librdkafka++.a'],
        'include': ['rdkafka.h', 'rdkafkacpp.h'],
        'pc': ['rdkafka.pc', 'rdkafka++.pc'],
    },

    'debian': {
        'dynamic': ['librdkafka.so.1', 'librdkafka++.so.1'],
        'static': ['librdkafka.a', 'librdkafka++.a'],
        'include': ['rdkafka.h', 'rdkafkacpp.h'],
        'pc': ['rdkafka.pc', 'rdkafka++.pc'],
    },

    'rhel':  {
        'dynamic': ['librdkafka.so.1', 'librdkafka++.so.1'],
        'static': ['librdkafka.a', 'librdkafka++.a'],
        'include': ['rdkafka.h', 'rdkafkacpp.h'],
        'pc': ['rdkafka.pc', 'rdkafka++.pc'],
    }
}

# Supported platforms
platforms = wanted_files.keys()



# Default documents to include in all packages
default_doc = ['../../README.md',
               '../../CONFIGURATION.md',
               '../../LICENSES.txt']

# Rename matching files
rename_files = {'librdkafka.so.1': 'librdkafka.so',
                'librdkafka++.so.1': 'librdkafka++.so'}


# Rename token values
rename_vals = {'plat': {'linux': 'debian',
                        'windows': win_ver},
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
        rinfo = re.findall(r'(?P<tag>[^-]+)-(?P<val>.*?)__', folder)
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
        for item in self.s3_client.list_objects(Bucket=s3_bucket, Prefix='librdkafka/').get('Contents'):
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
        self.platforms = platforms
        # Staging path, filled in later.
        self.stpath = None
        self.kv = {'version': version}
        self.files = dict()

    def add_file (self, file):
        self.files[file] = True

    def categorize (self):
        """ Categorize and arrange a Package's artifacts according to
            its platforms.
            Returns a fout map:
              category: [(artifact,file)]
        """

        fout = defaultdict(list)

        # Flat lists of files to collect keyed by platform,category
        collect_files = dict()
        for platform in wanted_files:
            for category, flist in wanted_files[platform].items():
                for f in flist:
                    collect_files[(platform,category,f)] = list()

        for a in self.artifacts:
            try:
                with zfile.ZFile(a.lpath, 'r') as zf:
                    if os.path.splitext(a.lpath)[-1] == '.rpm':
                        a.info['plat'] = 'rhel'

                    platform = a.info['plat']
                    if platform not in platforms:
                        continue

                    zfiles = zf.getnames()
                    if len(zfiles) == 0:
                        print('No files in %s?' % a)
                    for category, flist in wanted_files[platform].items():
                        for f in flist:
                            matches = [(a,x) for x in zfiles if os.path.basename(x) == f]
                            if len(matches) > 0:
                                collect_files[(platform,category,f)] += matches
                                fout[category] += matches

            except zfile.tarfile.ReadError as e:
                print('ignoring artifact: %s: %s' % (a.lpath, str(e)))

        # Verify that all wanted combinations were matched
        errors = 0
        for missing in [x for x in collect_files if len(collect_files[x]) == 0]:
            errors += 1
            print('ERROR: No matching artifact files for', missing)

        if errors > 0:
            raise Exception('Not all wanted files found in artifacts, see above.')
        return fout


    def layout (self, lydef):
        """
        Layout categorized files according to provided
        layout definition \p lydef.

        Returns a layout dict containing the matched artifacts.
        """

        # Categorize files
        fout = self.categorize()

        ly = defaultdict(list)

        # For each template path, attempt to map all files in that category
        # and add any files that renders completely to the layout.
        for tmplsrc, category in lydef.items():
             tmpl = Template(tmplsrc)
             for a, f in fout[category]:
                 # print('%s: Try %s matched to %s in %s' % (category, tmplsrc, f, a))
                 try:
                     path = os.path.join(tmpl.substitute(a.info),
                                         os.path.basename(f))
                     ly[path].append((a, f))
                 except KeyError as e:
                     print(' -- %s info key %s not found' % (a, e))
                     pass

        # Sort providing sources for each path.
        # E.g., prefer .redist. before .symbols., etc.
        for path in ly:
            ly[path].sort(reverse=True)

        return ly

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

    def extract_artifacts (self, layout):
        """ Extract members from artifacts into staging path """
        print('Extracting artifacts according to layout:')
        for path, afs in layout.items():
            artifact = afs[0][0]
            member = afs[0][1]
            print('  %s (from %s) -> %s' % (member, artifact, path))
            outf = os.path.join(self.stpath, path)
            zfile.ZFile.extract(artifact.lpath, member, outf)

            self.add_file(outf)

        # Rename files, if needed.
        for root, _, filenames in os.walk(self.stpath):
            for filename in filenames:
                fname = os.path.basename(filename)
                if fname in rename_files:
                    bpath = os.path.join(root, os.path.dirname(filename))
                    oldfile = os.path.join(bpath, fname)
                    newfile = os.path.join(bpath, rename_files[fname])
                    print('Renaming %s -> %s' % (oldfile, newfile))
                    os.rename(oldfile, newfile)

        # And rename them in the files map too
        rename_these = [x for x in self.files.keys() if os.path.basename(x) in rename_files]
        for oldfile in rename_these:
            newfile = os.path.join(os.path.dirname(oldfile),
                                   rename_files[os.path.basename(oldfile)])
            self.files[newfile] = self.files[oldfile]
            del self.files[oldfile]



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
        layout = self.xlayout()

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
                           destpath=os.path.join('build', 'native'))
        self.copy_template('librdkafka.redist.props',
                           destpath=os.path.join('build', 'net'))
        for f in default_doc:
            shutil.copy(f, self.stpath)

        self.extract_artifacts(layout)

        print('Tree extracted to %s' % self.stpath)

        # After creating a bare-bone nupkg layout containing the artifacts
        # and some spec and props files, call the 'nuget' utility to
        # make a proper nupkg of it (with all the metadata files).
        subprocess.check_call("./nuget.sh pack %s -BasePath '%s' -NonInteractive" %  \
                              (os.path.join(self.stpath, 'librdkafka.redist.nuspec'),
                               self.stpath), shell=True)
        return ['librdkafka.redist.%s.nupkg' % vless_version]

    def xlayout (self):
        """ Copy files from artifact nupkgs to new super-layout

            Buildtype: release, debug

            High-level requirements:
             * provide build artifacts: -> build/
               - static libraries
               - header files
               - layout:
                  build/native/librdkafka.targets
                  build/native/lib/<plat>/<arch>/<variant>/<toolset>/{static}
                  build/native/include/librdkafka/*.h

             * provide runtime artifacts: -> runtimes/
               - dynamic libraries
               - possibly symbol files
               - layout:
                  runtimes/<plat>-<arch>/native/{dynamic}
             * both cases:
               - docs -> ./

            runtimes from https://github.com/dotnet/corefx/blob/master/pkg/Microsoft.NETCore.Platforms/runtime.json
            * win7-x86
            * win7-x64
            * osx
            * osx-x64
            * debian-x64
            * rhel-x64  (rhel.7)

            This gives the following layout:
            build/native/include/librdkafka/rdkafka.h..
            build/native/net/librdkafka.redist.props

        """

        # Generate template tokens for artifacts
        for a in self.arts.artifacts:
            if 'bldtype' not in a.info:
                a.info['bldtype'] = 'release'

            a.info['variant'] = '%s-%s-%s' % (a.info.get('plat'),
                                              a.info.get('arch'),
                                              a.info.get('bldtype'))
            if 'toolset' not in a.info:
                a.info['toolset'] = 'v120'

        nuget_layout = {
            # Build
            'build/native/lib/${plat}/${arch}/${variant}/${toolset}/': 'static',
            'build/native/include/librdkafka/': 'include',

            # Runtime
            'runtimes/${plat}-${arch}/native/': 'dynamic',

            # All
            'content/docs/': 'doc'
        }

        layout = self.layout(nuget_layout)

        errors = 0
        print(' %s layout:' % self)
        for path, afs in layout.items():
            print('  %s provided by:' % path)
            for a, f in afs:
                print('    %s from artifact %s (and %d more)' % (f, a.fname, len(afs)-1))
                break
            if len(afs) == 0:
                print('     ERROR: no artifacts found')
                errors += 1
        print('')

        if errors > 0:
            raise Exception('Layout not satisfied by collected artifacts: %d missing' % errors)

        return layout




    def verify (self, path):
        """ Verify package """
        expect = ["librdkafka.redist.nuspec",
                  "LICENSES.txt",
                  "build/native/librdkafka.redist.props",
                  "build/native/librdkafka.redist.targets",
                  "build/native/include/librdkafka/rdkafka.h",
                  "build/native/include/librdkafka/rdkafkacpp.h",
                  "build/net/librdkafka.redist.props",
                  "runtimes/win7-x86/native/librdkafka.dll",
                  "runtimes/win7-x86/native/librdkafka.lib",
                  "runtimes/win7-x86/native/zlib.dll",
                  "runtimes/win7-x86/native/msvcr120.dll",
                  "runtimes/win7-x64/native/librdkafka.dll",
                  "runtimes/win7-x64/native/librdkafka.lib",
                  "runtimes/win7-x64/native/msvcr120.dll",
                  "runtimes/osx-x64/native/librdkafka++.dylib",
                  "runtimes/osx-x64/native/librdkafka.dylib",
                  "runtimes/debian-x64/native/librdkafka++.so",
                  "runtimes/debian-x64/native/librdkafka.so",
                  "runtimes/rhel-x64/native/librdkafka++.so",
                  "runtimes/rhel-x64/native/librdkafka.so"]
        missing = list()
        with zfile.ZFile(path, 'r') as zf:
            print('Verifying %s:' % path)

            # Zipfiles may url-encode filenames, unquote them before matching.
            pkgd = [urllib.unquote(x) for x in zf.getnames()]
            missing = [x for x in expect if x not in pkgd]

        if len(missing) > 0:
            print('Missing files in package %s:\n%s' % (path, '\n'.join(missing)))
            return False
        else:
            print('OK - %d expected files found' % expect)
            return True

