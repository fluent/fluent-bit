#!/usr/bin/env python3
#
# Packaging script.
# Assembles packages using CI artifacts.
#

import sys
import re
import os
import shutil
from fnmatch import fnmatch
from string import Template
from zfile import zfile
import boto3
import magic

if sys.version_info[0] < 3:
    from urllib import unquote as _unquote
else:
    from urllib.parse import unquote as _unquote


def unquote(path):
    # Removes URL escapes, and normalizes the path by removing ./.
    path = _unquote(path)
    if path[:2] == './':
        return path[2:]
    return path


# Rename token values
rename_vals = {'plat': {'windows': 'win'},
               'arch': {'x86_64': 'x64',
                        'amd64': 'x64',
                        'i386': 'x86',
                        'win32': 'x86'}}

# Filemagic arch mapping.
# key is (plat, arch, file_extension), value is a compiled filemagic regex.
# This is used to verify that an artifact has the expected file type.
magic_patterns = {
    ('win', 'x64', '.dll'): re.compile('PE32.*DLL.* x86-64, for MS Windows'),
    ('win', 'x86', '.dll'):
    re.compile('PE32.*DLL.* Intel 80386, for MS Windows'),
    ('win', 'x64', '.lib'): re.compile('current ar archive'),
    ('win', 'x86', '.lib'): re.compile('current ar archive'),
    ('linux', 'x64', '.so'): re.compile('ELF 64.* x86-64'),
    ('linux', 'arm64', '.so'): re.compile('ELF 64.* ARM aarch64'),
    ('osx', 'x64', '.dylib'): re.compile('Mach-O 64.* x86_64'),
    ('osx', 'arm64', '.dylib'): re.compile('Mach-O 64.*arm64')}

magic = magic.Magic()


def magic_mismatch(path, a):
    """ Verify that the filemagic for \\p path matches for artifact \\p a.
        Returns True if the magic file info does NOT match.
        Returns False if no matching is needed or the magic matches. """
    k = (a.info.get('plat', None), a.info.get('arch', None),
         os.path.splitext(path)[1])
    pattern = magic_patterns.get(k, None)
    if pattern is None:
        return False

    minfo = magic.id_filename(path)
    if not pattern.match(minfo):
        print(
            f"Warning: {path} magic \"{minfo}\" "
            f"does not match expected {pattern} for key {k}")
        return True

    return False


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
#  dist    - distro or runtime ("centos6", "mingw", "msvcr", "alpine", ..).
#  arch    - arch ("x64", ..)
#  tag     - git tag
#  sha     - git sha
#  bid     - builder's build-id
#  bldtype - Release, Debug (appveyor)
#  lnk     - Linkage ("std", "static", "all" (both std and static))
#  extra   - Extra build options, typically "gssapi" (for cyrus-sasl linking).

#
# Example:
#   librdkafka/p-librdkafka__bld-travis__plat-linux__arch-x64__tag-v0.0.62__sha-d051b2c19eb0c118991cd8bc5cf86d8e5e446cde__bid-1562.1/librdkafka.tar.gz


class MissingArtifactError(Exception):
    pass


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
            # Rename values, e.g., 'plat':'windows' to 'plat':'win'
            for k, v in self.info.items():
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

    def __lt__(self, other):
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
        for m, v in self.match.items():
            if m not in info or info[m] != v:
                unmatched.append(f"{m} = {v}")

        # Make sure all matches were satisfied, unless this is a
        # common artifact.
        if info.get('p', '') != 'common' and len(unmatched) > 0:
            return None

        return Artifact(self, path, info)

    def collect_s3(self):
        """ Collect and download build-artifacts from S3 based on
        git reference """
        print(
            'Collecting artifacts matching %s from S3 bucket %s' %
            (self.match, s3_bucket))
        self.s3 = boto3.resource('s3')
        self.s3_bucket = self.s3.Bucket(s3_bucket)
        self.s3_client = boto3.client('s3')

        # note: list_objects will return at most 1000 objects per call,
        #       use continuation token to read full list.
        cont_token = None
        more = True
        while more:
            if cont_token is not None:
                res = self.s3_client.list_objects_v2(
                    Bucket=s3_bucket,
                    Prefix='librdkafka/',
                    ContinuationToken=cont_token)
            else:
                res = self.s3_client.list_objects_v2(Bucket=s3_bucket,
                                                     Prefix='librdkafka/')

            if res.get('IsTruncated') is True:
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
        for f in [os.path.join(dp, f) for dp, dn,
                  filenames in os.walk(path) for f in filenames]:
            if not os.path.isfile(f):
                continue
            self.collect_single(f, req_tag)


class Mapping (object):
    """ Maps/matches a file in an input release artifact to
        the output location of the package, based on attributes and paths. """

    def __init__(self, attributes, artifact_fname_glob, path_in_artifact,
                 output_pkg_path=None, artifact_fname_excludes=[]):
        """
        @param attributes A dict of artifact attributes that must match.
                          If an attribute name (dict key) is prefixed
                          with "!" (e.g., "!plat") then the attribute
                          must not match.
        @param artifact_fname_glob Match artifacts with this filename glob.
        @param path_in_artifact On match, extract this file in the artifact,..
        @param output_pkg_path ..and write it to this location in the package.
                               Defaults to path_in_artifact.
        @param artifact_fname_excludes Exclude artifacts matching these
                                       filenames.

        Pass a list of Mapping objects to FIXME to perform all mappings.
        """
        super(Mapping, self).__init__()
        self.attributes = attributes
        self.fname_glob = artifact_fname_glob
        self.input_path = path_in_artifact
        if output_pkg_path is None:
            self.output_path = self.input_path
        else:
            self.output_path = output_pkg_path
        self.name = self.output_path
        self.fname_excludes = artifact_fname_excludes

    def __str__(self):
        return self.name


class Package (object):
    """ Generic Package class
        A Package is a working container for one or more output
        packages for a specific package type (e.g., nuget) """

    def __init__(self, version, arts):
        super(Package, self).__init__()
        self.version = version
        self.arts = arts
        # These may be overwritten by specific sub-classes:
        self.artifacts = arts.artifacts
        # Staging path, filled in later.
        self.stpath = None
        self.kv = {'version': version}
        self.files = dict()

    def add_file(self, file):
        self.files[file] = True

    def build(self):
        """ Build package output(s), return a list of paths "
        to built packages """
        raise NotImplementedError

    def cleanup(self):
        """ Optional cleanup routine for removing temporary files, etc. """
        pass

    def render(self, fname, destpath='.'):
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

    def copy_template(self, fname, target_fname=None, destpath='.'):
        """ Copy template file to destpath/fname
        where destpath is relative to stpath """

        if target_fname is None:
            target_fname = fname
        outf = os.path.join(self.stpath, destpath, target_fname)

        if not os.path.isdir(os.path.dirname(outf)):
            os.makedirs(os.path.dirname(outf), 0o0755)

        shutil.copy(os.path.join('templates', fname), outf)

        self.add_file(outf)

    def apply_mappings(self):
        """ Applies a list of Mapping to match and extract files from
            matching artifacts. If any of the listed Mappings can not be
            fulfilled an exception is raised. """

        assert self.mappings
        assert len(self.mappings) > 0

        for m in self.mappings:

            artifact = None
            for a in self.arts.artifacts:
                found = True

                for attr in m.attributes:
                    if attr[0] == '!':
                        # Require attribute NOT to match
                        origattr = attr
                        attr = attr[1:]

                        if attr in a.info and \
                           a.info[attr] != m.attributes[origattr]:
                            found = False
                            break
                    else:
                        # Require attribute to match
                        if attr not in a.info or \
                           a.info[attr] != m.attributes[attr]:
                            found = False
                            break

                if not fnmatch(a.fname, m.fname_glob):
                    found = False

                for exclude in m.fname_excludes:
                    if exclude in a.fname:
                        found = False
                        break

                if found:
                    artifact = a
                    break

            if artifact is None:
                raise MissingArtifactError(
                    '%s: unable to find artifact with tags %s matching "%s"' %
                    (m, str(m.attributes), m.fname_glob))

            output_path = os.path.join(self.stpath, m.output_path)

            try:
                zfile.ZFile.extract(artifact.lpath, m.input_path, output_path)
#            except KeyError:
#                continue
            except Exception as e:
                raise Exception(
                    '%s: file not found in archive %s: %s. Files in archive are:\n%s' %  # noqa: E501
                    (m, artifact.lpath, e, '\n'.join(zfile.ZFile(
                        artifact.lpath).getnames())))

            # Check that the file type matches.
            if magic_mismatch(output_path, a):
                os.unlink(output_path)
                continue

        # All mappings found and extracted.

    def verify(self, path):
        """ Verify package content based on the previously defined mappings """

        missing = list()
        with zfile.ZFile(path, 'r') as zf:
            print('Verifying %s:' % path)

            # Zipfiles may url-encode filenames, unquote them before matching.
            pkgd = [unquote(x) for x in zf.getnames()]
            missing = [x for x in self.mappings if x.output_path not in pkgd]

        if len(missing) > 0:
            print(
                'Missing files in package %s:\n%s' %
                (path, '\n'.join([str(x) for x in missing])))
            print('Actual: %s' % '\n'.join(pkgd))
            return False

        print('OK - %d expected files found' % len(self.mappings))
        return True
