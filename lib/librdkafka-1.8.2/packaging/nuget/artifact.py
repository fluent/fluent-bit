#!/usr/bin/env python3
#
#
# Collects CI artifacts from S3 storage, downloading them
# to a local directory.
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
#   p-confluent-kafka-python__bld-travis__plat-linux__tag-__sha-112130ce297656ea1c39e7c94c99286f95133a24__bid-271588764__/confluent_kafka-0.11.0-cp35-cp35m-manylinux1_x86_64.whl


import re
import os
import argparse
import boto3

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
                rdict = packaging.rename_vals.get(k, None)
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
        print('Downloading %s -> %s' % (self.path, self.lpath))
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

        print('?  %s' % path)

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

        # Match tag or sha to gitref
        unmatched = list()
        for m,v in self.match.items():
            if m not in info or info[m] != v:
                unmatched.append(m)

        # Make sure all matches were satisfied, unless this is a
        # common artifact.
        if info.get('p', '') != 'common' and len(unmatched) > 0:
            print(info)
            print('%s: %s did not match %s' % (info.get('p', None), folder, unmatched))
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


