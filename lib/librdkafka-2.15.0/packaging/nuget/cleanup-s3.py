#!/usr/bin/env python3
#
# Clean up test builds from librdkafka's S3 bucket.
# This also covers python builds.

import re
from datetime import datetime, timezone
import boto3
import argparse

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


def may_delete(path):
    """ Returns true if S3 object path is eligible for deletion, e.g.
        has a non-release/rc tag. """

    # The path contains the tokens needed to perform
    # matching of project, gitref, etc.
    rinfo = re.findall(r'(?P<tag>[^-]+)-(?P<val>.*?)(?:__|$)', path)
    if rinfo is None or len(rinfo) == 0:
        print(f"Incorrect folder/file name format for {path}")
        return False

    info = dict(rinfo)

    tag = info.get('tag', None)
    if tag is not None and (len(tag) == 0 or tag.startswith('$(')):
        # AppVeyor doesn't substite $(APPVEYOR_REPO_TAG_NAME)
        # with an empty value when not set, it leaves that token
        # in the string - so translate that to no tag.
        del info['tag']
        tag = None

    if tag is None:
        return True

    if re.match(r'^v?\d+\.\d+\.\d+(-?RC\d+)?$', tag,
                flags=re.IGNORECASE) is None:
        return True

    return False


def collect_s3(s3, min_age_days=60):
    """ Collect artifacts from S3 """
    now = datetime.now(timezone.utc)
    eligible = []
    totcnt = 0
    # note: list_objects will return at most 1000 objects per call,
    #       use continuation token to read full list.
    cont_token = None
    more = True
    while more:
        if cont_token is not None:
            res = s3.list_objects_v2(Bucket=s3_bucket,
                                     ContinuationToken=cont_token)
        else:
            res = s3.list_objects_v2(Bucket=s3_bucket)

        if res.get('IsTruncated') is True:
            cont_token = res.get('NextContinuationToken')
        else:
            more = False

        for item in res.get('Contents'):
            totcnt += 1
            age = (now - item.get('LastModified')).days
            path = item.get('Key')
            if age >= min_age_days and may_delete(path):
                eligible.append(path)

    return (eligible, totcnt)


def chunk_list(lst, cnt):
    """ Split list into lists of cnt """
    for i in range(0, len(lst), cnt):
        yield lst[i:i + cnt]


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--delete",
                        help="WARNING! Don't just check, actually delete "
                        "S3 objects.",
                        action="store_true")
    parser.add_argument("--age", help="Minimum object age in days.",
                        type=int, default=360)

    args = parser.parse_args()
    dry_run = args.delete is not True
    min_age_days = args.age

    if dry_run:
        op = "Eligible for deletion"
    else:
        op = "Deleting"

    s3 = boto3.client('s3')

    # Collect eligible artifacts
    eligible, totcnt = collect_s3(s3, min_age_days=min_age_days)
    print(f"{len(eligible)}/{totcnt} eligible artifacts to delete")

    # Delete in chunks of 1000 (max what the S3 API can do)
    for chunk in chunk_list(eligible, 1000):
        print(op + ":\n" + '\n'.join(chunk))
        if dry_run:
            continue

        res = s3.delete_objects(Bucket=s3_bucket,
                                Delete={
                                    'Objects': [{'Key': x} for x in chunk],
                                    'Quiet': True
                                })
        errors = res.get('Errors', [])
        if len(errors) > 0:
            raise Exception(f"Delete failed: {errors}")
