#!/usr/bin/env python3
#
#
# NuGet release packaging tool.
# Creates a NuGet package from CI artifacts on S3.
#


import os
import sys
import argparse
import packaging


dry_run = False



if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--no-s3", help="Don't collect from S3", action="store_true")
    parser.add_argument("--dry-run",
                        help="Locate artifacts but don't actually download or do anything",
                        action="store_true")
    parser.add_argument("--directory", help="Download directory (default: dl-<tag>)", default=None)
    parser.add_argument("--no-cleanup", help="Don't clean up temporary folders", action="store_true")
    parser.add_argument("--sha", help="Also match on this git sha1", default=None)
    parser.add_argument("--nuget-version", help="The nuget package version (defaults to same as tag)", default=None)
    parser.add_argument("--upload", help="Upload package to after building, using provided NuGet API key", default=None, type=str)
    parser.add_argument("--class", help="Packaging class (see packaging.py)", default="NugetPackage", dest="pkgclass")
    parser.add_argument("tag", help="Git tag to collect")

    args = parser.parse_args()
    dry_run = args.dry_run
    if not args.directory:
        args.directory = 'dl-%s' % args.tag

    match = {'tag': args.tag}
    if args.sha is not None:
        match['sha'] = args.sha

    pkgclass = getattr(packaging, args.pkgclass)

    try:
        match.update(getattr(pkgclass, 'match'))
    except:
        pass

    arts = packaging.Artifacts(match, args.directory)

    # Collect common local artifacts, such as support files.
    arts.collect_local('common', req_tag=False)

    if not args.no_s3:
        arts.collect_s3()
    else:
        arts.collect_local(arts.dlpath)

    if len(arts.artifacts) == 0:
        raise ValueError('No artifacts found for %s' % match)

    print('Collected artifacts (%s):' % (arts.dlpath))
    for a in arts.artifacts:
        print(' %s' % a.lpath)
    print('')

    package_version = match['tag']
    if args.nuget_version is not None:
        package_version = args.nuget_version

    print('')

    if dry_run:
        sys.exit(0)

    print('Building packages:')

    p = pkgclass(package_version, arts)
    pkgfile = p.build(buildtype='release')

    if not args.no_cleanup:
        p.cleanup()
    else:
        print(' --no-cleanup: leaving %s' % p.stpath)

    print('')

    if not p.verify(pkgfile):
        print('Package failed verification.')
        sys.exit(1)

    print('Created package: %s' % pkgfile)

    if args.upload is not None:
        print('Uploading %s to NuGet' % pkgfile)
        r = os.system("./push-to-nuget.sh '%s' %s" % (args.upload, pkgfile))
        assert int(r) == 0, "NuGet upload failed with exit code {}, see previous errors".format(r)
        print('%s successfully uploaded to NuGet' % pkgfile)
