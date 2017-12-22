#!/usr/bin/env python
#
#
# NuGet release packaging tool.
# Creates a NuGet package from CI artifacts on S3.
#


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
    parser.add_argument("tag", help="Git tag to collect")

    args = parser.parse_args()
    dry_run = args.dry_run
    if not args.directory:
        args.directory = 'dl-%s' % args.tag

    match = {'tag': args.tag}
    if args.sha is not None:
        match['sha'] = args.sha

    arts = packaging.Artifacts(match, args.directory)

    # Collect common local artifacts, such as support files.
    arts.collect_local('common', req_tag=False)

    if not args.no_s3:
        arts.collect_s3()
    else:
        arts.collect_local(arts.dlpath)

    if len(arts.artifacts) == 0:
        raise ValueError('No artifacts found for %s' % match)

    print('Collected artifacts:')
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

    p = packaging.NugetPackage(package_version, arts)
    pkgfile = p.build(buildtype='release')

    if not args.no_cleanup:
        p.cleanup()
    else:
        print(' --no-cleanup: leaving %s' % p.stpath)

    print('')

    if not p.verify(pkgfile):
        print('Package failed verification.')
        sys.exit(1)
    else:
        print('Created package: %s' % pkgfile)
