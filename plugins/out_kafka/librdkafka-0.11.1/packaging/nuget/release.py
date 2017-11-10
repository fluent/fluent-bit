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

    package_for = [packaging.NugetPackage]
    packages = list()

    print('Packaging classes: %s' % package_for)

    for pcl in package_for:
        p = pcl(match['tag'], arts)
        packages.append(p)
    print('')

    if dry_run:
        sys.exit(0)

    # Build packages
    print('Building packages:')
    pkgfiles = []
    for p in packages:
        paths = p.build(buildtype='release')
        for path in paths:
            # Verify package files
            if p.verify(path):
                pkgfiles.append(path)
        if not args.no_cleanup:
            p.cleanup()
        else:
            print(' --no-cleanup: leaving %s' % p.stpath)
    print('')

    if len(pkgfiles) > 0:
        print('Created packages:')
        for pkg in pkgfiles:
            print(pkg)
    else:
        print('No packages created')
        sys.exit(1)
