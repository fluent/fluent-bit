#!/usr/bin/env python3

import os
import tarfile
import zipfile
import rpmfile

class ZFile (object):
    def __init__(self, path, mode='r', ext=None):
        super(ZFile, self).__init__()

        if ext is not None:
            _ext = ext
        else:
            _ext = os.path.splitext(path)[-1]
        if _ext.startswith('.'):
            _ext = _ext[1:]

        if zipfile.is_zipfile(path) or _ext == 'zip':
            self.f = zipfile.ZipFile(path, mode)
        elif tarfile.is_tarfile(path) or _ext in ('tar', 'tgz', 'gz'):
            self.f = tarfile.open(path, mode)
        elif _ext == 'rpm':
            self.f = rpmfile.open(path, mode + 'b')
        else:
            raise ValueError('Unsupported file extension: %s' % path)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if callable(getattr(self.f, 'close', None)):
            self.f.close()

    def getnames(self):
        if isinstance(self.f, zipfile.ZipFile):
            return self.f.namelist()
        elif isinstance(self.f, tarfile.TarFile):
            return self.f.getnames()
        elif isinstance(self.f, rpmfile.RPMFile):
            return [x.name for x in self.f.getmembers()]
        else:
            raise NotImplementedError

    def headers(self):
        if isinstance(self.f, rpmfile.RPMFile):
            return self.f.headers
        else:
            return dict()

    def extract_to(self, member, path):
        """ Extract compress file's \p member to \p path
            If \p path is a directory the member's basename will used as
            filename, otherwise path is considered the full file path name. """

        if not os.path.isdir(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))

        if os.path.isdir(path):
            path = os.path.join(path, os.path.basename(member))

        with open(path, 'wb') as of:
            if isinstance(self.f, zipfile.ZipFile):
                zf = self.f.open(member)
            else:
                zf = self.f.extractfile(member)

            while True:
                b = zf.read(1024*100)
                if b:
                    of.write(b)
                else:
                    break

            zf.close()


    @classmethod
    def extract (cls, zpath, member, outpath):
        """
        Extract file member (full internal path) to output from
        archive zpath.
        """

        with ZFile(zpath) as zf:
            zf.extract_to(member, outpath)


    @classmethod
    def compress (cls, zpath, paths, stripcnt=0, ext=None):
        """
        Create new compressed file \p zpath containing files in \p paths
        """

        with ZFile(zpath, 'w', ext=ext) as zf:
            for p in paths:
                outp = os.path.sep.join(p.split(os.path.sep)[stripcnt:])
                print('zip %s to %s (stripcnt %d)' % (p, outp, stripcnt))
                zf.f.write(p, outp)

