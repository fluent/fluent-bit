# Run using:
# $ python setup.py build_ext -i

from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize
import os

os.environ['CFLAGS'] = '-I../../include/monkey'
os.environ['LDFLAGS'] = '-L../../src'

setup(ext_modules = cythonize(
    [
        Extension("monkey", ["monkey.pyx"], libraries=["monkey"])
    ]
    )
)
