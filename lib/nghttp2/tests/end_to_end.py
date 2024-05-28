#!/usr/bin/env python
"""End to end tests for the utility programs.

This test assumes the utilities inside src directory have already been
built.

At the moment top_buiddir is not in the environment, but top_builddir would be
more reliable than '..', so it's worth trying to pull it from the environment.
"""

__author__ = 'Jim Morrison <jim@twist.com>'


import os
import subprocess
import time
import unittest


_PORT = 9893


def _run_server(port, args):
  srcdir = os.environ.get('srcdir', '.')
  testdata = '%s/testdata' % srcdir
  top_builddir = os.environ.get('top_builddir', '..')
  base_args = ['%s/src/spdyd' % top_builddir, '-d', testdata]
  if args:
    base_args.extend(args)
  base_args.extend([str(port), '%s/privkey.pem' % testdata,
                    '%s/cacert.pem' % testdata])
  return subprocess.Popen(base_args)

def _check_server_up(port):
  # Check this check for now.
  time.sleep(1)

def _kill_server(server):
  while server.returncode is None:
    server.terminate()
    time.sleep(1)
    server.poll()


class EndToEndSpdyTests(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    cls.setUpServer([])

  @classmethod
  def setUpServer(cls, args):
    cls.server = _run_server(_PORT, args)
    _check_server_up(_PORT)

  @classmethod
  def tearDownClass(cls):
    _kill_server(cls.server)

  def setUp(self):
    build_dir = os.environ.get('top_builddir', '..')
    self.client = '%s/src/spdycat' % build_dir
    self.stdout = 'No output'

  def call(self, path, args):
     full_args = [self.client,'http://localhost:%d%s' % (_PORT, path)] + args
     p = subprocess.Popen(full_args, stdout=subprocess.PIPE,
                          stdin=subprocess.PIPE)
     self.stdout, self.stderr = p.communicate()
     return p.returncode


class EndToEndSpdy2Tests(EndToEndSpdyTests):
  def testSimpleRequest(self):
    self.assertEquals(0, self.call('/', []))

  def testSimpleRequestSpdy3(self):
    self.assertEquals(0, self.call('/', ['-v', '-3']))
    self.assertIn('NPN selected the protocol: spdy/3', self.stdout)

  def testFailedRequests(self):
    self.assertEquals(
        2, self.call('/', ['https://localhost:25/', 'http://localhost:79']))

  def testOneFailedRequest(self):
    self.assertEquals(1, subprocess.call([self.client, 'http://localhost:2/']))

  def testOneTimedOutRequest(self):
    self.assertEquals(1, self.call('/?spdyd_do_not_respond_to_req=yes',
                                   ['--timeout=2']))
    self.assertEquals(0, self.call('/', ['--timeout=20']))


class EndToEndSpdy3Tests(EndToEndSpdyTests):
  @classmethod
  def setUpClass(cls):
    cls.setUpServer(['-3'])

  def testSimpleRequest(self):
    self.assertEquals(0, self.call('/', ['-v']))
    self.assertIn('NPN selected the protocol: spdy/3', self.stdout)


if __name__ == '__main__':
  unittest.main()
