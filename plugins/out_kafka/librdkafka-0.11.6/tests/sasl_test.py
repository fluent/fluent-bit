#!/usr/bin/env python
#
#
# Run librdkafka regression tests on with different SASL parameters
# and broker verisons.
#
# Requires:
#  trivup python module
#  gradle in your PATH

from cluster_testing import LibrdkafkaTestCluster, print_report_summary, print_test_report_summary
from LibrdkafkaTestApp import LibrdkafkaTestApp


import time
import tempfile
import os
import sys
import argparse
import json
import tempfile

def test_it (version, deploy=True, conf={}, rdkconf={}, tests=None, debug=False):
    """
    @brief Create, deploy and start a Kafka cluster using Kafka \p version
    Then run librdkafka's regression tests.
    """

    cluster = LibrdkafkaTestCluster(version, conf, debug=debug)

    # librdkafka's regression tests, as an App.
    rdkafka = LibrdkafkaTestApp(cluster, version, _rdkconf, tests=tests)
    rdkafka.do_cleanup = False
    rdkafka.local_tests = False

    if deploy:
        cluster.deploy()

    cluster.start(timeout=30)

    print('# Connect to cluster with bootstrap.servers %s' % cluster.bootstrap_servers())
    rdkafka.start()
    print('# librdkafka regression tests started, logs in %s' % rdkafka.root_path())
    try:
        rdkafka.wait_stopped(timeout=60*30)
        rdkafka.dbg('wait stopped: %s, runtime %ds' % (rdkafka.state, rdkafka.runtime()))
    except KeyboardInterrupt:
        print('# Aborted by user')

    report = rdkafka.report()
    if report is not None:
        report['root_path'] = rdkafka.root_path()

    cluster.stop(force=True)

    cluster.cleanup()
    return report


def handle_report (report, version, suite):
    """ Parse test report and return tuple (Passed(bool), Reason(str)) """
    test_cnt = report.get('tests_run', 0)

    if test_cnt == 0:
        return (False, 'No tests run')

    passed = report.get('tests_passed', 0)
    failed = report.get('tests_failed', 0)
    if 'all' in suite.get('expect_fail', []) or version in suite.get('expect_fail', []):
        expect_fail = True
    else:
        expect_fail = False

    if expect_fail:
        if failed == test_cnt:
            return (True, 'All %d/%d tests failed as expected' % (failed, test_cnt))
        else:
            return (False, '%d/%d tests failed: expected all to fail' % (failed, test_cnt))
    else:
        if failed > 0:
            return (False, '%d/%d tests passed: expected all to pass' % (passed, test_cnt))
        else:
            return (True, 'All %d/%d tests passed as expected' % (passed, test_cnt))



if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Run librdkafka test suit using SASL on a trivupped cluster')

    parser.add_argument('--conf', type=str, dest='conf', default=None,
                        help='trivup JSON config object (not file)')
    parser.add_argument('--rdkconf', type=str, dest='rdkconf', default=None,
                        help='trivup JSON config object (not file) for LibrdkafkaTestApp')
    parser.add_argument('--tests', type=str, dest='tests', default=None,
                        help='Test to run (e.g., "0002")')
    parser.add_argument('--no-ssl', action='store_false', dest='ssl', default=True,
                        help='Don\'t run SSL tests')
    parser.add_argument('--no-sasl', action='store_false', dest='sasl', default=True,
                        help='Don\'t run SASL tests')
    parser.add_argument('--no-plaintext', action='store_false', dest='plaintext', default=True,
                        help='Don\'t run PLAINTEXT tests')

    parser.add_argument('--report', type=str, dest='report', default=None,
                        help='Write test suites report to this filename')
    parser.add_argument('--debug', action='store_true', dest='debug', default=False,
                        help='Enable trivup debugging')
    parser.add_argument('versions', type=str, default=None,
                        nargs='*', help='Limit broker versions to these')
    args = parser.parse_args()

    conf = dict()
    rdkconf = dict()

    if args.conf is not None:
        conf.update(json.loads(args.conf))
    if args.rdkconf is not None:
        rdkconf.update(json.loads(args.rdkconf))
    if args.tests is not None:
        tests = args.tests.split(',')
    else:
        tests = None

    # Test version,supported mechs + suite matrix
    versions = list()
    if len(args.versions):
        for v in args.versions:
            versions.append((v, ['SCRAM-SHA-512','PLAIN','GSSAPI']))
    else:
        versions = [('0.10.2.0', ['SCRAM-SHA-512','PLAIN','GSSAPI']),
                    ('0.9.0.1', ['GSSAPI']),
                    ('0.8.2.2', [])]
    sasl_plain_conf = {'sasl_mechanisms': 'PLAIN',
                       'sasl_users': 'myuser=mypassword'}
    sasl_scram_conf = {'sasl_mechanisms': 'SCRAM-SHA-512',
                       'sasl_users': 'myuser=mypassword'}
    ssl_sasl_plain_conf = {'sasl_mechanisms': 'PLAIN',
                           'sasl_users': 'myuser=mypassword',
                           'security.protocol': 'SSL'}
    sasl_kerberos_conf = {'sasl_mechanisms': 'GSSAPI',
                          'sasl_servicename': 'kafka'}
    suites = [{'name': 'SASL PLAIN',
               'run': (args.sasl and args.plaintext),
               'conf': sasl_plain_conf,
               'expect_fail': ['0.9.0.1', '0.8.2.2']},
              {'name': 'SASL SCRAM',
               'run': (args.sasl and args.plaintext),
               'conf': sasl_scram_conf,
               'expect_fail': ['0.9.0.1', '0.8.2.2']},
              {'name': 'PLAINTEXT (no SASL)',
               'run': args.plaintext},
              {'name': 'SSL (no SASL)',
               'run': args.ssl,
               'conf': {'security.protocol': 'SSL'},
               'expect_fail': ['0.8.2.2']},
              {'name': 'SASL_SSL PLAIN',
               'run': (args.sasl and args.ssl and args.plaintext),
               'conf': ssl_sasl_plain_conf,
               'expect_fail': ['0.9.0.1', '0.8.2.2']},
              {'name': 'SASL PLAIN with wrong username',
               'run': (args.sasl and args.plaintext),
               'conf': sasl_plain_conf,
               'rdkconf': {'sasl_users': 'wrongjoe=mypassword'},
               'tests': ['0001'],
               'expect_fail': ['all']},
              {'name': 'SASL Kerberos',
               'run': args.sasl,
               'conf': sasl_kerberos_conf,
               'expect_fail': ['0.8.2.2']}]


    pass_cnt = 0
    fail_cnt = 0
    for version,supported in versions:
        if len(args.versions) > 0 and version not in args.versions:
            print('### Skipping version %s' % version)
            continue

        for suite in suites:
            if not suite.get('run', True):
                continue

            _conf = conf.copy()
            _conf.update(suite.get('conf', {}))
            _rdkconf = _conf.copy()
            _rdkconf.update(rdkconf)
            _rdkconf.update(suite.get('rdkconf', {}))

            if 'version' not in suite:
                suite['version'] = dict()

            # Disable SASL broker config if broker version does
            # not support the selected mechanism
            mech = suite.get('conf', dict()).get('sasl_mechanisms', None)
            if mech is not None and mech not in supported:
                print('# Disabled SASL for broker version %s' % version)
                _conf.pop('sasl_mechanisms', None)

            # Run tests
            print('#### Version %s, suite %s: STARTING' % (version, suite['name']))
            if tests is None:
                tests_to_run = suite.get('tests', None)
            else:
                tests_to_run = tests
            report = test_it(version, tests=tests_to_run, conf=_conf, rdkconf=_rdkconf,
                             debug=args.debug)

            # Handle test report
            report['version'] = version
            passed,reason = handle_report(report, version, suite)
            report['PASSED'] = passed
            report['REASON'] = reason

            if passed:
                print('\033[42m#### Version %s, suite %s: PASSED: %s\033[0m' %
                      (version, suite['name'], reason))
                pass_cnt += 1
            else:
                print('\033[41m#### Version %s, suite %s: FAILED: %s\033[0m' %
                      (version, suite['name'], reason))
                print_test_report_summary('%s @ %s' % \
                                          (suite['name'], version), report)
                fail_cnt += 1
            print('#### Test output: %s/stderr.log' % (report['root_path']))

            suite['version'][version] = report

    # Write test suite report JSON file
    if args.report is not None:
        test_suite_report_file = args.report
        f = open(test_suite_report_file, 'w')
    else:
        fd, test_suite_report_file = tempfile.mkstemp(prefix='test_suite_',
                                                      suffix='.json',
                                                      dir='.')
        f = os.fdopen(fd, 'w')

    full_report = {'suites': suites, 'pass_cnt': pass_cnt,
                   'fail_cnt': fail_cnt, 'total_cnt': pass_cnt+fail_cnt}

    f.write(json.dumps(full_report).encode('ascii'))
    f.close()

    print('\n\n\n')
    print_report_summary(full_report)
    print('#### Full test suites report in: %s' % test_suite_report_file)

    if pass_cnt == 0 or fail_cnt > 0:
        sys.exit(1)
    else:
        sys.exit(0)
