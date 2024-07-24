#!/usr/bin/env python3
#
#
# Run librdkafka regression tests on different supported broker versions.
#
# Requires:
#  trivup python module
#  gradle in your PATH

from cluster_testing import read_scenario_conf
from broker_version_tests import test_it

import os
import sys
import argparse
import json


def version_as_number(version):
    if version == 'trunk':
        return sys.maxsize
    tokens = version.split('.')
    return float('%s.%s' % (tokens[0], tokens[1]))


def test_version(version, cmd=None, deploy=True, conf={}, debug=False,
                 exec_cnt=1,
                 root_path='tmp', broker_cnt=3, scenario='default',
                 kraft=False):
    """
    @brief Create, deploy and start a Kafka cluster using Kafka \\p version
    Then run librdkafka's regression tests. Use inherited environment.
    """
    conf['test_mode'] = 'bash'
    test_it(version, deploy, conf, {}, None, True, debug,
            scenario, kraft, True)
    return True


if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='Start a Kafka cluster and provide an interactive shell')

    parser.add_argument('versions', type=str, default=None, nargs='+',
                        help='Kafka version(s) to deploy')
    parser.add_argument('--no-deploy', action='store_false', dest='deploy',
                        default=True,
                        help='Dont deploy applications, '
                        'assume already deployed.')
    parser.add_argument('--conf', type=str, dest='conf', default=None,
                        help='''
    JSON config object (not file).
    This does not translate to broker configs directly.
    If broker config properties are to be specified,
    they should be specified with
    --conf \'{"conf": ["key=value", "key=value"]}\'''')
    parser.add_argument('--scenario', type=str, dest='scenario',
                        default='default',
                        help='Test scenario (see scenarios/ directory)')
    parser.add_argument('-c', type=str, dest='cmd', default=None,
                        help='Command to execute instead of shell')
    parser.add_argument('-n', type=int, dest='exec_cnt', default=1,
                        help='Number of times to execute -c ..')
    parser.add_argument('--debug', action='store_true', dest='debug',
                        default=False,
                        help='Enable trivup debugging')
    parser.add_argument(
        '--root',
        type=str,
        default=os.environ.get(
            'TRIVUP_ROOT',
            'tmp'),
        help='Root working directory')
    parser.add_argument(
        '--port',
        default=None,
        help='Base TCP port to start allocating from')
    parser.add_argument(
        '--kafka-src',
        dest='kafka_path',
        type=str,
        default=None,
        help='Path to Kafka git repo checkout (used for version=trunk)')
    parser.add_argument(
        '--brokers',
        dest='broker_cnt',
        type=int,
        default=3,
        help='Number of Kafka brokers')
    parser.add_argument('--ssl', dest='ssl', action='store_true',
                        default=False,
                        help='Enable SSL endpoints')
    parser.add_argument(
        '--sasl',
        dest='sasl',
        type=str,
        default=None,
        help='SASL mechanism (PLAIN, SCRAM-SHA-nnn, GSSAPI, OAUTHBEARER)')
    parser.add_argument(
        '--oauthbearer-method',
        dest='sasl_oauthbearer_method',
        type=str,
        default=None,
        help='OAUTHBEARER/OIDC method (DEFAULT, OIDC), \
             must config SASL mechanism to OAUTHBEARER')
    parser.add_argument(
        '--max-reauth-ms',
        dest='reauth_ms',
        type=int,
        default='10000',
        help='''
        Sets the value of connections.max.reauth.ms on the brokers.
        Set 0 to disable.''')
    parser.add_argument(
        '--kraft',
        dest='kraft',
        action='store_true',
        default=False,
        help='Run in KRaft mode')

    args = parser.parse_args()
    if args.conf is not None:
        args.conf = json.loads(args.conf)
    else:
        args.conf = {}

    args.conf.update(read_scenario_conf(args.scenario))

    if args.port is not None:
        args.conf['port_base'] = int(args.port)
    if args.kafka_path is not None:
        args.conf['kafka_path'] = args.kafka_path
    if args.ssl:
        args.conf['security.protocol'] = 'SSL'
    if args.sasl:
        if (args.sasl == 'PLAIN' or args.sasl.find('SCRAM')
                != -1) and 'sasl_users' not in args.conf:
            args.conf['sasl_users'] = 'testuser=testpass'
        args.conf['sasl_mechanisms'] = args.sasl
    retcode = 0
    if args.sasl_oauthbearer_method:
        if args.sasl_oauthbearer_method == "OIDC" and \
           args.conf['sasl_mechanisms'] != 'OAUTHBEARER':
            print('If config `--oauthbearer-method=OIDC`, '
                  '`--sasl` must be set to `OAUTHBEARER`')
            retcode = 3
            sys.exit(retcode)
        args.conf['sasl_oauthbearer_method'] = \
            args.sasl_oauthbearer_method

    if 'conf' not in args.conf:
        args.conf['conf'] = []

    args.conf['conf'].append(
        "connections.max.reauth.ms={}".format(
            args.reauth_ms))
    args.conf['conf'].append("log.retention.bytes=1000000000")

    for version in args.versions:
        r = test_version(version, cmd=args.cmd, deploy=args.deploy,
                         conf=args.conf, debug=args.debug,
                         exec_cnt=args.exec_cnt,
                         root_path=args.root, broker_cnt=args.broker_cnt,
                         scenario=args.scenario,
                         kraft=args.kraft)
        if not r:
            retcode = 2

    sys.exit(retcode)
