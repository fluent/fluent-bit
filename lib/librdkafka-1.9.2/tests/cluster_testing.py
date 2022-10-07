#!/usr/bin/env python3
#
#
# Cluster testing helper
#
# Requires:
#  trivup python module
#  gradle in your PATH

from trivup.trivup import Cluster
from trivup.apps.ZookeeperApp import ZookeeperApp
from trivup.apps.KafkaBrokerApp import KafkaBrokerApp
from trivup.apps.KerberosKdcApp import KerberosKdcApp
from trivup.apps.SslApp import SslApp
from trivup.apps.OauthbearerOIDCApp import OauthbearerOIDCApp

import os
import sys
import json
import argparse
import re
from jsoncomment import JsonComment


def version_as_list(version):
    if version == 'trunk':
        return [sys.maxsize]
    return [int(a) for a in re.findall('\\d+', version)][0:3]


def read_scenario_conf(scenario):
    """ Read scenario configuration from scenarios/<scenario>.json """
    parser = JsonComment(json)
    with open(os.path.join('scenarios', scenario + '.json'), 'r') as f:
        return parser.load(f)


class LibrdkafkaTestCluster(Cluster):
    def __init__(self, version, conf={}, num_brokers=3, debug=False,
                 scenario="default"):
        """
        @brief Create, deploy and start a Kafka cluster using Kafka \\p version

        Supported \\p conf keys:
         * security.protocol - PLAINTEXT, SASL_PLAINTEXT, SASL_SSL

        \\p conf dict is passed to KafkaBrokerApp classes, etc.
        """

        super(LibrdkafkaTestCluster, self).__init__(
            self.__class__.__name__,
            os.environ.get('TRIVUP_ROOT', 'tmp'), debug=debug)

        # Read trivup config from scenario definition.
        defconf = read_scenario_conf(scenario)
        defconf.update(conf)

        # Enable SSL if desired
        if 'SSL' in conf.get('security.protocol', ''):
            self.ssl = SslApp(self, defconf)

        self.brokers = list()

        # One ZK (from Kafka repo)
        ZookeeperApp(self)

        # Start Kerberos KDC if GSSAPI (Kerberos) is configured
        if 'GSSAPI' in defconf.get('sasl_mechanisms', []):
            kdc = KerberosKdcApp(self, 'MYREALM')
            # Kerberos needs to be started prior to Kafka so that principals
            # and keytabs are available at the time of Kafka config generation.
            kdc.start()

        if 'OAUTHBEARER'.casefold() == \
            defconf.get('sasl_mechanisms', "").casefold() and \
                'OIDC'.casefold() == \
                defconf.get('sasl_oauthbearer_method', "").casefold():
            self.oidc = OauthbearerOIDCApp(self)

        # Brokers
        defconf.update({'replication_factor': min(num_brokers, 3),
                        'version': version,
                        'security.protocol': 'PLAINTEXT'})
        self.conf = defconf

        for n in range(0, num_brokers):
            # Configure rack & replica selector if broker supports
            # fetch-from-follower
            if version_as_list(version) >= [2, 4, 0]:
                defconf.update(
                    {
                        'conf': [
                            'broker.rack=RACK${appid}',
                            'replica.selector.class=org.apache.kafka.common.replica.RackAwareReplicaSelector']})  # noqa: E501
            self.brokers.append(KafkaBrokerApp(self, defconf))

    def bootstrap_servers(self):
        """ @return Kafka bootstrap servers based on security.protocol """
        all_listeners = (
            ','.join(
                self.get_all(
                    'advertised_listeners',
                    '',
                    KafkaBrokerApp))).split(',')
        return ','.join([x for x in all_listeners if x.startswith(
            self.conf.get('security.protocol'))])


def result2color(res):
    if res == 'PASSED':
        return '\033[42m'
    elif res == 'FAILED':
        return '\033[41m'
    else:
        return ''


def print_test_report_summary(name, report):
    """ Print summary for a test run. """
    passed = report.get('PASSED', False)
    if passed:
        resstr = '\033[42mPASSED\033[0m'
    else:
        resstr = '\033[41mFAILED\033[0m'

    print('%6s  %-50s: %s' % (resstr, name, report.get('REASON', 'n/a')))
    if not passed:
        # Print test details
        for name, test in report.get('tests', {}).items():
            testres = test.get('state', '')
            if testres == 'SKIPPED':
                continue
            print('%s   --> %-20s \033[0m' %
                  ('%s%s\033[0m' %
                   (result2color(test.get('state', 'n/a')),
                    test.get('state', 'n/a')),
                   test.get('name', 'n/a')))
        print('%8s --> %s/%s' %
              ('', report.get('root_path', '.'), 'stderr.log'))


def print_report_summary(fullreport):
    """ Print summary from a full report suite """
    suites = fullreport.get('suites', list())
    print('#### Full test suite report (%d suite(s))' % len(suites))
    for suite in suites:
        for version, report in suite.get('version', {}).items():
            print_test_report_summary('%s @ %s' %
                                      (suite.get('name', 'n/a'), version),
                                      report)

    pass_cnt = fullreport.get('pass_cnt', -1)
    if pass_cnt == 0:
        pass_clr = ''
    else:
        pass_clr = '\033[42m'

    fail_cnt = fullreport.get('fail_cnt', -1)
    if fail_cnt == 0:
        fail_clr = ''
    else:
        fail_clr = '\033[41m'

    print('#### %d suites %sPASSED\033[0m, %d suites %sFAILED\033[0m' %
          (pass_cnt, pass_clr, fail_cnt, fail_clr))


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Show test suite report')
    parser.add_argument('report', type=str, nargs=1,
                        help='Show summary from test suites report file')

    args = parser.parse_args()

    passed = False
    with open(args.report[0], 'r') as f:
        passed = print_report_summary(json.load(f))

    if passed:
        sys.exit(0)
    else:
        sys.exit(1)
