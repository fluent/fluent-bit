#!/usr/bin/env python3
#
#
# Run librdkafka regression tests on different supported broker versions.
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

from cluster_testing import read_scenario_conf

import subprocess
import tempfile
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
                 root_path='tmp', broker_cnt=3, scenario='default'):
    """
    @brief Create, deploy and start a Kafka cluster using Kafka \\p version
    Then run librdkafka's regression tests.
    """

    print('## Test version %s' % version)

    cluster = Cluster('LibrdkafkaTestCluster', root_path, debug=debug)

    if conf.get('sasl_oauthbearer_method') == 'OIDC':
        oidc = OauthbearerOIDCApp(cluster)

    # Enable SSL if desired
    if 'SSL' in conf.get('security.protocol', ''):
        cluster.ssl = SslApp(cluster, conf)

    # One ZK (from Kafka repo)
    zk1 = ZookeeperApp(cluster)
    zk_address = zk1.get('address')

    # Start Kerberos KDC if GSSAPI is configured
    if 'GSSAPI' in args.conf.get('sasl_mechanisms', []):
        KerberosKdcApp(cluster, 'MYREALM').start()

    defconf = {'version': version}
    defconf.update(conf)

    print('conf: ', defconf)

    brokers = []
    for n in range(0, broker_cnt):
        # Configure rack & replica selector if broker supports
        # fetch-from-follower
        if version_as_number(version) >= 2.4:
            curr_conf = defconf.get('conf', list())
            defconf.update(
                {
                    'conf': [
                        'broker.rack=RACK${appid}',
                        'replica.selector.class=org.apache.kafka.common.replica.RackAwareReplicaSelector'] + curr_conf})  # noqa: E501
            print('conf broker', str(n), ': ', defconf)
        brokers.append(KafkaBrokerApp(cluster, defconf))

    cmd_env = os.environ.copy()

    # Generate test config file
    security_protocol = 'PLAINTEXT'
    fd, test_conf_file = tempfile.mkstemp(prefix='test_conf', text=True)
    os.write(fd, ('test.sql.command=sqlite3 rdktests\n').encode('ascii'))
    os.write(fd, 'broker.address.family=v4\n'.encode('ascii'))
    if version.startswith('0.9') or version.startswith('0.8'):
        os.write(fd, 'api.version.request=false\n'.encode('ascii'))
        os.write(
            fd, ('broker.version.fallback=%s\n' %
                 version).encode('ascii'))
    # SASL (only one mechanism supported)
    mech = defconf.get('sasl_mechanisms', '').split(',')[0]
    if mech != '':
        os.write(fd, ('sasl.mechanisms=%s\n' % mech).encode('ascii'))
        if mech == 'PLAIN' or mech.find('SCRAM') != -1:
            print(
                '# Writing SASL %s client config to %s' %
                (mech, test_conf_file))
            security_protocol = 'SASL_PLAINTEXT'
            # Use first user as SASL user/pass
            for up in defconf.get('sasl_users', '').split(','):
                u, p = up.split('=')
                os.write(fd, ('sasl.username=%s\n' % u).encode('ascii'))
                os.write(fd, ('sasl.password=%s\n' % p).encode('ascii'))
                break
        elif mech == 'OAUTHBEARER':
            security_protocol = 'SASL_PLAINTEXT'
            if defconf.get('sasl_oauthbearer_method') == 'OIDC':
                os.write(
                    fd, ('sasl.oauthbearer.method=OIDC\n'.encode(
                         'ascii')))
                os.write(
                    fd, ('sasl.oauthbearer.client.id=123\n'.encode(
                         'ascii')))
                os.write(
                    fd, ('sasl.oauthbearer.client.secret=abc\n'.encode(
                         'ascii')))
                os.write(
                    fd, ('sasl.oauthbearer.extensions=\
                         ExtensionworkloadIdentity=develC348S,\
                         Extensioncluster=lkc123\n'.encode(
                         'ascii')))
                os.write(
                    fd, ('sasl.oauthbearer.scope=test\n'.encode(
                         'ascii')))
                cmd_env['VALID_OIDC_URL'] = oidc.conf.get('valid_url')
                cmd_env['INVALID_OIDC_URL'] = oidc.conf.get('badformat_url')
                cmd_env['EXPIRED_TOKEN_OIDC_URL'] = oidc.conf.get(
                    'expired_url')

            else:
                os.write(
                    fd, ('enable.sasl.oauthbearer.unsecure.jwt=true\n'.encode(
                         'ascii')))
                os.write(fd, ('sasl.oauthbearer.config=%s\n' %
                         'scope=requiredScope principal=admin').encode(
                         'ascii'))
        else:
            print(
                '# FIXME: SASL %s client config not written to %s' %
                (mech, test_conf_file))

    # SSL support
    ssl = getattr(cluster, 'ssl', None)
    if ssl is not None:
        if 'SASL' in security_protocol:
            security_protocol = 'SASL_SSL'
        else:
            security_protocol = 'SSL'

        key = ssl.create_cert('librdkafka')

        os.write(fd, ('ssl.ca.location=%s\n' % ssl.ca['pem']).encode('ascii'))
        os.write(fd, ('ssl.certificate.location=%s\n' %
                 key['pub']['pem']).encode('ascii'))
        os.write(
            fd, ('ssl.key.location=%s\n' %
                 key['priv']['pem']).encode('ascii'))
        os.write(
            fd, ('ssl.key.password=%s\n' %
                 key['password']).encode('ascii'))

        for k, v in ssl.ca.items():
            cmd_env['SSL_ca_{}'.format(k)] = v

        # Set envs for all generated keys so tests can find them.
        for k, v in key.items():
            if isinstance(v, dict):
                for k2, v2 in v.items():
                    # E.g. "SSL_priv_der=path/to/librdkafka-priv.der"
                    cmd_env['SSL_{}_{}'.format(k, k2)] = v2
            else:
                cmd_env['SSL_{}'.format(k)] = v

    # Define bootstrap brokers based on selected security protocol
    print('# Using client security.protocol=%s' % security_protocol)
    all_listeners = (
        ','.join(
            cluster.get_all(
                'listeners',
                '',
                KafkaBrokerApp))).split(',')
    bootstrap_servers = ','.join(
        [x for x in all_listeners if x.startswith(security_protocol)])
    os.write(fd, ('bootstrap.servers=%s\n' %
             bootstrap_servers).encode('ascii'))
    os.write(fd, ('security.protocol=%s\n' %
             security_protocol).encode('ascii'))
    os.close(fd)

    if deploy:
        print('# Deploying cluster')
        cluster.deploy()
    else:
        print('# Not deploying')

    print('# Starting cluster, instance path %s' % cluster.instance_path())
    cluster.start()

    print('# Waiting for brokers to come up')

    if not cluster.wait_operational(30):
        cluster.stop(force=True)
        raise Exception('Cluster %s did not go operational, see logs in %s/%s' %  # noqa: E501
                        (cluster.name, cluster.root_path, cluster.instance))

    print('# Connect to cluster with bootstrap.servers %s' % bootstrap_servers)

    cmd_env['KAFKA_PATH'] = brokers[0].conf.get('destdir')
    cmd_env['RDKAFKA_TEST_CONF'] = test_conf_file
    cmd_env['ZK_ADDRESS'] = zk_address
    cmd_env['BROKERS'] = bootstrap_servers
    cmd_env['TEST_KAFKA_VERSION'] = version
    cmd_env['TRIVUP_ROOT'] = cluster.instance_path()
    cmd_env['TEST_SCENARIO'] = scenario

    # Provide a HTTPS REST endpoint for the HTTP client tests.
    cmd_env['RD_UT_HTTP_URL'] = 'https://jsonplaceholder.typicode.com/users'

    # Per broker env vars
    for b in [x for x in cluster.apps if isinstance(x, KafkaBrokerApp)]:
        cmd_env['BROKER_ADDRESS_%d' % b.appid] = \
            ','.join([x for x in b.conf['listeners'].split(
                ',') if x.startswith(security_protocol)])
        # Add each broker pid as an env so they can be killed indivdidually.
        cmd_env['BROKER_PID_%d' % b.appid] = str(b.proc.pid)
        # JMX port, if available
        jmx_port = b.conf.get('jmx_port', None)
        if jmx_port is not None:
            cmd_env['BROKER_JMX_PORT_%d' % b.appid] = str(jmx_port)

    if not cmd:
        cmd_env['PS1'] = '[TRIVUP:%s@%s] \\u@\\h:\\w$ ' % (
            cluster.name, version)
        cmd = 'bash --rcfile <(cat ~/.bashrc)'

    ret = True

    for i in range(0, exec_cnt):
        retcode = subprocess.call(
            cmd,
            env=cmd_env,
            shell=True,
            executable='/bin/bash')
        if retcode != 0:
            print('# Command failed with returncode %d: %s' % (retcode, cmd))
            ret = False

    try:
        os.remove(test_conf_file)
    except BaseException:
        pass

    cluster.stop(force=True)

    cluster.cleanup(keeptypes=['log'])
    return ret


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
                         scenario=args.scenario)
        if not r:
            retcode = 2

    sys.exit(retcode)
