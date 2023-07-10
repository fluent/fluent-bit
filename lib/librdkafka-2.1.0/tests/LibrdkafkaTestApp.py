#!/usr/bin/env python3
#
# librdkafka test trivup app module
#
# Requires:
#  trivup python module
#  gradle in your PATH

from trivup.trivup import App, UuidAllocator
from trivup.apps.ZookeeperApp import ZookeeperApp
from trivup.apps.KafkaBrokerApp import KafkaBrokerApp
from trivup.apps.KerberosKdcApp import KerberosKdcApp
from trivup.apps.OauthbearerOIDCApp import OauthbearerOIDCApp

import json


class LibrdkafkaTestApp(App):
    """ Sets up and executes the librdkafka regression tests.
        Assumes tests are in the current directory.
        Must be instantiated after ZookeeperApp and KafkaBrokerApp """

    def __init__(self, cluster, version, conf=None,
                 tests=None, scenario="default"):
        super(LibrdkafkaTestApp, self).__init__(cluster, conf=conf)

        self.appid = UuidAllocator(self.cluster).next(self, trunc=8)
        self.autostart = False
        self.local_tests = True
        self.test_mode = conf.get('test_mode', 'bare')
        self.version = version

        # Generate test config file
        conf_blob = list()
        self.security_protocol = 'PLAINTEXT'

        f, self.test_conf_file = self.open_file('test.conf', 'perm')
        f.write('broker.address.family=v4\n'.encode('ascii'))
        f.write(('test.sql.command=sqlite3 rdktests\n').encode('ascii'))
        f.write('test.timeout.multiplier=2\n'.encode('ascii'))

        sparse = conf.get('sparse_connections', None)
        if sparse is not None:
            f.write('enable.sparse.connections={}\n'.format(
                sparse).encode('ascii'))

        if version.startswith('0.9') or version.startswith('0.8'):
            conf_blob.append('api.version.request=false')
            conf_blob.append('broker.version.fallback=%s' % version)
        else:
            # any broker version with ApiVersion support
            conf_blob.append('broker.version.fallback=0.10.0.0')
            conf_blob.append('api.version.fallback.ms=0')

        # SASL (only one mechanism supported at a time)
        mech = self.conf.get('sasl_mechanisms', '').split(',')[0]
        if mech != '':
            conf_blob.append('sasl.mechanisms=%s' % mech)
            if mech == 'PLAIN' or mech.find('SCRAM-') != -1:
                self.security_protocol = 'SASL_PLAINTEXT'
                # Use first user as SASL user/pass
                for up in self.conf.get('sasl_users', '').split(','):
                    u, p = up.split('=')
                    conf_blob.append('sasl.username=%s' % u)
                    conf_blob.append('sasl.password=%s' % p)
                    break

            elif mech == 'OAUTHBEARER':
                self.security_protocol = 'SASL_PLAINTEXT'
                oidc = cluster.find_app(OauthbearerOIDCApp)
                if oidc is not None:
                    conf_blob.append('sasl.oauthbearer.method=%s\n' %
                                     oidc.conf.get('sasl_oauthbearer_method'))
                    conf_blob.append('sasl.oauthbearer.client.id=%s\n' %
                                     oidc.conf.get(
                                         'sasl_oauthbearer_client_id'))
                    conf_blob.append('sasl.oauthbearer.client.secret=%s\n' %
                                     oidc.conf.get(
                                         'sasl_oauthbearer_client_secret'))
                    conf_blob.append('sasl.oauthbearer.extensions=%s\n' %
                                     oidc.conf.get(
                                         'sasl_oauthbearer_extensions'))
                    conf_blob.append('sasl.oauthbearer.scope=%s\n' %
                                     oidc.conf.get('sasl_oauthbearer_scope'))
                    conf_blob.append('sasl.oauthbearer.token.endpoint.url=%s\n'
                                     % oidc.conf.get('valid_url'))
                    self.env_add('VALID_OIDC_URL', oidc.conf.get('valid_url'))
                    self.env_add(
                        'INVALID_OIDC_URL',
                        oidc.conf.get('badformat_url'))
                    self.env_add(
                        'EXPIRED_TOKEN_OIDC_URL',
                        oidc.conf.get('expired_url'))
                else:
                    conf_blob.append(
                        'enable.sasl.oauthbearer.unsecure.jwt=true\n')
                    conf_blob.append(
                        'sasl.oauthbearer.config=%s\n' %
                        self.conf.get('sasl_oauthbearer_config'))

            elif mech == 'GSSAPI':
                self.security_protocol = 'SASL_PLAINTEXT'
                kdc = cluster.find_app(KerberosKdcApp)
                if kdc is None:
                    self.log(
                        'WARNING: sasl_mechanisms is GSSAPI set but no '
                        'KerberosKdcApp available: client SASL config will '
                        'be invalid (which might be intentional)')
                else:
                    self.env_add('KRB5_CONFIG', kdc.conf['krb5_conf'])
                    self.env_add('KRB5_KDC_PROFILE', kdc.conf['kdc_conf'])
                    principal, keytab = kdc.add_principal(
                        self.name,
                        conf.get('advertised_hostname', self.node.name))
                    conf_blob.append('sasl.kerberos.service.name=%s' %
                                     self.conf.get('sasl_servicename',
                                                   'kafka'))
                    conf_blob.append('sasl.kerberos.keytab=%s' % keytab)
                    conf_blob.append(
                        'sasl.kerberos.principal=%s' %
                        principal.split('@')[0])

            else:
                self.log(
                    'WARNING: FIXME: SASL %s client config not written to %s: unhandled mechanism' %  # noqa: E501
                    (mech, self.test_conf_file))

        # SSL config
        if getattr(cluster, 'ssl', None) is not None:
            ssl = cluster.ssl

            key = ssl.create_cert('librdkafka%s' % self.appid)

            conf_blob.append('ssl.ca.location=%s' % ssl.ca['pem'])
            conf_blob.append('ssl.certificate.location=%s' % key['pub']['pem'])
            conf_blob.append('ssl.key.location=%s' % key['priv']['pem'])
            conf_blob.append('ssl.key.password=%s' % key['password'])

            # Some tests need fine-grained access to various cert files,
            # set up the env vars accordingly.
            for k, v in ssl.ca.items():
                self.env_add('SSL_ca_{}'.format(k), v)

            # Set envs for all generated keys so tests can find them.
            for k, v in key.items():
                if isinstance(v, dict):
                    for k2, v2 in v.items():
                        # E.g. "SSL_priv_der=path/to/librdkafka-priv.der"
                        self.env_add('SSL_{}_{}'.format(k, k2), v2)
                else:
                    self.env_add('SSL_{}'.format(k), v)

            if 'SASL' in self.security_protocol:
                self.security_protocol = 'SASL_SSL'
            else:
                self.security_protocol = 'SSL'

        # Define bootstrap brokers based on selected security protocol
        self.dbg('Using client security.protocol=%s' % self.security_protocol)
        all_listeners = (
            ','.join(
                cluster.get_all(
                    'advertised.listeners',
                    '',
                    KafkaBrokerApp))).split(',')
        bootstrap_servers = ','.join(
            [x for x in all_listeners if x.startswith(self.security_protocol)])
        if len(bootstrap_servers) == 0:
            bootstrap_servers = all_listeners[0]
            self.log(
                'WARNING: No eligible listeners for security.protocol=%s in %s: falling back to first listener: %s: tests will fail (which might be the intention)' %  # noqa: E501
                (self.security_protocol, all_listeners, bootstrap_servers))

        self.bootstrap_servers = bootstrap_servers

        conf_blob.append('bootstrap.servers=%s' % bootstrap_servers)
        conf_blob.append('security.protocol=%s' % self.security_protocol)

        f.write(('\n'.join(conf_blob)).encode('ascii'))
        f.close()

        self.env_add('TEST_SCENARIO', scenario)
        self.env_add('RDKAFKA_TEST_CONF', self.test_conf_file)
        self.env_add('TEST_KAFKA_VERSION', version)
        self.env_add('TRIVUP_ROOT', cluster.instance_path())

        if self.test_mode != 'bash':
            self.test_report_file = self.mkpath('test_report', pathtype='perm')
            self.env_add('TEST_REPORT', self.test_report_file)

            if tests is not None:
                self.env_add('TESTS', ','.join(tests))

    def start_cmd(self):
        self.env_add(
            'KAFKA_PATH',
            self.cluster.get_all(
                'destdir',
                '',
                KafkaBrokerApp)[0],
            False)
        self.env_add(
            'ZK_ADDRESS',
            self.cluster.get_all(
                'address',
                '',
                ZookeeperApp)[0],
            False)
        self.env_add('BROKERS', self.cluster.bootstrap_servers(), False)

        # Provide a HTTPS REST endpoint for the HTTP client tests.
        self.env_add(
            'RD_UT_HTTP_URL',
            'https://jsonplaceholder.typicode.com/users')

        # Per broker env vars
        for b in [x for x in self.cluster.apps if isinstance(
                x, KafkaBrokerApp)]:
            self.env_add('BROKER_ADDRESS_%d' % b.appid,
                         ','.join([x for x in
                                   b.conf['listeners'].split(',')
                                   if x.startswith(self.security_protocol)]))
            # Add each broker pid as an env so they can be killed
            # indivdidually.
            self.env_add('BROKER_PID_%d' % b.appid, str(b.proc.pid))
            # JMX port, if available
            jmx_port = b.conf.get('jmx_port', None)
            if jmx_port is not None:
                self.env_add('BROKER_JMX_PORT_%d' % b.appid, str(jmx_port))

        extra_args = list()
        if not self.local_tests:
            extra_args.append('-L')
        if self.conf.get('args', None) is not None:
            extra_args.append(self.conf.get('args'))
        extra_args.append('-E')
        return './run-test.sh -p%d -K %s %s' % (
            int(self.conf.get('parallel', 5)), ' '.join(extra_args),
            self.test_mode)

    def report(self):
        if self.test_mode == 'bash':
            return None

        try:
            with open(self.test_report_file, 'r') as f:
                res = json.load(f)
        except Exception as e:
            self.log(
                'Failed to read report %s: %s' %
                (self.test_report_file, str(e)))
            return {'root_path': self.root_path(), 'error': str(e)}
        return res

    def deploy(self):
        pass
