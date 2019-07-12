#!/usr/bin/env python
#
# librdkafka test trivup app module
#
# Requires:
#  trivup python module
#  gradle in your PATH

from trivup.trivup import Cluster, App, UuidAllocator
from trivup.apps.ZookeeperApp import ZookeeperApp
from trivup.apps.KafkaBrokerApp import KafkaBrokerApp
from trivup.apps.KerberosKdcApp import KerberosKdcApp

import json
import subprocess


class LibrdkafkaTestApp(App):
    """ Sets up and executes the librdkafka regression tests.
        Assumes tests are in the current directory.
        Must be instantiated after ZookeeperApp and KafkaBrokerApp """
    def __init__(self, cluster, version, conf=None, tests=None):
        super(LibrdkafkaTestApp, self).__init__(cluster, conf=conf)

        self.appid = UuidAllocator(self.cluster).next(self, trunc=8)
        self.autostart = False
        self.local_tests = True
        self.test_mode = conf.get('test_mode', 'bare')
        self.version = version

        # Generate test config file
        conf_blob = list()
        security_protocol='PLAINTEXT'

        f, self.test_conf_file = self.open_file('test.conf', 'perm')
        f.write('broker.address.family=v4\n'.encode('ascii'))
        f.write(('test.sql.command=sqlite3 rdktests\n').encode('ascii'))
        f.write('test.timeout.multiplier=2\n'.encode('ascii'))
        f.write(('\n'.join(conf_blob)).encode('ascii'))

        if version.startswith('0.9') or version.startswith('0.8'):
            conf_blob.append('api.version.request=false')
            conf_blob.append('broker.version.fallback=%s' % version)
        else:
            conf_blob.append('broker.version.fallback=0.10.0.0') # any broker version with ApiVersion support
            conf_blob.append('api.version.fallback.ms=0')

        # SASL (only one mechanism supported at a time)
        mech = self.conf.get('sasl_mechanisms', '').split(',')[0]
        if mech != '':
            conf_blob.append('sasl.mechanisms=%s' % mech)
            if mech == 'PLAIN' or mech.find('SCRAM-') != -1:
                security_protocol='SASL_PLAINTEXT'
                # Use first user as SASL user/pass
                for up in self.conf.get('sasl_users', '').split(','):
                    u,p = up.split('=')
                    conf_blob.append('sasl.username=%s' % u)
                    conf_blob.append('sasl.password=%s' % p)
                    break

            elif mech == 'GSSAPI':
                security_protocol='SASL_PLAINTEXT'
                kdc = cluster.find_app(KerberosKdcApp)
                if kdc is None:
                    self.log('WARNING: sasl_mechanisms is GSSAPI set but no KerberosKdcApp available: client SASL config will be invalid (which might be intentional)')
                else:
                    self.env_add('KRB5_CONFIG', kdc.conf['krb5_conf'])
                    self.env_add('KRB5_KDC_PROFILE', kdc.conf['kdc_conf'])
                    principal,keytab = kdc.add_principal(self.name,
                                                         conf.get('advertised_hostname', self.node.name))
                    conf_blob.append('sasl.kerberos.service.name=%s' % \
                                     self.conf.get('sasl_servicename', 'kafka'))
                    conf_blob.append('sasl.kerberos.keytab=%s' % keytab)
                    conf_blob.append('sasl.kerberos.principal=%s' % principal.split('@')[0])

            else:
                self.log('WARNING: FIXME: SASL %s client config not written to %s: unhandled mechanism' % (mech, self.test_conf_file))

        # SSL config
        if getattr(cluster, 'ssl', None) is not None:
            ssl = cluster.ssl

            key, req, pem = ssl.create_key('librdkafka%s' % self.appid)

            conf_blob.append('ssl.ca.location=%s' % ssl.ca_cert)
            conf_blob.append('ssl.certificate.location=%s' % pem)
            conf_blob.append('ssl.key.location=%s' % key)
            conf_blob.append('ssl.key.password=%s' % ssl.conf.get('ssl_key_pass'))

            if 'SASL' in security_protocol:
                security_protocol = 'SASL_SSL'
            else:
                security_protocol = 'SSL'

        # Define bootstrap brokers based on selected security protocol
        self.dbg('Using client security.protocol=%s' % security_protocol)
        all_listeners = (','.join(cluster.get_all('advertised.listeners', '', KafkaBrokerApp))).split(',')
        bootstrap_servers = ','.join([x for x in all_listeners if x.startswith(security_protocol)])
        if len(bootstrap_servers) == 0:
            bootstrap_servers = all_listeners[0]
            self.log('WARNING: No eligible listeners for security.protocol=%s in %s: falling back to first listener: %s: tests will fail (which might be the intention)' % (security_protocol, all_listeners, bootstrap_servers))

        self.bootstrap_servers = bootstrap_servers

        conf_blob.append('bootstrap.servers=%s' % bootstrap_servers)
        conf_blob.append('security.protocol=%s' % security_protocol)

        f.write(('\n'.join(conf_blob)).encode('ascii'))
        f.close()

        self.env_add('RDKAFKA_TEST_CONF', self.test_conf_file)
        self.env_add('TEST_KAFKA_VERSION', version)
        self.env_add('TRIVUP_ROOT', cluster.instance_path())

        if self.test_mode != 'bash':
            self.test_report_file = self.mkpath('test_report', pathtype='perm')
            self.env_add('TEST_REPORT', self.test_report_file)

            if tests is not None:
                self.env_add('TESTS', ','.join(tests))

    def start_cmd (self):
        self.env_add('KAFKA_PATH', self.cluster.get_all('destdir', '', KafkaBrokerApp)[0], False)
        self.env_add('ZK_ADDRESS', self.cluster.get_all('address', '', ZookeeperApp)[0], False)
        self.env_add('BROKERS', self.cluster.bootstrap_servers(), False)

        extra_args = list()
        if not self.local_tests:
            extra_args.append('-L')
        extra_args.append('-E')
        return './run-test.sh -p%d -K %s ./merged %s' % (int(self.conf.get('parallel', 5)), ' '.join(extra_args), self.test_mode)


    def report (self):
        if self.test_mode == 'bash':
            return None

        try:
            with open(self.test_report_file, 'r') as f:
                res = json.load(f)
        except Exception as e:
            self.log('Failed to read report %s: %s' % (self.test_report_file, str(e)))
            return {'root_path': self.root_path(), 'error': str(e)}
        return res

    def deploy (self):
        pass
