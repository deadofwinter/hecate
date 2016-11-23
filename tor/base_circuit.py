import datetime
import subprocess
import random
import urllib.request
import socket
import time

import socks
import stem
import stem.process
import stem.control

class BaseCircuit():
    """Class for controlling a TOR circuit

    A Circuit is the entire path through the TOR network.  Provides
    functionality to change the identity, check the latency of the
    circuit and configure follow on anonymization services.

    Args:
        socks_port: The local port for the TOR SOCKS5 proxy
        control_port: The local port open to control TOR.  Will be
            configured with a password
        data_dir: Directory for TOR to save it's data files
        exclude_nodes: list of countries to avoid traversing.  Relies
            on a given TOR node to publish its location so not
            guaranteed
        exclude_exits: list of countries to avoid exiting in.  Relies
            on a given TOR node to publish its location so not
            guaranteed
        exit_nodes: list of countries to only exit in.  Relies on a
            given TOR node to publish its location so not guranteed.
        entry_nodes: list of countries to enter the TOR network
            through. Relies on a given TOR node to publish its location
             so not guaranteed.
        trans_ip: The local IP Address for TOR to listen on if
            functioning as a transparent proxy.
        trans_port: The local port for TOR to listen on if functioning
            as a transparent proxy
        verbose: Turn verbose output on or off
    """
    def __init__(self, socks_port = 9050, control_port = 9051,
                 listen_ip = '127.0.0.1', data_dir = False,
                 exclude_nodes = [], exclude_exits = [],
                 exit_nodes = [], entry_nodes = [],
                 trans_ip = False, trans_port = False,
                 verbose = False):

        self.verbose = verbose
        self.listen_port = socks_port
        self.control_port = control_port

        #Create tor configuration
        self.tor_config = {
            'SocksPort': '%s:%s' % (listen_ip, socks_port),
            'ControlPort': '%s' % control_port,
        }

        self.add_to_config('DataDir', data_dir)

        self.add_to_config('ExcludeNodes', exclude_nodes)
        if exclude_nodes:
            self.tor_config['StrictNodes'] = '0'

        self.add_to_config('ExcludeExits', exclude_exits)
        self.add_to_config('ExitNodes', exit_nodes)
        self.add_to_config('EntryNodes', entry_nodes)

        if trans_ip and trans_port:
            self.tor_config['TransPort'] = '%s:%s' % (trans_ip, trans_port)

        self.control_passwd = self.gen_passwd()
        self.tor_config['HashedControlPassword'] = self.get_hash(self.control_passwd)

        self.proc = stem.process.launch_tor_with_config(
            self.tor_config,
            init_msg_handler = self._log,
            take_ownership = True)

        self.controller = stem.control.Controller.from_port(port = self.control_port)
        self.controller.authenticate(self.control_passwd)

    def add_to_config(self, key, value):
        """Add a key, value pair to tor_config if value is supplied

        Add a key,value pair to self.tor_config.  Ensures value is a
        string.
        """
        if value:
            if value is list:
                self.tor_config[key] = ','.join(value)
            else:
                self.tor_config[key] = str(value)

    def gen_passwd(self):
        """Generates a 20 character alphanumeric password

        Returns:
            A 20 character pseudoranom alphanumeric string
        """
        chars = ('abcdefghijklmnopqrstuvwxyz',
                 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456890')
        return ''.join(random.choice(chars) for _ in range(20))

    def get_hash(self, passwd):
        """Gets the tor hashed password for a provided String

        Returns:
            A string containing the correct hash value for a TOR
            password.
        """
        return subprocess.getoutput('tor --hash-password %s' % passwd)

    def change_identity(self):
        """Get a new exit IP Address

        Force the Circuit to get a new exit IP.  Utilizes either the
        NEWNYM signal built into TOR or forcibly closes all currently
        open circuits and reopens them

        Returns:
            True if the IP Address has changed
        """
        start = self.get_exit_ip()

        self.controller.authenticate(self.control_passwd)

        if self.controller.is_newnym_available():
            self.controller.signal(stem.Signal.NEWNYM)
        else:
           for c in self.controller.get_circuits():
               self.controller.close(c)

        end = self.get_exit_ip()

        return start != end

    def check_latency(self):
        """Retrieve a relative measure of Circuit Latency

        Latency is measured as the time required to check the Circuit's
        external IP Address.

        Returns:
            Float of the time
        """
        start = time.time()
        self.get_exit_ip()
        return time.time() - start

    def get_exit_ip(self):
        """Gets the exit IP Address for the Circuit

        Utilizes http://icanhazip.com and requires patching the socket
        module.

        Returns:
            A string containing the ip address
        """
        socks.set_default_proxy(socks.SOCKS5, "localhost", self.listen_port)
        socket.socket = socks.socksocket
        r = urllib.request.urlopen('http://icanhazip.com')
        return str(r.read()).strip()

    def _err(self, msg):
        print('[!!] %s %s' % (self._now(), msg))

    def _log(self, msg):
        if self.verbose:
            print('%s %s' % (self._now(), msg))

    def _alert(self, msg):
        print('[*] %s %s' % (self._now(), msg))

    def _now(self):
        return '{:%H:%M:%S}'.format(datetime.datetime.now())