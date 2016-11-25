from .base_circuit import BaseCircuit

class TransparentTorTunnel(BaseCircuit):
    """Create a tunnel across TOR as a transparent proxy for network
    traffic.

    Args:
        listen_ip: the IP address to listen on.
        listen_port: The port the SOCKS5 proxy will listen on.
            Default is 9040.
        control_port_offset: the control port will be
            control_port_offset higher than the listen_port. Default is
            100.
        exclude_nodes: list of countries to avoid traversing.  Relies
            on a given TOR node to publish its location so not
            guaranteed. Default is None
        exclude_exits: list of countries to avoid exiting in.  Relies
            on a given TOR node to publish its location so not
            guaranteed. Default is None.
        exit_nodes: list of countries to only exit in.  Relies on a
            given TOR node to publish its location so not guranteed.
            Default is None.
        entry_nodes: list of countries to enter the TOR network.
            through. Relies on a given TOR node to publish its location
             so not guaranteed. Default is None.
        verbose: Turn verbose output on or off.  Default is off (False)
    """

    def __init__(self, listen_ip='127.0.0.1', listen_port=9040,
                 control_port_offset=100, exclude_nodes = None,
                 exclude_exits=None, exit_nodes=None, entry_nodes=None,
                 verbose=False):

            super().__init__(
                trans_ip = listen_ip,
                trans_port = listen_port,
                socks_ip = None,
                socks_port = None,
                control_port = listen_port + control_port_offset,
                exclude_nodes = exclude_nodes,
                exclude_exits = exclude_exits,
                exit_nodes = exit_nodes,
                entry_nodes = entry_nodes,
                verbose = verbose)
