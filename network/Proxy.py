import logging
import socket
import threading

from enumerators.ProxyMode import ProxyMode
from network.ConnectionHandler import ConnectionHandler
from network.NetworkAddress import NetworkAddress
from network.WrappedSocket import WrappedSocket
from util.constants import TLS_1_0_HEADER, TLS_1_2_HEADER, TLS_1_1_HEADER, STANDARD_SOCKET_RECEIVE_SIZE


class Proxy:
    """
    Proxy server
    """

    def __init__(self, address: NetworkAddress,
                 timeout: int = 120,
                 record_frag: bool = False,
                 tcp_frag: bool = False,
                 frag_size: int = 20,
                 dot_ip: str = "8.8.4.4",
                 disabled_modes: list[ProxyMode] = None,
                 forward_proxy: NetworkAddress = None,
                 forward_proxy_mode: ProxyMode = ProxyMode.HTTPS,
                 forward_proxy_resolve_address: bool = False):
        # timeout for socket reads and message reception
        self.timeout = timeout
        # own port
        self.address = address
        # record fragmentation settings
        self.record_frag = record_frag
        self.tcp_frag = tcp_frag
        self.frag_size = frag_size
        # whether to use dot for domain resolution
        self.dot_ip = dot_ip
        self.disabled_modes = disabled_modes
        if self.disabled_modes is None:
            self.disabled_modes = []
        # settings for another proxy to contact further down the line
        self.forward_proxy = forward_proxy
        self.forward_proxy_mode = forward_proxy_mode
        self.forward_proxy_resolve_address = forward_proxy_resolve_address
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # TODO: replace with correct forwarding that cancels both sockets if one does
    def forward(self, from_socket: WrappedSocket, to_socket: WrappedSocket, direction: str, record_frag=False):
        """
        Forwards data between two sockets with optional record fragmentation. Falls back to forwarding if no TLS records
        can be parsed from the connection anymore.
        :param to_socket: Socket to receive data from.
        :param from_socket: Socket to forward data to.
        :param record_frag: Whether to fragment handshake records
        :param direction: Direction of the connection
        :return: None
        """
        try:
            while True:
                if not record_frag:
                    data = from_socket.recv(STANDARD_SOCKET_RECEIVE_SIZE)
                    if not data:
                        Proxy.debug("Connection closed, closing both sockets", direction)
                        to_socket.try_close()
                        break
                    else:
                        to_socket.send(data)
                else:
                    try:
                        record_header = from_socket.peek(5)
                    except:
                        Proxy.debug("Could not read record_header bytes. Disabling record fragmentation", direction)
                        record_frag = False
                        continue
                    base_header = record_header[:3]
                    record_len = int.from_bytes(record_header[3:], byteorder='big')
                    is_tls = base_header == TLS_1_0_HEADER or base_header == TLS_1_1_HEADER \
                             or base_header == TLS_1_2_HEADER
                    if not is_tls:
                        Proxy.debug(f"Received first non-handshake TLS record header: {record_header}. Turning off "
                                    f"TLS record fragmentation for this and following records", direction)
                        # did not receive tls record
                        record_frag = False
                        continue
                    else:
                        Proxy.debug("Received TLS handshake record - fragmenting", direction)
                    try:
                        record = from_socket.read(5 + record_len)[5:]
                    except:
                        Proxy.debug(f"Could not read {record_len} record bytes. Disabling record fragmentation",
                                    direction)
                        record_frag = False
                        continue
                    fragments = [record[i:i + self.frag_size] for i in range(0, record_len, self.frag_size)]
                    fragmented_message = b''
                    for fragment in fragments:
                        # construct header
                        fragmented_message += base_header + int.to_bytes(len(fragment), byteorder='big', length=2)
                        fragmented_message += fragment
                    to_socket.send(fragmented_message)
        except BrokenPipeError as e:
            Proxy.debug(f"Forwarding broken with {e}", direction)
            to_socket.try_close()
        except OSError as e:
            if e.errno == 9:
                # Bad file descriptor, socket closed by other forwarding queue
                to_socket.try_close()
            else:
                Proxy.debug(f"OSError while forwarding, closing sockets: {e}", direction)
                to_socket.try_close()
        except Exception as e:
            Proxy.debug(f"Exception while forwarding: {e}", direction)
            to_socket.try_close()

        logging.info(f"{direction}: Closed connection")

    def handle(self, client_socket: WrappedSocket, address: NetworkAddress):
        ConnectionHandler(
            client_socket,
            address,
            self.timeout,
            self.record_frag,
            self.tcp_frag,
            self.frag_size,
            self.dot_ip,
            self.disabled_modes,
            self.forward_proxy,
            self.forward_proxy_mode,
            self.forward_proxy_resolve_address
        ).handle()

    def start(self):
        """
        Starts the proxy. After calling the proxy is listening for connections.
        :return:
        """
        # opening server socket
        self.server.bind((self.address.host, self.address.port))
        self.server.listen()
        print(f"### Started proxy on {self.address.host}:{self.address.port} ###")
        if self.dot_ip:
            logging.debug(f"Using DoT resolver {self.dot_ip}")
        if self.forward_proxy:
            logging.debug(f"Using forward proxy {self.forward_proxy}")
        while True:  # listen for incoming connections
            client_socket, address = self.server.accept()
            address = NetworkAddress(address[0], address[1])
            client_socket = WrappedSocket(self.timeout, client_socket)
            logging.info(f"request from {address.host}:{address.port}")
            # spawn a new thread that runs the function handle()
            threading.Thread(self.handle(client_socket, address), args=(client_socket, address)).start()
