# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# Description: This script is the server-side implementation of the VPN.
import threading
import multiprocessing
import socket
import logging
import struct
import os
import ipaddress
import sys
import signal
import time
import platform
import traceback
import json
from queue import Queue, Empty
from typing import Dict, Tuple, Optional, List
from enum import Enum
from nat_manager import NAT
from protocol import MessageHandler, MsgType, PacketFlags, ConnectionState
from dataclasses import dataclass
try:
    import fcntl
    from scapy.all import Raw, conf
    from scapy.layers.inet import ICMP, TCP, UDP, IP
    from scapy.layers.l2 import Ether
    from scapy.packet import Packet
except ImportError as e:
    print("Please install the required dependencies:")
    print("pip install scapy")
    print(f"Error importing module: {e}")
    sys.exit(1)


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('VPN-Server')

# IOCTL for configuring TUN/TAP interfaces
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# VPN configuration
VPN_MTU = 1500  # Maximum transmission unit for VPN packets
KEEPALIVE_INTERVAL = 25  # Seconds
CLIENT_TIMEOUT = 90  # Seconds
CLIENT_WORKER_SLEEP = 5  # Seconds


class VPNServer:
    def __init__(self, bind_address="0.0.0.0", port=1194, vpn_network="10.8.0.0/24",
                  external_interface="ens33", max_clients=100, interface_name="tun0"):
        
        self.bind_address = bind_address
        self.port = port
        self.network = ipaddress.ip_network(vpn_network)
        self.external_interface = external_interface
        self.interface_name = interface_name
        self.dns_servers = ["8.8.8.8", "8.8.4.4"]
        self.server_vpn_ip = str(self.network[1])  # Server's virtual IP address
        self.external_interface_ip = None  # External IP address of the server

        self.server_socket = None
        self.scapy_socket = None

        self.tun_fd = None

        self.udp_read_queue = Queue()    # UDP packets from clients
        self.udp_write_queue = Queue()   # UDP packets to send to clients
        self.tun_read_queue = Queue()    # Packets from TUN interface
        self.tun_write_queue = Queue()   # Packets to write to TUN interface
        self.internet_queue = Queue()   # Packets to send to the internet

        self.max_clients = max_clients
        
        # Initialize client connection tracking
        self.active_clients = None  # addr -> {'handler': MessageHandler, 'state': ConnectionState, ...}
        self.ip_pool = None
        self.client_ips = None  # virtual_ip -> addr
        self.client_by_id = None  # client_id -> addr
        
        # Security tokens/nonces for authentication challenges
        self.auth_challenges = None  # addr -> (challenge, timestamp)
        
        self.message_handler = None  # MessageHandler instance for processing packets
        
        # NAT handler for internet traffic
        self.NAT = NAT("192.168.68.118")

        self.threads = []
        self.running = threading.Event()

    def _init_ip_pool(self, vpn_network):
        """Initialize the pool of available IP addresses for clients"""
        pool = []
        network = ipaddress.ip_network(vpn_network)
        
        # Skip the first IP (network address) and the second IP (server's IP)
        for ip in list(network.hosts())[2:]:
            pool.append(str(ip))
        
        logger.info(f"Initialized IP pool with {len(pool)} addresses")
        return pool
    
    def _get_next_ip(self):
        """Get the next available IP from the pool"""
        if not self.ip_pool:
            logger.error("IP pool exhausted")
            return None
            
        next_ip = self.ip_pool.pop(0)
        logger.info(f"Assigning IP {next_ip} from pool (remaining IPs: {len(self.ip_pool)})")
        
        # Debug: Log current pool state
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Current IP pool: {self.ip_pool}")
            
        return next_ip
    
    def _release_ip(self, ip):
        """Return an IP to the pool when a client disconnects"""
        if ip and ip not in self.ip_pool:
            self.ip_pool.insert(0, ip)  # Insert at the beginning of the pool
            logger.info(f"Released IP {ip} back to pool (pool size: {len(self.ip_pool)})")

    def _get_external_ip(self):
        """Get the IP address of the server's external interface"""
        try:
            import subprocess
            
            # Run the ip command to get the interface IP
            result = subprocess.run(
                f"ip addr show {self.external_interface} | grep 'inet ' | awk '{{print $2}}' | cut -d/ -f1",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0 and result.stdout.strip():
                ip = result.stdout.strip()
                logger.info(f"External interface {self.external_interface} has IP: {ip}")
                return ip
            else:
                logger.error(f"Failed to get IP for interface {self.external_interface}")
                logger.error(f"Command output: {result.stderr}")
                return "127.0.0.1"
        except Exception as e:
            logger.error(f"Error getting external IP: {e}")
            return "127.0.0.1"

    def _set_up_tun(self):

        try:
            if not os.path.exists('/dev/net/tun'):
                logger.info("Loading TUN/TAP module...")
                os.system("modprobe tun")
        except Exception as e:
            logger.error(f"Failed to load TUN module: {e}")
            logger.error("Please make sure the TUN module is available")
            sys.exit(1)
        try:
            # Open TUN device file
            self.tun_fd = os.open("/dev/net/tun", os.O_RDWR)
            # Create TUN interface
            ifr = struct.pack("16sH", self.interface_name.encode(), IFF_TUN | IFF_NO_PI)
            ifr = fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)

            flags = fcntl.fcntl(self.tun_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.tun_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            os.system("ip link set dev {} up".format(self.interface_name))
            
            os.system("ip addr add {}/24 dev {}".format(self.network[1], self.interface_name))

            os.system("ip route add default dev tun0")

            os.system("ip link set dev {} mtu {}".format(self.interface_name, str(VPN_MTU)))

            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

            print("TUN interface set up successfully.")
            print("TUN interface name: ", self.interface_name)

        except Exception as e:
            logger.error("Failed to set up TUN interface: {}".format(e))
            sys.exit(1)
    
    def _shutdown_tun(self):
        """Properly shut down the TUN interface"""
        try:
            if self.tun_fd is not None:
                os.system(f"ip link set dev {self.interface_name} down")
                os.system(f"ip addr flush dev {self.interface_name}")
                os.system(f"ip route flush dev {self.interface_name}")
                
                os.close(self.tun_fd)
                self.tun_fd = None
                logger.info(f"TUN interface '{self.interface_name}' shut down successfully")
        except Exception as e:
            logger.error(f"Error shutting down TUN interface: {e}")

    def _set_up_sockets(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(0.1)
            self.server_socket.bind((self.bind_address, self.port))
            logger.info("UDP socket bound to {}:{}".format(self.bind_address, self.port))

            self.scapy_socket = conf.L3socket()
            logger.info("Scapy L3 socket created")
        except Exception as e:
            logger.error("Failed to set up UDP socket: {}".format(e))
            sys.exit(1)
        
    def _shutdown_sockets(self):
        """Properly shut down the Server sockets"""
        try:
            if self.server_socket is not None:
                self.server_socket.close()
                self.server_socket = None
                logger.info("UDP socket closed")

            if self.scapy_socket is not None:
                self.scapy_socket.close()
                self.scapy_socket = None
                logger.info("Scapy socket closed")
        except OSError as e:
            logger.error(f"Error closing UDP socket: {e}")
        except socket.error as e:
            logger.error(f"Socket error while closing: {e}")
        except Exception as e:
            logger.error(f"Failed to close UDP socket: {e}")
    
    def start_server(self):
        """Initialize and start the VPN server"""
        if self.running.is_set():
            logger.warning("Server is already running")
            return

        try:
            self.active_clients = {}  # addr -> client state
            self.ip_pool = self._init_ip_pool(self.network)
            self.client_ips = {}  # virtual_ip -> addr
            self.client_by_id = {}  # client_id -> addr
            self.auth_challenges = {}  # addr -> (challenge, timestamp)

            self.external_interface_ip = self._get_external_ip()
            
            self.msg_handler = MessageHandler('server')
            
            self._set_up_tun()
            self._set_up_sockets()
            
            self.msg_handler.register_packet_callback(
                lambda packet, addr: self.udp_write_queue.put((packet, addr))
            )
            
            self.running.set()
            logger.info("VPN server started successfully")
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.stop_server()
            raise
    
    def stop_server(self):
        """Stop the server and clean up resources"""
        if not self.running.is_set():
            logger.warning("Server is not running")
            return
            
        logger.info("Shutting down VPN server...")
        
        self.running.clear()
        
        # Wait for threads to stop
        if hasattr(self, 'threads'):
            for thread in self.threads:
                if thread.is_alive():
                    thread.join(timeout=2)
                    if thread.is_alive():
                        logger.warning(f"Thread {thread.name} did not terminate gracefully")
        
        self._shutdown_tun()
        self._shutdown_sockets()
        
        logger.info("Server shutdown complete")
    
    # ============================
    # === Worker Threads Start ===
    # ============================

    def _udp_read_worker(self):
        """Read packets from the UDP socket and queue for processing"""
        logger.info("UDP read worker started")
        
        while self.running.is_set():
            try:
                data, addr = self.server_socket.recvfrom(VPN_MTU)
            
                if addr[0] == self.bind_address and addr[1] == self.port:
                    logger.info(f"Skipping packet from self: {addr}")
                    continue
                
                self.udp_read_queue.put((data, addr))
                
            except socket.timeout:
                time.sleep(0.01)
                continue
            except Exception as e:
                if self.running.is_set():
                    logger.error(f"Error in UDP read worker: {e}")
                    time.sleep(0.1)

    def _udp_packet_processor(self):
        """Process packets received from clients via UDP"""
        logger.info("UDP packet processor started")
        
        while self.running.is_set():
            try:
                retransmissions = self.msg_handler.check_retransmissions()
                for seq_num, packet in retransmissions:
                    client_addr = self.msg_handler.get_client_for_seq(seq_num)
                    if client_addr:
                        self.udp_write_queue.put((packet, client_addr))
                        logger.debug(f"Queued retransmission of packet {seq_num} to {client_addr}")
                
                if self.udp_read_queue.empty():
                    time.sleep(0.01)
                    continue
                    
                data, addr = self.udp_read_queue.get(timeout=0.1)
                client_ip, client_port = addr
                
                packet_info = self.msg_handler.process_packet(data, addr)
                
                if 'error' in packet_info:
                    logger.warning(f"Invalid packet from {addr}: {packet_info['error']}")
                    self.udp_read_queue.task_done()
                    continue
                
                msg_type = packet_info.get('type')
                
                if addr in self.active_clients:
                    self.active_clients[addr]['last_activity'] = time.time()
                
                if msg_type == MsgType.Request:
                    self._handle_client_request(packet_info, addr)
                    
                elif msg_type == MsgType.AuthResponse:
                    self._handle_client_auth_response(packet_info, addr)
                    
                elif msg_type == MsgType.Establish:
                    self._handle_client_establish(packet_info, addr)
                    
                elif msg_type == MsgType.Data:
                    self._handle_client_data(packet_info, addr)
                    
                elif msg_type == MsgType.KeepAlive:
                    self._handle_client_keepalive(packet_info, addr)
                    
                elif msg_type == MsgType.Disconnect:
                    self._handle_client_disconnect(packet_info, addr)
                    
                elif msg_type == MsgType.Ack:
                    # ACK is processed by the MessageHandler (already done in process_packet)
                    pass
                    
                elif msg_type == MsgType.Retransmit:
                    self._handle_client_retransmit(packet_info, addr)
                    
                elif msg_type == MsgType.Mtu:
                    self._handle_client_mtu(packet_info, addr)
                    
                else:
                    logger.warning(f"Unhandled message type {msg_type} from {addr}")
                
                self.udp_read_queue.task_done()
                    
            except Empty:
                continue
            except Exception as e:
                if self.running.is_set():
                    logger.error(f"Error processing UDP packet: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    time.sleep(0.1)
    

    def _udp_write_worker(self):
        """Worker thread to send queued packets to clients via UDP"""
        logger.info("UDP write worker started")
        while self.running.is_set():
            try:
                data, addr = self.udp_write_queue.get(timeout=0.1)
                
                if not addr or not isinstance(addr, tuple) or len(addr) != 2:
                    logger.warning(f"Invalid address for packet: {addr}")
                    self.udp_write_queue.task_done()
                    continue

                try:
                    self.server_socket.sendto(data, addr)
                except OSError as e:
                    logger.error(f"Socket error sending to {addr}: {e}")
                
                self.udp_write_queue.task_done()
                
            except Empty:
                time.sleep(0.01)
                continue
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except socket.timeout:
                continue
            except Exception as e:
                if self.running.is_set():
                    logger.error(f"Error in UDP write worker: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    time.sleep(0.1)

    def _tun_read_worker(self):
        """Worker thread to read from TUN interface and queue packets for sending to clients"""
        logger.info("TUN read worker started")
        while self.running.is_set():
            try:
                # Read packet from TUN interface (non-blocking)
                packet = os.read(self.tun_fd, VPN_MTU)
                
                if not packet:
                    time.sleep(0.001)
                    continue
                
                # Debug: print information about the packet
                try:
                    ip_packet = IP(packet)
                    logger.info(f"TUN read: {ip_packet.src} -> {ip_packet.dst}, proto: {ip_packet.proto}, len: {len(packet)}")
                    
                    # Find the client with matching VPN IP and forward the packet
                    for virtual_ip, client_addr in self.client_ips.items():
                        if ip_packet.dst == virtual_ip:
                            # Create VPN data packet
                            data_packet = self.msg_handler.create_data_packet(packet, client_addr=client_addr)
                            
                            # Queue for sending to the client
                            self.udp_write_queue.put((data_packet, client_addr))
                            logger.info(f"Forwarded packet from internet to client {virtual_ip}")
                            break
                    else:
                        logger.warning(f"No VPN client found for destination IP: {ip_packet.dst}")
                        
                except Exception as e:
                    logger.error(f"Error processing TUN packet: {e}")
                    
            except BlockingIOError:
                time.sleep(0.001)
            except Exception as e:
                if self.running.is_set():
                    logger.error(f"Error in TUN read worker: {e}")
                    time.sleep(0.1)


    def _tun_write_worker(self):
        """Worker thread to write packets from the queue to the TUN interface"""
        logger.info("TUN write worker started")
        while self.running.is_set():
            try:
                # Get the next packet with a timeout for interruptibility
                data, addr = self.udp_to_tun_queue.get(timeout=0.5)
                
                # Process the received packet (authentication, etc.)
                tun_packet = self._process_client_packet(data, addr)
                
                if tun_packet:
                    # Write to TUN interface
                    os.write(self.tun_fd, tun_packet)
                
                # Mark task as done
                self.udp_to_tun_queue.task_done()
                
            except Empty:
                # No data available, just continue
                continue
            except Exception as e:
                if self.running.is_set():
                    logger.error(f"Error in TUN write worker: {e}")
                    time.sleep(0.1)

    def _client_manager_worker(self):
        """Worker thread for managing client connections (timeouts, keepalives)"""
        logger.info("Client manager worker started")
        
        while self.running.is_set():
            try:
                now = time.time()

                # First check for expired authentication challenges
                auth_expired = []
                for addr, (_, timestamp) in self.auth_challenges.items():
                    if now - timestamp > 60:
                        auth_expired.append(addr)
                
                for addr in auth_expired:
                    if addr in self.auth_challenges:
                        del self.auth_challenges[addr]
                        logger.debug(f"Removed expired auth challenge for {addr}")
                        
                        if addr in self.active_clients and self.active_clients[addr]['state'] == ConnectionState.AUTHENTICATING:
                            self._remove_client(addr, reason="Authentication timeout")
                
                self._cleanup_stale_clients()
                
                for addr, client in self.active_clients.items():
                    if client['state'] == ConnectionState.CONNECTED and now - client['last_activity'] > KEEPALIVE_INTERVAL:
                        keepalive = self.msg_handler.create_keepalive_packet(client_addr=addr)
                        self.udp_write_queue.put((keepalive, addr))
                        logger.debug(f"Queued keepalive to {addr}")
                
                time.sleep(CLIENT_WORKER_SLEEP)
                
            except Exception as e:
                if self.running.is_set():
                    logger.error(f"Error in client manager worker: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    time.sleep(1)

    # ==========================
    # === Worker Threads End ===
    # ==========================

    #==============================
    # === Client Handling Start ===
    #==============================

    def _handle_client_request(self, packet_info, addr):
        """Handle a connection request from a client"""
        try:
            # Extract client info from payload
            client_info = json.loads(packet_info['payload'].decode())
            client_id = client_info.get('client_id')
            
            logger.info(f"Connection request from {addr}, client_id: {client_id}")
            logger.info(f"\nPacket info: {packet_info}\n")
            
            # Generate authentication challenge
            challenge = os.urandom(16)
            self.auth_challenges[addr] = (challenge, time.time())
            
            # Send authentication challenge
            auth_packet = self.msg_handler.create_auth_challenge_packet(challenge, addr)
            self.udp_write_queue.put((auth_packet, addr))
            
            # Initialize client state
            self.active_clients[addr] = {
                'client_id': client_id,
                'state': ConnectionState.AUTHENTICATING,
                'last_activity': time.time(),
                'virtual_ip': None,
                'mtu': VPN_MTU
            }

            self.client_by_id[client_id] = addr
            
            logger.info(f"Sent authentication challenge to {addr}")
            
        except Exception as e:
            logger.error(f"Error handling client request: {e}")
            error_packet = self.msg_handler.create_error_packet(str(e), client_addr=addr)
            self.udp_write_queue.put((error_packet, addr))
    
    def _handle_client_auth_response(self, packet_info, addr):
        """Handle an authentication response from a client"""
        try:
            # Check if client is in authenticating state
            if addr not in self.active_clients or self.active_clients[addr]['state'] != ConnectionState.AUTHENTICATING:
                logger.warning(f"Unexpected authentication response from {addr}")
                return
            
            logger.info(f"Client {addr} authentication response received")
            logger.info(f"\nPacket info: {packet_info}\n")

            # Verify the authentication response
            if addr not in self.auth_challenges:
                logger.warning(f"No authentication challenge found for {addr}")
                error_packet = self.msg_handler.create_error_packet("Authentication failed", client_addr=addr)
                self.udp_write_queue.put((error_packet, addr))
                self._remove_client(addr, reason="Authentication failed")
                return
            
            challenge, _ = self.auth_challenges[addr]
            
            # For demo purposes, we're just checking if the response matches the challenge
            # In a real implementation, you would verify a proper authentication token
            if packet_info['payload'] != challenge:
                logger.warning(f"Authentication failed for {addr}")
                error_packet = self.msg_handler.create_error_packet("Authentication failed", client_addr=addr)
                self.udp_write_queue.put((error_packet, addr))
                self._remove_client(addr, reason="Authentication failed")
                return
            
            # Authentication successful
            logger.info(f"Authentication successful for {addr}")
            
            # Assign a virtual IP to the client
            virtual_ip = self._get_next_ip()
            if not virtual_ip:
                logger.error(f"No available IP addresses for client {addr}")
                error_packet = self.msg_handler.create_error_packet("No available IP addresses", client_addr=addr)
                self.udp_write_queue.put((error_packet, addr))
                self._remove_client(addr, reason="No available IP addresses")
                return
            
            # Update client state
            self.active_clients[addr]['state'] = ConnectionState.ESTABLISHING
            self.active_clients[addr]['virtual_ip'] = virtual_ip
            
            # Map virtual IP to client address
            self.client_ips[virtual_ip] = addr
            
            # Clean up the challenge
            del self.auth_challenges[addr]
            
            # Create and send configuration
            config = {
                'virtual_ip': virtual_ip,
                'subnet_mask': '255.255.255.0',
                'server_ip': str(self.network[1]),
                'mtu': VPN_MTU,
                'dns_servers': self.dns_servers,
                'routes': ['0.0.0.0/0'],
                'keepalive_interval': KEEPALIVE_INTERVAL
            }
            
            # Send configuration packet
            config_packet = self.msg_handler.create_config_packet(config, client_addr=addr)
            self.udp_write_queue.put((config_packet, addr))
            
            logger.info(f"Sent configuration to {addr}, assigned IP: {virtual_ip}")
            
        except Exception as e:
            logger.error(f"Error handling authentication response: {e}")
            error_packet = self.msg_handler.create_error_packet(str(e), client_addr=addr)
            self.udp_write_queue.put((error_packet, addr))
    
    def _handle_client_establish(self, packet_info, addr):
        """Handle a connection establishment confirmation from a client"""
        try:
            # Check if client is in the right state
            if addr not in self.active_clients or self.active_clients[addr]['state'] != ConnectionState.ESTABLISHING:
                logger.warning(f"Unexpected establish message from {addr}")
                return
            
            logger.info(f"Client {addr} confirmed connection establishment")
            
            # Update client state to CONNECTED
            self.active_clients[addr]['state'] = ConnectionState.CONNECTED
            self.active_clients[addr]['last_activity'] = time.time()
            
            # Important: Clear any pending packets from unacked_packets for this client
            # This prevents retransmission of handshake packets
            self._clear_pending_packets_for_client(addr)
            
            # At this point, the VPN connection is fully established
            client_id = self.active_clients[addr]['client_id']
            virtual_ip = self.active_clients[addr]['virtual_ip']
            logger.info(f"Client {client_id} ({addr}) connected with virtual IP {virtual_ip}")
            
        except Exception as e:
            logger.error(f"Error handling client establish message: {e}")
            import traceback
            logger.error(traceback.format_exc())

    def _clear_pending_packets_for_client(self, client_addr):
        """Remove any pending packets for a client from the retransmission queue"""
        # First, find all sequence numbers associated with this client
        sequences_to_remove = []
        for seq_num, addr in self.msg_handler.seq_to_client.items():
            if addr == client_addr:
                sequences_to_remove.append(seq_num)
        
        # Then remove them from the unacked_packets dictionary
        for seq_num in sequences_to_remove:
            if seq_num in self.msg_handler.unacked_packets:
                logger.info(f"Clearing unacked packet {seq_num} for client {client_addr}")
                del self.msg_handler.unacked_packets[seq_num]
            
            # Also clean up sequence tracking
            if seq_num in self.msg_handler.seq_to_client:
                del self.msg_handler.seq_to_client[seq_num]
        
        logger.info(f"Cleared {len(sequences_to_remove)} pending packets for client {client_addr}")

    def _handle_client_data(self, packet_info, addr):
        """Handle data packets from a client"""
        try:
            # Check if client is in the right state
            if addr not in self.active_clients or self.active_clients[addr]['state'] != ConnectionState.CONNECTED:
                logger.warning(f"Unexpected data packet from {addr}")
                return
            
            encapsulated_data = packet_info['payload']
        
            if not encapsulated_data:
                logger.warning(f"Empty data packet from {addr}")
                return
            
            logger.debug(f"Received data packet from {addr}, size: {len(encapsulated_data)} bytes")
            
            try:
                ip_packet = IP(encapsulated_data)
                
                logger.info(f"Packet details: src={ip_packet.src}, dst={ip_packet.dst}, proto={ip_packet.proto}")

                if ip_packet.src == '0.0.0.0' or not self._is_valid_ip(ip_packet.src):
                    client_vpn_ip = self.active_clients[addr]['virtual_ip']
                    logger.warning(f"Invalid source IP {ip_packet.src}, replacing with client VPN IP {client_vpn_ip}")
                    ip_packet.src = client_vpn_ip

                if ip_packet.dst == self.server_vpn_ip:
                    logger.info(f"Packet destined for server VPN IP: {ip_packet.dst}")
                    # Handle packet locally - for ICMP, we'll respond directly
                    if ip_packet.proto == 1:  # ICMP
                        self._handle_icmp_to_server(ip_packet, addr)
                    else:
                        logger.info(f"Non-ICMP packet to server: proto={ip_packet.proto}")
            except Exception as e:
                logger.error(f"Error processing IP packet: {e}")
                logger.error(traceback.format_exc())
            
        except Exception as e:
            logger.error(f"Error handling client data: {e}")
        
    def _is_valid_ip(self, ip_str):
        """Check if the IP address is valid"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return not ip.is_unspecified and not ip.is_loopback and not ip.is_link_local
        except ValueError:
            return False

    def _handle_icmp_to_server(self, ip_packet, client_addr):
        """Handle ICMP packets destined for the server itself"""
        try:
            if ICMP in ip_packet and ip_packet[ICMP].type == 8:
                logger.info(f"ICMP Echo request from {ip_packet.src} to server")
                
                # Create a reply packet
                reply = IP(
                    src=ip_packet.dst,  # Server's VPN IP
                    dst=ip_packet.src   # Client's VPN IP
                ) / ICMP(
                    type=0,             # Echo reply
                    id=ip_packet[ICMP].id,
                    seq=ip_packet[ICMP].seq
                ) / ip_packet[ICMP].payload
                
                reply = IP(bytes(reply))
                
                # Create and queue a data packet to send back to the client
                data_packet = self.msg_handler.create_data_packet(bytes(reply), client_addr=client_addr)
                self.udp_write_queue.put((data_packet, client_addr))
                
                logger.info(f"Sent ICMP Echo reply to {ip_packet.src}")
        except Exception as e:
            logger.error(f"Error handling ICMP to server: {e}")
            import traceback
            logger.error(traceback.format_exc())

    def _handle_client_keepalive(self, packet_info, addr):
        """Handle a keepalive packet from a client"""
        try:
            # Check if client is known
            if addr not in self.active_clients:
                logger.warning(f"Keepalive from unknown client {addr}")
                return
            
            # Update last activity time
            self.active_clients[addr]['last_activity'] = time.time()
            
            
        except Exception as e:
            logger.error(f"Error handling client keepalive: {e}")
    
    def _handle_client_disconnect(self, packet_info, addr):
        """Handle a disconnect request from a client"""
        try:
            if addr not in self.active_clients:
                logger.warning(f"Disconnect from unknown client {addr}")
                return
            
            reason = "Client requested disconnection"
            if packet_info['payload']:
                try:
                    reason = packet_info['payload'].decode('utf-8')
                except UnicodeDecodeError:
                    logger.warning(f"Could not decode disconnect reason from {addr}")

            logger.info(f"Client {addr} requested disconnection: {reason}")
            
            virtual_ip = self.active_clients[addr].get('virtual_ip')
            
            self._remove_client(addr, reason=reason)
            
            ack_packet = self.msg_handler.create_ack_packet(packet_info['seq_num'], client_addr=addr)
            self.udp_write_queue.put((ack_packet, addr))
            
            logger.info(f"Client {addr} disconnected: {reason}, released IP {virtual_ip}")
            
        except Exception as e:
            logger.error(f"Error handling client disconnect: {e}")
            import traceback
            logger.error(traceback.format_exc())

    def _cleanup_stale_clients(self):
        """Remove clients that haven't communicated within the timeout period"""
        now = time.time()
        stale_clients = []
        
        for addr, client in self.active_clients.items():
            if now - client['last_activity'] > CLIENT_TIMEOUT:
                stale_clients.append(addr)
        
        for addr in stale_clients:
            self._remove_client(addr, reason="Connection timeout")
        
        return stale_clients

    def _handle_client_retransmit(self, packet_info, addr):
        """Handle a retransmission request from a client"""
        try:
            # Extract the sequence number to retransmit
            seq_num_bytes = packet_info['payload']
            if len(seq_num_bytes) >= 4:
                seq_num = struct.unpack('>I', seq_num_bytes[:4])[0]
                logger.debug(f"Retransmission request for sequence {seq_num} from {addr}")
                
                # Check if we have this packet in our unacked packets
                if seq_num in self.msg_handler.unacked_packets:
                    packet, _, _ = self.msg_handler.unacked_packets[seq_num]
                    self.udp_write_queue.put((packet, addr))
                    logger.debug(f"Retransmitting packet {seq_num} to {addr}")
                else:
                    logger.warning(f"Cannot retransmit packet {seq_num} to {addr}: not found")
            else:
                logger.warning(f"Invalid retransmit request from {addr}")
            
        except Exception as e:
            logger.error(f"Error handling client retransmit: {e}")
            import traceback
            logger.error(traceback.format_exc())

    def _remove_client(self, addr, reason="Unspecified"):
        """Remove a client and clean up its resources"""
        try:
            if addr in self.active_clients:
                client = self.active_clients[addr]
                logger.info(f"Removing client {addr} with reason: {reason}")
                
                with threading.Lock():
                    if client.get('virtual_ip'):
                        virtual_ip = client['virtual_ip']
                        logger.info(f"Releasing IP {virtual_ip} back to pool")
                        
                        if virtual_ip in self.client_ips:
                            del self.client_ips[virtual_ip]
                        
                        self._release_ip(virtual_ip)
                    
                    if 'client_id' in client and client['client_id'] in self.client_by_id:
                        del self.client_by_id[client['client_id']]
                    
                    if addr in self.msg_handler.client_seq_nums:
                        del self.msg_handler.client_seq_nums[addr]
                    
                    del self.active_clients[addr]
                
                logger.info(f"Client {addr} removed successfully: {reason}")
                
            else:
                logger.warning(f"Attempted to remove non-existent client {addr}")
                
        except Exception as e:
            logger.error(f"Error removing client {addr}: {e}")
            import traceback
            logger.error(traceback.format_exc())

    # ===========================
    # === Client Handling End ===
    # ===========================

    def run_server(self):
        """Start all worker threads"""
        if not self.running.is_set():
            logger.error("Server not started. Call start_server() first.")
            return
        
        # Define all worker threads
        thread_specs = [
            # I/O threads
            ("UDP Reader", self._udp_read_worker),
            ("UDP Writer", self._udp_write_worker),
            # ("TUN Reader", self._tun_read_worker),
            # ("TUN Writer", self._tun_write_worker),
            
            # # Processor threads
            ("UDP Processor", self._udp_packet_processor),
            # ("TUN Processor", self._tun_packet_processor),
            
            # # Management thread
            ("Client Manager", self._client_manager_worker),
        ]
        
        # Start all workers
        threads = []
        for name, target in thread_specs:
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            threads.append(thread)
            logger.info(f"Started {name} thread")
        
        # Store threads for cleanup
        self.threads = threads
        
        logger.info("All server workers started")
        return threads


def check_linux_and_sudo():
    """
    Check if the script is running on Linux with superuser privileges.
    Raises exceptions if either condition is not met.
    """
    # Check if running on Linux
    if platform.system() != 'Linux':
        raise OSError("This script is designed to run only on Linux operating systems.")
    
    # Check if running with superuser privileges
    if os.geteuid() != 0:
        raise PermissionError("This script requires superuser privileges. Please run with sudo.")
    
    logger.info("Running on Linux with superuser privileges.")


def set_signal_handler(vpn_server):
    """Set up signal handlers to gracefully shutdown the server"""
    def signal_handler(sig, frame):
        sig_name = signal.Signals(sig).name
        logger.info(f"Received signal {sig_name} ({sig}). Shutting down...")
        vpn_server.stop_server()
        sys.exit(0)
    
    # Register handlers for various signals
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination request
    signal.signal(signal.SIGHUP, signal_handler)   # Terminal closed
    
    logger.info("Signal handlers registered")

def main():
    try:
        check_linux_and_sudo()

        vpn_server = VPNServer()
        
        # Set up signal handlers before starting the server
        set_signal_handler(vpn_server)
        
        vpn_server.start_server()

        vpn_server.run_server()

        logger.info("VPN server started successfully")

        # Main loop
        logger.info("Server running. Press Ctrl+C to stop.")
        while vpn_server.running.is_set():
            time.sleep(1)
            
    except KeyboardInterrupt:
        # This should be caught by the signal handler, but just in case
        logger.info("Keyboard interrupt received. Shutting down...")
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
    finally:
        # Ensure resources are cleaned up even if an exception occurs
        if 'vpn_server' in locals():
            vpn_server.stop_server()
        logger.info("Server shutdown complete")

if __name__ == "__main__":
    main()