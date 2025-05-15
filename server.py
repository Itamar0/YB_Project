# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# Description: This script is the server-side implementation of the VPN.
import threading
import socket
import logging
import struct
import os
import ipaddress
import sys
import signal
import time
import subprocess
import platform
import traceback
import json
from queue import Queue, Empty
from protocol import MsgType, ConnectionState
from reliable_protocol import ReliableMessageHandler
from user_manager import ServerUserManager
try:
    import fcntl
    from scapy.layers.inet import ICMP, TCP, UDP, IP
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
VPN_MTU = 1400  # VPN encapsulation accounted for
VPN_MSS = 1340  # MSS should be lower than MTU (MTU - IP header - UDP header)
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

        self.tun_fd = None

        self.udp_read_queue = Queue()    # UDP packets from clients
        self.udp_write_queue = Queue()   # UDP packets to send to clients
        self.tun_read_queue = Queue()    # Packets from TUN interface

        self.max_clients = max_clients
        
        # Initialize client connection tracking
        self.active_clients = None  # addr -> {'handler': MessageHandler, 'state': ConnectionState, ...}
        self.ip_pool = None
        self.client_ips = None  # virtual_ip -> addr
        self.client_by_id = None  # client_id -> addr
        
        # Security tokens/nonces for authentication challenges
        self.auth_challenges = None  # addr -> (challenge, timestamp)
        
        self.message_handler = None  # MessageHandler instance for processing packets

        self.user_manager = ServerUserManager() # User management (authentication, registration, etc.)

        self.authenticated_clients = {}  # addr -> session_token

        self.threads = []
        self.running = threading.Event()

        self.state_lock = threading.RLock()

    def _get_client_state(self, client_addr):
        """Return the connection state for a specific client"""
        if client_addr in self.active_clients:
            return self.active_clients[client_addr]['state']
        return ConnectionState.DISCONNECTED

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
            # Getting the interface IP
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
        """Set up the TUN interface correctly"""
        try:
            # Check if TUN module is loaded
            if not os.path.exists('/dev/net/tun'):
                logger.info("Loading TUN/TAP module...")
                os.system("modprobe tun")
                    
        except Exception as e:
            logger.error(f"Failed to load TUN module: {e}")
            logger.error("Please make sure the TUN module is available")
            sys.exit(1)
            
        try:
            self.tun_fd = os.open("/dev/net/tun", os.O_RDWR)
            
            # Create TUN interface with proper flags
            ifr = struct.pack("16sH", self.interface_name.encode(), IFF_TUN | IFF_NO_PI)
            ifr = fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)
            
            # Set non-blocking mode for read operations
            flags = fcntl.fcntl(self.tun_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.tun_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            # Bring interface up
            os.system(f"ip link set dev {self.interface_name} up")
            
            # Configure IP address for TUN interface
            os.system(f"ip addr add {self.server_vpn_ip}/24 dev {self.interface_name}")
            
            # Set MTU to avoid fragmentation issues
            os.system(f"ip link set dev {self.interface_name} mtu {VPN_MTU}")
            
            # Disable TCP offloading features that can interfere with tunneled traffic
            os.system(f"ethtool -K {self.interface_name} tso off gso off")
            os.system(f"ethtool -K {self.interface_name} tx-checksum-ip-generic off")
            
            # Ensure all offloading features are properly disabled
            self._ensure_server_offloading_disabled()
            
            logger.info(f"TUN interface '{self.interface_name}' created with MTU {VPN_MTU}")
            
        except Exception as e:
            logger.error(f"Failed to set up TUN interface: {e}")
            logger.error(traceback.format_exc())
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

    def _ensure_server_offloading_disabled(self):
        """
        Ensure all offloading features are properly disabled on server interfaces
        """
        logger.info("Ensuring complete offloading disabling for server...")
        
        missing_features = [
            "rx", "tx", "sg", "ufo", "gro", "lro", 
            "rx-checksum", "tx-checksum-ipv4", "tx-checksum-ipv6"
        ]
        
        if self.interface_name:
            logger.info(f"Disabling missing offloading features on {self.interface_name}...")
            
            for feature in missing_features:
                cmd = f"ethtool -K {self.interface_name} {feature} off"
                result = os.system(cmd)
                if result != 0:
                    logger.warning(f"Failed to disable {feature} on {self.interface_name}")
            
            try:
                output = subprocess.check_output(
                    f"ethtool -k {self.interface_name} | grep -E 'tcp-segmentation-offload|generic-segmentation-offload|tx-checksumming|rx-checksumming'", 
                    shell=True, stderr=subprocess.PIPE, text=True
                )
                logger.info(f"TUN interface offloading status:\n{output.strip()}")
            except Exception as e:
                logger.warning(f"Could not verify offloading settings on {self.interface_name}: {e}")
        
        if self.external_interface:
            logger.info(f"Disabling offloading on external interface {self.external_interface}...")
            
            external_features = [
                "tso", "gso", "rx", "tx", "sg", "ufo", "gro", "lro",
                "tx-checksum-ip-generic", "rx-checksum", "tx-checksum-ipv4", 
                "tx-checksum-ipv6"
            ]
            
            for feature in external_features:
                os.system(f"ethtool -K {self.external_interface} {feature} off 2>/dev/null")
            
            # Verify settings
            try:
                output = subprocess.check_output(
                    f"ethtool -k {self.external_interface} | grep -E 'tcp-segmentation-offload|generic-segmentation-offload|tx-checksumming|rx-checksumming'", 
                    shell=True, stderr=subprocess.PIPE, text=True
                )
                logger.info(f"External interface offloading status:\n{output.strip()}")
            except Exception as e:
                logger.warning(f"Could not verify offloading settings on {self.external_interface}: {e}")
        
        # Server-specific kernel parameters (only ones not already in _setup_networking)
        server_params = {
            "net.ipv4.tcp_mtu_probing": "1",       # Enable MTU probing
            "net.ipv4.tcp_timestamps": "1",        # Important for accurate RTT
            "net.ipv4.tcp_thin_dupack": "1",       # Better retransmit for thin streams
            "net.ipv4.conf.default.rp_filter": "0" # Disable for new interfaces
        }
        
        for param, value in server_params.items():
            os.system(f"sysctl -w {param}={value} 2>/dev/null")
        
        logger.info("Server offloading and TCP parameters verification complete")

    def _force_tcp_checksum_recalculation(self, packet_data):
        """
        Force checksum recalculation for TCP packets
        This is critical for fixing the checksum mismatch issues
        """
        try:
            # Parse the IP packet
            ip_packet = IP(packet_data)
            
            # If this is a TCP packet, recalculate checksums
            if TCP in ip_packet:
                # Delete checksums to force recalculation
                del ip_packet[TCP].chksum
                del ip_packet.chksum
                
                # Rebuild the packet with recalculated checksums
                return bytes(ip_packet)
            
            # For non-TCP packets, return original data
            return packet_data
            
        except Exception as e:
            logger.warning(f"Error in checksum recalculation: {e}, using original packet")
            return packet_data

    def _setup_networking(self):
        """Configure networking and routing for the VPN server"""
        try:
            # Enable IP forwarding
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            
            # Verify IP forwarding is enabled
            ip_forward_status = os.popen("cat /proc/sys/net/ipv4/ip_forward").read().strip()
            if ip_forward_status != "1":
                logger.error("Failed to enable IP forwarding, trying alternative method")
                os.system("sysctl -w net.ipv4.ip_forward=1")
                
                ip_forward_status = os.popen("cat /proc/sys/net/ipv4/ip_forward").read().strip()
                if ip_forward_status != "1":
                    logger.error("Failed to enable IP forwarding. VPN traffic won't be forwarded!")
            
            # Set up NAT (IP masquerading)
            # Clear any existing NAT rules that might conflict
            os.system("iptables -t nat -F POSTROUTING")
            
            # Add NAT rule to masquerade VPN traffic going out through external interface
            nat_cmd = f"iptables -t nat -A POSTROUTING -s {self.network} -o {self.external_interface} -j MASQUERADE"
            os.system(nat_cmd)
            logger.info(f"NAT rule configured: {nat_cmd}")
            
            # Set up proper forwarding rules
            # Clear existing rules and set default policies
            os.system("iptables -F FORWARD")
            
            # Allow forwarding from VPN to external interface
            forward1 = f"iptables -A FORWARD -i {self.interface_name} -o {self.external_interface} -j ACCEPT"
            os.system(forward1)
            
            # Allow return traffic
            forward2 = f"iptables -A FORWARD -i {self.external_interface} -o {self.interface_name} -m state --state RELATED,ESTABLISHED -j ACCEPT"
            os.system(forward2)
            
            # Configure routing
            # Make sure the kernel knows how to route VPN subnet traffic
            os.system(f"ip route add {self.network} dev {self.interface_name}")
            
            # TCP MSS Clamping (CRITICAL FOR TCP)
            # Clear existing MSS clamping rules
            os.system("iptables -t mangle -F FORWARD 2>/dev/null || true")
            
            # This adjusts TCP SYN packets to have a proper MSS value that fits in the VPN tunnel
            os.system(f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {VPN_MSS}")
            os.system(f"iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss {VPN_MSS+1}: -j TCPMSS --clamp-mss-to-pmtu")
            
            # Enable better connection tracking
            os.system("modprobe nf_conntrack")
            os.system("sysctl -w net.netfilter.nf_conntrack_max=65536 2>/dev/null || sysctl -w net.nf_conntrack_max=65536 2>/dev/null")
            os.system("sysctl -w net.ipv4.tcp_sack=1")
            os.system("sysctl -w net.ipv4.tcp_window_scaling=1")
            
            # Configure firewall to allow VPN traffic
            os.system(f"iptables -A INPUT -i {self.interface_name} -j ACCEPT")
            os.system(f"iptables -A OUTPUT -o {self.interface_name} -j ACCEPT")
            os.system(f"iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
            os.system(f"iptables -A FORWARD -s {self.network} -j ACCEPT")
            
            # Allow traffic on the UDP port used by VPN
            os.system(f"iptables -A INPUT -p udp --dport {self.port} -j ACCEPT")
            
            # Disable ICMP redirects (can cause routing issues)
            os.system("sysctl -w net.ipv4.conf.all.send_redirects=0")
            os.system("sysctl -w net.ipv4.conf.all.accept_redirects=0")
            
            # Enable Path MTU Discovery
            os.system("sysctl -w net.ipv4.ip_no_pmtu_disc=0")
            
            # Disable all TCP offloading features
            os.system(f"ethtool -K {self.interface_name} rx off tx off sg off tso off ufo off gso off gro off lro off 2>/dev/null || true")
            os.system(f"ethtool -K {self.external_interface} rx off tx off sg off tso off ufo off gso off gro off lro off 2>/dev/null || true")
            
            # Dump the routing table for verification
            route_table = os.popen("ip route").read()
            logger.info(f"Routing table:\n{route_table}")
            
            # Display the NAT rules for verification
            nat_rules = os.popen("iptables -t nat -L -v -n").read()
            logger.info(f"NAT rules:\n{nat_rules}")
            
            # Display MSS clamping rules
            mss_rules = os.popen("iptables -t mangle -L -v -n").read()
            logger.info(f"MSS clamping rules:\n{mss_rules}")
            
            logger.info(f"Network configuration complete: VPN subnet {self.network} forwarded through {self.external_interface}")
            
        except Exception as e:
            logger.error(f"Failed to set up networking: {e}")
            logger.error(traceback.format_exc())
            raise

    def _set_up_sockets(self):
        try:
            # Set up the Server's UDP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
            self.server_socket.settimeout(0.1)
            self.server_socket.bind((self.bind_address, self.port))
            logger.info(f"UDP socket bound to {self.bind_address}:{self.port} with 1MB buffers")
        except Exception as e:
            logger.error(f"Failed to set up sockets: {e}")
            sys.exit(1)
        
    def _shutdown_sockets(self):
        """Properly shut down the Server sockets"""
        try:
            if self.server_socket is not None:
                self.server_socket.close()
                self.server_socket = None
                logger.info("UDP socket closed")
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
            
            self.msg_handler = ReliableMessageHandler('server')
            
            self.msg_handler.client_state_callback = self._get_client_state
            
            self._set_up_tun()
            self._setup_networking()
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
        
        # Stop the reliability worker thread
        if hasattr(self, 'msg_handler') and hasattr(self.msg_handler, 'stop'):
            self.msg_handler.stop()
        
        # Wait for threads to stop
        if hasattr(self, 'threads'):
            for thread in self.threads:
                if thread.is_alive():
                    thread.join(timeout=2)
                    if thread.is_alive():
                        logger.warning(f"Thread {thread.name} did not terminate gracefully")
        
        # Clean up iptables rules
        os.system(f"iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {VPN_MSS} 2>/dev/null || true")
        os.system(f"iptables -t nat -D POSTROUTING -s {self.network} -o {self.external_interface} -j MASQUERADE 2>/dev/null || true")
        
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
                data, addr = self.udp_read_queue.get(timeout=0.1)
                client_ip, client_port = addr
                
                packet_info = self.msg_handler.process_packet(data, addr)
                
                if 'error' in packet_info:
                    logger.debug(f"Invalid packet from {addr}: {packet_info['error']}")
                    self.udp_read_queue.task_done()
                    continue
                
                msg_type = packet_info.get('type')
                
                if addr in self.active_clients:
                    self.active_clients[addr]['last_activity'] = time.time()
                
                if msg_type == MsgType.KeyExchangeInit:
                    self._handle_key_exchange_init(packet_info, addr)
                    
                elif msg_type == MsgType.Login:
                    self._handle_client_login(packet_info, addr)
                    
                elif msg_type == MsgType.Signup:
                    self._handle_client_signup(packet_info, addr)
                
                elif msg_type == MsgType.Request:
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
                    pass
                    
                elif msg_type == MsgType.Retransmit:
                    pass
                    
                else:
                    logger.warning(f"Unhandled message type {msg_type} from {addr}")
                
                self.udp_read_queue.task_done()
                    
            except Empty:
                time.sleep(0.01)
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
                
                try:
                    ip_packet = IP(packet)
                    logger.info(f"TUN read: {ip_packet.src} -> {ip_packet.dst}, proto: {ip_packet.proto}, len: {len(packet)}")
                    
                    if ip_packet.dst in self.client_ips:
                        client_addr = self.client_ips[ip_packet.dst]
                        
                        # Force checksum recalculation for all TCP packets
                        if TCP in ip_packet:
                            del ip_packet[TCP].chksum
                            del ip_packet.chksum
                            packet = bytes(ip_packet)
                            
                            # Additional processing for SYN packets (MSS clamping)
                            if ip_packet[TCP].flags & 0x02:  # SYN flag
                                for i, option in enumerate(ip_packet[TCP].options):
                                    if option[0] == 'MSS':
                                        current_mss = option[1]
                                        if current_mss > VPN_MSS:
                                            # Update the MSS option
                                            new_options = list(ip_packet[TCP].options)
                                            new_options[i] = ('MSS', VPN_MSS)
                                            ip_packet[TCP].options = new_options
                                            logger.info(f"Updated return SYN packet MSS from {current_mss} to {VPN_MSS}")
                                            # Recalculate checksums again after MSS change
                                            del ip_packet[TCP].chksum
                                            del ip_packet.chksum
                                            packet = bytes(ip_packet)
                        else:
                            # For non-TCP packets, only recalculate if needed
                            modified = False
                            
                            # Ensure TTL is reasonable
                            if ip_packet.ttl < 10:
                                ip_packet.ttl = 64
                                logger.debug(f"Adjusted TTL to 64 for return packet to {ip_packet.dst}")
                                modified = True
                            
                            # If packet was modified, recalculate checksums
                            if modified:
                                if UDP in ip_packet:
                                    del ip_packet[UDP].chksum
                                del ip_packet.chksum
                                packet = bytes(ip_packet)
                        
                        # Create VPN data packet to send to the client
                        data_packet = self.msg_handler.create_data_packet(packet, client_addr=client_addr)
                        
                        # Queue for sending to the client
                        self.udp_write_queue.put((data_packet, client_addr))
                        logger.info(f"Forwarded return packet to client {ip_packet.dst}")
                    else:
                        logger.warning(f"No client found for destination IP: {ip_packet.dst}")
                    
                except Exception as e:
                    logger.error(f"Error processing TUN read packet: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    
            except BlockingIOError:
                # No data available (non-blocking read)
                time.sleep(0.001)
            except Exception as e:
                if self.running.is_set():
                    logger.error(f"Error in TUN read worker: {e}")
                    logger.error(traceback.format_exc())
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

    def _handle_key_exchange_init(self, packet_info, addr):
        """Handle initial key exchange from client (BEFORE authentication)"""
        try:
            # Extract client's public key
            client_public_key = packet_info['payload']
            
            logger.info(f"Received key exchange init from {addr}")
            
            # Create key exchange response with server's public key
            key_exchange_response = self.msg_handler.create_key_exchange_response_packet(
                client_public_key, 
                client_addr=addr
            )
            
            # Send the key exchange response
            self.udp_write_queue.put((key_exchange_response, addr))
            
            logger.info(f"Sent key exchange response to {addr}")
            
        except Exception as e:
            logger.error(f"Error handling key exchange: {e}")
            error_packet = self.msg_handler.create_error_packet(str(e), client_addr=addr)
            self.udp_write_queue.put((error_packet, addr))

    def _handle_client_login(self, packet_info, addr):
        """Handle login request from client"""
        try:
            # Parse login data
            login_data = json.loads(packet_info['payload'].decode())
            username = login_data.get('username')
            password = login_data.get('password')
            
            logger.info(f"Login attempt from {addr} for user: {username}")
            
            # Authenticate user
            result = self.user_manager.authenticate_user(username, password)
            
            # Send response
            response_packet = self.msg_handler.create_packet(
                MsgType.LoginResponse,
                json.dumps(result).encode(),
                client_addr=addr
            )
            
            self.udp_write_queue.put((response_packet, addr))
            
            # If successful, store the session
            if result['success']:
                self.authenticated_clients[addr] = result['session_token']
                logger.info(f"Client {addr} logged in as {username}")
            
        except Exception as e:
            logger.error(f"Error handling login: {e}")
            error_response = {
                'success': False,
                'message': 'Server error during login'
            }
            error_packet = self.msg_handler.create_packet(
                MsgType.LoginResponse,
                json.dumps(error_response).encode(),
                client_addr=addr
            )
            self.udp_write_queue.put((error_packet, addr))

    def _handle_client_signup(self, packet_info, addr):
        """Handle signup request from client"""
        try:
            # Parse signup data
            signup_data = json.loads(packet_info['payload'].decode())
            username = signup_data.get('username')
            password = signup_data.get('password')
            
            logger.info(f"Signup attempt from {addr} for username: {username}")
            
            # Register user
            result = self.user_manager.register_user(username, password)
            
            # Send response
            response_packet = self.msg_handler.create_packet(
                MsgType.SignupResponse,
                json.dumps(result).encode(),
                client_addr=addr
            )
            
            self.udp_write_queue.put((response_packet, addr))
            
            logger.info(f"Signup result for {username}: {result['message']}")
            
        except Exception as e:
            logger.error(f"Error handling signup: {e}")
            error_response = {
                'success': False,
                'message': 'Server error during signup'
            }
            error_packet = self.msg_handler.create_packet(
                MsgType.SignupResponse,
                json.dumps(error_response).encode(),
                client_addr=addr
            )
            self.udp_write_queue.put((error_packet, addr))

    def _handle_client_request(self, packet_info, addr):
        """Handle a connection request from a client"""
        try:
            if addr not in self.authenticated_clients:
                logger.warning(f"Connection request from unauthenticated client {addr}")
                error_packet = self.msg_handler.create_error_packet(
                    "Please login first", 
                    client_addr=addr
                )
                self.udp_write_queue.put((error_packet, addr))
                return
            # Extract client info from payload
            client_info = json.loads(packet_info['payload'].decode())
            client_id = client_info.get('client_id')
            
            logger.info(f"Connection request from {addr}, client_id: {client_id}")
            
            # Check if this client is already in a higher state
            if addr in self.active_clients:
                current_state = self.active_clients[addr]['state']
                
                # If already authenticated or connected, re-send the last challenge instead of creating a new one
                if self.msg_handler._state_is_advanced_or_equal(current_state, ConnectionState.AUTHENTICATING):
                    if addr in self.auth_challenges:
                        # Resend the existing challenge
                        challenge, _ = self.auth_challenges[addr]
                        
                        # Send authentication challenge with state information
                        auth_packet = self.msg_handler.create_packet(
                            MsgType.Authenticate, 
                            challenge, 
                            client_addr=addr,
                            current_state=current_state,
                            target_state=ConnectionState.AUTHENTICATING
                        )
                        
                        # Send the packet
                        self.udp_write_queue.put((auth_packet, addr))
                        
                        logger.info(f"Resent existing authentication challenge to {addr}")
                        return
            
            # Generate a new authentication challenge
            challenge = os.urandom(16)
            self.auth_challenges[addr] = (challenge, time.time())
            
            # Determine current connection state
            current_state = ConnectionState.DISCONNECTED
            if addr in self.active_clients:
                current_state = self.active_clients[addr]['state']
            
            # Send authentication challenge with state information
            auth_packet = self.msg_handler.create_packet(
                MsgType.Authenticate, 
                challenge, 
                client_addr=addr,
                current_state=current_state,
                target_state=ConnectionState.AUTHENTICATING
            )
            
            # Get sequence number from the packet
            seq_num = struct.unpack('>I', auth_packet[9:13])[0]
            
            # Register delivery confirmation callback
            def on_auth_challenge_delivered(success=True):
                if success:
                    logger.info(f"Authentication challenge confirmed received by client {addr}")
                else:
                    logger.error(f"Authentication challenge delivery to {addr} failed")
                    self._remove_client(addr, reason="Failed to deliver authentication challenge")
            
            self.msg_handler.register_delivery_callback(seq_num, on_auth_challenge_delivered)
            
            # Send the packet
            self.udp_write_queue.put((auth_packet, addr))
            
            # Initialize client state to AUTHENTICATING
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
            if addr not in self.active_clients:
                logger.warning(f"Auth response from unknown client {addr}")
                return
                
            if self.active_clients[addr]['state'] != ConnectionState.AUTHENTICATING:
                logger.warning(f"Unexpected authentication response from {addr}")
                return
            
            logger.info(f"Client {addr} authentication response received")

            # Verify the authentication response
            if addr not in self.auth_challenges:
                logger.warning(f"No authentication challenge found for {addr}")
                error_packet = self.msg_handler.create_error_packet("Authentication failed", client_addr=addr)
                self.udp_write_queue.put((error_packet, addr))
                self._remove_client(addr, reason="Authentication failed")
                return
            
            challenge, _ = self.auth_challenges[addr]
            
            # Check if response matches challenge
            if packet_info['payload'] != challenge:
                logger.warning(f"Authentication failed for {addr}")
                error_packet = self.msg_handler.create_error_packet("Authentication failed", client_addr=addr)
                self.udp_write_queue.put((error_packet, addr))
                self._remove_client(addr, reason="Authentication failed")
                return
            
            # Authentication successful
            logger.info(f"Authentication successful for {addr}")
            
            # If client already has a virtual IP (from a previous session), try to reuse it
            if addr in self.active_clients and self.active_clients[addr].get('virtual_ip'):
                virtual_ip = self.active_clients[addr]['virtual_ip']
                logger.info(f"Reusing previous IP assignment {virtual_ip} for client {addr}")
            else:
                # Assign a new virtual IP to the client
                virtual_ip = self._get_next_ip()
                if not virtual_ip:
                    logger.error(f"No available IP addresses for client {addr}")
                    error_packet = self.msg_handler.create_error_packet("No available IP addresses", client_addr=addr)
                    self.udp_write_queue.put((error_packet, addr))
                    self._remove_client(addr, reason="No available IP addresses")
                    return
            
            # Update client state to ESTABLISHING
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
            
            # Send configuration packet with state information
            config_packet = self.msg_handler.create_packet(
                MsgType.Config, 
                json.dumps(config).encode(), 
                client_addr=addr,
                current_state=ConnectionState.ESTABLISHING,  # Current state
                target_state=ConnectionState.CONNECTED  # Target state after this message
            )
            
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
            
            # At this point, the VPN connection is fully established
            client_id = self.active_clients[addr]['client_id']
            virtual_ip = self.active_clients[addr]['virtual_ip']
            logger.info(f"Client {client_id} ({addr}) connected with virtual IP {virtual_ip}")
            
        except Exception as e:
            logger.error(f"Error handling client establish message: {e}")
            import traceback
            logger.error(traceback.format_exc())

    def _handle_client_data(self, packet_info, addr):
        """Handle a data packet from a client"""
        try:
            # Verify client is connected
            if addr not in self.active_clients or self.active_clients[addr]['state'] != ConnectionState.CONNECTED:
                logger.warning(f"Unexpected data packet from {addr}")
                return
            
            encapsulated_data = packet_info['payload']
            if not encapsulated_data:
                logger.warning(f"Empty data packet from {addr}")
                return
            
            # Parse the IP packet
            try:
                ip_packet = IP(encapsulated_data)
                
                # Validate and correct source IP if needed
                modified = False
                if ip_packet.src != self.active_clients[addr]['virtual_ip']:
                    old_src = ip_packet.src
                    ip_packet.src = self.active_clients[addr]['virtual_ip']
                    logger.warning(f"Modified source IP to {ip_packet.src}")
                    modified = True
                
                # Special handling for TCP packets
                if TCP in ip_packet:
                    tcp_segment = ip_packet[TCP]
                    
                    # If this is a SYN packet, ensure MSS is properly set
                    if tcp_segment.flags & 0x02:  # SYN flag
                        for i, option in enumerate(tcp_segment.options):
                            if option[0] == 'MSS':
                                current_mss = option[1]
                                if current_mss > VPN_MSS:
                                    # Actually update the MSS option in the packet
                                    new_options = list(tcp_segment.options)
                                    new_options[i] = ('MSS', VPN_MSS)
                                    tcp_segment.options = new_options
                                    modified = True
                                    logger.info(f"Updated SYN packet MSS from {current_mss} to {VPN_MSS}")
                    
                    # Ensure TTL is reasonable to prevent premature packet drops
                    if ip_packet.ttl < 10:
                        ip_packet.ttl = 64
                        logger.debug(f"Adjusted TTL to 64 for packet from {ip_packet.src} to {ip_packet.dst}")
                        modified = True
                    
                    # Force checksum recalculation for ALL TCP packets
                    packet_bytes = self._force_tcp_checksum_recalculation(bytes(ip_packet) if modified else encapsulated_data)
                    
                    # Log the packet forwarding
                    log_msg = f"Forwarded TCP packet from {ip_packet.src}:{ip_packet[TCP].sport} to {ip_packet.dst}:{ip_packet[TCP].dport}"
                    if ip_packet[TCP].flags & 0x02:
                        log_msg += " [SYN]"
                    elif ip_packet[TCP].flags & 0x10:
                        log_msg += " [ACK]"
                    elif ip_packet[TCP].flags & 0x01:
                        log_msg += " [FIN]"
                    elif ip_packet[TCP].flags & 0x04:
                        log_msg += " [RST]"
                    logger.info(log_msg)
                else:
                    # If packet was modified, recalculate checksums
                    if modified:
                        # Delete existing checksums to force recalculation
                        if UDP in ip_packet:
                            del ip_packet[UDP].chksum
                        del ip_packet.chksum
                        
                        # Rebuild the packet to recalculate all checksums
                        packet_bytes = bytes(ip_packet)
                    else:
                        # No changes, use original packet
                        packet_bytes = encapsulated_data
                    
                    logger.info(f"Forwarded packet from {ip_packet.src} to {ip_packet.dst} ({len(bytes(ip_packet))} bytes)")
                
                # Write the possibly modified packet to the TUN interface
                os.write(self.tun_fd, packet_bytes)
                
            except Exception as e:
                logger.warning(f"Error handling client data: {e}, trying to recover")
                
                try:
                    # Try to recover by simply forcing TCP checksum recalculation
                    recovered_packet = self._force_tcp_checksum_recalculation(encapsulated_data)
                    logger.info("Attempting packet recovery with forced checksum recalculation")
                    os.write(self.tun_fd, recovered_packet)
                except:
                    # Last resort - pass through the original packet
                    logger.warning("Recovery failed, writing original packet")
                    os.write(self.tun_fd, encapsulated_data)
            
        except Exception as e:
            logger.error(f"Error handling client data: {e}")
            logger.error(traceback.format_exc())
        
    def _is_valid_ip(self, ip_str):
        """Check if the IP address is valid"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return not ip.is_unspecified and not ip.is_loopback and not ip.is_link_local
        except ValueError:
            return False
        
    def _should_route_to_vpn_network(self, dst_ip):
        """Determine if a destination IP is within the VPN network"""
        try:
            return ipaddress.ip_address(dst_ip) in self.network
        except ValueError:
            return False
        
    def _route_to_vpn_client(self, ip_packet, src_client_addr):
        """Route packet to another VPN client"""
        try:
            dst_ip = ip_packet.dst
            
            if dst_ip in self.client_ips:
                dst_client_addr = self.client_ips[dst_ip]
                
                if dst_client_addr == src_client_addr:
                    logger.warning(f"Dropping packet addressed to its sender: {dst_ip}")
                    return
                    
                raw_packet = bytes(ip_packet)
                data_packet = self.msg_handler.create_data_packet(raw_packet, client_addr=dst_client_addr)
                
                self.udp_write_queue.put((data_packet, dst_client_addr))
                logger.debug(f"Routed packet from {src_client_addr} to VPN client {dst_client_addr}")
            else:
                logger.warning(f"Cannot route to {dst_ip}: No VPN client with this IP")
        except Exception as e:
            logger.error(f"Error routing to VPN client: {e}")

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
            
            # [RELIABILITY REMOVED] No more sending ACK packets
            
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
            ("TUN Reader", self._tun_read_worker),
            
            # Processor threads
            ("UDP Processor", self._udp_packet_processor),
            
            # Management thread
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
