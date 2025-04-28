import socket
import logging
import struct
import os
import sys
import ipaddress
import fcntl
import threading
import signal
import json
import time
import subprocess
import platform
import traceback
import time
from queue import Queue, Empty
from enum import Enum
from typing import Optional, Tuple, Dict, Any, List
from dataclasses import dataclass
from protocol import MessageHandler, MsgType, PacketFlags, ConnectionState  
try:
    import fcntl
    from scapy.all import Raw
    from scapy.layers.inet import ICMP, TCP, UDP, IP
    from scapy.layers.l2 import Ether
    from scapy.packet import Packet
except ImportError:
    print("Please install the required dependencies:")
    print("pip install scapy")
    print("pip install python-pytun")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('VPN-Client')

# IOCTL for configuring TUN/TAP interfaces
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# VPN configuration 
VPN_MTU = 1400  # Reduced from 1500 to account for VPN encapsulation
VPN_MSS = 1340  # MSS should be lower than MTU (MTU - IP header - TCP header)
KEEPALIVE_INTERVAL = 25  # Seconds
CLIENT_TIMEOUT = 90  # Seconds

SERVER_ADRESS = "10.68.121.209"
SERVER_PORT = 1194


class VPNClient:
    def __init__(self, address="0.0.0.0", port=1193, external_interface="ens33"):

        self.bind_address = address
        self.port = port

        self.server_address = SERVER_ADRESS
        self.server_port = SERVER_PORT

        self.external_interface = external_interface
        self.virtual_interface = None

        self.virtual_ip = None
        self.server_virtual_ip = None
        self.subnet_mask = None
        self.dns_servers = []
        self.routes = []
        self.VPN_MTU = VPN_MTU

        self.client_socket = None
        self.tun_fd = None

        self.udp_read_queue = Queue()    # UDP packets from clients
        self.udp_write_queue = Queue()   # UDP packets to send to clients
        self.tun_read_queue = Queue()    # Packets from TUN interface
        self.tun_write_queue = Queue()   # Packets to write to TUN interface
        self.internet_queue = Queue()   # Packets to send to the internet

        self.threads = []  # List to store threads for cleanup
        self.running = threading.Event()

        # Connection state
        self.connection_state = ConnectionState.DISCONNECTED
        self.last_activity = 0
        
        # Authentication state
        self.auth_challenge = None
        
        # Message handler
        self.msg_handler = None
        
        # Connection events
        self.connected_event = threading.Event()
        self.authenticated_event = threading.Event()

    def _subnet_mask_to_cidr(self, subnet_mask):
        """Convert a subnet mask (e.g. 255.255.255.0) to CIDR prefix length (e.g. 24)"""
        try:
            octets = subnet_mask.split('.')
            if len(octets) != 4:
                logger.warning(f"Invalid subnet mask format: {subnet_mask}, using default /24")
                return 24
                
            bit_count = 0
            for octet in octets:
                octet_int = int(octet)
                # Count the number of 1 bits in this octet
                while octet_int:
                    bit_count += octet_int & 1
                    octet_int >>= 1
                    
            return bit_count
        except Exception as e:
            logger.error(f"Error converting subnet mask to CIDR: {e}")
            return 24  # Default to /24 on error
        
    def _get_external_ip(self):
        """Get the IP address of the server's external interface"""
        try:    
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
        """Set up the TUN interface"""
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
            ifr = struct.pack("16sH", b"tun%d", IFF_TUN | IFF_NO_PI)
            ifr = fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)
            
            # Get the interface name
            self.virtual_interface = ifr[:16].strip(b'\x00').decode()
            
            # Set non-blocking mode
            flags = fcntl.fcntl(self.tun_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.tun_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            # Disable all TCP offloading features that can interfere with tunneled traffic
            os.system(f"ethtool -K {self.virtual_interface} rx off tx off sg off tso off ufo off gso off gro off lro off 2>/dev/null || true")
            if self.external_interface:
                os.system(f"ethtool -K {self.external_interface} tso off gso off 2>/dev/null || true")
                os.system(f"ethtool -K {self.external_interface} tx-checksum-ip-generic off 2>/dev/null || true")
            
            # Add comprehensive offloading disabling to ensure it's properly disabled
            self._ensure_client_offloading_disabled()
            
            logger.info(f"TUN interface '{self.virtual_interface}' created")
            
        except Exception as e:
            logger.error(f"Failed to set up TUN interface: {e}")
            raise

    def _ensure_client_offloading_disabled(self):
        """
        Ensure all offloading features are properly disabled on client interfaces
        with verification and no silent failures
        """
        logger.info("Ensuring complete offloading disabling for client...")
        
        # Features that might be silently failing with "|| true" in the original code
        essential_features = [
            "rx", "tx", "sg", "tso", "ufo", "gso", "gro", "lro"
        ]
        
        # Additional features that should be disabled on client
        additional_features = [
            "tx-checksum-ip-generic", "rx-checksum", "tx-checksum-ipv4",
            "tx-checksum-ipv6", "tx-nocache-copy", "rx-gro-hw"
        ]
        
        # Critical: Ensure proper disabling on virtual interface
        if self.virtual_interface:
            logger.info(f"Ensuring offloading features disabled on {self.virtual_interface}...")
            
            # First try combined disabling for essential features (no || true)
            essential_str = " ".join([f"{f} off" for f in essential_features])
            result = os.system(f"ethtool -K {self.virtual_interface} {essential_str} 2>/dev/null")
            
            # If combined fails, try individual disabling with verification
            if result != 0:
                for feature in essential_features:
                    cmd = f"ethtool -K {self.virtual_interface} {feature} off"
                    result = os.system(cmd)
                    if result != 0:
                        logger.warning(f"Failed to disable {feature} on {self.virtual_interface}")
            
            # Additional features
            for feature in additional_features:
                os.system(f"ethtool -K {self.virtual_interface} {feature} off 2>/dev/null")
            
            # Verify settings
            try:
                output = subprocess.check_output(
                    f"ethtool -k {self.virtual_interface} | grep -E 'tcp-segmentation-offload|generic-segmentation-offload|tx-checksumming|rx-checksumming'", 
                    shell=True, stderr=subprocess.PIPE, text=True
                )
                logger.info(f"Virtual interface offloading status:\n{output.strip()}")
            except Exception as e:
                logger.warning(f"Could not verify offloading settings on {self.virtual_interface}: {e}")
        
        # Critical: The external interface needs more disabling than original code provides
        if self.external_interface:
            logger.info(f"Ensuring sufficient offloading disabled on {self.external_interface}...")
            
            # External interface needs more features disabled than in original code
            external_features = [
                "tso", "gso", "tx-checksum-ip-generic", "tx-checksum-ipv4", 
                "tx-checksum-ipv6", "rx-checksum", "sg"
            ]
            
            for feature in external_features:
                cmd = f"ethtool -K {self.external_interface} {feature} off"
                result = os.system(cmd)
                if result != 0:
                    logger.warning(f"Failed to disable {feature} on {self.external_interface}")
            
            # Verify settings
            try:
                output = subprocess.check_output(
                    f"ethtool -k {self.external_interface} | grep -E 'tcp-segmentation-offload|generic-segmentation-offload|tx-checksumming|rx-checksumming'", 
                    shell=True, stderr=subprocess.PIPE, text=True
                )
                logger.info(f"External interface offloading status:\n{output.strip()}")
            except Exception as e:
                logger.warning(f"Could not verify offloading settings on {self.external_interface}: {e}")
        
        # Client-specific kernel parameters (only ones not already in _setup_client_nat)
        client_params = {
            "net.ipv4.tcp_mtu_probing": "1",       # Enable MTU probing
            "net.ipv4.tcp_timestamps": "1",        # Important for accurate RTT calculation
            "net.ipv4.tcp_thin_dupack": "1",       # Better retransmit for thin streams
            "net.ipv4.tcp_early_retrans": "1"      # Faster recovery from packet loss
        }
        
        for param, value in client_params.items():
            os.system(f"sysctl -w {param}={value} 2>/dev/null")
        
        # Force rp_filter again (critical for client)
        if self.virtual_interface:  
            os.system(f"sysctl -w net.ipv4.conf.{self.virtual_interface}.rp_filter=0")
        os.system("sysctl -w net.ipv4.conf.all.rp_filter=0")
        os.system("sysctl -w net.ipv4.conf.default.rp_filter=0")
        
        logger.info("Client offloading and TCP parameters verification complete")

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

    def _setup_client_nat(self):
        """Set up NAT and routing for the VPN client"""
        try:
            # Enable IP forwarding
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            
            # Get subnet from virtual IP and mask
            cidr_prefix = self._subnet_mask_to_cidr(self.subnet_mask)
            vpn_subnet = f"{self.server_virtual_ip}/{cidr_prefix}"
            
            # Clear existing rules that might conflict
            os.system("ip rule flush")
            os.system("ip route flush table 200")
            
            # Add default rules back
            os.system("ip rule add from all lookup main pref 32766")
            os.system("ip rule add from all lookup default pref 32767")
            
            # Create VPN routing table
            # Default route via VPN server's virtual IP
            os.system(f"ip route add default via {self.server_virtual_ip} dev {self.virtual_interface} table 200")
            
            # Add route for the entire VPN subnet in both main and VPN tables
            os.system(f"ip route add {vpn_subnet} dev {self.virtual_interface}")
            os.system(f"ip route add {vpn_subnet} dev {self.virtual_interface} table 200")
            
            # Make sure traffic to the VPN server's real IP goes through physical interface
            os.system(f"ip rule add to {self.server_address}/32 table main")
            
            # *** CRITICAL FOR RETURN TRAFFIC ***
            # This ensures packets FOR our virtual IP arrive correctly
            os.system(f"ip rule add to {self.virtual_ip}/32 table main")
            
            # Route traffic FROM our virtual IP through the VPN
            os.system(f"ip rule add from {self.virtual_ip} table 200")
            
            # Enable connection tracking and state management
            os.system("sysctl -w net.netfilter.nf_conntrack_max=65536 2>/dev/null || sysctl -w net.nf_conntrack_max=65536 2>/dev/null")
            os.system("sysctl -w net.ipv4.tcp_sack=1")
            os.system("sysctl -w net.ipv4.tcp_window_scaling=1")
            
            # Set up iptables MSS clamping for TCP connections
            # Clear existing rules
            os.system("iptables -t mangle -F POSTROUTING 2>/dev/null || true")
            os.system("iptables -t mangle -F OUTPUT 2>/dev/null || true")
            
            # Add MSS clamping rules to ensure TCP connections work
            os.system(f"iptables -t mangle -A POSTROUTING -o {self.virtual_interface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {VPN_MSS}")
            os.system(f"iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {VPN_MSS}")
            os.system(f"iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
            
            # *** ADDED: ENSURE PROPER CONNECTION TRACKING ***
            # Accept established and related connections
            os.system(f"iptables -A INPUT -i {self.virtual_interface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
            os.system(f"iptables -A OUTPUT -o {self.virtual_interface} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
            
            # Accept all traffic on the TUN interface
            os.system(f"iptables -A INPUT -i {self.virtual_interface} -j ACCEPT")
            os.system(f"iptables -A OUTPUT -o {self.virtual_interface} -j ACCEPT")
            
            # Enable Path MTU Discovery
            os.system("sysctl -w net.ipv4.ip_no_pmtu_disc=0")
            
            # Disable ICMP redirects
            os.system("sysctl -w net.ipv4.conf.all.send_redirects=0")
            os.system("sysctl -w net.ipv4.conf.all.accept_redirects=0")
            
            # *** CRITICAL: Disable reverse path filtering on the VPN interface ***
            # This ensures packets with "asymmetric routing" aren't dropped
            os.system(f"sysctl -w net.ipv4.conf.{self.virtual_interface}.rp_filter=0")
            os.system("sysctl -w net.ipv4.conf.all.rp_filter=0")
            
            # Verify configuration
            route_table = os.popen("ip route").read()
            logger.info(f"Routing table:\n{route_table}")
            
            routing_rules = os.popen("ip rule list").read()
            logger.info(f"Routing rules:\n{routing_rules}")
            
            mss_rules = os.popen("iptables -t mangle -L -v -n").read()
            logger.info(f"MSS clamping rules:\n{mss_rules}")
            
            logger.info("Client routing and NAT configured properly")
            
        except Exception as e:
            logger.error(f"Failed to set up client NAT: {e}")
            raise

    def _configure_tun(self, config):
        """Configure the TUN interface with the received settings"""
        try:
            self.virtual_ip = config['virtual_ip']
            self.server_virtual_ip = config['server_ip']
            self.subnet_mask = config['subnet_mask']
            self.dns_servers = config['dns_servers']
            self.routes = config['routes']
            self.VPN_MTU = config['mtu']

            cidr_prefix = self._subnet_mask_to_cidr(self.subnet_mask)
            logger.info(f"Converted subnet mask {self.subnet_mask} to CIDR prefix /{cidr_prefix}")
            
            # Configure interface
            os.system(f"ip link set dev {self.virtual_interface} up")
            os.system(f"ip addr add {self.virtual_ip}/{cidr_prefix} dev {self.virtual_interface}")
            os.system(f"ip link set dev {self.virtual_interface} mtu {self.VPN_MTU}")

            # Setup NAT and routing
            self._setup_client_nat()
            
            # Add routes
            for route in self.routes:
                if route == '0.0.0.0/0':
                    # Default route needs a gateway
                    os.system(f"ip route add default via {self.server_virtual_ip} dev {self.virtual_interface} metric 10")
                else:
                    # Other routes can be added without gateway
                    os.system(f"ip route add {route} dev {self.virtual_interface}")
            
            # Configure DNS resolution
            # First backup the existing resolv.conf
            os.system("cp /etc/resolv.conf /etc/resolv.conf.vpn_backup")
            
            # Create a new resolv.conf with the VPN DNS servers
            with open('/etc/resolv.conf', 'w') as f:
                for dns in self.dns_servers:
                    f.write(f"nameserver {dns}\n")
            
            # Restart nscd if it exists (DNS cache daemon)
            os.system("systemctl restart nscd 2>/dev/null || service nscd restart 2>/dev/null || true")
            
            logger.info(f"TUN interface configured with IP {self.virtual_ip} and MTU {self.VPN_MTU}")
            logger.info(f"DNS servers: {', '.join(self.dns_servers)}")
            
        except Exception as e:
            logger.error(f"Failed to configure TUN interface: {e}")
            raise

    def _cleanup_client_nat(self):
        """Clean up client NAT rules"""
        try:
            # Remove MASQUERADE rule
            os.system(f"iptables -t nat -D POSTROUTING -o {self.external_interface} -j MASQUERADE")
            
            # Remove SNAT rule
            os.system(f"iptables -t nat -D POSTROUTING -s {self.external_interface_ip} -o {self.virtual_interface} -j SNAT --to-source {self.virtual_ip}")
            
            # Remove forwarding rules
            os.system(f"iptables -D FORWARD -i {self.external_interface} -o {self.virtual_interface} -j ACCEPT")
            os.system(f"iptables -D FORWARD -i {self.virtual_interface} -o {self.external_interface} -j ACCEPT")
            
            # Remove packet marking
            os.system(f"iptables -t mangle -D OUTPUT -d {self.server_address} -j MARK --set-mark 1")
            os.system("ip rule del fwmark 1 table 100")
            os.system("ip route flush table 100")
            
            logger.info("Client NAT cleanup complete")
        except Exception as e:
            logger.error(f"Error cleaning up client NAT: {e}")

    def _shutdown_tun(self):
        """Clean up the TUN interface"""
        try:
            if self.virtual_interface:
                # Remove routes
                for route in self.routes:
                    try:
                        os.system(f"ip route del {route} dev {self.virtual_interface}")
                    except:
                        pass
                
                # Remove IP address and shut down interface
                os.system(f"ip addr flush dev {self.virtual_interface}")
                os.system(f"ip link set dev {self.virtual_interface} down")
                
            if self.tun_fd is not None:
                os.close(self.tun_fd)
                self.tun_fd = None
                
            logger.info("TUN interface shut down")
            
        except Exception as e:
            logger.error(f"Error shutting down TUN interface: {e}")

    def _set_up_socket(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Increase socket buffer sizes for better performance
            self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)  # 1MB receive buffer
            self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)  # 1MB send buffer
            
            self.client_socket.settimeout(0.1)  # Set a timeout for recvfrom
            self.client_socket.bind((self.bind_address, self.port))
            logger.info(f"Socket bound to {self.bind_address}:{self.port} with 1MB buffers")
        except socket.error as e:
            logger.error(f"Socket error: {e}")
            raise

    def _shutdown_socket(self):
        """Clean up the socket"""
        try:
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
            logger.info("Socket closed")
        except Exception as e:
            logger.error(f"Error closing socket: {e}")

    def start_client(self):
        """Initialize and start the VPN client"""
        if self.running.is_set():
            logger.warning("Client is already running")
            return
        
        try:
            self.msg_handler = MessageHandler('client')

            self.external_interface_ip = self._get_external_ip()

            logger.info(f"Using real IP address: {self.external_interface_ip}")

            self._set_up_tun()
            self._set_up_socket()

            # Set up the message handler with a packet send callback that uses the write queue
            self.msg_handler.register_packet_callback(
                lambda packet: self.udp_write_queue.put(packet)
            )

            self.running.set()
            logger.info("VPN client started successfully")
        except Exception as e:
            logger.error(f"Failed to start client: {e}")
            self.stop_client()  # Clean up any partially initialized resources
            raise

    def stop_client(self):
        """Stop the client and clean up resources"""
        if not self.running.is_set():
            logger.warning("Client is not running")
            return
            
        logger.info("Shutting down VPN client...")
        
        # Send disconnect message if we're connected
        if self.connection_state == ConnectionState.CONNECTED:
            try:
                disconnect_packet = self.msg_handler.create_disconnect_packet("Client shutting down")
                self.client_socket.sendto(disconnect_packet, (self.server_address, self.server_port))
                logger.info("Sent disconnect message to server")
            except:
                pass
        
        # Signal all threads to stop
        self.running.clear()
        
        # Wait for threads to stop
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2)
                if thread.is_alive():
                    logger.warning(f"Thread {thread.name} did not terminate gracefully")
        
        # Clean up iptables rules
        os.system(f"iptables -t mangle -D POSTROUTING -o {self.virtual_interface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {VPN_MSS} 2>/dev/null || true")
        os.system(f"iptables -t mangle -D OUTPUT -o {self.virtual_interface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {VPN_MSS} 2>/dev/null || true")
        
        # Restore original DNS configuration
        if os.path.exists("/etc/resolv.conf.vpn_backup"):
            os.system("mv /etc/resolv.conf.vpn_backup /etc/resolv.conf")
            logger.info("Restored original DNS configuration")
        
        # Clean up routing
        if self.virtual_interface:
            try:
                os.system(f"ip rule del from {self.virtual_ip} table 200 2>/dev/null || true")
                os.system(f"ip route flush table 200 2>/dev/null || true")
            except:
                pass
        
        self._shutdown_tun()
        self._shutdown_socket()
        
        self.connection_state = ConnectionState.DISCONNECTED
        self.connected_event.clear()
        self.authenticated_event.clear()
        
        logger.info("Client shutdown complete")

    # ============================
    # === Worker Threads Start ===
    # ============================

    def _udp_read_worker(self):
        while self.running.is_set():
            try:
                data, addr = self.client_socket.recvfrom(VPN_MTU)
                if addr[0] == self.bind_address:
                    # Ignore packets sent by the server itself
                    continue
                # Put the received data into the queue for processing
                self.udp_read_queue.put((data, addr))
                
            except socket.timeout:
                # Socket timeout - no data received
                continue
            except BlockingIOError:
                # Socket is not ready for reading
                continue
            except socket.error as e:
                logger.error(f"Socket error: {e}")
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error in UDP read loop: {e}")
                time.sleep(0.1)  # Avoid spinning too fast on errors

    
    def _udp_packet_processor(self):
        """Process packets received from the server via UDP"""
        logger.info("UDP packet processor started")
        
        while self.running.is_set():
            try:

                data, addr = self.udp_read_queue.get(timeout=0.1)
                server_ip, server_port = addr
                
                # Only process packets from the configured server
                if server_ip != self.server_address or server_port != self.server_port:
                    logger.warning(f"Received packet from unknown source: {addr}")
                    self.udp_read_queue.task_done()
                    continue
                
                # Parse the packet using the protocol handler
                packet_info = self.msg_handler.process_packet(data)
                
                if 'error' in packet_info:
                    logger.debug(f"Invalid packet from server: {packet_info['error']}")
                    self.udp_read_queue.task_done()
                    continue
                
                # Update last activity time
                self.last_activity = time.time()
                
                # Get the message type
                msg_type = packet_info.get('type')
                
                # Handle the packet based on its type
                if msg_type == MsgType.Authenticate:
                    self._handle_auth_challenge(packet_info)
                    
                elif msg_type == MsgType.Config:
                    self._handle_config(packet_info)
                    
                elif msg_type == MsgType.Data:
                    self._handle_data(packet_info)
                    
                elif msg_type == MsgType.KeepAlive:
                    self._handle_keepalive(packet_info)
                    
                elif msg_type == MsgType.Disconnect:
                    self._handle_disconnect(packet_info)
                    
                elif msg_type == MsgType.Error:
                    self._handle_error(packet_info)
                    
                elif msg_type == MsgType.Ack:
                    pass
                    
                elif msg_type == MsgType.Retransmit:
                    pass
                    
                elif msg_type == MsgType.Mtu:
                    self._handle_mtu(packet_info)
                    
                else:
                    logger.warning(f"Unhandled message type {msg_type} from server")
                
                # Mark task as done
                self.udp_read_queue.task_done()
                
            except Empty:
                # No data available, just continue
                time.sleep(0.1)
                continue
            except Exception as e:
                if self.running.is_set():
                    logger.error(f"Error processing UDP packet: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    time.sleep(0.1)


    def _udp_write_worker(self):
        """Worker thread to send packets to the server via UDP"""
        logger.info("UDP write worker started")
        
        while self.running.is_set():
            try:
                try:
                    data = self.udp_write_queue.get(timeout=0.1)
                    
                    self.client_socket.sendto(data, (self.server_address, self.server_port))
                    
                    self.udp_write_queue.task_done()
                    
                except Empty:
                    if (self.connection_state == ConnectionState.CONNECTED and 
                        time.time() - self.last_activity > KEEPALIVE_INTERVAL):
                        keepalive = self.msg_handler.create_keepalive_packet()
                        self.udp_write_queue.put(keepalive)
                        self.last_activity = time.time()
                        logger.debug("Queued keepalive to server")
                    time.sleep(0.1)

            except socket.timeout:
                time.sleep(0.01)
                continue
            except BlockingIOError:
                time.sleep(0.01)
                continue
            except socket.error as e:
                logger.error(f"Socket error: {e}")
                time.sleep(0.1)
            except Exception as e:
                if self.running.is_set():
                    logger.error(f"Error in UDP write worker: {e}")
                    time.sleep(0.1)

    def _tun_read_worker(self):
        """Worker thread to read from TUN interface and forward to the VPN server"""
        logger.info("TUN read worker started")
        
        packet_counter = 0
        last_stats = time.time()
        
        while self.running.is_set():
            try:
                if self.connection_state == ConnectionState.CONNECTED and self.tun_fd is not None:
                    try:
                        packet = os.read(self.tun_fd, self.VPN_MTU)
                        
                        if packet:
                            
                            # Process the packet
                            processed_packet = self._process_outbound_packet(packet)
                            
                            if processed_packet:
                                # Create VPN data packet
                                data_packet = self.msg_handler.create_data_packet(processed_packet)

                                processed_packet = IP(processed_packet)
                                logger.info(f"Sending packet to server: {processed_packet.summary()}")
                                
                                # Queue for sending to the server
                                self.udp_write_queue.put(data_packet)
                                
                    except BlockingIOError:
                        # No data available on non-blocking read
                        pass
                    except Exception as e:
                        logger.error(f"Error reading from TUN: {e}")
                        import traceback
                        logger.error(traceback.format_exc())
                
                # Small sleep to prevent CPU spinning
                time.sleep(0.001)
                    
            except Exception as e:
                if self.running.is_set():
                    logger.error(f"Error in TUN read worker: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
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
                time.sleep(0.1)
                continue
            except Exception as e:
                if self.running.is_set():
                    logger.error(f"Error in TUN write worker: {e}")
                    time.sleep(0.1)

    def _connection_manager_worker(self):
        """Worker thread for managing the VPN connection"""
        logger.info("Connection manager worker started")
        
        last_keepalive = time.time()
        
        while self.running.is_set():
            try:
                now = time.time()
                
                # Only perform connection management when connected
                if self.connection_state == ConnectionState.CONNECTED:
                    if now - self.last_activity > CLIENT_TIMEOUT:
                        logger.warning(f"Server timeout detected. Last activity: {int(now - self.last_activity)} seconds ago")
                        
                        # Send one final keepalive to check if server is responsive
                        keepalive = self.msg_handler.create_keepalive_packet()
                        self.udp_write_queue.put(keepalive)
                        logger.info("Sent final keepalive attempt before reconnect")
                        
                        # Wait briefly for a response
                        time.sleep(2)
                        
                        if now - self.last_activity > CLIENT_TIMEOUT:
                            logger.error("Connection to server lost, attempting to reconnect")
                            self.connection_state = ConnectionState.DISCONNECTED
                            self.connected_event.clear()
                            
                            # Clean up current resources
                            try:
                                self._shutdown_tun()
                                self._set_up_tun()
                            except Exception as e:
                                logger.error(f"Error recreating TUN interface: {e}")
                                time.sleep(5)
                                continue
                            
                            # Try to reconnect
                            logger.info("Attempting to reconnect...")
                            self.connect_to_server()
                    
                    # Send periodic keepalives when due
                    elif now - last_keepalive > KEEPALIVE_INTERVAL:
                        keepalive = self.msg_handler.create_keepalive_packet()
                        self.udp_write_queue.put(keepalive)
                        logger.debug("Sent keepalive to server")
                        last_keepalive = now
                
                # If we're in ERROR state, attempt recovery
                elif self.connection_state == ConnectionState.ERROR:
                    logger.warning("Connection in ERROR state, attempting to recover")
                    # Wait a bit before retrying
                    time.sleep(5)
                    self.connection_state = ConnectionState.DISCONNECTED
                    
                    # Clean up and recreate resources
                    try:
                        self._shutdown_tun()
                        self._set_up_tun()
                    except Exception as e:
                        logger.error(f"Error recreating TUN interface: {e}")
                        time.sleep(5)
                        continue
                    
                    self.connect_to_server()
                
                time.sleep(5)
                
            except Exception as e:
                if self.running.is_set():
                    logger.error(f"Error in connection manager worker: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    time.sleep(5)

    # ==========================
    # === Worker Threads End ===
    # ==========================

    #==============================
    # === Server Handling Start ===
    #==============================

    def connect_to_server(self, timeout=30):
        """
        Initiate connection to the VPN server and wait for it to complete
        
        Returns:
            bool: True if connection was successful, False otherwise
        """
        if self.connection_state == ConnectionState.CONNECTED:
            logger.info("Already connected to server")
            return True
        
        self.connected_event.clear()
        self.authenticated_event.clear()
        
        self.connection_state = ConnectionState.CONNECTING
        
        try:
            client_info = {
                'protocol_version': 1,
                'client_version': '1.0',
                'platform': platform.system(),
                'capabilities': ['compression', 'encryption']
            }
            
            request_packet = self.msg_handler.create_request_packet(client_info)
            self.udp_write_queue.put(request_packet)
            
            logger.info(f"Sent connection request to {self.server_address}:{self.server_port}")
            
            if self.connected_event.wait(timeout):
                logger.info("Connected to server successfully")
                return True
            else:
                logger.error("Connection timed out")
                self.connection_state = ConnectionState.DISCONNECTED
                return False
            
        except Exception as e:
            logger.error(f"Error connecting to server: {e}")
            self.connection_state = ConnectionState.DISCONNECTED
            return False
        
    def _handle_auth_challenge(self, packet_info):
        """Handle an authentication challenge from the server"""
        try:
            if self.connection_state != ConnectionState.CONNECTING:
                logger.warning("Received authentication challenge in unexpected state")
                return
            
            self.connection_state = ConnectionState.AUTHENTICATING
            
            self.auth_challenge = packet_info['payload']
            
            auth_response = self.msg_handler.create_auth_response_packet(self.auth_challenge)
            
            self.udp_write_queue.put(auth_response)
            
            logger.info("Sent authentication response to server")
            
        except Exception as e:
            logger.error(f"Error handling authentication challenge: {e}")
            self.connection_state = ConnectionState.ERROR

    def _handle_config(self, packet_info):
        """Handle configuration packet from the server"""
        try:
            # Check if we're in the correct state
            if self.connection_state != ConnectionState.AUTHENTICATING:
                logger.warning("Received config packet in unexpected state")
                return
            
            # Parse the configuration data
            config_json = packet_info['payload']
            try:
                # Convert bytes to string and parse JSON
                config = json.loads(config_json.decode('utf-8'))
                logger.info(f"Received configuration packet from server:\n{config}")
                
                # Configure the TUN interface with the received settings
                self._configure_tun(config)
            except json.JSONDecodeError:
                logger.error("Failed to parse configuration JSON")
                self.connection_state = ConnectionState.ERROR
                return
            
            # Send establish packet to confirm configuration received
            establish_packet = self.msg_handler.create_establish_packet()
            self.udp_write_queue.put(establish_packet)
            logger.info("Sent establish confirmation to server")
            
            # Update state AFTER sending establish packet
            self.connection_state = ConnectionState.CONNECTED
            
            # Set the connected event
            self.connected_event.set()
            
            logger.info("VPN client configured and connected to server")
            
        except Exception as e:
            logger.error(f"Error handling config packet: {e}")
            self.connection_state = ConnectionState.ERROR

    def _handle_data(self, packet_info):
        """Handle data packets from the server"""
        try:
            encapsulated_data = packet_info['payload']
            if not encapsulated_data:
                logger.warning(f"Empty data packet from Server")
                return
            
            # Parse the packet for processing and logging
            try:
                ip_packet = IP(encapsulated_data)
                
                # Track if packet needs modification
                modified = False
                
                # Validate the destination is actually our virtual IP
                # Don't modify destination - it might be broadcast or multicast traffic
                if ip_packet.dst != self.virtual_ip and not ip_packet.dst.startswith('255.'):
                    logger.warning(f"Received packet destined for {ip_packet.dst} but our VPN IP is {self.virtual_ip}")
                
                # Ensure TTL is reasonable to prevent premature packet drops
                if ip_packet.ttl < 10:
                    ip_packet.ttl = 64
                    logger.debug(f"Adjusted TTL to 64 for packet from {ip_packet.src} to {ip_packet.dst}")
                    modified = True
                
                # Special handling for TCP packets
                if TCP in ip_packet:
                    tcp_packet = ip_packet[TCP]
                    
                    # Check if it's a SYN packet with an MSS option
                    if tcp_packet.flags & 0x02:  # SYN flag
                        for i, option in enumerate(tcp_packet.options):
                            if option[0] == 'MSS':
                                current_mss = option[1]
                                if current_mss > VPN_MSS:
                                    # Update the MSS option
                                    new_options = list(tcp_packet.options)
                                    new_options[i] = ('MSS', VPN_MSS)
                                    tcp_packet.options = new_options
                                    modified = True
                                    logger.info(f"Updated SYN packet MSS from {current_mss} to {VPN_MSS}")
                    
                    # Log TCP-specific details
                    tcp_flags = tcp_packet.flags
                    flag_str = []
                    if tcp_flags & 0x02: flag_str.append("SYN")
                    if tcp_flags & 0x10: flag_str.append("ACK")
                    if tcp_flags & 0x01: flag_str.append("FIN")
                    if tcp_flags & 0x04: flag_str.append("RST")
                    flag_str = "-".join(flag_str) if flag_str else "None"
                    
                    logger.info(f"Received TCP packet: {ip_packet.src}:{tcp_packet.sport} -> "
                            f"{ip_packet.dst}:{tcp_packet.dport} [Flags: {flag_str}]")
                    
                    # Force checksum recalculation for ALL TCP packets
                    packet_to_write = self._force_tcp_checksum_recalculation(encapsulated_data)
                else:
                    # If packet was modified, recalculate checksums
                    if modified:
                        # Delete existing checksums to force recalculation
                        if UDP in ip_packet:
                            del ip_packet[UDP].chksum
                        del ip_packet.chksum
                        
                        # Rebuild the packet to recalculate checksums
                        packet_to_write = bytes(ip_packet)
                    else:
                        # Use original packet if no modifications
                        packet_to_write = encapsulated_data
                    
                    logger.info(f"Received data packet from server: {ip_packet.summary()}")
                
                # Write to TUN interface
                os.write(self.tun_fd, packet_to_write)
                
            except Exception as e:
                logger.warning(f"Error parsing/modifying packet: {e}")
                # Still try to write the original packet
                os.write(self.tun_fd, encapsulated_data)
                
        except Exception as e:
            logger.error(f"Error handling data packet: {e}")
            import traceback
            logger.error(traceback.format_exc())

    def _process_outbound_packet(self, packet):
        """Process an outbound packet before sending it through the VPN"""
        try:
            # Parse the packet
            ip_packet = IP(packet)
            
            # Track if packet needs modification
            modified = False
            
            # Ensure source IP is correct
            if ip_packet.src != self.virtual_ip and not self._is_unspecified_ip(ip_packet.src):
                ip_packet.src = self.virtual_ip
                modified = True
                logger.debug(f"Corrected source IP to {self.virtual_ip}")
            
            # Make sure TTL is reasonable
            if ip_packet.ttl < 10:
                ip_packet.ttl = 64
                modified = True
                logger.debug(f"Adjusted TTL to 64 for outbound packet")
            
            # Special TCP handling for all TCP packets
            if TCP in ip_packet:
                tcp_packet = ip_packet[TCP]
                
                # Handle MSS in SYN packets
                if tcp_packet.flags & 0x02:  # SYN flag
                    mss_value = None
                    for i, option in enumerate(tcp_packet.options):
                        if option[0] == 'MSS':
                            mss_value = option[1]
                            if mss_value > VPN_MSS:
                                # Update the MSS option
                                new_options = list(tcp_packet.options)
                                new_options[i] = ('MSS', VPN_MSS)
                                tcp_packet.options = new_options
                                modified = True
                                logger.info(f"Updated outbound SYN packet MSS from {mss_value} to {VPN_MSS}")
                    
                    logger.info(f"Outbound TCP SYN: {ip_packet.src}:{tcp_packet.sport} -> {ip_packet.dst}:{tcp_packet.dport} (MSS: {mss_value})")
                elif tcp_packet.flags & 0x04:  # RST flag
                    logger.info(f"Outbound TCP RST: {ip_packet.src}:{tcp_packet.sport} -> {ip_packet.dst}:{tcp_packet.dport}")
                elif tcp_packet.flags & 0x01:  # FIN flag
                    logger.info(f"Outbound TCP FIN: {ip_packet.src}:{tcp_packet.sport} -> {ip_packet.dst}:{tcp_packet.dport}")
                else:
                    logger.debug(f"Outbound TCP: {ip_packet.src}:{tcp_packet.sport} -> {ip_packet.dst}:{tcp_packet.dport} flags={tcp_packet.flags}")
                
                # Always force checksum recalculation for TCP packets
                return self._force_tcp_checksum_recalculation(packet if not modified else bytes(ip_packet))
            
            # For non-TCP packets, if modified, recalculate checksums
            if modified:
                # Delete existing checksums to force recalculation
                if UDP in ip_packet:
                    del ip_packet[UDP].chksum
                del ip_packet.chksum
                
                # Rebuild the packet with recalculated checksums
                return bytes(ip_packet)
            else:
                # Return original packet if no modifications
                return packet
                
        except Exception as e:
            logger.error(f"Error processing outbound packet: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # Return original packet if there was an error in processing
            return packet
        
    def _get_port(self, packet):
        """Helper method to get the source port from a packet"""
        if packet.haslayer(TCP):
            return packet[TCP].sport
        elif packet.haslayer(UDP):
            return packet[UDP].sport
        return None

    def _get_dst_port(self, packet):
        """Helper method to get the destination port from a packet"""
        if packet.haslayer(TCP):
            return packet[TCP].dport
        elif packet.haslayer(UDP):
            return packet[UDP].dport
        return None
    
    def _is_unspecified_ip(self, ip_str):
        """Check if the IP address is unspecified (0.0.0.0) or invalid"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_unspecified
        except ValueError:
            return True

    def _handle_keepalive(self, packet_info):
        """Handle a keepalive packet from the server"""
        try:
            # Update last activity time
            self.last_activity = time.time()
            
            # Log the keepalive (optional)
            logger.debug(f"Received keepalive from server")
            
            # For keepalives, we don't need to send an acknowledgment to avoid unnecessary traffic
            # However, this is a good place to verify the connection is still healthy
            
        except Exception as e:
            logger.error(f"Error handling server keepalive: {e}")

    def _handle_mtu(self, packet_info):
        """Handle an MTU discovery packet from the server"""
        try:
            if len(packet_info['payload']) >= 4:
                # Extract the MTU size from the payload
                mtu_size = struct.unpack('>I', packet_info['payload'][:4])[0]
                logger.info(f"Received MTU discovery packet suggesting MTU: {mtu_size}")
                
                # If our MTU doesn't match, update it
                if self.VPN_MTU != mtu_size:
                    old_mtu = self.VPN_MTU
                    self.VPN_MTU = mtu_size
                    
                    # Only update the interface if we're connected
                    if self.connection_state == ConnectionState.CONNECTED and self.virtual_interface:
                        try:
                            os.system(f"ip link set dev {self.virtual_interface} mtu {self.VPN_MTU}")
                            logger.info(f"Updated TUN interface MTU from {old_mtu} to {self.VPN_MTU}")
                        except Exception as e:
                            logger.error(f"Failed to update interface MTU: {e}")
                    
            else:
                logger.warning("Invalid MTU packet from server (payload too small)")
                
        except Exception as e:
            logger.error(f"Error handling MTU packet: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
    def _handle_disconnect(self, packet_info):
        """Handle a disconnect request from the server"""
        try:
            # Decode the reason from the payload
            reason = packet_info['payload'].decode('utf-8') if packet_info['payload'] else "Server requested disconnection"
            
            logger.info(f"Server requested disconnection: {reason}")
            
            # [RELIABILITY REMOVED] No more sending ACK packets
            
            # Update connection state
            self.connection_state = ConnectionState.DISCONNECTED
            self.connected_event.clear()
            
            # Clean up resources (but don't fully stop the client)
            self._shutdown_tun()
            
            # If this was unexpected, you could add reconnection logic here
            
        except Exception as e:
            logger.error(f"Error handling server disconnect: {e}")
            import traceback
            logger.error(traceback.format_exc())


    def _handle_error(self, packet_info):
        """Handle an error message from the server"""
        try:
            # Decode error message from payload
            error_msg = packet_info['payload'].decode('utf-8') if packet_info['payload'] else "Unknown error"
            
            logger.error(f"Received error from server: {error_msg}")
            
            # Depending on the error, we might want to change connection state
            if "Authentication failed" in error_msg:
                self.connection_state = ConnectionState.ERROR
                self.authenticated_event.clear()
                logger.error("Authentication failed")
            elif "No available IP addresses" in error_msg:
                self.connection_state = ConnectionState.ERROR
                logger.error("Server cannot allocate IP address")
            else:
                # For other errors, we might want to try reconnecting
                self.connection_state = ConnectionState.ERROR
                
            # Send acknowledgment for the error packet
            ack_packet = self.msg_handler.create_ack_packet(packet_info['seq_num'])
            self.udp_write_queue.put(ack_packet)
            
        except Exception as e:
            logger.error(f"Error handling server error message: {e}")
            import traceback
            logger.error(traceback.format_exc())

    def _handle_retransmit(self, packet_info):
        """Handle a retransmission request from the server"""
        try:
            if len(packet_info['payload']) >= 4:
                seq_num = struct.unpack('>I', packet_info['payload'][:4])[0]
                logger.debug(f"Received retransmission request for packet {seq_num}")
                
                if seq_num in self.msg_handler.unacked_packets:
                    packet, _, _ = self.msg_handler.unacked_packets[seq_num]
                    self.udp_write_queue.put(packet)
                    logger.debug(f"Retransmitting packet {seq_num}")
                else:
                    logger.warning(f"Cannot retransmit packet {seq_num}: not found")
            else:
                logger.warning("Invalid retransmit request from server")
        except Exception as e:
            logger.error(f"Error handling retransmit request: {e}")
            import traceback
            logger.error(traceback.format_exc())


    # ===========================
    # === Server Handling End ===
    # ===========================


    def run_client(self):
        """Start all worker threads"""
        if not self.running.is_set():
            logger.error("Client not started. Call start_client() first.")
            return
        
        # Define all worker threads
        thread_specs = [
            # I/O threads
            ("UDP Reader", self._udp_read_worker),
            ("UDP Writer", self._udp_write_worker),
            ("TUN Reader", self._tun_read_worker),
            # ("TUN Writer", self._tun_write_worker),
            
            # # Processor threads
            ("UDP Processor", self._udp_packet_processor),
            # ("TUN Processor", self._tun_packet_processor),
            
            # # Management thread
            ("Client Manager", self._connection_manager_worker),
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

        # Connect to the server
        self.connect_to_server()

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

def set_signal_handler(vpn_client):
    """Set up signal handlers to gracefully shutdown the server"""
    def signal_handler(sig, frame):
        sig_name = signal.Signals(sig).name
        logger.info(f"Received signal {sig_name} ({sig}). Shutting down...")
        vpn_client.stop_client()
        sys.exit(0)
    
    # Register handlers for various signals
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination request
    signal.signal(signal.SIGHUP, signal_handler)   # Terminal closed
    
    logger.info("Signal handlers registered")


def main():
    try:
        check_linux_and_sudo()

        vpn_client = VPNClient()
        
        # Set up signal handlers before starting the server
        set_signal_handler(vpn_client)
        
        vpn_client.start_client()

        vpn_client.run_client()

        logger.info("VPN client started successfully")

        # Main loop
        logger.info("Client running. Press Ctrl+C to stop.")
        while vpn_client.running.is_set():
            time.sleep(1)
            
    except KeyboardInterrupt:
        # This should be caught by the signal handler, but just in case
        logger.info("Keyboard interrupt received. Shutting down...")
    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
    finally:
        # Ensure resources are cleaned up even if an exception occurs
        if 'vpn_client' in locals():
            vpn_client.stop_client()
        logger.info("Client shutdown complete")

if __name__ == "__main__":
    main()
