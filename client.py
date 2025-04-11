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
VPN_MTU = 1500  # Maximum transmission unit for VPN packets
KEEPALIVE_INTERVAL = 25  # Seconds
CLIENT_TIMEOUT = 90  # Seconds

SERVER_ADRESS = "192.168.68.118"
SERVER_PORT = 1194

class VPNClient:
    def __init__(self, address="0.0.0.0", port=1193):

        self.bind_address = address
        self.port = port

        self.server_address = SERVER_ADRESS
        self.server_port = SERVER_PORT

        self.network_interface = None
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
            
            logger.info(f"TUN interface '{self.virtual_interface}' created")
            
        except Exception as e:
            logger.error(f"Failed to set up TUN interface: {e}")
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
            
            os.system(f"ip link set dev {self.virtual_interface} up")
            os.system(f"ip addr add {self.virtual_ip}/24 dev {self.virtual_interface}")
            os.system(f"ip link set dev {self.virtual_interface} mtu {self.VPN_MTU}")
            
            for route in self.routes:
                os.system(f"ip route add {route} dev {self.virtual_interface}")
            
            resolv_conf = ""
            for dns in self.dns_servers:
                resolv_conf += f"nameserver {dns}\n"
                
            # This is a simplified approach - in a real implementation you might want
            # to modify the system's resolv.conf or use resolvconf/NetworkManager
            
            logger.info(f"TUN interface configured with IP {self.virtual_ip}")
            
        except Exception as e:
            logger.error(f"Failed to configure TUN interface: {e}")
            raise

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
        """Set up the UDP socket for communication"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.client_socket.settimeout(0.1)  # Set a timeout for recvfrom
            self.client_socket.bind((self.bind_address, self.port))
            logger.info(f"Socket bound to {self.bind_address}:{self.port}")
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
                # Check if we need to retransmit any packets
                retransmissions = self.msg_handler.check_retransmissions()
                for seq_num, packet in retransmissions:
                    self.udp_write_queue.put(packet)
                    logger.debug(f"Queued retransmission of packet {seq_num} to server")
                    
                    
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
                    logger.warning(f"Invalid packet from server: {packet_info['error']}")
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
                    self._handle_retransmit(packet_info)
                    
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
        
        while self.running.is_set():
            try:
                if self.connection_state == ConnectionState.CONNECTED and self.tun_fd is not None:
                    try:
                        packet = os.read(self.tun_fd, self.VPN_MTU)
                        
                        if packet:
                            processed_packet = self._process_outbound_packet(packet)
                            
                            if processed_packet:
                                data_packet = self.msg_handler.create_data_packet(processed_packet)
                                
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
        try:
            encapsulated_data = packet_info['payload']
        
            if not encapsulated_data:
                logger.warning(f"Empty data packet from Server")
                return
                
            try:
                ip_packet = IP(encapsulated_data)
                
                logger.info(f"Packet details:\n")
                logger.info(ip_packet.show())
            except Exception as e:
                logger.error(f"Error processing IP packet: {e}")
                logger.error(traceback.format_exc())
        except Exception as e:
            logger.error(f"Error handling data packet: {e}")
            return

    def _process_outbound_packet(self, packet):
        """Process an outbound packet before sending it through the VPN"""
        try:
            ip_packet = IP(packet)
            
            if ip_packet.src == '0.0.0.0' or self._is_unspecified_ip(ip_packet.src):
                ip_packet.src = self.virtual_ip
                logger.debug(f"Replaced unspecified source IP with VPN IP {self.virtual_ip}")
            
            del ip_packet.chksum

            if ip_packet.haslayer(TCP):
                del ip_packet[TCP].chksum
            elif ip_packet.haslayer(UDP):
                del ip_packet[UDP].chksum

            logger.info(ip_packet.show())
            
            return bytes(ip_packet)
        except Exception as e:
            logger.error(f"Error processing outbound packet: {e}")
            return packet
    
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
            
            # Send acknowledgment for the disconnect packet
            ack_packet = self.msg_handler.create_ack_packet(packet_info['seq_num'])
            self.udp_write_queue.put(ack_packet)
            
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