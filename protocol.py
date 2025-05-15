# Description: This file contains the protocol definition for the VPN server and client.
import json
import time
import struct
import hashlib
import random
import zlib
import logging
import hashlib
from crypto import VPNCrypto
from enum import Enum
from typing import Optional

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('VPN-Protocol')

# Protocol Constants
MAGIC_NUMBER = 0xF7A50D12  # Magic number to identify VPN packets
PROTOCOL_VERSION = 1  # Protocol version
MAX_RETRIES = 5  # Maximum number of retransmission attempts
BASE_TIMEOUT = 1.0  # Base timeout in seconds
MAX_PACKET_SIZE = 1472  # Maximum UDP payload size (avoiding fragmentation)
ACK_TIMEOUT = 2.0  # Timeout for acknowledgments in seconds
BUFFER_CLEANUP_INTERVAL = 30.0  # Seconds between buffer cleanup
MAX_BUFFER_AGE = 60.0  # Maximum age of buffered packets in seconds


class MsgType(Enum):
    """Message types supported by the VPN protocol"""
    Request = 1        # Initial connection request from client
    Authenticate = 2   # Authentication challenge from server
    AuthResponse = 3   # Authentication response from client
    Config = 4         # Configuration data from server
    Establish = 5      # Connection established and ready for data
    Data = 6           # Data packet
    KeepAlive = 7      # Keep alive message
    Disconnect = 8     # Disconnect request
    Error = 9          # Error message
    Ack = 10           # Acknowledgment
    Retransmit = 11    # Request for retransmission
    Mtu = 12           # MTU probe or response
    Login = 13         # Login request
    LoginResponse = 14 # Login response
    Signup = 15        # Signup request
    SignupResponse = 16 # Signup response
    KeyExchangeInit = 17   # Client initiates key exchange
    KeyExchangeResponse = 18  # Server responds to key exchange


class PacketFlags(Enum):
    """Flags for packet headers"""
    NONE = 0x00        # No flags
    ACK = 0x01         # Acknowledgment flag
    SYN = 0x02         # Synchronize - for connection initiation
    FIN = 0x04         # Finish - for connection termination
    RST = 0x08         # Reset connection
    MTU = 0x10         # MTU discovery packet
    FRAG = 0x20        # Fragmented packet
    RETRY = 0x40       # Retry/Retransmission
    URGENT = 0x80      # Urgent data

class ConnectionState(Enum):
    """State of a VPN connection"""
    DISCONNECTED = 0
    CONNECTING = 1
    AUTHENTICATING = 2
    ESTABLISHING = 3
    CONNECTED = 4
    DISCONNECTING = 5
    ERROR = 6


class MessageHandler():
    """Handles the creation, parsing, and tracking of protocol messages"""
    
    def __init__(self, role, client_id=None, psk=None, cert_path=None, key_path=None):
        """
        Initialize the message handler
        
        Args:
            role: 'server' or 'client'
            client_id: Optional unique ID for the client
        """
        self.role = role
        self.magic_number = MAGIC_NUMBER
        self.version = PROTOCOL_VERSION
        self.client_id = client_id or self._generate_client_id()

        self.crypto = VPNCrypto()
        self.encrypted = False
        
        # Sequence tracking
        self.next_seq_num = random.randint(1, 10000)
        self.expected_seq_num = 0
        
        self.client_seq_nums = {}  # addr -> {'seq': next_seq, 'expected': expected_seq}
        self.seq_to_client = {}    # seq_num -> addr (for message routing)
        
        self.current_mtu = MAX_PACKET_SIZE
        
        # Buffer for out-of-order packets
        self.packet_buffer = {}  # key -> (packet_data, timestamp)
        
        self.packet_send_callback = None

    def _generate_client_id(self) -> str:
        """Generate a unique client ID"""
        return hashlib.md5(str(time.time() + random.random()).encode()).hexdigest()[:8]

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate CRC32 checksum for packet data"""
        return zlib.crc32(data) & 0xFFFFFFFF
    
    def register_packet_callback(self, callback):
        """
        Register a callback function to handle sending packets
        
        Args:
            callback: Function that takes (packet_data, addr) and sends it
        """
        self.packet_send_callback = callback

    def _cleanup_buffers(self):
        """Clean up stale entries in packet buffers and tracking dictionaries"""
        now = time.time()
        
        # Only run periodically
        if now - self.last_buffer_cleanup < BUFFER_CLEANUP_INTERVAL:
            return
            
        self.last_buffer_cleanup = now
        
        # Clean up old buffered packets
        for key in list(self.packet_buffer.keys()):
            _, timestamp = self.packet_buffer[key]
            if now - timestamp > MAX_BUFFER_AGE:
                del self.packet_buffer[key]
                logger.debug(f"Removed stale buffered packet {key}")

    def _create_header(self, msg_type: MsgType, seq_num: int, 
                       ack_num: int = 0, flags: int = 0, payload_length: int = 0) -> bytes:
        """
        Create a packet header
        
        Args:
            msg_type: Type of message
            seq_num: Sequence number
            ack_num: Acknowledgment number
            flags: Packet flags
            payload_length: Length of the payload
            
        Returns:
            Encoded header as bytes
        """
        # Pack header: magic(4), version(1), type(1), seq(4), ack(4), flags(1), length(2)
        return struct.pack('>IBBIIBH', 
                          self.magic_number,
                          self.version,
                          msg_type.value,
                          seq_num,
                          ack_num,
                          flags,
                          payload_length)
    

    def create_packet(self, msg_type: MsgType, payload: bytes = b'', 
                 ack_num: int = 0, flags: int = 0, client_addr: tuple = None) -> bytes:
        """Create a packet with optional encryption"""
        # Get appropriate sequence number
        if client_addr and self.role == 'server' and client_addr in self.client_seq_nums:
            seq_num = self.client_seq_nums[client_addr]['seq']
            self.seq_to_client[seq_num] = client_addr
            self.client_seq_nums[client_addr]['seq'] += 1
        else:
            seq_num = self.next_seq_num
            self.next_seq_num += 1
        
        encrypt_payload = (self.encrypted and msg_type != MsgType.KeyExchangeInit 
                        and msg_type != MsgType.KeyExchangeResponse)
        
        if encrypt_payload and payload:
            flags |= 0x100  # Encryption flag (bit 8)
            
            encrypted_payload = self.crypto.encrypt(payload)
            if encrypted_payload is None:
                logger.error(f"Encryption failed for message type {msg_type}")
                encrypted_payload = payload
                flags &= ~0x100  # Clear encryption flag
            else:
                payload = encrypted_payload
        
        # Create the header
        header = self._create_header(msg_type, seq_num, ack_num, flags, len(payload))
        
        # Calculate checksum over header + payload
        packet_data = header + payload
        checksum = self._calculate_checksum(packet_data)
        
        # Add checksum to packet
        packet = packet_data + struct.pack('>I', checksum)
        
        return packet
    
    def parse_packet(self, packet_data: bytes) -> dict:
        """Parse a packet with optional decryption"""
        try:
            if len(packet_data) < 21:  # Header (17) + Checksum (4)
                return {'error': 'Packet too small'}
            
            # Split header, payload, and checksum
            header = packet_data[:-4]
            received_checksum = struct.unpack('>I', packet_data[-4:])[0]
            
            # Verify checksum
            calculated_checksum = self._calculate_checksum(header)
            if calculated_checksum != received_checksum:
                return {'error': 'Checksum mismatch'}
            
            # Parse header
            magic, version, msg_type, seq_num, ack_num, flags, payload_length = struct.unpack(
            '>IBBIIBH', header[:17]
            )
            
            # Verify magic number and version
            if magic != self.magic_number:
                return {'error': 'Invalid magic number'}
            if version != self.version:
                return {'error': 'Protocol version mismatch'}
            
            # Extract payload
            payload = packet_data[17:-4]
            
            # Verify payload length
            if len(payload) != payload_length:
                return {'error': 'Payload length mismatch'}
            
            # Convert message type to enum
            try:
                msg_type = MsgType(msg_type)
            except ValueError:
                return {'error': 'Invalid message type'}
                
            # Check if payload is encrypted (encryption flag set)
            is_encrypted = (flags & 0x100) != 0
            
            # Decrypt payload if needed
            if is_encrypted and self.encrypted and payload:
                # Don't try to decrypt key exchange messages
                if msg_type != MsgType.KeyExchangeInit and msg_type != MsgType.KeyExchangeResponse:
                    decrypted_payload = self.crypto.decrypt(payload)
                    if decrypted_payload is None:
                        return {'error': 'Decryption failed'}
                    payload = decrypted_payload
            
            # Return parsed packet information
            return {
                'type': msg_type,
                'seq_num': seq_num,
                'ack_num': ack_num,
                'flags': flags,
                'payload': payload,
                'encrypted': is_encrypted
            }
            
        except Exception as e:
            return {'error': f'Parsing error: {str(e)}'}
    
    def process_packet(self, packet_data: bytes, sender_addr: tuple = None) -> dict:
        """
        Process a received packet and update internal state
        
        Args:
            packet_data: Raw packet data
            sender_addr: (ip, port) tuple of sender
            
        Returns:
            Dictionary with parsed packet information and actions to take
        """
        # Parse the packet
        packet_info = self.parse_packet(packet_data)
        
        # Check for parsing errors
        if 'error' in packet_info:
            return packet_info
        else:
            logger.debug(f"Processing {packet_info['type']} packet seq={packet_info['seq_num']} from {sender_addr}")
        
        # Initialize client seq nums if this is a new client (server-side)
        if self.role == 'server' and sender_addr and sender_addr not in self.client_seq_nums:
            self.client_seq_nums[sender_addr] = {
                'seq': random.randint(1, 10000),
                'expected': packet_info['seq_num'] + 1
            }
        
        # Handle out-of-order packets
        if self.role == 'client':
            expected = self.expected_seq_num
            if packet_info['seq_num'] > expected:
                self.packet_buffer[packet_info['seq_num']] = (packet_data, time.time())
                
        elif self.role == 'server' and sender_addr in self.client_seq_nums:
            expected = self.client_seq_nums[sender_addr]['expected']
            if packet_info['seq_num'] > expected:
                # Store out-of-order packet
                client_addr_str = f"{sender_addr[0]}:{sender_addr[1]}"
                buffer_key = f"{client_addr_str}_{packet_info['seq_num']}"
                self.packet_buffer[buffer_key] = (packet_data, time.time())
        
        # Update expected sequence number
        if self.role == 'client':
            self.expected_seq_num = packet_info['seq_num'] + 1
        elif self.role == 'server' and sender_addr in self.client_seq_nums:
            self.client_seq_nums[sender_addr]['expected'] = packet_info['seq_num'] + 1
        
        # Return processed packet info with default action
        return {**packet_info, 'action': 'process'}
    
    def get_client_for_seq(self, seq_num: int) -> Optional[tuple]:
        """
        Get the client address associated with a sequence number
        
        Args:
            seq_num: Sequence number to look up
            
        Returns:
            (ip, port) tuple of client or None if not found
        """
        return self.seq_to_client.get(seq_num)

    # =========================================
    # Message Creation Methods
    # =========================================
    
    def create_request_packet(self, client_info: dict = None) -> bytes:
        """
        Create a connection request packet (client -> server)
        
        Args:
            client_info: Optional client information to include
            
        Returns:
            Request packet as bytes
        """
        if client_info is None:
            client_info = {}
        
        # Add client ID and protocol version to client info
        client_info['client_id'] = self.client_id
        client_info['protocol_version'] = self.version
        
        payload = json.dumps(client_info).encode()
        
        # Create packet with SYN flag
        return self.create_packet(MsgType.Request, payload, flags=PacketFlags.SYN.value)
    
    def create_auth_challenge_packet(self, challenge: bytes, client_addr: tuple = None) -> bytes:
        """
        Create an authentication challenge packet (server -> client)
        
        Args:
            challenge: Authentication challenge data
            client_addr: (ip, port) tuple of client
            
        Returns:
            Authentication challenge packet as bytes
        """
        return self.create_packet(MsgType.Authenticate, challenge, client_addr=client_addr)
    
    def create_auth_response_packet(self, response: bytes) -> bytes:
        """
        Create an authentication response packet (client -> server)
        
        Args:
            response: Authentication response data
            
        Returns:
            Authentication response packet as bytes
        """
        return self.create_packet(MsgType.AuthResponse, response)
    
    def create_config_packet(self, config: dict, client_addr: tuple = None) -> bytes:
        """
        Create a configuration packet (server -> client)
        
        Args:
            config: Configuration dictionary
            client_addr: (ip, port) tuple of client (for server-side use)
            
        Returns:
            Configuration packet as bytes
        """
        config_json = json.dumps(config).encode()
        return self.create_packet(MsgType.Config, config_json, client_addr=client_addr)
    
    def create_establish_packet(self, client_addr: tuple = None) -> bytes:
        """
        Create a connection established packet
        
        Args:
            client_addr: (ip, port) tuple of client (for server-side use)
            
        Returns:
            Establish packet as bytes
        """
        return self.create_packet(MsgType.Establish, client_addr=client_addr)
    
    def create_data_packet(self, data: bytes, client_addr: tuple = None) -> bytes:
        """
        Create a data packet
        
        Args:
            data: Payload data
            client_addr: (ip, port) tuple of client (for server-side use)
            
        Returns:
            Data packet as bytes
        """
        return self.create_packet(MsgType.Data, data, client_addr=client_addr)
    
    def create_keepalive_packet(self, client_addr: tuple = None) -> bytes:
        """
        Create a keepalive packet
        
        Args:
            client_addr: (ip, port) tuple of client (for server-side use)
            
        Returns:
            Keepalive packet as bytes
        """
        return self.create_packet(MsgType.KeepAlive, client_addr=client_addr)
    
    def create_disconnect_packet(self, reason: str = "", client_addr: tuple = None) -> bytes:
        """
        Create a disconnect packet
        
        Args:
            reason: Reason for disconnection
            client_addr: (ip, port) tuple of client (for server-side use)
            
        Returns:
            Disconnect packet as bytes
        """
        return self.create_packet(MsgType.Disconnect, reason.encode(), 
                                 flags=PacketFlags.FIN.value, client_addr=client_addr)
    
    def create_error_packet(self, error_msg: str, client_addr: tuple = None) -> bytes:
        """
        Create an error packet
        
        Args:
            error_msg: Error message
            client_addr: (ip, port) tuple of client (for server-side use)
            
        Returns:
            Error packet as bytes
        """
        return self.create_packet(MsgType.Error, error_msg.encode(), client_addr=client_addr)
    
    def create_ack_packet(self, ack_num: int, client_addr: tuple = None) -> bytes:
        """
        Create an acknowledgment packet
        
        Args:
            ack_num: Sequence number to acknowledge
            client_addr: (ip, port) tuple of client (for server-side use)
            
        Returns:
            Acknowledgment packet as bytes
        """
        return self.create_packet(MsgType.Ack, ack_num=ack_num, 
                                flags=PacketFlags.ACK.value, client_addr=client_addr)
    
    def create_retransmit_request(self, seq_num: int, client_addr: tuple = None) -> bytes:
        """
        Create a packet requesting retransmission
        
        Args:
            seq_num: Sequence number to request
            client_addr: (ip, port) tuple of client (for server-side use)
            
        Returns:
            Retransmit request packet as bytes
        """
        payload = struct.pack('>I', seq_num)
        return self.create_packet(MsgType.Retransmit, payload, 
                                 flags=PacketFlags.RETRY.value, client_addr=client_addr)
    
    def create_mtu_probe_packet(self, size: int, client_addr: tuple = None) -> bytes:
        """
        Create an MTU probe packet
        
        Args:
            size: Size of probe in bytes
            client_addr: (ip, port) tuple of client (for server-side use)
            
        Returns:
            MTU probe packet as bytes
        """
        # Create a payload of the specified size
        probe_size = struct.pack('>I', size)
        padding = b'\x00' * (size - 21 - 4)  # 17 for header + 4 for probe_size
        payload = probe_size + padding
        
        return self.create_packet(MsgType.Mtu, payload, 
                                flags=PacketFlags.MTU.value, client_addr=client_addr)
    
    def create_key_exchange_init_packet(self) -> bytes:
        """Create a key exchange initialization packet (client -> server)"""
        # Generate a new keypair
        public_key = self.crypto.generate_keypair()
        
        # Create packet with public key as payload
        return self.create_packet(MsgType.KeyExchangeInit, public_key)

    def create_key_exchange_response_packet(self, client_public_key, client_addr=None) -> bytes:
        """Create a key exchange response packet (server -> client)"""
        # Set the peer's public key
        self.crypto.set_peer_public_key(client_public_key)
        
        # Generate our keypair and get the public key bytes
        public_key = self.crypto.generate_keypair()
        
        # Generate the shared key
        self.crypto.generate_shared_key()
        
        self.encrypted = True
        
        return self.create_packet(MsgType.KeyExchangeResponse, public_key, client_addr=client_addr)

    def handle_key_exchange_response(self, peer_public_key) -> bool:
        """Process a key exchange response (client-side)"""
        # Set the peer's public key
        if not self.crypto.set_peer_public_key(peer_public_key):
            return False
        
        # Generate the shared key
        if not self.crypto.generate_shared_key():
            return False
        
        # Enable encryption for future messages
        self.encrypted = True
        return True
