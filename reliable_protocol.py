import threading
import time
import struct
import random
from queue import Queue, Empty
from typing import Callable

# Import the module, not specific classes to avoid circular imports
import protocol

# Control messages that need reliability
CONTROL_MESSAGE_TYPES = {
    protocol.MsgType.Request,
    protocol.MsgType.Authenticate,
    protocol.MsgType.AuthResponse,
    protocol.MsgType.Config,
    protocol.MsgType.Establish,
    protocol.MsgType.Disconnect,
    protocol.MsgType.Error,
    protocol.MsgType.Mtu,
    protocol.MsgType.Login,
    protocol.MsgType.LoginResponse,
    protocol.MsgType.Signup,
    protocol.MsgType.SignupResponse,
    protocol.MsgType.KeyExchangeInit,
    protocol.MsgType.KeyExchangeResponse
}

# Pure data messages - no reliability needed
DATA_MESSAGE_TYPES = {
    protocol.MsgType.Data,
    protocol.MsgType.KeepAlive  # KeepAlives don't need guaranteed delivery
}

# Reliability parameters
RETRANSMISSION_BASE_TIMEOUT = 0.5  # seconds
MAX_RETRANSMISSIONS = 5
MAX_EXPONENTIAL_FACTOR = 8  # Maximum multiplier for exponential backoff
BUFFER_CLEANUP_INTERVAL = 30.0  # Seconds between buffer cleanup

# Use the logger from protocol
logger = protocol.logger

class ReliableMessageHandler(protocol.MessageHandler):
    """Enhanced MessageHandler with reliability for control messages"""
    
    def __init__(self, role, client_id=None, psk=None, cert_path=None, key_path=None):
        """Initialize with parent constructor"""
        super().__init__(role, client_id, psk, cert_path, key_path)
        
        # Tracking for unacknowledged packets
        self.unacked_packets = {}  # seq_num -> (packet_data, timestamp, retries)
        self.pending_acks = set()  # Set of sequence numbers we need to acknowledge
        
        # Queue for pending acknowledgments
        self.ack_queue = Queue()
        
        # Lock for thread safety
        self.lock = threading.RLock()
        
        # Message delivery confirmation callbacks
        self.delivery_callbacks = {}  # seq_num -> callback function
        
        # State transition tracking
        self.state_transitions = {}  # seq_num -> (current_state, target_state)
        
        # Message type tracking for better debugging
        self.seq_to_msg_type = {}    # seq_num -> MsgType
        
        # Connection state callback - to be set by the client/server
        self.connection_state_callback = None  # For client to report its state
        self.client_state_callback = None      # For server to report client's state
        
        # Last cleanup time - initialize BEFORE starting the thread
        self.last_buffer_cleanup = time.time()
        
        # Start reliability worker thread
        self.running = True
        self.reliability_thread = threading.Thread(
            target=self._reliability_worker,
            name="ReliabilityWorker",
            daemon=True
        )
        self.reliability_thread.start()
        
        logger.info(f"ReliableMessageHandler initialized ({role} mode)")
    
    def stop(self):
        """Stop the reliability worker thread"""
        self.running = False
        if self.reliability_thread.is_alive():
            self.reliability_thread.join(timeout=2)
            logger.info("Reliability worker thread stopped")
    
    def _register_state_transition(self, seq_num, msg_type, current_state, target_state):
        """
        Register a message as causing a state transition.
        This allows us to cancel retransmissions if the state has advanced.
        
        Args:
            seq_num: Sequence number of the message
            msg_type: Message type (for debugging)
            current_state: State when message was sent
            target_state: State the message aims to transition to
        """
        with self.lock:
            self.state_transitions[seq_num] = (current_state, target_state)
            self.seq_to_msg_type[seq_num] = msg_type
            logger.debug(f"Registered state transition for seq={seq_num} [{msg_type.name}]: {current_state} → {target_state}")

    def _should_cancel_retransmission(self, seq_num, client_addr=None):
        """
        Determine if a packet retransmission should be canceled based on connection state.
        
        Args:
            seq_num: Sequence number of the packet
            client_addr: Client address for server-side checks
            
        Returns:
            bool: True if retransmission should be canceled
        """
        # If we don't have state transition info for this packet, check if we received an ACK
        if seq_num not in self.state_transitions:
            # If already acknowledged, definitely cancel
            if seq_num not in self.unacked_packets:
                return True
            return False
        
        try:    
            current_state, target_state = self.state_transitions[seq_num]
            msg_type = self.seq_to_msg_type.get(seq_num, "Unknown")
            
            # Get current connection state
            actual_state = None
            if self.role == 'client':
                if self.connection_state_callback:
                    actual_state = self.connection_state_callback()
            elif self.role == 'server' and client_addr and self.client_state_callback:
                actual_state = self.client_state_callback(client_addr)
            
            # If we can't determine state, allow retransmission
            if actual_state is None:
                return False
                
            # If connection state has advanced beyond or equal to the target state,
            # we can cancel the retransmission
            if self._state_is_advanced_or_equal(actual_state, target_state):
                logger.info(f"Canceling retransmission of seq={seq_num} [{msg_type}]: state already at {actual_state}")
                return True
            
            # Special handling for authentication messages
            if msg_type == protocol.MsgType.Authenticate and self._state_is_advanced_or_equal(actual_state, protocol.ConnectionState.ESTABLISHING):
                logger.info(f"Canceling authentication retransmission: already in {actual_state} state")
                return True
                
            # Special handling for config messages
            if msg_type == protocol.MsgType.Config and self._state_is_advanced_or_equal(actual_state, protocol.ConnectionState.CONNECTED):
                logger.info(f"Canceling config retransmission: already in {actual_state} state")
                return True
                
            # Special handling for request messages
            if msg_type == protocol.MsgType.Request and self._state_is_advanced_or_equal(actual_state, protocol.ConnectionState.AUTHENTICATING):
                logger.info(f"Canceling request retransmission: already in {actual_state} state")
                return True
            
            # Allow retransmission by default
            return False
        except Exception as e:
            logger.error(f"Error in _should_cancel_retransmission: {e}")
            return False  # If there's an error, allow retransmission to be safe

    def _state_is_advanced(self, current_state, reference_state):
        """Check if current_state is more advanced than reference_state"""
        try:
            # Create an ordering of states
            state_order = {
                protocol.ConnectionState.DISCONNECTED: 0,
                protocol.ConnectionState.CONNECTING: 1,
                protocol.ConnectionState.AUTHENTICATING: 2,
                protocol.ConnectionState.ESTABLISHING: 3,
                protocol.ConnectionState.CONNECTED: 4,
                protocol.ConnectionState.DISCONNECTING: 5,
                protocol.ConnectionState.ERROR: -1  # Error is a special case
            }
            
            # Get numeric values for the states
            current_value = state_order.get(current_state, -1)
            reference_value = state_order.get(reference_state, -1)
            
            # Consider the state advanced if its value is greater
            return current_value > reference_value
        except Exception as e:
            logger.error(f"Error in _state_is_advanced: {e}")
            return False  # If there's an error, assume state has not advanced
        
    def _state_is_advanced_or_equal(self, current_state, reference_state):
        """Check if current_state is equal to or more advanced than reference_state"""
        try:
            # Create an ordering of states
            state_order = {
                protocol.ConnectionState.DISCONNECTED: 0,
                protocol.ConnectionState.CONNECTING: 1,
                protocol.ConnectionState.AUTHENTICATING: 2,
                protocol.ConnectionState.ESTABLISHING: 3,
                protocol.ConnectionState.CONNECTED: 4,
                protocol.ConnectionState.DISCONNECTING: 5,
                protocol.ConnectionState.ERROR: -1  # Error is a special case
            }
            
            # Get numeric values for the states
            current_value = state_order.get(current_state, -1)
            reference_value = state_order.get(reference_state, -1)
            
            # Consider the state advanced or equal if its value is greater or equal
            return current_value >= reference_value
        except Exception as e:
            logger.error(f"Error in _state_is_advanced_or_equal: {e}")
            return False  # If there's an error, assume state has not advanced

    def create_packet(self, msg_type, payload: bytes = b'', 
                     ack_num: int = 0, flags: int = 0, client_addr = None,
                     current_state=None, target_state=None) -> bytes:
        """
        Create a packet and track it if it's a control message that needs reliability
        
        Args:
            msg_type: Type of message
            payload: Payload data
            ack_num: Acknowledgment number
            flags: Packet flags
            client_addr: (ip, port) tuple of client (for server-side use)
            current_state: Connection state when sending this message
            target_state: Expected connection state after this message is processed
        """
        # Original packet creation logic
        with self.lock:
            if client_addr and self.role == 'server' and client_addr in self.client_seq_nums:
                seq_num = self.client_seq_nums[client_addr]['seq']
                self.seq_to_client[seq_num] = client_addr
                self.client_seq_nums[client_addr]['seq'] += 1
            else:
                seq_num = self.next_seq_num
                self.next_seq_num += 1
            
            header = self._create_header(msg_type, seq_num, ack_num, flags, len(payload))
            packet_data = header + payload
            checksum = self._calculate_checksum(packet_data)
            packet = packet_data + struct.pack('>I', checksum)
            
            # Track packet for reliability if it's a control message
            if msg_type in CONTROL_MESSAGE_TYPES:
                # Don't track ACK packets for reliability
                if msg_type != protocol.MsgType.Ack and not (flags & protocol.PacketFlags.ACK.value):
                    self.unacked_packets[seq_num] = (packet, time.time(), 0)
                    
                    # Register state transition if provided
                    if current_state is not None and target_state is not None:
                        self._register_state_transition(seq_num, msg_type, current_state, target_state)
                    
                    logger.debug(f"Tracking control message seq={seq_num} type={msg_type.name} for reliability")
                
            return packet

    def register_delivery_callback(self, seq_num: int, callback: Callable):
        """Register a callback to be called when a packet is acknowledged"""
        with self.lock:
            self.delivery_callbacks[seq_num] = callback
            logger.debug(f"Registered delivery callback for packet seq={seq_num}")
    
    def process_packet(self, packet_data: bytes, sender_addr = None) -> dict:
        """Process a received packet with reliability handling"""
        # Parse the packet
        packet_info = self.parse_packet(packet_data)
        
        # Check for parsing errors
        if 'error' in packet_info:
            return packet_info
        
        # Get important packet information
        msg_type = packet_info['type']
        seq_num = packet_info['seq_num']
        ack_num = packet_info['ack_num']
        flags = packet_info['flags']
        
        # Get current connection state
        current_state = None
        if self.role == 'client' and self.connection_state_callback:
            current_state = self.connection_state_callback()
        elif self.role == 'server' and sender_addr and self.client_state_callback:
            current_state = self.client_state_callback(sender_addr)
        
        # Handle ACK packets
        if msg_type == protocol.MsgType.Ack or (flags & protocol.PacketFlags.ACK.value):
            with self.lock:
                # If this is acknowledging one of our packets, mark it as delivered
                if ack_num in self.unacked_packets:
                    msg_type_str = self.seq_to_msg_type.get(ack_num, "Unknown")
                    logger.debug(f"Received ACK for packet seq={ack_num} [{msg_type_str}]")
                    
                    # Remove from unacked packets
                    del self.unacked_packets[ack_num]
                    
                    # Also remove from state transitions if present
                    if ack_num in self.state_transitions:
                        del self.state_transitions[ack_num]
                    
                    # Remove from message type tracking
                    if ack_num in self.seq_to_msg_type:
                        del self.seq_to_msg_type[ack_num]
                    
                    # Call delivery callback if registered
                    if ack_num in self.delivery_callbacks:
                        try:
                            self.delivery_callbacks[ack_num](success=True)
                        except Exception as e:
                            logger.error(f"Error in delivery callback: {e}")
                        del self.delivery_callbacks[ack_num]
        
        # Handle duplicate control messages based on state
        if msg_type in CONTROL_MESSAGE_TYPES and current_state:
            # Duplicate detection for authentication messages
            if msg_type == protocol.MsgType.Authenticate:
                if self._state_is_advanced(current_state, protocol.ConnectionState.AUTHENTICATING):
                    # Already past authentication, acknowledge but don't process
                    logger.debug(f"Received duplicate Authentication message in state {current_state}, acknowledging only")
                    self.ack_queue.put((seq_num, sender_addr if self.role == 'server' else None))
                    return {**packet_info, 'action': 'ignore', 'duplicate': True}
            
            # Duplicate detection for configuration messages
            elif msg_type == protocol.MsgType.Config:
                if self._state_is_advanced(current_state, protocol.ConnectionState.ESTABLISHING):
                    # Already configured, acknowledge but don't process
                    logger.debug(f"Received duplicate Config message in state {current_state}, acknowledging only")
                    self.ack_queue.put((seq_num, sender_addr if self.role == 'server' else None))
                    return {**packet_info, 'action': 'ignore', 'duplicate': True}
        
        # Initialize client seq nums if this is a new client (server-side)
        if self.role == 'server' and sender_addr and sender_addr not in self.client_seq_nums:
            with self.lock:
                self.client_seq_nums[sender_addr] = {
                    'seq': random.randint(1, 10000),
                    'expected': packet_info['seq_num'] + 1
                }
        
        # Handle out-of-order packets
        if self.role == 'client':
            expected = self.expected_seq_num
            if seq_num > expected:
                # Store out-of-order packet
                self.packet_buffer[seq_num] = (packet_data, time.time())
                logger.debug(f"Stored out-of-order packet seq={seq_num} (expected {expected})")
        elif self.role == 'server' and sender_addr in self.client_seq_nums:
            expected = self.client_seq_nums[sender_addr]['expected']
            if seq_num > expected:
                # Store out-of-order packet
                client_addr_str = f"{sender_addr[0]}:{sender_addr[1]}"
                buffer_key = f"{client_addr_str}_{seq_num}"
                self.packet_buffer[buffer_key] = (packet_data, time.time())
                logger.debug(f"Stored out-of-order packet from {client_addr_str} seq={seq_num} (expected {expected})")
        
        # Update expected sequence number
        if self.role == 'client':
            self.expected_seq_num = max(self.expected_seq_num, seq_num + 1)
        elif self.role == 'server' and sender_addr in self.client_seq_nums:
            self.client_seq_nums[sender_addr]['expected'] = max(
                self.client_seq_nums[sender_addr]['expected'], 
                seq_num + 1
            )
        
        # For control messages, send acknowledgment
        if msg_type in CONTROL_MESSAGE_TYPES and msg_type != protocol.MsgType.Ack:
            # Queue acknowledgment to be sent
            with self.lock:
                if self.role == 'server':
                    self.ack_queue.put((seq_num, sender_addr))
                    logger.debug(f"Queued ACK for control packet seq={seq_num} [{str(msg_type)}] from {sender_addr}")
                else:
                    self.ack_queue.put((seq_num, None))
                    logger.debug(f"Queued ACK for control packet seq={seq_num} [{str(msg_type)}] from server")
        
        # Return processed packet info
        return {**packet_info, 'action': 'process'}
    
    def _reliability_worker(self):
        """Worker thread that handles retransmissions and acknowledgments"""
        logger.info("Reliability worker started")
        
        # Initialize last_buffer_cleanup if not already done
        if not hasattr(self, 'last_buffer_cleanup'):
            self.last_buffer_cleanup = time.time()
            logger.warning("Initialized missing last_buffer_cleanup attribute")
        
        while self.running:
            try:
                # Process pending acknowledgments
                while not self.ack_queue.empty():
                    try:
                        seq_num, client_addr = self.ack_queue.get_nowait()
                        ack_packet = self.create_ack_packet(seq_num, client_addr)
                        
                        if self.packet_send_callback:
                            if client_addr:
                                self.packet_send_callback(ack_packet, client_addr)
                                logger.debug(f"Sent ACK for packet seq={seq_num} to {client_addr}")
                            else:
                                self.packet_send_callback(ack_packet)
                                logger.debug(f"Sent ACK for packet seq={seq_num} to server")
                        
                        self.ack_queue.task_done()
                    except Empty:
                        break
                
                # Check for packets that need retransmission
                now = time.time()
                to_retransmit = []
                to_remove = []
                
                with self.lock:
                    for seq_num, (packet, timestamp, retries) in list(self.unacked_packets.items()):
                        # Calculate timeout with exponential backoff
                        timeout = RETRANSMISSION_BASE_TIMEOUT * min(2 ** retries, MAX_EXPONENTIAL_FACTOR)
                        
                        if now - timestamp > timeout:
                            # Get client address if server role
                            client_addr = self.get_client_for_seq(seq_num) if self.role == 'server' else None
                            
                            # Check if retransmission should be canceled due to state advancement
                            if self._should_cancel_retransmission(seq_num, client_addr):
                                # Add to removal list
                                to_remove.append(seq_num)
                                msg_type = self.seq_to_msg_type.get(seq_num, "Unknown")
                                logger.info(f"Canceling retransmission of seq={seq_num} [{msg_type}] due to state advancement")
                                
                                # Call delivery callback with success, as we're considering this delivered
                                if seq_num in self.delivery_callbacks:
                                    try:
                                        self.delivery_callbacks[seq_num](success=True)
                                    except Exception as e:
                                        logger.error(f"Error in delivery callback: {e}")
                                    del self.delivery_callbacks[seq_num]
                                
                                continue
                            
                            if retries >= MAX_RETRANSMISSIONS:
                                # Too many retries, consider the packet lost
                                msg_type = self.seq_to_msg_type.get(seq_num, "Unknown")
                                logger.warning(f"Packet seq={seq_num} [{msg_type}] abandoned after {retries} retries")
                                to_remove.append(seq_num)
                                
                                # Call delivery callback with failure if registered
                                if seq_num in self.delivery_callbacks:
                                    try:
                                        self.delivery_callbacks[seq_num](success=False)
                                    except Exception as e:
                                        logger.error(f"Error in delivery failure callback: {e}")
                                    del self.delivery_callbacks[seq_num]
                            else:
                                # Queue for retransmission
                                to_retransmit.append((packet, client_addr, seq_num))
                                
                                # Update retry count and timestamp
                                self.unacked_packets[seq_num] = (packet, now, retries + 1)
                                msg_type = self.seq_to_msg_type.get(seq_num, "Unknown")
                                logger.debug(f"Retransmitting packet seq={seq_num} [{msg_type}] (retry {retries+1})")
                    
                    # Clean up packets that don't need retransmission
                    for seq_num in to_remove:
                        if seq_num in self.unacked_packets:
                            del self.unacked_packets[seq_num]
                        if seq_num in self.state_transitions:
                            del self.state_transitions[seq_num]
                        if seq_num in self.seq_to_msg_type:
                            del self.seq_to_msg_type[seq_num]
                
                # Perform retransmissions outside the lock
                for packet, client_addr, seq_num in to_retransmit:
                    # Final state check before actually sending (double-check to prevent race conditions)
                    should_cancel = False
                    with self.lock:
                        if self._should_cancel_retransmission(seq_num, client_addr):
                            should_cancel = True
                            msg_type = self.seq_to_msg_type.get(seq_num, "Unknown")
                            logger.info(f"Last-minute cancellation of retransmission seq={seq_num} [{msg_type}]")
                            
                            # Clean up
                            if seq_num in self.unacked_packets:
                                del self.unacked_packets[seq_num]
                            if seq_num in self.state_transitions:
                                del self.state_transitions[seq_num]
                            if seq_num in self.seq_to_msg_type:
                                del self.seq_to_msg_type[seq_num]
                            
                            # Call delivery callback with success
                            if seq_num in self.delivery_callbacks:
                                try:
                                    self.delivery_callbacks[seq_num](success=True)
                                except Exception as e:
                                    logger.error(f"Error in delivery callback: {e}")
                                del self.delivery_callbacks[seq_num]
                    
                    # Only send if not canceled
                    if not should_cancel and self.packet_send_callback:
                        if client_addr:
                            self.packet_send_callback(packet, client_addr)
                        else:
                            self.packet_send_callback(packet)
                
                # Clean up stale buffers periodically
                if now - self.last_buffer_cleanup > BUFFER_CLEANUP_INTERVAL:
                    self._cleanup_buffers()
                    self.last_buffer_cleanup = now
                
                # Sleep a bit to avoid excessive CPU usage
                time.sleep(0.05)
                
            except Exception as e:
                logger.error(f"Error in reliability worker: {e}")
                import traceback
                logger.error(traceback.format_exc())
                time.sleep(0.1)
    
    def wait_for_delivery(self, seq_num, timeout=5.0):
        """
        Wait for a specific packet to be acknowledged
        
        Args:
            seq_num: Sequence number to wait for
            timeout: Maximum time to wait in seconds
            
        Returns:
            True if packet was acknowledged, False if timeout
        """
        delivery_event = threading.Event()
        
        def on_delivery(success=True):
            if success:
                delivery_event.set()
        
        # Register callback
        self.register_delivery_callback(seq_num, on_delivery)
        
        # Wait for delivery or timeout
        result = delivery_event.wait(timeout)
        
        # Clean up callback if timeout
        if not result:
            with self.lock:
                if seq_num in self.delivery_callbacks:
                    del self.delivery_callbacks[seq_num]
        
        return result