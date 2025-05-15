# vpn_gui_app.py - Updated with modern dark theme

import sys
import json
import logging
import threading
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QStackedWidget, QMessageBox,
    QGroupBox, QFormLayout
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QTimer
from PyQt5.QtGui import QFont, QPalette, QColor

from client import VPNClient
from protocol import MsgType, ConnectionState
from reliable_protocol import ReliableMessageHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('VPN-GUI')

# Define color scheme
DARK_BG = "#0a0f1c"  # Very dark blue-black
DARKER_BG = "#060913"  # Even darker for contrast
CARD_BG = "#0f1729"  # Slightly lighter for cards/panels
ACCENT_BLUE = "#0066cc"  # Bright blue accent
LIGHT_BLUE = "#4d94ff"  # Lighter blue for hover states
TEXT_PRIMARY = "#ffffff"  # White text
TEXT_SECONDARY = "#a0aec0"  # Grayish blue text
SUCCESS_GREEN = "#00cc66"  # Green for connected state
ERROR_RED = "#ff4444"  # Red for errors
BORDER_COLOR = "#1a2744"  # Subtle border color

class VPNClientWithAuth(VPNClient):
    """Extended VPN Client with authentication functionality"""
    
    def send_login(self, username, password):
        """Send login request to server (requires encryption)"""
        try:
            if not hasattr(self.msg_handler, 'encrypted') or not self.msg_handler.encrypted:
                logger.info("Waiting for encryption to be established...")
                if not self.encryption_ready_event.wait(5.0):
                    logger.error("Encryption not established, cannot send login")
                    return False
            
            login_data = {
                'username': username,
                'password': password
            }
            
            login_packet = self.msg_handler.create_packet(
                MsgType.Login,
                json.dumps(login_data).encode()
            )
            
            self.auth_response_event.clear()
            self.last_auth_response = None
            
            if self.client_socket:
                self.client_socket.sendto(login_packet, (self.server_address, self.server_port))
                logger.info(f"Sent login request for user: {username}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error sending login request: {e}")
            return False
    
    def send_signup(self, username, password):
        """Send signup request to server (requires encryption)"""
        try:
            if not hasattr(self.msg_handler, 'encrypted') or not self.msg_handler.encrypted:
                logger.info("Waiting for encryption to be established...")
                if not self.encryption_ready_event.wait(5.0):
                    logger.error("Encryption not established, cannot send signup")
                    return False
            
            signup_data = {
                'username': username,
                'password': password
            }
            
            signup_packet = self.msg_handler.create_packet(
                MsgType.Signup,
                json.dumps(signup_data).encode()
            )
            
            self.auth_response_event.clear()
            self.last_auth_response = None
            
            if self.client_socket:
                self.client_socket.sendto(signup_packet, (self.server_address, self.server_port))
                logger.info(f"Sent signup request for user: {username}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error sending signup request: {e}")
            return False
    
    def wait_for_auth_response(self, timeout=5):
        """Wait for authentication response"""
        try:
            if self.auth_response_event.wait(timeout):
                return self.last_auth_response
            else:
                return {'success': False, 'message': 'Response timeout'}
        except Exception as e:
            logger.error(f"Error waiting for auth response: {e}")
            return {'success': False, 'message': 'Error waiting for response'}
    
    def start_minimal_infrastructure(self):
        """Start minimal infrastructure for authentication only"""
        try:
            self._set_up_socket()
            
            self.msg_handler = ReliableMessageHandler('client')
            self.msg_handler.register_packet_callback(
                lambda packet: self.udp_write_queue.put(packet)
            )
            
            self.running.set()
            
            self.udp_read_thread = threading.Thread(
                target=self._udp_read_worker,
                name="UDP Reader",
                daemon=True
            )
            self.udp_read_thread.start()
            
            self.udp_write_thread = threading.Thread(
                target=self._udp_write_worker,
                name="UDP Writer",
                daemon=True
            )
            self.udp_write_thread.start()
            
            self.udp_processor_thread = threading.Thread(
                target=self._udp_packet_processor,
                name="UDP Processor",
                daemon=True
            )
            self.udp_processor_thread.start()
            
            logger.info("Minimal infrastructure started for authentication")
            
            self.initiate_secure_connection()
            
            return True
                
        except Exception as e:
            logger.error(f"Failed to start minimal infrastructure: {e}")
            return False
    
    def initiate_secure_connection(self):
        """Start secure connection with key exchange"""

        if hasattr(self.msg_handler, 'encrypted') and self.msg_handler.encrypted:
            return True
            
        if not self.key_exchange_in_progress.acquire(False):
            logger.info("Key exchange already in progress, waiting...")
            return self.encryption_ready_event.wait(5.0)
        
        try:
            self.connection_state = ConnectionState.CONNECTING
            
            self.encryption_ready_event.clear()
            
            key_exchange_init = self.msg_handler.create_key_exchange_init_packet()
            self.udp_write_queue.put(key_exchange_init)
            
            logger.info(f"Sent key exchange init to {self.server_address}:{self.server_port}")
            return True
        finally:
            self.key_exchange_in_progress.release()


class MainWindow(QMainWindow):
    """Main VPN application window"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure VPN Client")
        self.setGeometry(100, 100, 600, 400)
        
        # Apply dark theme styling to the main window
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {DARK_BG};
            }}
        """)
        
        # Create VPN client instance
        self.vpn_client = VPNClientWithAuth()
        
        # Start minimal infrastructure for authentication
        self.vpn_client.start_minimal_infrastructure()
        
        # Current user session
        self.current_user = None
        self.auth_token = None
        
        # Set up UI
        self.setup_ui()
        
        # Monitor timer for connection status
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.update_connection_status)
        
    def setup_ui(self):
        """Set up the user interface"""
        # Create central widget and stacked layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create stacked widget for multiple screens
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setStyleSheet(f"background-color: {DARK_BG};")
        main_layout.addWidget(self.stacked_widget)
        
        # Create screens
        self.create_login_screen()
        self.create_dashboard_screen()
        
        # Show login screen first
        self.stacked_widget.setCurrentIndex(0)
    
    def create_login_screen(self):
        """Create the login/signup screen"""
        try:
            login_widget = QWidget()
            login_widget.setStyleSheet(f"background-color: {DARK_BG};")
            layout = QVBoxLayout(login_widget)
            layout.setContentsMargins(40, 40, 40, 40)
            
            # Title
            title = QLabel("SECURE VPN")
            title.setFont(QFont("Arial", 32, QFont.Bold))
            title.setAlignment(Qt.AlignCenter)
            title.setStyleSheet(f"""
                color: {TEXT_PRIMARY};
                margin-bottom: 10px;
                letter-spacing: 3px;
            """)
            layout.addWidget(title)
            
            # Subtitle
            subtitle = QLabel("Advanced Security Protocol")
            subtitle.setFont(QFont("Arial", 12))
            subtitle.setAlignment(Qt.AlignCenter)
            subtitle.setStyleSheet(f"""
                color: {TEXT_SECONDARY};
                margin-bottom: 40px;
                letter-spacing: 1px;
            """)
            layout.addWidget(subtitle)
            
            # Login form
            form_group = QGroupBox()
            form_group.setStyleSheet(f"""
                QGroupBox {{
                    background-color: {CARD_BG};
                    border: 1px solid {BORDER_COLOR};
                    border-radius: 10px;
                    padding: 20px;
                    margin-top: 10px;
                }}
            """)
            form_layout = QFormLayout()
            form_layout.setSpacing(15)
            
            # Style for input fields
            input_style = f"""
                QLineEdit {{
                    background-color: {DARKER_BG};
                    border: 1px solid {BORDER_COLOR};
                    border-radius: 5px;
                    padding: 10px;
                    color: {TEXT_PRIMARY};
                    font-size: 14px;
                }}
                QLineEdit:focus {{
                    border: 1px solid {ACCENT_BLUE};
                }}
            """
            
            self.username_input = QLineEdit()
            self.username_input.setPlaceholderText("Enter username")
            self.username_input.setStyleSheet(input_style)
            
            self.password_input = QLineEdit()
            self.password_input.setPlaceholderText("Enter password")
            self.password_input.setEchoMode(QLineEdit.Password)
            self.password_input.setStyleSheet(input_style)
            
            # Style for labels
            label_style = f"color: {TEXT_SECONDARY}; font-size: 14px; font-weight: bold;"
            
            username_label = QLabel("Username:")
            username_label.setStyleSheet(label_style)
            password_label = QLabel("Password:")
            password_label.setStyleSheet(label_style)
            
            form_layout.addRow(username_label, self.username_input)
            form_layout.addRow(password_label, self.password_input)
            
            form_group.setLayout(form_layout)
            layout.addWidget(form_group)
            
            layout.addSpacing(20)
            
            # Buttons
            button_layout = QHBoxLayout()
            button_layout.setSpacing(15)
            
            button_style = f"""
                QPushButton {{
                    background-color: {ACCENT_BLUE};
                    color: {TEXT_PRIMARY};
                    border: none;
                    border-radius: 5px;
                    padding: 12px;
                    font-size: 14px;
                    font-weight: bold;
                    min-width: 120px;
                }}
                QPushButton:hover {{
                    background-color: {LIGHT_BLUE};
                }}
                QPushButton:pressed {{
                    background-color: {ACCENT_BLUE};
                }}
                QPushButton:disabled {{
                    background-color: {BORDER_COLOR};
                    color: {TEXT_SECONDARY};
                }}
            """
            
            self.login_btn = QPushButton("LOGIN")
            self.login_btn.setStyleSheet(button_style)
            self.login_btn.clicked.connect(self.handle_login)
            
            self.signup_btn = QPushButton("SIGN UP")
            self.signup_btn.setStyleSheet(button_style)
            self.signup_btn.clicked.connect(self.handle_signup)
            
            button_layout.addWidget(self.login_btn)
            button_layout.addWidget(self.signup_btn)
            
            layout.addLayout(button_layout)
            
            layout.addSpacing(20)
            
            # Status label
            self.auth_status_label = QLabel()
            self.auth_status_label.setAlignment(Qt.AlignCenter)
            self.auth_status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
            layout.addWidget(self.auth_status_label)
            
            layout.addStretch()
            
            self.stacked_widget.addWidget(login_widget)
        except Exception as e:
            logger.error(f"Error creating login screen: {e}")
            QMessageBox.critical(self, "Error", f"Failed to create login screen: {e}")
    
    def create_dashboard_screen(self):
        """Create the main dashboard screen"""
        try:
            dashboard_widget = QWidget()
            dashboard_widget.setStyleSheet(f"background-color: {DARK_BG};")
            layout = QVBoxLayout(dashboard_widget)
            layout.setContentsMargins(30, 30, 30, 30)
            layout.setSpacing(20)
            
            # Header
            header_layout = QHBoxLayout()
            
            self.user_label = QLabel("Welcome")
            self.user_label.setFont(QFont("Arial", 16))
            self.user_label.setStyleSheet(f"color: {TEXT_PRIMARY};")
            header_layout.addWidget(self.user_label)
            
            header_layout.addStretch()
            
            logout_btn = QPushButton("LOGOUT")
            logout_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    color: {TEXT_SECONDARY};
                    border: 1px solid {BORDER_COLOR};
                    border-radius: 5px;
                    padding: 8px 16px;
                    font-size: 12px;
                }}
                QPushButton:hover {{
                    border-color: {ACCENT_BLUE};
                    color: {ACCENT_BLUE};
                }}
            """)
            logout_btn.clicked.connect(self.handle_logout)
            header_layout.addWidget(logout_btn)
            
            layout.addLayout(header_layout)
            
            # Connection status
            status_group = QGroupBox()
            status_group.setStyleSheet(f"""
                QGroupBox {{
                    background-color: {CARD_BG};
                    border: 1px solid {BORDER_COLOR};
                    border-radius: 10px;
                    padding: 30px;
                    margin-top: 10px;
                }}
            """)
            status_layout = QVBoxLayout()
            
            self.connection_status = QLabel("DISCONNECTED")
            self.connection_status.setFont(QFont("Arial", 28, QFont.Bold))
            self.connection_status.setAlignment(Qt.AlignCenter)
            self.connection_status.setStyleSheet(f"color: {ERROR_RED}; letter-spacing: 2px;")
            status_layout.addWidget(self.connection_status)
            
            self.status_details = QLabel("")
            self.status_details.setAlignment(Qt.AlignCenter)
            self.status_details.setStyleSheet(f"color: {TEXT_SECONDARY}; margin-top: 10px;")
            status_layout.addWidget(self.status_details)
            
            status_group.setLayout(status_layout)
            layout.addWidget(status_group)
            
            # Connect button
            self.connect_btn = QPushButton("CONNECT TO VPN")
            self.connect_btn.setMinimumHeight(60)
            self.connect_btn.setFont(QFont("Arial", 16, QFont.Bold))
            self.connect_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {ACCENT_BLUE};
                    color: {TEXT_PRIMARY};
                    border: none;
                    border-radius: 8px;
                    font-size: 16px;
                    letter-spacing: 1px;
                }}
                QPushButton:hover {{
                    background-color: {LIGHT_BLUE};
                }}
                QPushButton:disabled {{
                    background-color: {BORDER_COLOR};
                    color: {TEXT_SECONDARY};
                }}
            """)
            self.connect_btn.clicked.connect(self.toggle_vpn_connection)
            layout.addWidget(self.connect_btn)
            
            # Connection info
            info_group = QGroupBox()
            info_group.setStyleSheet(f"""
                QGroupBox {{
                    background-color: {CARD_BG};
                    border: 1px solid {BORDER_COLOR};
                    border-radius: 10px;
                    padding: 20px;
                    margin-top: 10px;
                }}
            """)
            info_layout = QFormLayout()
            info_layout.setSpacing(15)
            
            # Style for info labels
            label_style = f"""
                QLabel {{
                    color: {TEXT_SECONDARY};
                    font-size: 14px;
                }}
            """
            value_style = f"""
                QLabel {{
                    color: {TEXT_PRIMARY};
                    font-size: 14px;
                    font-weight: bold;
                }}
            """
            
            ip_title = QLabel("Your VPN IP:")
            ip_title.setStyleSheet(label_style)
            server_title = QLabel("Server:")
            server_title.setStyleSheet(label_style)
            
            self.ip_label = QLabel("N/A")
            self.ip_label.setStyleSheet(value_style)
            self.server_label = QLabel(f"{self.vpn_client.server_address}:{self.vpn_client.server_port}")
            self.server_label.setStyleSheet(value_style)
            
            info_layout.addRow(ip_title, self.ip_label)
            info_layout.addRow(server_title, self.server_label)
            
            info_group.setLayout(info_layout)
            layout.addWidget(info_group)
            
            layout.addStretch()
            
            self.stacked_widget.addWidget(dashboard_widget)
        except Exception as e:
            logger.error(f"Error creating dashboard screen: {e}")
            QMessageBox.critical(self, "Error", f"Failed to create dashboard screen: {e}")
    
    def handle_login(self):
        """Handle login button click"""
        try:
            username = self.username_input.text().strip()
            password = self.password_input.text()
            
            if not username or not password:
                self.auth_status_label.setText("Please enter both username and password")
                self.auth_status_label.setStyleSheet(f"color: {ERROR_RED}; font-size: 13px;")
                return
            
            self.auth_status_label.setText("Authenticating...")
            self.auth_status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
            self.login_btn.setEnabled(False)
            self.signup_btn.setEnabled(False)
            
            # Send login request
            if self.vpn_client.send_login(username, password):
                # Wait for response
                response = self.vpn_client.wait_for_auth_response()
                
                if response['success']:
                    self.current_user = username
                    self.auth_token = response.get('session_token')
                    self.vpn_client.auth_token = self.auth_token
                    
                    self.user_label.setText(f"Welcome, {username}")
                    self.stacked_widget.setCurrentIndex(1)
                    
                    # Clear form
                    self.username_input.clear()
                    self.password_input.clear()
                    self.auth_status_label.clear()
                else:
                    self.auth_status_label.setText(f"Login failed: {response['message']}")
                    self.auth_status_label.setStyleSheet(f"color: {ERROR_RED}; font-size: 13px;")
            else:
                self.auth_status_label.setText("Failed to send login request")
                self.auth_status_label.setStyleSheet(f"color: {ERROR_RED}; font-size: 13px;")
            
            self.login_btn.setEnabled(True)
            self.signup_btn.setEnabled(True)
        except Exception as e:
            logger.error(f"Error during login: {e}")
            self.auth_status_label.setText(f"Error: {e}")
            self.auth_status_label.setStyleSheet(f"color: {ERROR_RED}; font-size: 13px;")
            self.login_btn.setEnabled(True)
            self.signup_btn.setEnabled(True)
    
    def handle_signup(self):
        """Handle signup button click"""
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            self.auth_status_label.setText("Please enter both username and password")
            self.auth_status_label.setStyleSheet(f"color: {ERROR_RED}; font-size: 13px;")
            return
        
        self.auth_status_label.setText("Creating account...")
        self.auth_status_label.setStyleSheet(f"color: {TEXT_SECONDARY}; font-size: 13px;")
        self.login_btn.setEnabled(False)
        self.signup_btn.setEnabled(False)
        
        if self.vpn_client.send_signup(username, password):
            response = self.vpn_client.wait_for_auth_response()
            
            if response['success']:
                self.auth_status_label.setText("Account created! Please login.")
                self.auth_status_label.setStyleSheet(f"color: {SUCCESS_GREEN}; font-size: 13px;")
                QMessageBox.information(self, "Success", "Account created successfully! Please login.")
            else:
                self.auth_status_label.setText(f"Signup failed: {response['message']}")
                self.auth_status_label.setStyleSheet(f"color: {ERROR_RED}; font-size: 13px;")
        else:
            self.auth_status_label.setText("Failed to send signup request")
            self.auth_status_label.setStyleSheet(f"color: {ERROR_RED}; font-size: 13px;")
        
        self.login_btn.setEnabled(True)
        self.signup_btn.setEnabled(True)
    
    def toggle_vpn_connection(self):
        """Toggle VPN connection on/off"""
        try:
            if self.connect_btn.text() == "CONNECT TO VPN":
                self.start_vpn_connection()
            else:
                self.stop_vpn_connection()
        except Exception as e:
            logger.error(f"Error toggling VPN connection: {e}")
            QMessageBox.critical(self, "Error", f"Failed to toggle VPN connection: {e}")
    
    def start_vpn_connection(self):
        """Start VPN connection"""
        try:
            self.connect_btn.setEnabled(False)
            self.connection_status.setText("CONNECTING...")
            self.connection_status.setStyleSheet(f"color: {TEXT_SECONDARY}; letter-spacing: 2px;")
            
            def connect_thread():
                try:
                    self.vpn_client.stop_client()
                    time.sleep(1)
                    
                    # Start full VPN client
                    self.vpn_client.start_client()
                    self.vpn_client.auth_token = self.auth_token
                    self.vpn_client.run_client()
                    
                    self.vpn_client.initiate_secure_connection()
                    if not self.vpn_client.encryption_ready_event.wait(5.0):
                        logger.error("Key exchange timed out")
                        self.connection_status.setText("KEY EXCHANGE FAILED")
                        self.connection_status.setStyleSheet(f"color: {ERROR_RED}; letter-spacing: 2px;")
                        self.connect_btn.setText("CONNECT TO VPN")
                        self.connect_btn.setEnabled(True)
                        return
                    
                    # Connect to server
                    if self.vpn_client.connect_to_server():
                        # Wait a bit for the configuration to be fully processed
                        time.sleep(2)
                        
                        self.connection_status.setText("CONNECTED")
                        self.connection_status.setStyleSheet(f"color: {SUCCESS_GREEN}; letter-spacing: 2px;")
                        self.connect_btn.setText("DISCONNECT FROM VPN")
                        self.connect_btn.setStyleSheet(f"""
                            QPushButton {{
                                background-color: {ERROR_RED};
                                color: {TEXT_PRIMARY};
                                border: none;
                                border-radius: 8px;
                                font-size: 16px;
                                letter-spacing: 1px;
                            }}
                            QPushButton:hover {{
                                background-color: #ff6666;
                            }}
                        """)
                        
                        self.monitor_timer.start(1000)
                        self.update_connection_status()
                    else:
                        self.connection_status.setText("CONNECTION FAILED")
                        self.connection_status.setStyleSheet(f"color: {ERROR_RED}; letter-spacing: 2px;")
                        self.connect_btn.setText("CONNECT TO VPN")
                except Exception as e:
                    logger.error(f"Connection error: {e}")
                    self.connection_status.setText("ERROR")
                    self.connection_status.setStyleSheet(f"color: {ERROR_RED}; letter-spacing: 2px;")
                finally:
                    self.connect_btn.setEnabled(True)
            
            threading.Thread(target=connect_thread, daemon=True).start()
        except Exception as e:
            logger.error(f"Error starting VPN connection: {e}")
            self.connection_status.setText("ERROR")
            self.connection_status.setStyleSheet(f"color: {ERROR_RED}; letter-spacing: 2px;")
            self.connect_btn.setEnabled(True)
    
    def stop_vpn_connection(self):
        """Stop VPN connection"""
        try:
            self.monitor_timer.stop()
            self.connect_btn.setEnabled(False)
            self.connection_status.setText("DISCONNECTING...")
            self.connection_status.setStyleSheet(f"color: {TEXT_SECONDARY}; letter-spacing: 2px;")
            
            def disconnect_thread():
                try:
                    self.vpn_client.stop_client()
                    time.sleep(1)
                    self.vpn_client.start_minimal_infrastructure()
                    
                    self.connection_status.setText("DISCONNECTED")
                    self.connection_status.setStyleSheet(f"color: {ERROR_RED}; letter-spacing: 2px;")
                    self.connect_btn.setText("CONNECT TO VPN")
                    self.connect_btn.setStyleSheet(f"""
                        QPushButton {{
                            background-color: {ACCENT_BLUE};
                            color: {TEXT_PRIMARY};
                            border: none;
                            border-radius: 8px;
                            font-size: 16px;
                            letter-spacing: 1px;
                        }}
                        QPushButton:hover {{
                            background-color: {LIGHT_BLUE};
                        }}
                    """)
                    self.ip_label.setText("N/A")
                finally:
                    self.connect_btn.setEnabled(True)
            
            threading.Thread(target=disconnect_thread, daemon=True).start()
        except Exception as e:
            logger.error(f"Error stopping VPN connection: {e}")
            self.connection_status.setText("ERROR")
    
    def update_connection_status(self):
        """Update connection status display"""
        try:
            if self.vpn_client.connection_state == ConnectionState.CONNECTED:
                if hasattr(self.vpn_client, 'virtual_ip') and self.vpn_client.virtual_ip:
                    self.ip_label.setText(self.vpn_client.virtual_ip)
                else:
                    self.ip_label.setText("Obtaining IP...")
                    
                self.status_details.setText("VPN tunnel is active and secure")
            else:
                self.connection_status.setText("DISCONNECTED")
                self.connection_status.setStyleSheet(f"color: {ERROR_RED}; letter-spacing: 2px;")
                self.connect_btn.setText("CONNECT TO VPN")
                self.ip_label.setText("N/A")
                self.monitor_timer.stop()
        except Exception as e:
            logger.error(f"Error updating connection status: {e}")
            self.connection_status.setText("ERROR")
            self.connection_status.setStyleSheet(f"color: {ERROR_RED}; letter-spacing: 2px;")
    
    def handle_logout(self):
        """Handle logout"""
        try:
            if self.vpn_client.connection_state == ConnectionState.CONNECTED:
                self.stop_vpn_connection()
            
            self.current_user = None
            self.auth_token = None
            self.vpn_client.auth_token = None
            
            # Return to login screen
            self.stacked_widget.setCurrentIndex(0)
        except Exception as e:
            logger.error(f"Error during logout: {e}")
            QMessageBox.critical(self, "Error", f"Failed to logout: {e}")
    
    def closeEvent(self, event):
        """Handle application close"""
        try:
            if self.vpn_client.connection_state == ConnectionState.CONNECTED:
                self.vpn_client.stop_client()
            else:
                self.vpn_client.stop_client()
            event.accept()
        except Exception as e:
            logger.error(f"Error closing application: {e}")
            event.ignore()
            QMessageBox.critical(self, "Error", f"Failed to close application: {e}")


def main():
    """Main function to run the application"""
    try:
        app = QApplication(sys.argv)
        
        # Set application style
        app.setStyle('Fusion')
        
        # Create and apply dark palette
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(DARK_BG))
        dark_palette.setColor(QPalette.WindowText, QColor(TEXT_PRIMARY))
        dark_palette.setColor(QPalette.Base, QColor(DARKER_BG))
        dark_palette.setColor(QPalette.AlternateBase, QColor(CARD_BG))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(CARD_BG))
        dark_palette.setColor(QPalette.ToolTipText, QColor(TEXT_PRIMARY))
        dark_palette.setColor(QPalette.Text, QColor(TEXT_PRIMARY))
        dark_palette.setColor(QPalette.Button, QColor(CARD_BG))
        dark_palette.setColor(QPalette.ButtonText, QColor(TEXT_PRIMARY))
        dark_palette.setColor(QPalette.BrightText, QColor(TEXT_PRIMARY))
        dark_palette.setColor(QPalette.Link, QColor(ACCENT_BLUE))
        dark_palette.setColor(QPalette.Highlight, QColor(ACCENT_BLUE))
        dark_palette.setColor(QPalette.HighlightedText, QColor(TEXT_PRIMARY))
        
        app.setPalette(dark_palette)
        
        # Set global stylesheet for QMessageBox and other dialogs
        app.setStyleSheet(f"""
            QMessageBox {{
                background-color: {CARD_BG};
                color: {TEXT_PRIMARY};
            }}
            QMessageBox QPushButton {{
                background-color: {ACCENT_BLUE};
                color: {TEXT_PRIMARY};
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                min-width: 80px;
            }}
            QMessageBox QPushButton:hover {{
                background-color: {LIGHT_BLUE};
            }}
        """)
        
        window = MainWindow()
        window.show()
        
        sys.exit(app.exec_())
    except Exception as e:
        logger.error(f"Error starting application: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()