# server_user_manager.py
import sqlite3
import os
import time
import hashlib
import logging
from typing import Dict, Optional
import threading

logger = logging.getLogger('VPN-UserManager')

class ServerUserManager:
    """Server-side user management with SQLite database"""
    
    def __init__(self, db_file="vpn_users.db"):
        # Ensure absolute path and create directory if needed
        if not os.path.isabs(db_file):
            # Use the current working directory
            db_file = os.path.abspath(db_file)
        
        # Create directory if it doesn't exist
        db_dir = os.path.dirname(db_file)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            
        self.db_file = db_file
        self._lock = threading.Lock()
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database with required tables"""
        conn = None
        with self._lock:
            try:
                # Use explicit connection parameters
                conn = sqlite3.connect(self.db_file, check_same_thread=False)
                cursor = conn.cursor()
                
                # Create users table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        last_login REAL
                    )
                ''')
                
                # Create sessions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_token TEXT UNIQUE NOT NULL,
                        user_id INTEGER NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_session_token ON sessions(session_token)')
                
                conn.commit()
                logger.info(f"Database initialized successfully at: {self.db_file}")
                
            except sqlite3.Error as e:
                logger.error(f"Database initialization error: {e}")
                logger.error(f"Database path: {self.db_file}")
                raise
            finally:
                if conn:  # Only close if conn was successfully created
                    conn.close()
    
    def _get_connection(self):
        """Get a database connection"""
        return sqlite3.connect(self.db_file, check_same_thread=False)
    
    def _hash_password(self, password: str, salt: str = None) -> tuple:
        """Hash password with salt"""
        if salt is None:
            salt = os.urandom(32).hex()
        
        # Use PBKDF2 for password hashing
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        ).hex()
        
        return pwd_hash, salt
    
    def register_user(self, username: str, password: str) -> Dict:
        """Register a new user"""
        with self._lock:
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                # Check if username already exists
                cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
                if cursor.fetchone():
                    return {
                        'success': False,
                        'message': 'Username already exists'
                    }
                
                # Hash the password
                pwd_hash, salt = self._hash_password(password)
                
                # Insert new user
                cursor.execute('''
                    INSERT INTO users (username, password_hash, salt, created_at)
                    VALUES (?, ?, ?, ?)
                ''', (username, pwd_hash, salt, time.time()))
                
                conn.commit()
                logger.info(f"New user registered: {username}")
                
                return {
                    'success': True,
                    'message': 'User registered successfully'
                }
                
            except sqlite3.Error as e:
                logger.error(f"Error registering user: {e}")
                return {
                    'success': False,
                    'message': 'Registration failed due to server error'
                }
            finally:
                conn.close()
    
    def authenticate_user(self, username: str, password: str) -> Dict:
        """Authenticate a user"""
        with self._lock:
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                # Get user data
                cursor.execute('''
                    SELECT id, password_hash, salt 
                    FROM users 
                    WHERE username = ?
                ''', (username,))
                
                user_data = cursor.fetchone()
                
                if not user_data:
                    return {
                        'success': False,
                        'message': 'Invalid username or password',
                        'session_token': None
                    }
                
                user_id, stored_hash, salt = user_data
                
                # Verify password
                pwd_hash, _ = self._hash_password(password, salt)
                
                if pwd_hash != stored_hash:
                    return {
                        'success': False,
                        'message': 'Invalid username or password',
                        'session_token': None
                    }
                
                # Generate session token
                session_token = os.urandom(32).hex()
                expires_at = time.time() + (24 * 60 * 60)  # 24 hours
                
                # Store session
                cursor.execute('''
                    INSERT INTO sessions (session_token, user_id, created_at, expires_at)
                    VALUES (?, ?, ?, ?)
                ''', (session_token, user_id, time.time(), expires_at))
                
                # Update last login
                cursor.execute('''
                    UPDATE users 
                    SET last_login = ? 
                    WHERE id = ?
                ''', (time.time(), user_id))
                
                conn.commit()
                logger.info(f"User authenticated: {username}")
                
                return {
                    'success': True,
                    'message': 'Login successful',
                    'session_token': session_token
                }
                
            except sqlite3.Error as e:
                logger.error(f"Error authenticating user: {e}")
                return {
                    'success': False,
                    'message': 'Authentication failed due to server error',
                    'session_token': None
                }
            finally:
                conn.close()
    
    def validate_session(self, session_token: str) -> Optional[str]:
        """Validate a session token and return username if valid"""
        with self._lock:
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                # Check if session is valid and not expired
                cursor.execute('''
                    SELECT u.username, s.expires_at
                    FROM sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.session_token = ?
                ''', (session_token,))
                
                result = cursor.fetchone()
                
                if not result:
                    return None
                
                username, expires_at = result
                
                # Check if session has expired
                if time.time() > expires_at:
                    # Clean up expired session
                    cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
                    conn.commit()
                    return None
                
                return username
                
            except sqlite3.Error as e:
                logger.error(f"Error validating session: {e}")
                return None
            finally:
                conn.close()
    
    def invalidate_session(self, session_token: str):
        """Invalidate a session token"""
        with self._lock:
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                # Get username before deleting session
                cursor.execute('''
                    SELECT u.username
                    FROM sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.session_token = ?
                ''', (session_token,))
                
                result = cursor.fetchone()
                
                if result:
                    username = result[0]
                    
                    # Delete the session
                    cursor.execute('DELETE FROM sessions WHERE session_token = ?', (session_token,))
                    conn.commit()
                    
                    logger.info(f"Session invalidated for user: {username}")
                
            except sqlite3.Error as e:
                logger.error(f"Error invalidating session: {e}")
            finally:
                conn.close()
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions from database"""
        with self._lock:
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                # Delete expired sessions
                cursor.execute('''
                    DELETE FROM sessions 
                    WHERE expires_at < ?
                ''', (time.time(),))
                
                deleted_count = cursor.rowcount
                
                if deleted_count > 0:
                    conn.commit()
                    logger.info(f"Cleaned up {deleted_count} expired sessions")
                
            except sqlite3.Error as e:
                logger.error(f"Error cleaning up sessions: {e}")
            finally:
                conn.close()
    
    def get_user_stats(self) -> Dict:
        """Get statistics about users and sessions"""
        with self._lock:
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                # Get total users
                cursor.execute('SELECT COUNT(*) FROM users')
                total_users = cursor.fetchone()[0]
                
                # Get active sessions
                cursor.execute('SELECT COUNT(*) FROM sessions WHERE expires_at > ?', (time.time(),))
                active_sessions = cursor.fetchone()[0]
                
                # Get users logged in last 24 hours
                cursor.execute('''
                    SELECT COUNT(*) FROM users 
                    WHERE last_login > ?
                ''', (time.time() - (24 * 60 * 60),))
                recent_logins = cursor.fetchone()[0]
                
                return {
                    'total_users': total_users,
                    'active_sessions': active_sessions,
                    'recent_logins': recent_logins
                }
                
            except sqlite3.Error as e:
                logger.error(f"Error getting user stats: {e}")
                return {
                    'total_users': 0,
                    'active_sessions': 0,
                    'recent_logins': 0
                }
            finally:
                conn.close()