#!/opt/honeypot/venv/bin/python3
"""
Dionaea Log Processor - Improved Version with Incremental Updates
Processes dionaea logs and creates web-ready data files
Live demo available at: ibaim.eus/honey
"""

import json
import datetime
import os
import re
import sys
import shutil
from collections import defaultdict, Counter
from pathlib import Path

# Try to import optional dependencies
try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False

class DionaeaLogProcessor:
    def __init__(self, 
                 log_path='/opt/dionaea/var/log/dionaea/dionaea.log',
                 output_dir='/tmp/honeypot_data',
                 verbose=False,
                 incremental=True,
                 binaries_dir='/opt/dionaea/var/lib/dionaea/binaries'):
        
        self.log_path = log_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.verbose = verbose
        self.incremental = incremental
        self.binaries_dir = Path(binaries_dir)
        self.processed_log_path = self.output_dir / 'processed_dionaea.log'
        
        # Persistent attack database to survive log rotations
        self.persistent_db_path = self.output_dir / 'persistent_attacks.json'
        self.backup_db_path = self.output_dir / 'persistent_attacks_backup.json'
        
        # GeoIP setup
        self.geoip_reader = None
        if HAS_GEOIP:
            geoip_paths = [
                '/opt/dionaea/var/lib/GeoIP/GeoLite2-City.mmdb',
                '/usr/share/GeoIP/GeoLite2-City.mmdb',
                '/var/lib/GeoIP/GeoLite2-City.mmdb'
            ]
            
            for path in geoip_paths:
                if os.path.exists(path):
                    try:
                        self.geoip_reader = geoip2.database.Reader(path)
                        if self.verbose:
                            print(f"Using GeoIP database: {path}")
                        break
                    except Exception as e:
                        if self.verbose:
                            print(f"Failed to load GeoIP from {path}: {e}")
                        continue

    def get_location(self, ip):
        """Get geographic location of IP address"""
        # Skip private/local IPs
        if ip.startswith(('192.168.', '10.', '172.16.', '127.', '0.0.0.0')):
            return {"country": "Private/Local", "city": "Local Network", "lat": 0, "lon": 0}
            
        if not self.geoip_reader:
            return {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}
        
        try:
            response = self.geoip_reader.city(ip)
            return {
                "country": response.country.name or "Unknown",
                "city": response.city.name or "Unknown", 
                "lat": float(response.location.latitude) if response.location.latitude else 0,
                "lon": float(response.location.longitude) if response.location.longitude else 0
            }
        except:
            return {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}

    def guess_service_from_port(self, port):
        """Guess service type from port number"""
        port_map = {
            '21': 'ftp', '22': 'ssh', '23': 'telnet', '25': 'smtp',
            '53': 'dns', '80': 'http', '110': 'pop3', '135': 'epmap',
            '139': 'netbios', '143': 'imap', '443': 'https', '445': 'smb',
            '993': 'imaps', '995': 'pop3s', '1433': 'mssql', '3306': 'mysql',
            '3389': 'rdp', '5060': 'sip', '1723': 'pptp', '5000': 'upnp',
            '11211': 'memcache', '27017': 'mongo', '1883': 'mqtt',
            '631': 'printer', '69': 'tftp'
        }
        return port_map.get(str(port), f'port-{port}')

    def analyze_binaries(self):
        """Analyze collected malware binaries from both folder and log entries"""
        binary_stats = {
            'total_binaries': 0,
            'binary_sizes': {},
            'recent_samples': [],  # Changed from recent_binaries to match web interface
            'size_distribution': {
                '1kb': 0,      # < 1KB
                '1_10kb': 0,   # 1-10KB  
                '10_100kb': 0, # 10-100KB
                '100kb_1mb': 0, # 100KB-1MB
                '1mb': 0       # > 1MB
            },
            'file_types': {},
            'download_events': [],  # Events from logs
            'upload_events': []     # Events from logs
        }
        
        # Part 1: Analyze physical binary files in directory
        binary_files_from_folder = self.analyze_binary_folder()
        
        # Part 2: Extract binary-related events from logs  
        binary_events_from_logs = self.extract_binary_events_from_logs()
        
        # Combine results from both sources
        all_binaries = binary_files_from_folder + binary_events_from_logs
        
        # Process combined data
        if all_binaries:
            # Sort by timestamp (newest first)
            all_binaries.sort(key=lambda x: x.get('timestamp', x.get('modified', '')), reverse=True)
            
            binary_stats['total_binaries'] = len(all_binaries)
            binary_stats['recent_samples'] = all_binaries[:10]  # Last 10 samples
            
            # Calculate statistics
            sizes = [b['size'] for b in all_binaries if 'size' in b and b['size'] > 0]
            if sizes:
                binary_stats['binary_sizes'] = {
                    'min': min(sizes),
                    'max': max(sizes),
                    'avg': sum(sizes) // len(sizes),
                    'total': sum(sizes)
                }
            
            # Aggregate file types and size distribution
            for binary in all_binaries:
                # File type counting
                file_type = binary.get('file_type', binary.get('type', 'unknown'))
                binary_stats['file_types'][file_type] = binary_stats['file_types'].get(file_type, 0) + 1
                
                # Size distribution
                size = binary.get('size', 0)
                if size < 1024:  # < 1KB
                    binary_stats['size_distribution']['1kb'] += 1
                elif size < 10 * 1024:  # 1-10KB
                    binary_stats['size_distribution']['1_10kb'] += 1
                elif size < 100 * 1024:  # 10-100KB
                    binary_stats['size_distribution']['10_100kb'] += 1
                elif size < 1024 * 1024:  # 100KB-1MB
                    binary_stats['size_distribution']['100kb_1mb'] += 1
                else:  # > 1MB
                    binary_stats['size_distribution']['1mb'] += 1
        
        if self.verbose:
            print(f"Analyzed {len(binary_files_from_folder)} files from folder and {len(binary_events_from_logs)} events from logs")
            print(f"Total unique binaries: {binary_stats['total_binaries']}")
                
        return binary_stats

    def analyze_binary_folder(self):
        """Analyze physical binary files in the binaries directory"""
        binary_files = []
        
        if not self.binaries_dir.exists():
            if self.verbose:
                print(f"Binaries directory not found: {self.binaries_dir}")
            return binary_files
        
        try:
            for file_path in self.binaries_dir.iterdir():
                if file_path.is_file():
                    try:
                        stat = file_path.stat()
                        binary_info = {
                            'filename': file_path.name,
                            'size': stat.st_size,
                            'timestamp': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'hash': file_path.name if len(file_path.name) == 32 else 'unknown',
                            'source': 'folder'
                        }
                        
                        # Try to detect file type by reading first few bytes
                        try:
                            with open(file_path, 'rb') as f:
                                header = f.read(16)
                                file_type = self.detect_file_type(header)
                                binary_info['file_type'] = file_type
                        except:
                            binary_info['file_type'] = 'unknown'
                        
                        binary_files.append(binary_info)
                        
                    except Exception as e:
                        if self.verbose:
                            print(f"Error analyzing binary {file_path.name}: {e}")
                        continue
            
            if self.verbose:
                print(f"Found {len(binary_files)} files in binaries directory")
                
        except Exception as e:
            if self.verbose:
                print(f"Error scanning binaries directory: {e}")
        
        return binary_files

    def extract_binary_events_from_logs(self):
        """Extract binary download/upload events from Dionaea logs"""
        binary_events = []
        
        if not os.path.exists(self.log_path):
            if self.verbose:
                print(f"Log file not found for binary extraction: {self.log_path}")
            return binary_events
        
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    # Look for binary-related patterns in logs
                    patterns = [
                        # Download events
                        r'\[(\d{2})(\d{2})(\d{4}) (\d{2}:\d{2}:\d{2})\].*download.*(?:url|URL).*?(\d+)\s*bytes.*?(?:file|filename).*?([a-fA-F0-9]{32}|\w+\.\w+)',
                        r'\[(\d{2})(\d{2})(\d{4}) (\d{2}:\d{2}:\d{2})\].*download.*complete.*?(\d+)\s*bytes.*?([a-fA-F0-9]{32}|\w+\.\w+)',
                        r'\[(\d{2})(\d{2})(\d{4}) (\d{2}:\d{2}:\d{2})\].*file.*received.*?(\d+)\s*bytes.*?([a-fA-F0-9]{32}|\w+\.\w+)',
                        # Upload events  
                        r'\[(\d{2})(\d{2})(\d{4}) (\d{2}:\d{2}:\d{2})\].*upload.*?(\d+)\s*bytes.*?([a-fA-F0-9]{32}|\w+\.\w+)',
                        r'\[(\d{2})(\d{2})(\d{4}) (\d{2}:\d{2}:\d{2})\].*file.*sent.*?(\d+)\s*bytes.*?([a-fA-F0-9]{32}|\w+\.\w+)',
                    ]
                    
                    for pattern in patterns:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            try:
                                # Parse timestamp (DDMMYYYY format)
                                day, month, year, time_str = match.group(1), match.group(2), match.group(3), match.group(4)
                                size = int(match.group(5))
                                filename = match.group(6)
                                
                                # Create datetime object
                                dt = datetime.datetime(
                                    int(year), int(month), int(day),
                                    int(time_str[0:2]), int(time_str[3:5]), int(time_str[6:8])
                                )
                                
                                # Determine event type
                                event_type = 'download' if 'download' in line.lower() or 'received' in line.lower() else 'upload'
                                
                                # Guess file type from filename or content
                                file_type = self.guess_file_type_from_name(filename)
                                
                                binary_event = {
                                    'filename': filename,
                                    'size': size,
                                    'timestamp': dt.isoformat(),
                                    'file_type': file_type,
                                    'event_type': event_type,
                                    'source': 'log'
                                }
                                
                                binary_events.append(binary_event)
                                break
                                
                            except Exception as e:
                                if self.verbose:
                                    print(f"Error parsing binary event from line: {line.strip()}")
                                    print(f"Error: {e}")
                                continue
            
            if self.verbose and binary_events:
                print(f"Extracted {len(binary_events)} binary events from logs")
                                
        except Exception as e:
            if self.verbose:
                print(f"Error reading log for binary events: {e}")
        
        return binary_events

    def guess_file_type_from_name(self, filename):
        """Guess file type from filename extension"""
        if not filename or '.' not in filename:
            return 'unknown'
        
        ext = filename.lower().split('.')[-1]
        
        # Executable files
        if ext in ['exe', 'dll', 'scr', 'com', 'bat', 'cmd', 'pif']:
            return 'Windows_executable'
        elif ext in ['sh', 'bin', 'run']:
            return 'Linux_executable'
        
        # Archives
        elif ext in ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz']:
            return f'{ext.upper()}_archive'
        
        # Scripts
        elif ext in ['py', 'pl', 'php', 'js', 'vbs', 'ps1']:
            return f'{ext.upper()}_script'
        
        # Documents
        elif ext in ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']:
            return f'{ext.upper()}_document'
        
        # Images
        elif ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff']:
            return f'{ext.upper()}_image'
        
        else:
            return f'{ext.upper()}_file'

    def detect_file_type(self, header):
        """Detect file type from binary header"""
        if len(header) < 2:
            return 'unknown'
        # PE executable (Windows)
        if header[:2] == b'MZ':
            return 'PE_executable'
        # ELF executable (Linux)
        elif header[:4] == b'\x7fELF':
            return 'ELF_executable'
        # ZIP archive (includes JAR, APK, DOCX, etc.)
        elif header[:2] == b'PK':
            return 'ZIP_archive'
        # GZIP compressed
        elif header[:2] == b'\x1f\x8b':
            return 'GZIP_archive'
        # RAR archive
        elif header[:4] == b'Rar!':
            return 'RAR_archive'
        # 7-Zip archive
        elif header[:6] == b'7z\xbc\xaf\x27\x1c':
            return '7ZIP_archive'
        # PDF document
        elif header[:4] == b'%PDF':
            return 'PDF_document'
        # JPEG image
        elif header[:2] == b'\xff\xd8':
            return 'JPEG_image'
        # PNG image
        elif header[:8] == b'\x89PNG\r\n\x1a\n':
            return 'PNG_image'
        # GIF image
        elif header[:3] == b'GIF':
            return 'GIF_image'
        # BMP image
        elif header[:2] == b'BM':
            return 'BMP_image'
        # Microsoft Office documents
        elif header[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
            return 'MS_Office_document'
        # RTF document
        elif header[:5] == b'{\\rtf':
            return 'RTF_document'
        # Windows batch file
        elif header[:2] == b'@e' or header[:3] == b'rem' or header[:4] == b'echo':
            return 'Batch_script'
        # Shell script
        elif header[:2] == b'#!' or header[:8] == b'#!/bin/s':
            return 'Shell_script'
        # Python script
        elif header[:7] == b'#!/usr/' and b'python' in header[:20]:
            return 'Python_script'
        # Perl script
        elif header[:7] == b'#!/usr/' and b'perl' in header[:20]:
            return 'Perl_script'
        # HTML/XML
        elif header[:5].lower() == b'<html' or header[:4] == b'<xml' or header[:5] == b'<?xml':
            return 'HTML_XML_document'
        # JavaScript
        elif b'function' in header[:50] or b'var ' in header[:50] or b'let ' in header[:50]:
            return 'JavaScript_file'
        # Text-based files with suspicious content
        elif any(keyword in header.lower() for keyword in [b'password', b'exploit', b'payload', b'shell', b'backdoor']):
            return 'Suspicious_text'
        # Generic text file
        elif all(b > 31 or b in [9, 10, 13] for b in header[:50] if header):  # Printable ASCII + common whitespace
            return 'Text_file'
        # Script files (text-based)
        elif header[0] in [0x20, 0x09] or (0x20 <= header[0] <= 0x7E):
            return 'script_text'
        # Unknown binary
        else:
            return 'unknown_binary'

    def load_persistent_attacks(self):
        """Load persistent attack database that survives log rotations"""
        persistent_attacks = []
        
        try:
            # Try to load from main database
            if self.persistent_db_path.exists():
                with open(self.persistent_db_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        persistent_attacks = data
                    else:
                        # Handle old format
                        persistent_attacks = data.get('attacks', [])
                        
                if self.verbose:
                    print(f"Loaded {len(persistent_attacks)} attacks from persistent database")
                    
            # Try backup if main fails or is empty
            elif self.backup_db_path.exists():
                with open(self.backup_db_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        persistent_attacks = data
                    else:
                        persistent_attacks = data.get('attacks', [])
                        
                if self.verbose:
                    print(f"Loaded {len(persistent_attacks)} attacks from backup database")
                    
        except Exception as e:
            if self.verbose:
                print(f"Error loading persistent attacks: {e}")
                
        return persistent_attacks

    def save_persistent_attacks(self, attacks):
        """Save attacks to persistent database with backup"""
        try:
            # Create backup of current database
            if self.persistent_db_path.exists():
                import shutil
                shutil.copy2(self.persistent_db_path, self.backup_db_path)
            
            # Save new data
            with open(self.persistent_db_path, 'w') as f:
                json.dump(attacks, f, indent=2, default=str)
                
            if self.verbose:
                print(f"Saved {len(attacks)} attacks to persistent database")
                
        except Exception as e:
            if self.verbose:
                print(f"Error saving persistent attacks: {e}")

    def load_existing_data(self):
        """Load existing JSON data files for incremental updates"""
        existing_data = {
            'attacks': [],
            'summary': {},
            'hourly_stats': {},
            'daily_stats': {},
            'binary_stats': {}
        }
        
        try:
            # First try to load from persistent database
            persistent_attacks = self.load_persistent_attacks()
            if persistent_attacks:
                existing_data['attacks'] = persistent_attacks
            else:
                # Fallback to regular attacks.json
                attacks_file = self.output_dir / 'attacks.json'
                if attacks_file.exists():
                    with open(attacks_file, 'r') as f:
                        existing_data['attacks'] = json.load(f)
                    
            # Load existing stats
            for stat_type in ['summary', 'hourly_stats', 'daily_stats', 'binary_stats']:
                stat_file = self.output_dir / f'{stat_type}.json'
                if stat_file.exists():
                    with open(stat_file, 'r') as f:
                        existing_data[stat_type] = json.load(f)
                        
        except Exception as e:
            if self.verbose:
                print(f"Error loading existing data: {e}")
                
        return existing_data

    def get_last_processed_position(self):
        """Get the last processed position in the log file"""
        if not self.processed_log_path.exists():
            return 0
            
        try:
            with open(self.processed_log_path, 'r') as f:
                return int(f.read().strip())
        except:
            return 0

    def save_processed_position(self, position):
        """Save the current processed position in the log file"""
        try:
            with open(self.processed_log_path, 'w') as f:
                f.write(str(position))
        except Exception as e:
            if self.verbose:
                print(f"Error saving processed position: {e}")

    def detect_log_rotation(self):
        """Detect if log file was rotated or deleted"""
        if not os.path.exists(self.log_path):
            if self.verbose:
                print("Log file not found - possible rotation or deletion")
            return True
            
        try:
            # Check if log file is significantly smaller than expected
            file_size = os.path.getsize(self.log_path)
            last_position = self.get_last_processed_position()
            
            if last_position > file_size and file_size < 1000:  # File is much smaller
                if self.verbose:
                    print("Log file appears to have been rotated (size decreased significantly)")
                return True
                
            # Check file modification time
            if self.processed_log_path.exists():
                log_mtime = os.path.getmtime(self.log_path)
                processed_mtime = os.path.getmtime(self.processed_log_path)
                
                # If log is much newer (more than 1 hour difference), likely rotated
                if (log_mtime - processed_mtime) > 3600:
                    if self.verbose:
                        print("Log file appears to have been rotated (timestamp difference)")
                    return True
                    
        except Exception as e:
            if self.verbose:
                print(f"Error detecting log rotation: {e}")
            return True
            
        return False

    def clear_old_log_data(self):
        """Clear old log data to keep processing fast"""
        if not os.path.exists(self.log_path):
            return
            
        try:
            # Get file stats before reading
            file_stats = os.stat(self.log_path)
            
            # Only truncate if file is larger than 5MB or has more than 50000 lines
            if file_stats.st_size > 5000000:  # 5MB
                with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                if len(lines) > 50000:
                    # Keep last 50000 lines
                    with open(self.log_path, 'w', encoding='utf-8') as f:
                        f.writelines(lines[-50000:])
                        
                    # Reset processed position since we truncated the file
                    self.save_processed_position(0)
                    
                    # Clear processed hashes since file was truncated
                    hash_file = self.output_dir / 'processed_hashes.txt'
                    if hash_file.exists():
                        hash_file.unlink()
                    
                    if self.verbose:
                        print(f"Truncated log file from {len(lines)} to 50000 lines")
                        
        except Exception as e:
            if self.verbose:
                print(f"Error clearing old log data: {e}")

    def get_last_processed_position(self):
        """Get the last processed position in the log file"""
        if not self.processed_log_path.exists():
            return 0
            
        try:
            # Check if log file was modified since last processing
            if os.path.exists(self.log_path):
                log_mtime = os.path.getmtime(self.log_path)
                processed_mtime = os.path.getmtime(self.processed_log_path)
                
                # If log is older than processed file, start from beginning
                if log_mtime < processed_mtime:
                    return 0
            
            with open(self.processed_log_path, 'r') as f:
                position = int(f.read().strip())
                
                # Validate position against current file size
                if os.path.exists(self.log_path):
                    file_size = os.path.getsize(self.log_path)
                    if position > file_size:
                        return 0
                        
                return position
        except:
            return 0

    def parse_dionaea_log(self):
        """Parse Dionaea log file with incremental processing and log rotation detection"""
        new_attacks = []
        
        # Check for log rotation first
        log_rotated = self.detect_log_rotation()
        
        if not os.path.exists(self.log_path):
            if self.verbose:
                print(f"Log file not found: {self.log_path}")
            # Reset position tracking if log file is missing
            self.save_processed_position(0)
            return new_attacks
        
        # Reset position tracking if log was rotated
        if log_rotated:
            if self.verbose:
                print("Log rotation detected, starting from beginning of new log")
            self.save_processed_position(0)
            # Clear hash file since we're starting fresh
            hash_file = self.output_dir / 'processed_hashes.txt'
            if hash_file.exists():
                hash_file.unlink()
        
        # Get last processed position for incremental updates
        last_position = self.get_last_processed_position() if self.incremental else 0
        current_position = last_position
        
        # Keep track of processed line hashes to avoid reprocessing
        processed_hashes = set()
        hash_file = self.output_dir / 'processed_hashes.txt'
        
        # Load existing processed hashes (skip if log was rotated)
        if hash_file.exists() and self.incremental and not log_rotated:
            try:
                with open(hash_file, 'r') as f:
                    processed_hashes = set(line.strip() for line in f if line.strip())
            except Exception as e:
                if self.verbose:
                    print(f"Error loading processed hashes: {e}")
        
        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Get file size
                f.seek(0, 2)  # Seek to end
                file_size = f.tell()
                
                # If last position is beyond file size, reset to 0 (file was truncated)
                if last_position > file_size:
                    last_position = 0
                    current_position = 0
                    # Clear processed hashes since file was truncated
                    processed_hashes.clear()
                
                # Skip to last processed position
                f.seek(last_position)
                
                # Read line by line without using iterator
                while True:
                    line_start = f.tell()
                    line = f.readline()
                    
                    if not line:  # End of file
                        current_position = f.tell()
                        break
                    
                    current_position = f.tell()
                    
                    # Create a hash of the line to avoid reprocessing
                    import hashlib
                    line_hash = hashlib.md5(line.encode()).hexdigest()
                    
                    # Skip if we've already processed this line (unless log was rotated)
                    if not log_rotated and line_hash in processed_hashes:
                        continue
                    
                    # Look for connection patterns in Dionaea logs
                    patterns = [
                        # Pattern for connection accept messages
                        r'\[(\d{2})(\d{2})(\d{4}) (\d{2}:\d{2}:\d{2})\].*connection.*from.*?(\d+\.\d+\.\d+\.\d+).*?to.*?:(\d+)',
                        r'\[(\d{2})(\d{2})(\d{4}) (\d{2}:\d{2}:\d{2})\].*accept.*from.*?(\d+\.\d+\.\d+\.\d+).*on.*?(\d+)',
                    ]
                    
                    for pattern in patterns:
                        match = re.search(pattern, line)
                        if match:
                            try:
                                # Parse the timestamp (DDMMYYYY format)
                                day, month, year, time_str = match.group(1), match.group(2), match.group(3), match.group(4)
                                src_ip = match.group(5)
                                dst_port = match.group(6)
                                
                                # Create datetime object
                                dt = datetime.datetime(
                                    int(year), int(month), int(day),
                                    int(time_str[0:2]), int(time_str[3:5]), int(time_str[6:8])
                                )
                                
                                service = self.guess_service_from_port(dst_port)
                                location = self.get_location(src_ip)
                                
                                attack = {
                                    'timestamp': dt.isoformat(),
                                    'src_ip': src_ip,
                                    'src_port': "unknown",  # Not always available in logs
                                    'dst_port': dst_port,
                                    'service': service,
                                    'country': location['country'],
                                    'city': location['city'],
                                    'lat': location['lat'],
                                    'lon': location['lon']
                                }
                                
                                new_attacks.append(attack)
                                processed_hashes.add(line_hash)
                                break
                                
                            except Exception as e:
                                if self.verbose:
                                    print(f"Error parsing line: {line.strip()}")
                                    print(f"Error: {e}")
                                continue
                    
                    # Add non-matching lines to processed hashes too
                    processed_hashes.add(line_hash)
                
                # Save current position and processed hashes
                if self.incremental:
                    self.save_processed_position(current_position)
                    
                    # Save processed hashes (keep only last 10000 to manage file size)
                    if len(processed_hashes) > 10000:
                        processed_hashes = set(list(processed_hashes)[-10000:])
                    
                    try:
                        with open(hash_file, 'w') as f:
                            for h in processed_hashes:
                                f.write(f"{h}\n")
                    except Exception as e:
                        if self.verbose:
                            print(f"Error saving processed hashes: {e}")
                                
        except Exception as e:
            if self.verbose:
                print(f"Error reading {self.log_path}: {e}")
            
        if self.verbose and new_attacks:
            print(f"Parsed {len(new_attacks)} new log entries")
            
        return new_attacks

    def process_logs(self):
        """Process all available dionaea logs with incremental updates"""
        if self.verbose:
            print("Processing dionaea logs...")
        
        # Load existing data for incremental updates BEFORE clearing logs
        existing_data = self.load_existing_data() if self.incremental else {
            'attacks': [], 'summary': {}, 'hourly_stats': {}, 'daily_stats': {}, 'binary_stats': {}
        }
        
        if self.verbose and existing_data['attacks']:
            print(f"Loaded {len(existing_data['attacks'])} existing attacks")
        
        # Create a set of existing attack signatures for deduplication
        existing_signatures = set()
        for attack in existing_data['attacks']:
            key = f"{attack['timestamp']}_{attack['src_ip']}_{attack['dst_port']}"
            existing_signatures.add(key)
        
        # Parse new attacks from log (before truncation to maintain position tracking)
        new_attacks = self.parse_dionaea_log()
        
        # Filter out attacks that already exist (true deduplication)
        truly_new_attacks = []
        for attack in new_attacks:
            key = f"{attack['timestamp']}_{attack['src_ip']}_{attack['dst_port']}"
            if key not in existing_signatures:
                truly_new_attacks.append(attack)
                if self.verbose:
                    print(f"Found truly new attack: {attack['src_ip']} -> {attack['dst_port']} ({attack['service']})")
        
        # Clear old log data AFTER processing to maintain incremental tracking
        self.clear_old_log_data()
        
        # Combine existing and truly new attacks
        all_attacks = existing_data['attacks'] + truly_new_attacks
        
        # Sort by timestamp and keep last 2000 attacks to manage file size
        attacks = sorted(all_attacks, key=lambda x: x['timestamp'])[-2000:]
        
        # Save to persistent database to survive log rotations
        self.save_persistent_attacks(attacks)
        
        if self.verbose:
            print(f"Total attacks after adding new ones: {len(attacks)}")
        
        # Analyze collected binaries
        binary_stats = self.analyze_binaries()
        
        # Generate statistics from all attacks
        ip_stats = Counter()
        service_stats = Counter()
        country_stats = Counter()
        hourly_stats = defaultdict(int)
        daily_stats = defaultdict(int)
        
        for attack in attacks:
            ip_stats[attack['src_ip']] += 1
            service_stats[attack['service']] += 1
            country_stats[attack['country']] += 1
            
            try:
                dt = datetime.datetime.fromisoformat(attack['timestamp'].replace('Z', ''))
                hour_key = dt.strftime('%Y-%m-%d %H:00')
                day_key = dt.strftime('%Y-%m-%d')
                hourly_stats[hour_key] += 1
                daily_stats[day_key] += 1
            except Exception as e:
                if self.verbose:
                    print(f"Error parsing timestamp {attack['timestamp']}: {e}")
                pass
        
        # Generate summary
        summary = {
            'total_attacks': len(attacks),
            'unique_ips': len(ip_stats),
            'unique_countries': len(country_stats),
            'services_count': len(service_stats),
            'total_binaries': binary_stats['total_binaries'],
            'unique_file_types': len(binary_stats['file_types']),
            'malware_downloads': len([b for b in binary_stats.get('recent_samples', []) if b.get('event_type') == 'download' or b.get('source') == 'folder']),
            'total_malware_size': binary_stats.get('binary_sizes', {}).get('total', 0),
            'top_attackers': dict(ip_stats.most_common(15)),
            'services_targeted': dict(service_stats.most_common()),
            'countries': dict(country_stats.most_common()),
            'last_updated': datetime.datetime.now().isoformat(),
            'last_24h_attacks': sum(v for k, v in daily_stats.items() if k >= (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y-%m-%d')),
            'new_attacks_this_run': len(truly_new_attacks)
        }

        # Save data files (update existing files)
        self.save_json_file('attacks.json', attacks[-1000:])  # Keep last 1000 for display
        self.save_json_file('summary.json', summary)
        self.save_json_file('hourly_stats.json', dict(hourly_stats))
        self.save_json_file('daily_stats.json', dict(daily_stats))
        self.save_json_file('binary_stats.json', binary_stats)
        
        if self.verbose:
            print(f"\nProcessing Summary:")
            print(f"Truly new attacks found: {len(truly_new_attacks)}")
            print(f"Total unique attacks: {len(attacks)}")
            print(f"Unique attacking IPs: {len(ip_stats)}")
            print(f"Countries: {len(country_stats)}")
            print(f"Services targeted: {len(service_stats)}")
            print(f"Malware binaries collected: {binary_stats['total_binaries']}")
            print(f"Data saved to: {self.output_dir}")
        
        return summary

    def save_json_file(self, filename, data):
        """Save data to JSON file"""
        filepath = self.output_dir / filename
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            if self.verbose:
                print(f"Saved {filename}")
        except Exception as e:
            print(f"Error saving {filename}: {e}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Process Dionaea logs')
    parser.add_argument('--log-path', default='/opt/dionaea/var/log/dionaea/dionaea.log', help='Path to dionaea.log')
    parser.add_argument('--output-dir', default='/tmp/honeypot_data', help='Output directory for JSON files')
    parser.add_argument('--binaries-dir', default='/opt/dionaea/var/lib/dionaea/binaries', help='Path to binaries directory')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--upload-user', help='Remote username for upload')
    parser.add_argument('--upload-host', help='Remote hostname for upload')
    parser.add_argument('--upload-path', help='Remote path for upload')
    parser.add_argument('--no-incremental', action='store_true', help='Disable incremental processing')
    
    args = parser.parse_args()
    
    processor = DionaeaLogProcessor(
        log_path=args.log_path,
        output_dir=args.output_dir,
        verbose=args.verbose,
        incremental=not args.no_incremental,
        binaries_dir=args.binaries_dir
    )
    
    summary = processor.process_logs()
    
    # Handle upload if requested
    if args.upload_user and args.upload_host and args.upload_path:
        upload_command = [
            'rsync', '-avz', '--progress',
            f'{args.output_dir}/',
            f'{args.upload_user}@{args.upload_host}:{args.upload_path}'
        ]
        
        try:
            import subprocess
            result = subprocess.run(upload_command, capture_output=True, text=True)
            if result.returncode == 0:
                if args.verbose:
                    print(f"Upload successful to {args.upload_host}:{args.upload_path}")
            else:
                print(f"Upload failed: {result.stderr}")
                sys.exit(1)
        except Exception as e:
            print(f"Upload error: {e}")
            sys.exit(1)
    
    return summary

if __name__ == "__main__":
    main()
