#!/opt/honeypot/venv/bin/python3
"""
Dionaea Log Processor - Improved Version with Incremental Updates
Processes dionaea logs and creates web-ready data files
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
                 output_dir='/root/honeypot_data',
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
        """Analyze captured malware binaries with UTF-8 safe operations"""
        binary_stats = {
            'total_binaries': 0,
            'binary_sizes': {},
            'recent_binaries': [],  # Recent binary captures
            'size_distribution': {
                '1kb': 0,      # < 1KB
                '1_10kb': 0,   # 1-10KB  
                '10_100kb': 0, # 10-100KB
                '100kb_1mb': 0, # 100KB-1MB
                '1mb': 0       # > 1MB
            },
            'file_types': {}
        }
        
        if not self.binaries_dir.exists():
            if self.verbose:
                print(f"Binaries directory not found: {self.binaries_dir}")
            return binary_stats
        
        try:
            binary_files = []
            for file_path in self.binaries_dir.iterdir():
                if file_path.is_file():
                    try:
                        stat = file_path.stat()
                        binary_info = {
                            'filename': file_path.name,
                            'size': stat.st_size,
                            'timestamp': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            'hash': file_path.name if len(file_path.name) == 32 else 'unknown',
                            'type': 'binary'
                        }
                        
                        # Try to detect file type by reading first few bytes with UTF-8 safety
                        try:
                            with open(file_path, 'rb') as f:
                                header = f.read(16)
                                file_type = self.detect_file_type(header)
                                binary_info['file_type'] = file_type
                        except Exception as e:
                            if self.verbose:
                                print(f"Error reading binary {file_path.name}: {e}")
                            binary_info['file_type'] = 'unknown'
                        
                        binary_files.append(binary_info)
                        
                    except Exception as e:
                        if self.verbose:
                            print(f"Error analyzing binary {file_path.name}: {e}")
                        continue
            
            # Sort by timestamp (newest first)
            binary_files.sort(key=lambda x: x['timestamp'], reverse=True)
            
            binary_stats['total_binaries'] = len(binary_files)
            binary_stats['recent_binaries'] = binary_files[:10]  # Last 10 binaries
            
            # Calculate statistics
            sizes = [b['size'] for b in binary_files]
            if sizes:
                binary_stats['binary_sizes'] = {
                    'min': min(sizes),
                    'max': max(sizes),
                    'avg': sum(sizes) // len(sizes),
                    'total': sum(sizes)
                }
            
            # File type and size distribution
            for binary in binary_files:
                # File type counting
                file_type = binary.get('file_type', 'unknown')
                binary_stats['file_types'][file_type] = binary_stats['file_types'].get(file_type, 0) + 1
                
                # Size distribution
                size = binary['size']
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
                print(f"Analyzed {len(binary_files)} binary files")
                
        except Exception as e:
            if self.verbose:
                print(f"Error scanning binaries directory: {e}")
        
        return binary_stats

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
        # Shell script
        elif header[:2] == b'#!':
            return 'shell_script'
        # Unknown binary
        else:
            return 'unknown_binary'

    def load_persistent_attacks(self):
        """Load persistent attack database that survives log rotations"""
        persistent_attacks = []
        
        try:
            # Try to load from main database
            if self.persistent_db_path.exists():
                with open(self.persistent_db_path, 'r', encoding='utf-8') as f:
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
                with open(self.backup_db_path, 'r', encoding='utf-8') as f:
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
            # Create backup of current database before overwriting
            if self.persistent_db_path.exists():
                import shutil
                shutil.copy2(self.persistent_db_path, self.backup_db_path)
                if self.verbose:
                    print(f"Created backup of persistent database")
            
            # Write to temporary file first to avoid corruption
            temp_path = self.output_dir / 'persistent_attacks_temp.json'
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(attacks, f, indent=2, default=str, ensure_ascii=False)
            
            # Verify the temp file was written correctly
            if temp_path.exists() and temp_path.stat().st_size > 0:
                # Atomically move temp file to final location
                import shutil
                shutil.move(temp_path, self.persistent_db_path)
                if self.verbose:
                    print(f"Saved {len(attacks)} attacks to persistent database")
            else:
                raise Exception("Temporary file was not created or is empty")
                
        except Exception as e:
            if self.verbose:
                print(f"Error saving persistent attacks: {e}")
            # Try to restore from backup if save failed
            if self.backup_db_path.exists():
                try:
                    import shutil
                    shutil.copy2(self.backup_db_path, self.persistent_db_path)
                    if self.verbose:
                        print("Restored persistent database from backup")
                except Exception as restore_error:
                    print(f"Failed to restore from backup: {restore_error}")

    def load_existing_data(self):
        """Load existing JSON data files for incremental updates"""
        existing_data = {
            'attacks': [],
            'summary': {},
            'hourly_stats': {},
            'daily_stats': {}
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
                    with open(attacks_file, 'r', encoding='utf-8') as f:
                        existing_data['attacks'] = json.load(f)
                    
            # Load existing stats
            for stat_type in ['summary', 'hourly_stats', 'daily_stats']:
                stat_file = self.output_dir / f'{stat_type}.json'
                if stat_file.exists():
                    with open(stat_file, 'r', encoding='utf-8') as f:
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
            
            # Only truncate if file is larger than 1MB or has more than 10000 lines
            if file_stats.st_size > 1000000:  # 1MB
                with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    
                if len(lines) > 10000:
                    # Keep last 10000 lines
                    with open(self.log_path, 'w', encoding='utf-8') as f:
                        f.writelines(lines[-10000:])
                        
                    # Reset processed position since we truncated the file
                    self.save_processed_position(0)
                    
                    # Clear processed hashes since file was truncated
                    hash_file = self.output_dir / 'processed_hashes.txt'
                    if hash_file.exists():
                        hash_file.unlink()
                    
                    if self.verbose:
                        print(f"Truncated log file from {len(lines)} to 10000 lines")
                        
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

    def create_sample_data(self):
        """Create sample data for testing"""
        sample_attacks = []
        base_time = datetime.datetime.now() - datetime.timedelta(hours=2)
        
        sample_ips = [
            ('45.142.212.33', 'Russia', 'Moscow', 55.7558, 37.6176),
            ('103.99.0.122', 'China', 'Shanghai', 31.2304, 121.4737), 
            ('185.220.101.76', 'Germany', 'Frankfurt', 50.1109, 8.6821),
            ('198.51.100.42', 'USA', 'New York', 40.7128, -74.0060),
            ('192.0.2.146', 'France', 'Paris', 48.8566, 2.3522)
        ]
        
        services = ['ssh', 'http', 'ftp', 'telnet', 'smb', 'mysql']
        ports = {'ssh': 22, 'http': 80, 'ftp': 21, 'telnet': 23, 'smb': 445, 'mysql': 3306}
        
        for i in range(20):  # Create fewer samples for testing
            ip, country, city, lat, lon = sample_ips[i % len(sample_ips)]
            service = services[i % len(services)]
            port = ports[service]
            
            timestamp = base_time + datetime.timedelta(minutes=i*2)
            
            attack = {
                'timestamp': timestamp.isoformat(),
                'src_ip': ip,
                'src_port': str(1000 + i),
                'dst_port': str(port),
                'service': service,
                'country': country,
                'city': city,
                'lat': lat,
                'lon': lon
            }
            sample_attacks.append(attack)
            
        if self.verbose:
            print("Created sample attacks for testing")
        return sample_attacks

    def process_logs(self):
        """Process all available dionaea logs with incremental updates"""
        if self.verbose:
            print("Processing dionaea logs...")
        
        # Load existing data for incremental updates BEFORE clearing logs
        existing_data = self.load_existing_data() if self.incremental else {
            'attacks': [], 'summary': {}, 'hourly_stats': {}, 'daily_stats': {}
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
        
        if not truly_new_attacks and not existing_data['attacks']:
            # Only create sample data if no existing data and no new attacks
            if self.verbose:
                print("No existing data or new attacks found, creating sample data...")
            truly_new_attacks = self.create_sample_data()
            existing_data = {'attacks': [], 'summary': {}, 'hourly_stats': {}, 'daily_stats': {}}
        
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
        
        # Generate summary with binaries instead of services count
        summary = {
            'total_attacks': len(attacks),
            'unique_ips': len(ip_stats),
            'unique_countries': len(country_stats),
            'total_binaries': binary_stats['total_binaries'],  # Changed from services_count
            'top_attackers': dict(ip_stats.most_common(15)),
            'services_targeted': dict(service_stats.most_common()),
            'countries': dict(country_stats.most_common()),
            'last_updated': datetime.datetime.now().isoformat(),
            'last_24h_attacks': sum(v for k, v in daily_stats.items() if k >= (datetime.datetime.now() - datetime.timedelta(days=1)).strftime('%Y-%m-%d')),
            'new_attacks_this_run': len(truly_new_attacks),
            'binary_stats': binary_stats  # Add full binary stats
        }

        # Save data files (update existing files)
        self.save_json_file('attacks.json', attacks[-1000:])  # Keep last 1000 for display
        self.save_json_file('summary.json', summary)
        self.save_json_file('hourly_stats.json', dict(hourly_stats))
        self.save_json_file('daily_stats.json', dict(daily_stats))
        
        # Verify files were saved correctly
        files_to_check = ['attacks.json', 'summary.json', 'hourly_stats.json', 'daily_stats.json']
        for filename in files_to_check:
            filepath = self.output_dir / filename
            if not filepath.exists():
                print(f"ERROR: Failed to save {filename}")
            elif self.verbose:
                file_size = filepath.stat().st_size
                print(f"Verified {filename} saved ({file_size} bytes)")
        
        if self.verbose:
            print(f"\nProcessing Summary:")
            print(f"Truly new attacks found: {len(truly_new_attacks)}")
            print(f"Total unique attacks: {len(attacks)}")
            print(f"Unique attacking IPs: {len(ip_stats)}")
            print(f"Countries: {len(country_stats)}")
            print(f"Services targeted: {len(service_stats)}")
            print(f"Total binaries captured: {binary_stats['total_binaries']}")
            print(f"Data saved to: {self.output_dir}")
        
        return summary

    def save_json_file(self, filename, data):
        """Save data to JSON file with UTF-8 encoding and atomic write"""
        filepath = self.output_dir / filename
        temp_filepath = self.output_dir / f"{filename}.tmp"
        
        try:
            # Write to temporary file first
            with open(temp_filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str, ensure_ascii=False)
            
            # Verify temp file was written correctly
            if temp_filepath.exists() and temp_filepath.stat().st_size > 0:
                # Atomically move temp file to final location
                import shutil
                shutil.move(temp_filepath, filepath)
                if self.verbose:
                    print(f"Saved {filename}")
            else:
                raise Exception("Temporary file was not created or is empty")
                
        except Exception as e:
            print(f"Error saving {filename}: {e}")
            # Clean up temp file if it exists
            if temp_filepath.exists():
                try:
                    temp_filepath.unlink()
                except:
                    pass

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Process Dionaea logs')
    parser.add_argument('--log-path', default='/opt/dionaea/var/log/dionaea/dionaea.log', help='Path to dionaea.log')
    parser.add_argument('--output-dir', default='/root/honeypot_data', help='Output directory for JSON files')
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