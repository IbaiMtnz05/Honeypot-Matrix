#!/bin/bash
# Clear all honeypot logs and start from 0
# Usage: ./clear_honeypot_logs.sh

LOG_DIR="/opt/dionaea/var/log/dionaea"
BINARIES_DIR="/opt/dionaea/var/lib/dionaea/binaries"
OUTPUT_DIR="/root/honeypot_data"

# Remove log files
rm -f "$LOG_DIR"/*.log
rm -f "$LOG_DIR"/*.gz

# Remove processed hashes and persistent DB
rm -f "$OUTPUT_DIR"/processed_hashes.txt
rm -f "$OUTPUT_DIR"/persistent_attacks.json
rm -f "$OUTPUT_DIR"/persistent_attacks_backup.json

# Remove output JSON files
rm -f "$OUTPUT_DIR"/*.json

# Remove binaries
rm -f "$BINARIES_DIR"/*

# Recreate empty log file
touch "$LOG_DIR/dionaea.log"

echo "All honeypot logs and binaries cleared. System is reset."
