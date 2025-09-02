#!/bin/bash
# Honeypot data processor and uploader - Continuous execution version
# Live demo available at: ibaim.eus/honey

# Configuration - MODIFY THESE
REMOTE_USER="your-user"
REMOTE_HOST="your-server.com"
REMOTE_PATH="/path/to/your/web/files"
LOG_FILE="/var/log/honeypot_upload.log"
PROCESS_INTERVAL=15
PYTHON_SCRIPT="/opt/honeypot/process_dionaea.py"
OUTPUT_DIR="/root/honeypot_data"

# Ensure required directories exist
sudo mkdir -p /var/log
mkdir -p "$OUTPUT_DIR"

# Function to log messages with timestamp
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" | tee -a "$LOG_FILE"
}

# Function to process dionaea logs
process_logs() {
    log_message "Processing dionaea logs..."
    
    # Execute the Python script with incremental processing
    python3 "$PYTHON_SCRIPT" \
        --output-dir "$OUTPUT_DIR" \
        --verbose 2>&1 | tee -a "$LOG_FILE"
    
    local exit_code=${PIPESTATUS[0]}
    
    if [ $exit_code -eq 0 ]; then
        log_message "Log processing successful"
        return 0
    else
        log_message "Log processing failed with exit code $exit_code"
        return 1
    fi
}

# Function to upload data to server
upload_data() {
    log_message "Uploading data to $REMOTE_HOST..."
    
    # Use rsync for efficient incremental uploads
    rsync -avz --progress --timeout=60 \
        "$OUTPUT_DIR/" \
        "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH" 2>&1 | tee -a "$LOG_FILE"
    
    local exit_code=${PIPESTATUS[0]}
    
    if [ $exit_code -eq 0 ]; then
        log_message "Upload successful"
        return 0
    else
        log_message "Upload failed with exit code $exit_code"
        return 1
    fi
}

# Function to create and upload a timestamped backup of summary.json
backup_summary() {
    local now_year=$(date +%Y)
    local now_month=$(date +%m)
    local now_day=$(date +%d)
    local now_hour=$(date +%H)
    local now_minute=$(date +%M)
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="$OUTPUT_DIR/backups/$now_year/$now_month/$now_day"
    local backup_file="$backup_dir/summary_${timestamp}.json"
    local remote_backup_dir="~/www/honey/backups/$now_year/$now_month/$now_day"

    mkdir -p "$backup_dir"
    cp "$OUTPUT_DIR/summary.json" "$backup_file"

    # Upload backup to your server
    rsync -avz --progress --timeout=60 "$backup_file" "$REMOTE_USER@$REMOTE_HOST:$remote_backup_dir/"
    log_message "Backup created and uploaded: $backup_file -> $REMOTE_HOST:$remote_backup_dir/"
}

# Function to check if processes are running
check_dependencies() {
    # Check if Python script exists
    if [ ! -f "$PYTHON_SCRIPT" ]; then
        log_message "ERROR: Python script not found at $PYTHON_SCRIPT"
        return 1
    fi
    
    # Check if rsync is available
    if ! command -v rsync &> /dev/null; then
        log_message "ERROR: rsync not found. Installing..."
        sudo apt-get update && sudo apt-get install -y rsync
    fi
    
    # Check if python3 is available
    if ! command -v python3 &> /dev/null; then
        log_message "ERROR: python3 not found"
        return 1
    fi
    
    return 0
}

# Function to handle cleanup on exit
cleanup() {
    log_message "Shutting down honeypot data processor..."
    exit 0
}

# Function to run single cycle
run_cycle() {
    local cycle_start=$(date +%s)
    
    log_message "Starting processing cycle..."
    
    # Process logs
    if process_logs; then
        # Only upload if processing was successful
        upload_data
    else
        log_message "Skipping upload due to processing failure"
    fi
    
    local cycle_end=$(date +%s)
    local cycle_duration=$((cycle_end - cycle_start))
    
    log_message "Cycle completed in ${cycle_duration} seconds"
}

# Function for continuous monitoring mode
continuous_mode() {
    log_message "Starting continuous honeypot data processing (every ${PROCESS_INTERVAL}s)..."
    log_message "Press Ctrl+C to stop"
    
    while true; do
        run_cycle
        
        log_message "Waiting ${PROCESS_INTERVAL} seconds until next cycle..."
        sleep "$PROCESS_INTERVAL"
    done
}

# Function for single run mode
single_run_mode() {
    log_message "Running single processing cycle..."
    run_cycle
    log_message "Single run completed"
}

# Main execution
main() {
    # Set up signal handlers
    trap cleanup SIGINT SIGTERM
    
    log_message "Honeypot data processor starting..."
    
    # Check dependencies
    if ! check_dependencies; then
        log_message "ERROR: Dependency check failed"
        exit 1
    fi
    
    # Parse command line arguments
    case "${1:-continuous}" in
        "single")
            single_run_mode
            ;;
        "continuous"|"")
            continuous_mode
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [single|continuous|help]"
            echo "  single     - Run one processing cycle and exit"
            echo "  continuous - Run continuously every ${PROCESS_INTERVAL} seconds (default)"
            echo "  help       - Show this help message"
            exit 0
            ;;
        *)
            log_message "ERROR: Unknown mode '$1'. Use 'single', 'continuous', or 'help'"
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"
