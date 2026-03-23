#!/bin/bash

set -euo pipefail # Exit on error, undefined vars, pipe failures

# Script metadata
SCRIPT_VERSION="3.0"
SCRIPT_NAME="Zeek Network Security Monitor Installer"
LOG_FILE="/var/log/zeek-install.log"
ZEEK_USER="zeek"
ZEEK_HOME="/opt/zeek"
ZEEK_LOGS="/var/log/zeek"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging function
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Function to print colored output with logging
print_status() {
  echo -e "${GREEN}[+]${NC} $1"
  log "STATUS: $1"
}

print_warning() {
  echo -e "${YELLOW}[!]${NC} $1"
  log "WARNING: $1"
}

print_error() {
  echo -e "${RED}[-]${NC} $1"
  log "ERROR: $1"
}

print_info() {
  echo -e "${BLUE}[i]${NC} $1"
  log "INFO: $1"
}

# Function to print banner
banner() {
  local msg="$1"
  echo
  echo "===================================================================="
  echo ">>> $msg"
  echo "===================================================================="
  echo
  log "BANNER: $msg"
}

# Error handler
error_handler() {
  local line_no=$1
  print_error "Script failed at line $line_no. Check $LOG_FILE for details."
  print_info "Cleaning up temporary files..."
  cleanup_on_error
  exit 1
}

# Cleanup function for error cases
cleanup_on_error() {
  if [ -d "zeek" ]; then
    rm -rf zeek
    print_status "Cleaned up zeek source directory"
  fi
}

# Set error trap
trap 'error_handler $LINENO' ERR

# Function to clean build cache
clean_build_cache() {
  banner "Cleaning Build Cache"

  if [ -d "zeek" ]; then
    cd zeek
    if [ -f "Makefile" ]; then
      make clean || true
      print_status "Cleaned build cache"
    fi
    cd ..
  fi
}

# Function to reset source directory
reset_source_directory() {
  banner "Resetting Source Directory"

  if [ -d "zeek" ]; then
    rm -rf zeek
    print_status "Removed existing source directory"
  fi
}

# Function to check system requirements
check_requirements() {
  banner "Checking System Requirements"

  # Check OS
  if [ ! -f /etc/os-release ]; then
    print_error "Cannot determine OS version"
    exit 1
  fi

  source /etc/os-release
  print_info "Detected OS: $PRETTY_NAME"

  # Check if supported OS
  case "$ID" in
  ubuntu | debian)
    print_status "Supported OS detected"
    ;;
  *)
    print_warning "This script is optimized for Ubuntu/Debian. Proceed with caution."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      exit 1
    fi
    ;;
  esac

  # Check available memory (Zeek compilation is memory intensive)
  local mem_kb
  mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  local mem_gb=$((mem_kb / 1024 / 1024))

  if [ "$mem_gb" -lt 2 ]; then
    print_warning "Less than 2GB RAM detected. Compilation may fail or be very slow."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      exit 1
    fi
  else
    print_status "Memory check passed: ${mem_gb}GB available"
  fi

  # Check available disk space
  local available_space
  available_space=$(df / | tail -1 | awk '{print $4}')
  local available_gb=$((available_space / 1024 / 1024))

  if [ "$available_gb" -lt 5 ]; then
    print_warning "Less than 5GB disk space available. Installation may fail."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      exit 1
    fi
  else
    print_status "Disk space check passed: ${available_gb}GB available"
  fi
}

# Function to detect and validate network interface
detect_interface() {
  banner "Network Interface Configuration"

  print_info "Available network interfaces:"
  ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "  " $2}' | sed 's/@.*//'

  # Try to detect primary interface
  local primary_interface
  primary_interface=$(ip route | grep default | awk '{print $5}' | head -n1)

  if [ -n "$primary_interface" ]; then
    print_info "Auto-detected primary interface: $primary_interface"
    read -p "Use $primary_interface for Zeek monitoring? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
      read -p "Enter interface name: " primary_interface
    fi
  else
    print_warning "Could not auto-detect primary interface"
    read -p "Enter interface name for Zeek monitoring: " primary_interface
  fi

  # Validate interface exists
  if ! ip link show "$primary_interface" &>/dev/null; then
    print_error "Interface $primary_interface does not exist"
    exit 1
  fi

  print_status "Will use interface: $primary_interface"
  echo "$primary_interface"
}

# Function to create zeek user
create_zeek_user() {
  banner "Creating Zeek User"

  if id "$ZEEK_USER" &>/dev/null; then
    print_warning "User $ZEEK_USER already exists"
  else
    useradd -r -s /bin/false -d "$ZEEK_HOME" -c "Zeek Network Monitor" "$ZEEK_USER"
    print_status "Created user: $ZEEK_USER"
  fi

  # Create directories with proper ownership
  mkdir -p "$ZEEK_HOME" "$ZEEK_LOGS"
  chown -R "$ZEEK_USER:$ZEEK_USER" "$ZEEK_HOME" "$ZEEK_LOGS"
  print_status "Created directories with proper ownership"
}

# Function to backup existing installation
backup_existing() {
  if [ -d "/usr/local/zeek" ]; then
    banner "Backing Up Existing Installation"
    local backup_dir="/usr/local/zeek.backup.$(date +%Y%m%d_%H%M%S)"
    mv /usr/local/zeek "$backup_dir"
    print_status "Backed up existing installation to $backup_dir"
  fi
}

# Enhanced dependency installation with retry logic
install_dependencies() {
  banner "Installing Dependencies"

  local max_retries=3
  local retry_count=0

  while [ $retry_count -lt $max_retries ]; do
    if apt-get update && apt-get install -y \
      figlet \
      cmake \
      make \
      gcc \
      g++ \
      flex \
      libfl-dev \
      bison \
      libpcap-dev \
      libssl-dev \
      python3 \
      python3-dev \
      python3-pip \
      swig \
      zlib1g-dev \
      git \
      curl \
      wget \
      libgeoip-dev \
      libcurl4-openssl-dev \
      libjemalloc-dev \
      libncurses-dev \
      libgoogle-perftools-dev \
      libtcmalloc-minimal4 \
      libmaxminddb-dev \
      nodejs \
      npm \
      libzmq3-dev \
      libzmq5 \
      pkg-config; then

      print_status "Dependencies installed successfully"
      break
    else
      retry_count=$((retry_count + 1))
      print_warning "Dependency installation failed (attempt $retry_count/$max_retries)"
      if [ $retry_count -eq $max_retries ]; then
        print_error "Failed to install dependencies after $max_retries attempts"
        exit 1
      fi
      sleep 5
    fi
  done
}

# Function to stop existing services
stop_existing_services() {
  banner "Stopping Existing Services"

  # Stop systemd service if it exists
  if systemctl is-active --quiet zeek 2>/dev/null; then
    systemctl stop zeek
    print_status "Stopped existing zeek systemd service"
  fi

  # Stop zeekctl managed processes
  if command -v zeekctl &>/dev/null; then
    /usr/local/zeek/bin/zeekctl stop >/dev/null 2>&1 || true
    print_status "Stopped existing zeekctl processes"
  fi

  # Stop and remove Docker container
  if command -v docker &>/dev/null; then
    docker stop zeek >/dev/null 2>&1 || print_info "No running zeek container found"
    docker rm zeek >/dev/null 2>&1 || print_info "No existing zeek container to remove"
  fi
}

# Enhanced Zeek compilation with progress monitoring
compile_zeek() {
  banner "Downloading and Compiling Zeek"

  # Clone with progress
  print_info "Cloning Zeek repository..."
  if [ -d "zeek" ]; then
    print_warning "Removing existing zeek directory"
    rm -rf zeek
  fi

  git clone --recurse-submodules --progress https://github.com/zeek/zeek
  cd zeek

  print_info "Configuring build..."
  ./configure --prefix="$ZEEK_HOME" \
    --enable-jemalloc \
    --enable-perftools \
    --with-pcap=/usr

  print_info "Starting compilation (this may take 15-45 minutes)..."
  local cpu_cores
  cpu_cores=$(nproc)
  print_info "Using $cpu_cores CPU cores for compilation"

  # Use nice to lower priority and avoid system overload
  nice -n 10 make -j"$cpu_cores"

  print_info "Installing Zeek..."
  make install

  print_status "Zeek compilation and installation completed"
}

# Function to configure Zeek with JSON logging, MAC logging, and the detected interface
configure_zeek() {
  banner "Configuring Zeek"

  local interface="$1"

  # Configure node.cfg
  if [ -f "$ZEEK_HOME/etc/node.cfg" ]; then
    # Backup original config
    cp "$ZEEK_HOME/etc/node.cfg" "$ZEEK_HOME/etc/node.cfg.backup"

    # Update interface
    sed -i "s/interface=.*/interface=$interface/" "$ZEEK_HOME/etc/node.cfg"
    print_status "Configured interface: $interface in node.cfg"
  else
    print_error "node.cfg not found at $ZEEK_HOME/etc/node.cfg"
    exit 1
  fi

  # Configure local.zeek for JSON logs, MAC logging, and additional features
  local local_zeek="$ZEEK_HOME/share/zeek/site/local.zeek"
  if [ -f "$local_zeek" ]; then
    # Backup original
    cp "$local_zeek" "$local_zeek.backup"

    cat >>"$local_zeek" <<'EOF'

# =============================================================================
# JSON Log Output
# Outputs all Zeek logs in JSON format for easy parsing/ingestion by SIEMs,
# Elastic Stack, Splunk, etc.
# =============================================================================
@load policy/tuning/json-logs.zeek

# =============================================================================
# MAC Address Logging
# Logs the source and destination MAC addresses for all connections.
# Useful for identifying devices on the local network and detecting spoofing.
# =============================================================================
@load policy/protocols/conn/mac-logging

# =============================================================================
# Known Hosts / Services / Certs
# Tracks hosts, services, and SSL certs seen on the network.
# =============================================================================
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssl/known-certs

# =============================================================================
# File Hashing
# Computes MD5/SHA1/SHA256 hashes of all files transferred over the network.
# =============================================================================
@load policy/files/hash-all-files

# =============================================================================
# Vulnerability & Intelligence
# =============================================================================
@load policy/frameworks/software/vulnerable
@load policy/integration/collective-intel

# =============================================================================
# Scan Detection
# Detects network port scans and address scans.
# =============================================================================
@load policy/misc/scan

# =============================================================================
# Log Rotation & Memory Tuning
# =============================================================================
redef Log::default_rotation_interval = 1hr;
redef Log::default_mail_alarms_interval = 24hr;

# Memory optimization - expire old table entries every 10 minutes
redef table_expire_interval = 10min;
EOF

    print_status "JSON logging enabled"
    print_status "MAC address logging enabled"
    print_status "Enhanced Zeek configuration applied"
  else
    print_error "local.zeek not found"
    exit 1
  fi

  # Set proper ownership
  chown -R "$ZEEK_USER:$ZEEK_USER" "$ZEEK_HOME"
  chown -R "$ZEEK_USER:$ZEEK_USER" "$ZEEK_LOGS"
}

# Function to update PATH — both system-wide and for the invoking user
update_system_path() {
  banner "Updating System PATH"

  # -------------------------------------------------------------------------
  # 1. System-wide PATH via /etc/profile.d (applies to all users on login)
  # -------------------------------------------------------------------------
  cat >/etc/profile.d/zeek.sh <<EOF
#!/bin/bash
export PATH="\$PATH:$ZEEK_HOME/bin"
EOF
  chmod +x /etc/profile.d/zeek.sh
  print_status "Added Zeek to system-wide PATH via /etc/profile.d/zeek.sh"

  # -------------------------------------------------------------------------
  # 2. Current invoking user's ~/.bashrc
  #    SUDO_USER is set when the script is run via sudo, giving us the real
  #    user's home directory. Falls back to root's home if run directly.
  # -------------------------------------------------------------------------
  local target_user="${SUDO_USER:-root}"
  local target_home
  target_home=$(getent passwd "$target_user" | cut -d: -f6)

  if [ -n "$target_home" ] && [ -d "$target_home" ]; then
    local bashrc="$target_home/.bashrc"

    # Only add if not already present to avoid duplicates
    if ! grep -q "$ZEEK_HOME/bin" "$bashrc" 2>/dev/null; then
      echo "" >>"$bashrc"
      echo "# Zeek Network Security Monitor" >>"$bashrc"
      echo "export PATH=\$PATH:$ZEEK_HOME/bin" >>"$bashrc"
      print_status "Added Zeek to $target_user's ~/.bashrc"
    else
      print_warning "Zeek PATH entry already present in $bashrc — skipping"
    fi
  else
    print_warning "Could not determine home directory for user '$target_user'"
  fi

  # -------------------------------------------------------------------------
  # 3. Update PATH for the current shell session immediately
  # -------------------------------------------------------------------------
  export PATH="$PATH:$ZEEK_HOME/bin"
  print_status "Updated PATH for current shell session"

  print_info "Note: Open a new terminal (or run 'source ~/.bashrc') to use 'zeek' and 'zeekctl' directly."
}

# Enhanced systemd service creation
create_systemd_service() {
  banner "Creating Enhanced Systemd Service"

  cat >/etc/systemd/system/zeek.service <<EOF
[Unit]
Description=Zeek Network Security Monitor
Documentation=https://docs.zeek.org/
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=forking
User=$ZEEK_USER
Group=$ZEEK_USER
ExecStartPre=/bin/bash -c 'test -f $ZEEK_HOME/bin/zeekctl'
ExecStart=$ZEEK_HOME/bin/zeekctl start
ExecStop=$ZEEK_HOME/bin/zeekctl stop
ExecReload=$ZEEK_HOME/bin/zeekctl deploy
Restart=on-failure
RestartSec=30
TimeoutStartSec=300
TimeoutStopSec=120
WorkingDirectory=$ZEEK_HOME
Environment=PATH=$ZEEK_HOME/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=ZEEK_HOME=$ZEEK_HOME

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$ZEEK_LOGS $ZEEK_HOME/spool $ZEEK_HOME/logs

# Capabilities for packet capture
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

  print_status "Created enhanced systemd service"
}

# Function to setup log rotation
setup_log_rotation() {
  banner "Setting Up Log Rotation"

  cat >/etc/logrotate.d/zeek <<EOF
$ZEEK_LOGS/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        systemctl reload zeek || true
    endscript
}
EOF

  print_status "Configured log rotation for Zeek logs"
}

# Function to perform post-installation verification
verify_installation() {
  banner "Verifying Installation"

  # Check if zeek binary exists and is executable
  if [ -x "$ZEEK_HOME/bin/zeek" ]; then
    print_status "Zeek binary found and executable"

    # Check version
    local version
    version=$("$ZEEK_HOME/bin/zeek" --version 2>/dev/null | head -1 || echo "Unknown")
    print_info "Zeek version: $version"
  else
    print_error "Zeek binary not found or not executable"
    return 1
  fi

  # Check zeekctl
  if [ -x "$ZEEK_HOME/bin/zeekctl" ]; then
    print_status "ZeekControl found and executable"
  else
    print_error "ZeekControl not found"
    return 1
  fi

  # Verify JSON logging is configured
  local local_zeek="$ZEEK_HOME/share/zeek/site/local.zeek"
  if grep -q "json-logs.zeek" "$local_zeek" 2>/dev/null; then
    print_status "JSON logging confirmed in configuration"
  else
    print_warning "JSON logging directive not found — check local.zeek manually"
  fi

  # Verify MAC logging is configured
  if grep -q "mac-logging" "$local_zeek" 2>/dev/null; then
    print_status "MAC address logging confirmed in configuration"
  else
    print_warning "MAC logging directive not found — check local.zeek manually"
  fi

  # Test configuration
  print_info "Testing Zeek configuration..."
  if sudo -u "$ZEEK_USER" "$ZEEK_HOME/bin/zeekctl" check; then
    print_status "Zeek configuration is valid"
  else
    print_error "Zeek configuration test failed"
    return 1
  fi

  return 0
}

# Function to display post-installation instructions
show_completion_info() {
  banner "Installation Complete!"

  cat <<EOF
${GREEN}✅ Zeek Network Security Monitor has been successfully installed!${NC}

${BLUE}Active Features:${NC}
  • JSON log output      — all logs written in JSON format
  • MAC address logging  — layer-2 MAC addresses captured in conn.log
  • File hashing         — MD5/SHA1/SHA256 for transferred files
  • Scan detection       — port and address scan alerts
  • Known hosts/services — baseline tracking for anomaly detection

${BLUE}Quick Start Commands:${NC}
  • Start Zeek:    sudo systemctl start zeek
  • Stop Zeek:     sudo systemctl stop zeek
  • Check status:  sudo systemctl status zeek
  • View logs:     sudo journalctl -u zeek -f

${BLUE}Zeek Control Commands:${NC}
  • Deploy config: sudo -u $ZEEK_USER $ZEEK_HOME/bin/zeekctl deploy
  • Check status:  sudo -u $ZEEK_USER $ZEEK_HOME/bin/zeekctl status
  • Check config:  sudo -u $ZEEK_USER $ZEEK_HOME/bin/zeekctl check

${BLUE}Viewing JSON Logs:${NC}
  • Pretty-print:  cat $ZEEK_LOGS/current/conn.log | python3 -m json.tool
  • Filter with jq: cat $ZEEK_LOGS/current/conn.log | jq '.id.orig_h'
  • MAC addresses:  cat $ZEEK_LOGS/current/conn.log | jq '{src: .orig_l2_addr, dst: .resp_l2_addr}'

${BLUE}Important Locations:${NC}
  • Installation:  $ZEEK_HOME
  • Logs:          $ZEEK_LOGS
  • Config:        $ZEEK_HOME/etc/
  • Site policy:   $ZEEK_HOME/share/zeek/site/local.zeek
  • Install log:   $LOG_FILE

${BLUE}Next Steps:${NC}
  1. Open a new terminal or run: source ~/.bashrc
  2. Start the service:          sudo systemctl start zeek
  3. Deploy config:              sudo -u $ZEEK_USER zeekctl deploy
  4. Monitor JSON logs:          tail -f $ZEEK_LOGS/current/conn.log | jq .

${YELLOW}Note:${NC} Zeek runs as user '$ZEEK_USER' for improved security.
For any issues, check the installation log at: $LOG_FILE
EOF
}

# Main installation function
main() {
  # Print script header
  clear
  figlet -f small "$SCRIPT_NAME" 2>/dev/null || echo "$SCRIPT_NAME"
  echo "Version: $SCRIPT_VERSION"
  echo "Log file: $LOG_FILE"
  echo

  # Initialize log file
  log "Starting Zeek installation script v$SCRIPT_VERSION"

  # Check if running as root
  if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root. Please use sudo."
    exit 1
  fi

  print_status "Running as root"

  # Confirmation prompt
  print_warning "This script will install Zeek Network Security Monitor"
  print_info "Features: JSON logging, MAC address logging, file hashing, scan detection"
  print_info "This process may take 30-60 minutes depending on your system"

  # Clean up any existing source directory
  if [ -d "zeek" ]; then
    print_warning "Previous Zeek source directory found - removing it"
    rm -rf zeek
    print_status "Cleaned up previous source directory"
  fi

  read -p "Continue with installation? (y/N): " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Installation cancelled by user"
    exit 0
  fi

  # Run installation steps
  check_requirements
  backup_existing
  stop_existing_services
  install_dependencies
  create_zeek_user

  # Detect interface
  local interface
  interface=$(detect_interface)

  # Main compilation
  local start_time
  start_time=$(date +%s)
  compile_zeek
  local end_time
  end_time=$(date +%s)
  local compile_duration=$((end_time - start_time))
  print_info "Compilation took $((compile_duration / 60)) minutes and $((compile_duration % 60)) seconds"

  # Configuration
  configure_zeek "$interface"
  update_system_path
  setup_log_rotation
  create_systemd_service

  # Cleanup
  cd ..
  rm -rf zeek
  print_status "Cleaned up source directory"

  # Final verification
  if verify_installation; then
    # Enable service
    systemctl daemon-reload
    systemctl enable zeek.service
    print_status "Zeek service enabled for automatic startup"

    show_completion_info
    log "Zeek installation completed successfully"
  else
    print_error "Installation verification failed"
    exit 1
  fi
}

# Interrupt handler
interrupt_handler() {
  print_warning "Installation interrupted by user"
  cleanup_on_error
  exit 130
}

trap interrupt_handler SIGINT SIGTERM

# Run main function
main "$@"
