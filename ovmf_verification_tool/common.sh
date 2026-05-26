# Shared Configurations and Helpers for OVMF TEE Verification Tools
#

# --- COMMON VARIABLES & DEFAULTS ---
DEFAULT_PROJECT="chewbacca-images-dev"
DEFAULT_REGION="us-central1"
DEFAULT_ZONE="us-central1-b"

# Default images for TEE verification and offline calculation
DEFAULT_BAREMETAL_IMAGE="acoshost-presubmit-debug-6ca97b6801"
DEFAULT_OFFLINE_EXTRACT_IMAGE="acoshost-debug-d23a809c65"


# Normalize user name for safe GCP resource naming
USER_NAME="${USER:-$(whoami)}"
USER_NAME=$(echo "${USER_NAME}" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-')

# --- LOGGING UTILITIES ---
# Color definitions (only use if stdout is connected to a terminal)
if [ -t 1 ]; then
    COLOR_BLUE="\033[1;34m"
    COLOR_GREEN="\033[1;32m"
    COLOR_YELLOW="\033[1;33m"
    COLOR_RED="\033[1;31m"
    COLOR_RESET="\033[0m"
else
    COLOR_BLUE=""
    COLOR_GREEN=""
    COLOR_YELLOW=""
    COLOR_RED=""
    COLOR_RESET=""
fi

log_info() {
    echo -e "${COLOR_BLUE}==>${COLOR_RESET} $1"
}

log_success() {
    echo -e "${COLOR_GREEN}[+] SUCCESS:${COLOR_RESET} $1"
}

log_warn() {
    echo -e "${COLOR_YELLOW}[!] WARNING:${COLOR_RESET} $1" >&2
}

log_error() {
    echo -e "${COLOR_RED}[-] ERROR:${COLOR_RESET} $1" >&2
}

# --- COMMON GCLOUD WRAPPER FUNCTIONS ---
# Check if GCloud auth is active
check_gcloud_auth() {
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q "@"; then
        log_warn "No active GCloud account detected. You may need to run 'gcloud auth login' if operations fail."
        return 1
    fi
    return 0
}
