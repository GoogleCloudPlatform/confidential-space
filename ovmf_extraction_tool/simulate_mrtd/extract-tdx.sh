#!/bin/bash
#
# ACOS TDX Firmware Extractor & Offline MRTD Calculator
#

set -eo pipefail

# Source shared configurations and logging helpers
source "$(dirname "${BASH_SOURCE[0]}")/../common.sh"

# ==========================================
# Pre-flight Checks
# ==========================================
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run with sudo: sudo $0 $*"
    exit 1
fi

ORIG_USER="${SUDO_USER:-$USER}"

# ==========================================
# Configurations & Variables
# ==========================================
PROJECT_ID="${DEFAULT_PROJECT}"
IMAGE_NAME="${DEFAULT_OFFLINE_EXTRACT_IMAGE}"
REGION="us-west1"

TARGET_FILE="OVMF.inteltdx.fd"
OUTPUT_FILE="mrtd_output.txt"

RUN_EXPORT=false
LOCAL_TARBALL=""
LOOP_DEV=""

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOUNT_POINT="${WORKSPACE_DIR}/mnt_acos_oem"
CONTAINER_EXTRACT_DIR="${WORKSPACE_DIR}/tdx-container"

ARCHIVE_NAME="${IMAGE_NAME}.tar.gz"
BUCKET_NAME="chewbacca-export-${REGION}-$RANDOM"

# ==========================================
# Teardown / Cleanup
# ==========================================
cleanup() {
    log_info "Running teardown cleanup..."

    if mountpoint -q "${MOUNT_POINT}"; then
        umount "${MOUNT_POINT}" || true
    fi

    if [ -n "${LOOP_DEV}" ]; then
        losetup -d "${LOOP_DEV}" || true
    fi

    if [ -d "${CONTAINER_EXTRACT_DIR}" ]; then
        rm -rf "${CONTAINER_EXTRACT_DIR}"
    fi

    if [ -d "${MOUNT_POINT}" ]; then
        rm -rf "${MOUNT_POINT}"
    fi

    chown -R "${ORIG_USER}" "${WORKSPACE_DIR}" || true

    log_info "Teardown complete."
}
trap cleanup EXIT

# ==========================================
# Help and Usage
# ==========================================
usage() {
    echo "Usage: sudo $0 [options]"
    echo ""
    echo "Options:"
    echo "  -i <image>    ACOS Host Image Name to export (Auto-triggers export phase)"
    echo "  -p <project>  GCP Project ID (Requires -i and -r)"
    echo "  -r <region>   GCP Region for bucket (Requires -i and -p)"
    echo "  -e            Run full image export using default values (if -i is omitted)"
    echo "  -t <file>     Path to a local ACOS image tarball (.tar.gz)"
    echo "  -h            Show this help message"
    echo ""
    exit 1
}

# Track which specific flags were passed
FLAG_I=false
FLAG_P=false
FLAG_R=false

while getopts "p:i:r:t:eh" opt; do
    case ${opt} in
        i ) IMAGE_NAME="$OPTARG"; FLAG_I=true; RUN_EXPORT=true ;;
        p ) PROJECT_ID="$OPTARG"; FLAG_P=true ;;
        r ) REGION="$OPTARG"; FLAG_R=true ;;
        t ) LOCAL_TARBALL="$OPTARG" ;;
        e ) RUN_EXPORT=true ;;
        h ) usage ;;
        * ) usage ;;
    esac
done

# --- STRICT TRIPLET VALIDATION ---
# If -p or -r are used, ensure ALL THREE (-i, -p, -r) were explicitly provided.
if [ "${FLAG_P}" = true ] || [ "${FLAG_R}" = true ]; then
    if [ "${FLAG_I}" = false ] || [ "${FLAG_P}" = false ] || [ "${FLAG_R}" = false ]; then
        log_error "STRICT MODE: If you specify a custom project (-p) or region (-r), you must explicitly provide all three flags together: -i, -p, and -r."
        usage
    fi
fi

# ==========================================
# Image Export & Extraction logic
# ==========================================
export_and_download_image() {
    log_info "Creating temporary regional bucket gs://${BUCKET_NAME}..."
    sudo -i -u "${ORIG_USER}" gcloud storage buckets create "gs://${BUCKET_NAME}" --project="${PROJECT_ID}" --location="${REGION}"

    log_info "Exporting raw GCE image..."
    sudo -i -u "${ORIG_USER}" gcloud compute images export \
        --destination-uri="gs://${BUCKET_NAME}/${ARCHIVE_NAME}" \
        --image="${IMAGE_NAME}" \
        --project="${PROJECT_ID}"

    log_info "Downloading image archive locally..."
    sudo -i -u "${ORIG_USER}" gcloud storage cp "gs://${BUCKET_NAME}/${ARCHIVE_NAME}" "${WORKSPACE_DIR}/"

    log_info "Deleting temporary export bucket..."
    sudo -i -u "${ORIG_USER}" gcloud storage rm --recursive "gs://${BUCKET_NAME}" || log_warn "Failed to auto-delete bucket. Moving on..."

    log_info "Extracting archive to disk.raw..."
    tar -xzvf "${WORKSPACE_DIR}/${ARCHIVE_NAME}" -C "${WORKSPACE_DIR}"
}

mount_oem_partition() {
    log_info "Attaching disk.raw to a loop device..."
    LOOP_DEV=$(losetup -fP --show "${WORKSPACE_DIR}/disk.raw")
    log_info "Disk attached to loop device: ${LOOP_DEV}"

    local oem_part="${LOOP_DEV}p8"
    log_info "Mounting OEM partition (${oem_part}) read-only..."

    mkdir -p "${MOUNT_POINT}"
    mount -o ro "${oem_part}" "${MOUNT_POINT}"
}

unpack_virt_container() {
    log_info "Checking TDX virtualization container layout..."
    mkdir -p "${CONTAINER_EXTRACT_DIR}"

    if [ -f "${MOUNT_POINT}/tdx-qemu-app.tar" ]; then
        log_info "Legacy layout detected: Unpacking tdx-qemu-app.tar..."
        tar -xf "${MOUNT_POINT}/tdx-qemu-app.tar" -C "${CONTAINER_EXTRACT_DIR}"

        log_info "Unpacking nested image layers..."
        find "${CONTAINER_EXTRACT_DIR}" -name "*.tar" -exec tar -xf {} -C "${CONTAINER_EXTRACT_DIR}" \; 2>/dev/null || true
        find "${CONTAINER_EXTRACT_DIR}" -name "*.tar.gz" -exec tar -xzf {} -C "${CONTAINER_EXTRACT_DIR}" \; 2>/dev/null || true
    elif [ -d "${MOUNT_POINT}/tdx-qemu-app" ]; then
        log_info "New layout detected: tdx-qemu-app is already an uncompressed directory."
    else
        log_warn "Could not find tdx-qemu-app directory or tarball. Will attempt global search on partition."
    fi
}

retrieve_target_file() {
    log_info "Searching for target file ${TARGET_FILE}..."
    local file_path

    file_path=$(find "${MOUNT_POINT}" -name "${TARGET_FILE}" -print -quit)

    if [ -z "${file_path}" ] && [ -d "${CONTAINER_EXTRACT_DIR}" ]; then
        file_path=$(find "${CONTAINER_EXTRACT_DIR}" -name "${TARGET_FILE}" -print -quit)
    fi

    if [ -n "${file_path}" ]; then
        log_info "Target firmware located: ${file_path}"
        cp "${file_path}" "${WORKSPACE_DIR}/"
        log_success "${TARGET_FILE} extracted successfully!"
    else
        log_error "Failed to locate target firmware file ${TARGET_FILE}."
        exit 1
    fi
}

calculate_mrtd() {
    log_info "Calculating Offline MRTD measurement..."

    if [ ! -f "${WORKSPACE_DIR}/extract_image_ovmf.go" ]; then
        log_error "Go helper missing at: ${WORKSPACE_DIR}/extract_image_ovmf.go"
        exit 1
    fi

    if [ ! -f "${WORKSPACE_DIR}/${TARGET_FILE}" ]; then
        log_error "Firmware file missing at: ${WORKSPACE_DIR}/${TARGET_FILE}. Run with -i or -e to export."
        exit 1
    fi

    log_info "Running Go offline measurement generator..."

    sudo -i -u "${ORIG_USER}" bash -c "cd '${WORKSPACE_DIR}' && go run extract_image_ovmf.go '${TARGET_FILE}' > '${WORKSPACE_DIR}/${OUTPUT_FILE}'"

    echo ""
    echo "======================================================================"
    echo " Offline MRTD Output Results:"
    echo "======================================================================"
    cat "${WORKSPACE_DIR}/${OUTPUT_FILE}"
    echo "======================================================================"
    echo ""
}

# ==========================================
# Main Flow
# ==========================================
main() {
    # Safeguard: Ensure the user isn't trying to run an empty instance of the script
    if [ "${RUN_EXPORT}" = false ] && [ -z "${LOCAL_TARBALL}" ]; then
        if [ ! -f "${WORKSPACE_DIR}/${TARGET_FILE}" ]; then
            log_error "Missing ${TARGET_FILE}. You must specify an image to export (-i) or a local tarball (-t)."
            usage
        fi
    fi

    if [ -n "${LOCAL_TARBALL}" ]; then
        log_info "Skipping image export phase. Using local tarball: ${LOCAL_TARBALL}"
        if [ ! -f "${WORKSPACE_DIR}/disk.raw" ]; then
            tar -xzvf "${LOCAL_TARBALL}" -C "${WORKSPACE_DIR}"
        else
            log_info "disk.raw already exists in workspace, skipping extraction..."
        fi
        mount_oem_partition
        unpack_virt_container
        retrieve_target_file
    elif [ "${RUN_EXPORT}" = true ]; then
        export_and_download_image
        mount_oem_partition
        unpack_virt_container
        retrieve_target_file
    fi

    calculate_mrtd
}

main "$@"