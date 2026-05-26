# OVMF Verification Tooling

This directory contains tools to automate the extraction of Intel TDX firmware (`OVMF.inteltdx.fd`) from Google Compute Engine (GCE) ACOS host images and calculate the expected offline MRTD measurement.

## Directory Structure

* **`common.sh`**: Shared configuration variables and logging helpers.
* **`simulate_mrtd/extract-tdx.sh`**: The main extraction pipeline. Automates GCP image export, loopback mounting, intelligent firmware extraction, and cleanup.
* **`simulate_mrtd/extract_image_ovmf.go`**: Go utility that calculates the expected MRTD hash from the extracted firmware.

---

## Prerequisites

1. **System:** Linux environment with `sudo` privileges (required for loopback devices/mounting).
2. **Software:** Go (`>= 1.18`) installed and in your `PATH`.
3. **GCP Permissions:** Your active `gcloud` identity needs:
   * `roles/compute.admin` (to export images)
   * `roles/storage.admin` (to create/delete temp export buckets)

---

## Quick Start / Usage

Navigate to the tooling directory first:
```bash
cd simulate_mrtd
```

### Fast Run (Firmware Already Extracted)

If `OVMF.inteltdx.fd` is already in your directory from a previous run, calculate the MRTD instantly:

```bash
sudo ./extract-tdx.sh
```

### Extract from a Local Tarball (Recommended)
Bypass the lengthy cloud export by using a locally downloaded ACOS `.tar.gz` export. (If `disk.raw` is already extracted, it skips extraction to save time).

```bash
sudo ./extract-tdx.sh -t /path/to/acos-image.tar.gz
```

### Full Cloud Export (Default Config)

Strict Mode: If you override the project (`-p`) or region (`-r`), you must explicitly provide all three targeting flags together.

```bash
sudo ./extract-tdx.sh -i "acos-tdx-host-v2" -p "my-custom-project" -r "us-central1"
```
### Flag Reference

| Flag   | Argument   | Description                                      | Dependencies                     |
|:-------|:-----------|:-------------------------------------------------|:---------------------------------|
| -t     | `<file>`   | Path to a local .tar.gz ACOS image export.       | Mutually exclusive with -i & -e. |
| -e     |            | Triggers full image export using default values. | None.                            |
| -i     | `<image>`  | ACOS Host Image Name. Auto-triggers export.      | Required if using -p or -r.      |
| -p     | `<project>`| GCP Project ID.                                  | Requires -i and -r.              |
| -r     | `<region>` | GCP Region for the temp export bucket.           | Requires -i and -p.              |
| -h     |            | Show help menu.                                  | None.                            |



