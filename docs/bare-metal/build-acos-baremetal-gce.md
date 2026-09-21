# User guide: Build confidential aCOS images from source and run on bare metal in GCE

## 1. Overview

This guide provides instructions for building a custom OS image and deploying it
in a confidential bare metal execution environment on Google Cloud. This
deployment runs a specialized host OS called attested Container-Optimized OS
(aCOS host) and leverages the
[C3 machine series](https://docs.cloud.google.com/compute/docs/general-purpose-machines#c3_series).
The aCOS host manages and launches isolated guest Confidential Virtual Machines
(CVMs) through QEMU and libvirt.

You’ll configure a Linux development environment, compile the host, Key
Protection, and workload guest operating systems from open source repositories,
and assemble them into a custom debug OS image. On Google Cloud, you’ll set up
Virtual Private Cloud networks, deploy the custom debug image on C3 machines in
Compute Engine (GCE), launch confidential instances, and perform SSH and file
transfer operations for debugging. From there, you can independently verify
Trusted Computing Base measurements, software bills of materials, logs, and
open-source VMM builds.

Before proceeding, you should be familiar with confidential bare metal execution
environments on Google Cloud. You should be comfortable working in a Linux-based
development environment and have practical experience managing Google Cloud
resources, including containers, and compiling custom OS images from source.

### 1.1 Key components

The following are the core components for this confidential architecture:

*   **aCOS Host (Host OS):** A hardened or debug host operating system that runs
    directly on the bare-metal node. It initializes hardware Confidential
    Computing (CC) modes, manages networking, and executes local guest virtual
    machines.
*   **Key Oracle VM / Key Protection Service (KPS):** A kernel-isolated guest VM
    (key_oracle_vm_image.qcow2) responsible for managing cryptographic keys and
    secure attestation flows.
*   **Workload Guest VM:** A Unified Kernel Image-based guest VM
    (workload_vm_image.qcow2) housing the target workload container and
    application runtime.

# 2. Prerequisites

To perform the steps in this guide, you must have a [Google Cloud](https://cloud.google.com/)
account and your local development environment must meet the following
requirements:

*   **Operating System:** You must use a Linux-based development environment
    (Debian 12+, Ubuntu 22.04 LTS+, or COS). 100GB of free disk space is
    recommended.
*   **CPU and Hypervisor:** x86_64 architecture with KVM enabled (`/dev/kvm`
    accessible)
*   **Tools:** Use your Linux distribution’s built-in package manager to install
    Docker / Podman runtime, Bazel (v6.0+), Python 3.10+, qemu-img, and zstd,
    git, curl, and tar. If your distribution comes with tar pre-installed,
    update it.
*   **Google Cloud SDK:** The gcloud CLI must be configured and authenticated
    for a project with adequate [permissions](#212-assign-roles) to manage GCE
    images and Cloud Build tasks. For gcloud CLI installation instructions, see
    [Install the Google Cloud CLI](https://docs.cloud.google.com/sdk/docs/install-sdk).
*   **Storage:** To facilitate image file transfers,
    [Create a Google Cloud Storage (GCS) bucket](https://docs.cloud.google.com/storage/docs/creating-buckets).

## 2.1 Required APIs and IAM roles

To manage instances, builds, and data, enable the following APIs for your cloud
project and assign appropriate Identify and Access Management (IAM) roles.
Before enabling APIs, your project must have a
[Cloud Billing](https://docs.cloud.google.com/billing/docs/how-to/modify-project)
account attached.

### 2.1.1 Enable APIs

The following APIs are required on your project:

*   Compute Engine API (`compute.googleapis.com`)
*   Cloud Build API (`cloudbuild.googleapis.com`)
*   Cloud Storage API (`storage.googleapis.com`)

To enable the APIs, open a terminal and run the following gcloud command:

```
gcloud services enable compute.googleapis.com cloudbuild.googleapis.com storage.googleapis.com
```

### 2.1.2 Assign roles

To complete the steps in this guide, you must assign the following IAM roles to
users and service accounts:

*   **Storage Object Admin**
    ([roles/storage.objectAdmin](https://docs.cloud.google.com/storage/docs/access-control/iam-roles#storage.objectAdmin))
    on a GCS bucket: To upload OS images for creating GCE image resources
*   **Compute Admin**
    ([roles/compute.admin](https://docs.cloud.google.com/compute/docs/access/iam#compute.admin)):
    To create GCE images and run GCE virtual machines (VMs)
*   **Cloud Build Editor**
    ([roles/cloudbuild.builds.editor](https://docs.cloud.google.com/build/docs/iam-roles-permissions#predefined_roles)):
    To run Cloud Build jobs for preloading Confidential Space images from a
    Container-Optimized OS baseline

For instructions on managing roles, see
[Manage access to projects, folders, and organizations](https://docs.cloud.google.com/iam/docs/granting-changing-revoking-access).

# 3. Compile the custom debug image from source

Compile the baseline host OS, the workload OS, and the key protection OS. Those
components are then assembled into the custom debug OS image. **The build
processes for each of these components can take 30 minutes to complete.**

## 3.1 Compile and export the baseline host OS

Complete the following steps to compile the host OS, which is a transparent,
open-source, aCOS-based image, and upload to GCS.

### 3.1.1 Download Container-Optimized OS source code

Confidential Space images are built using Container-Optimized OS. For this
guide, we’ll use standard Chromium OS development tools to check out source code
for the **release-R125** branch.

#### 3.1.1.1 Install `depot_tools`

If you haven’t installed `depot_tools`, a suite of tools to assist with
development in a Chromium environment, run the following command to clone the
repository and add it to your `PATH`:

```html
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH="$PATH:<DEPOT_TOOLS>"
```

Replace ***DEPOT_TOOLS*** with the path to your depot_tools directory.

#### 3.1.1.2 Initialize and sync the source repository

Create a working directory (named `cos-src` in this example) and use the `repo`
tool (installed with depot_tools) to fetch the COS manifest and source code:

```
mkdir $HOME/cos-src
cd $HOME/cos-src

# Initialize the repository targeting the release-R125 branch
repo init -u https://cos.googlesource.com/cos/manifest.git -b release-R125

# Synchronize the source code (this might take several minutes or longer, depending on the speed of your connection)
repo sync
```

### 3.1.2 Build the baseline OS image

After syncing the source code, enter the Chromium OS SDK chroot environment
(installed with depot_tools) to configure and build the disk image. You can
choose between the **cchost-amd64-gcp** board for a hardened image or the
**cchostdebug-amd64-gcp** board for a debug image. **Note:** The C3 instances
discussed later in this guide require debug images.

#### 3.1.2.1 Enter the SDK chroot

Initialize and enter the isolated build environment:

```
cd $HOME/cos-src
cros_sdk --enter
```

#### 3.1.2.2 Build packages and image

To build packages and images, execute the
[standard COS build workflow](https://docs.cloud.google.com/container-optimized-os/docs/how-to/building-from-open-source)
inside the chroot:

```
# Compile all required system packages
build_packages --board=cchostdebug-amd64-gcp --nowithautotest

# Generate base and test disk images
build_image --board=cchostdebug-amd64-gcp --disk_layout=base base test
```

It’s recommended that you build `base` and `test` images simultaneously.

*   **base:** A hardened, production-ready OS suitable for deployment.
*   **test:** Includes debugging utilities, automatic test frameworks, a
    pre-configured root password (`test0000`), and a pre-baked SSH certificate.
    The corresponding private key is available at
    `src/build/images/lakitu/latest/id_rsa`. These features are useful for local
    inspection using QEMU.

#### 3.1.2.3 Sign the image with developer keys

To sign the image, run `sign_official_cos_build.sh` on the resulting disk image
inside the chroot:

```
cd /mnt/host/source/src/build/images/cchostdebug-amd64-gcp/latest
VBOOT=/mnt/host/source/src/platform/vboot_reference
export PATH=$PATH:$VBOOT/scripts/image_signing
cp -r $VBOOT/tests/devkeys/uefi/db $VBOOT/tests/devkeys
sudo --preserve-env=PATH $(which sign_official_cos_build.sh) base local \
    chromiumos_base_image.bin $VBOOT/tests/devkeys \
    signed_base_image.bin "" ima_hash
/mnt/host/source/src/scripts/set_uki_boot.sh \
    --board cchostdebug-amd64-gcp \
    --image_path signed_base_image.bin
```

#### 3.1.2.4 Exit the chroot

When the build finishes successfully, leave the SDK environment:

```
exit
```

### 3.1.3 Create a baseline GCE image

The preceding compilation step produced a raw disk image. To establish the
customization baseline, the raw image must be packaged and imported into GCE.

#### 3.1.3.1 Archive the raw disk image

To archive the raw disk image, run the following command to navigate to the
build output directory, create a compressed archive named `cos_gce.tar.gz`, and
rename the image inside the archive `disk.raw` as required by GCE import tools:

```
cd $HOME/cos-src/src/build/images/cchostdebug-amd64-gcp/latest/

tar -Sczf cos_gce.tar.gz signed_base_image.bin \
    --transform 's|signed_base_image.bin|disk.raw|'
```

#### 3.1.3.2 Upload the archive to GCS

To copy the archive to GCS, run the following command:

```html
# Upload the compressed image
gcloud storage cp cos_gce.tar.gz gs://<GCS_BUCKET>/base/stable-channel/cos_gce.tar.gz
```

Replace ***GCS_BUCKET*** with the name of your Cloud Storage bucket. Take note
of the exact file path inside of the GCS bucket — this is important for
subsequent steps.

The `vmlinux` associated with this build is needed in later sections of this
guide. To upload `vmlinux` to GCS, run the following command:

```html
gcloud storage cp vmlinux gs://<GCS_BUCKET>/
```

Replace ***GCS_BUCKET*** with the name of your Cloud Storage bucket.

#### 3.1.3.3 Import the archive into GCE

> **Tip:** To avoid naming conflicts if you plan to reuse this guide and/or
> retain the image archive, consider appending the archive name with a timestamp
> or other unique value.

To register the archive as a GCE image (`cos-r125-cchost-base`, in this
example), run the following command:

```html
# Create the baseline Compute Engine image
gcloud compute images create cos-r125-cchost-base \
    --source-uri=gs://<GCS_BUCKET>/base/stable-channel/cos_gce.tar.gz \   --guest-os-features=TDX_CAPABLE,SNP_SVSM_CAPABLE,SEV_CAPABLE,GVNIC,SEV_LIVE_MIGRATABLE,SEV_SNP_CAPABLE,UEFI_COMPATIBLE,SEV_LIVE_MIGRATABLE_V2,IDPF,VIRTIO_SCSI_MULTIQUEUE
```

Replace ***GCS_BUCKET*** with the name of your Cloud Storage bucket.

The following list defines the configuration parameters in the preceding gcloud
command:

*   **TDX_CAPABLE:** Enables **Intel TDX** (Trust Domain Extensions).
*   **SEV_SNP_CAPABLE:** Enables **AMD SEV-SNP** (Secure Nested Paging), which
    adds strong memory integrity protection to prevent hypervisor-based
    side-channel attacks.
*   **SEV_CAPABLE:** Enables **AMD SEV** (Secure Encrypted Virtualization),
    which encrypts VM memory so the hypervisor cannot access it.
*   **SNP_SVSM_CAPABLE:** Indicates the guest supports **Secure VM Service
    Module** (SVSM), which is required for running services like a virtual TPM
    (vTPM) within an SEV-SNP environment.
*   **GVNIC:** Required to use the **Google Virtual NIC**.
*   **IDPF:** Enables the **Infrastructure Data Path Function** driver.
*   **VIRTIO_SCSI_MULTIQUEUE:** Allows the guest to use multiple "queues" for
    disk I/O.
*   **UEFI_COMPATIBLE:** Tells GCE to boot the image using **UEFI** instead of
    Legacy BIOS.
*   **SEV_LIVE_MIGRATABLE:** Indicates the guest kernel supports live migration
    while SEV is active.
*   **SEV_LIVE_MIGRATABLE_V2:** An updated version of the live migration tag. It
    generally requires a more recent kernel (6.1+ or 6.6+) and provides more
    robust migration for confidential VMs.

## 3.2 Compile and export the Key

Protection OS Perform the following steps to compile the Key Protection OS and
export it to GCS. The Key Protection OS manages cryptographic keys within a
dedicated, isolated Confidential Virtual Machine (CVM) on the baremetal host.

### 3.2.1 Download Key Protection source code

To clone the Key Protection Module from Github, run the following command:

```
git clone https://github.com/GoogleCloudPlatform/key-protection-module
```

### 3.2.2 Compile the Key Protection Module Docker image

In the root of the `key-protection-module` project, run the following Docker
command to compile the Key Protection Module Docker image:

```html
docker build -t gcr.io/<PROJECT_ID>/key-protection-module:latest .
docker push gcr.io/<PROJECT_ID>/key-protection-module:latest
```

Replace ***PROJECT_ID*** with the ID of your project.

### 3.2.3 Compile the Key Protection OS

To compile the Key Protection OS with Google Cloud Build, run the following
command:

```html
sed -i -e '/VERSION=/i \        gcloud storage cp gs://<GCS_BUCKET>/vmlinux .' image/cloudbuild.yaml
sed -i -e '/VERSION=/i \        exit 0' image/cloudbuild.yaml
gcloud builds submit --config image/cloudbuild.yaml --substitutions _BASE_IMAGE=cos-r125-cchost-base,_BASE_IMAGE_PROJECT=<PROJECT_ID>,_OUTPUT_IMAGE_NAME=cos-r125-cchost-kps,_OUTPUT_IMAGE_PROJECT=<PROJECT_ID>,_OUTPUT_IMAGE_FAMILY=cos-r125-cchost-kps,_BUCKET_NAME=<GCS_BUCKET>,_IMAGE_ENV=debug,_KPS_DOCKER_IMAGE_REF=gcr.io/<PROJECT_ID>/key-protection-module:latest,_ZONE=<ZONE> .
```

Replace the following:

*   ***GCS_BUCKET:*** The name of your Cloud Storage bucket
*   ***PROJECT_ID***: The ID of your project
*   **ZONE:** The zone where the builder instance is provisioned

To export the Key Protection OS image archive to GCS, run the following command:

```html
gcloud compute images export --image --destination-uri gs://<GCS_BUCKET>/cos-r125-cchost-kps.tar.gz
```

Replace ***GCS_BUCKET*** with the name of your Cloud Storage bucket.

## 3.3 Compile and export the workload guest OS

Perform the following steps to compile the workload guest OS and export it to
GCS. The workload guest OS is an open-source, Linux-based stack that runs within
a Confidential Space environment on the bare metal host. It operates within a
Trusted Execution Environment (TEE) isolated by Intel TDX to provide
hardware-based DRAM encryption and data security.

### 3.3.1 Download the workload/launcher source code

To get the workload/launcher source code, run the following command to clone
`go-tpm-tools` from Github:

```
git clone https://github.com/google/go-tpm-tools
```

### 3.3.2 Compile the workload OS

To compile the workload OS, you must first apply a patch to the `go-tpm-tools`
repository. The patch simplifies the build process by removing image measurement
steps and specific worker pool requirements, while adding a necessary
certificate download step. To apply the patch, copy the following text to a
patch file (for example, `fix-build.patch`).

```
diff --git a/launcher/image/bc_cloudbuild.yaml b/launcher/image/bc_cloudbuild.yaml
index 2811178..f6cc895 100644
--- a/launcher/image/bc_cloudbuild.yaml
+++ b/launcher/image/bc_cloudbuild.yaml
@@ -9,6 +9,9 @@ substitutions:
   '_WSD_CONTAINER_IMAGE_REF': ''

 steps:
+  - name: 'gcr.io/cloud-builders/curl'
+    id: DownloadGoogleRoots
+    args: ['-sSL', 'https://pki.goog/roots.pem', '-o', 'launcher/image/google_roots.pem']
   - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
     id: 'ExportBaseImage'
     args:
@@ -16,6 +19,7 @@ steps:
       - 'compute'
       - 'images'
       - 'export'
+      - '--zone=${_ZONE}'
       - '--image=${_BASE_IMAGE}'
       - '--image-project=${_BASE_IMAGE_PROJECT}'
       - '--destination-uri=gs://${_BUCKET_NAME}/oem-preloader-${BUILD_ID}/${_BASE_IMAGE}.tar.gz'
@@ -215,22 +219,6 @@ steps:
   - name: 'alpine'
     id: 'RenameOutputImage'
     args: ['mv', 'output.bin', 'disk.raw']
-  - name: 'us-docker.pkg.dev/confidential-space-images-dev/cs-tools/measure@sha256:dae4766caef4a93c52736feb829bf2c505b7d48ce44d0ecb33e77d61bb4be888'
-    id: 'MeasureImage'
-    env:
-      - 'IMAGE_ENV=${_IMAGE_ENV}'
-      - 'OUTPUT_IMAGE_NAME=${_OUTPUT_IMAGE_NAME}'
-    entrypoint: 'bash'
-    args:
-      - '-c'
-      - |
-        set -exuo pipefail
-        echo "measuring BC image $${OUTPUT_IMAGE_NAME} (env=$${IMAGE_ENV})"
-        /usr/local/bin/measure.sh ./disk.raw measure_output_bc_$${IMAGE_ENV}.json        "$${IMAGE_ENV}" x86_64 sha256
-        /usr/local/bin/measure.sh ./disk.raw measure_output_bc_$${IMAGE_ENV}_sha384.json "$${IMAGE_ENV}" x86_64 sha384
-
-        gcloud storage cp measure_output_bc_$${IMAGE_ENV}.json        gs://${PROJECT_ID}-rims/bc/$${OUTPUT_IMAGE_NAME}.json
-        gcloud storage cp measure_output_bc_$${IMAGE_ENV}_sha384.json gs://${PROJECT_ID}-rims/bc/$${OUTPUT_IMAGE_NAME}_sha384.json
   - name: 'alpine'
     id: 'TarOutputImage'
     args: ['tar', '-zcf', './out_image.tar.gz', 'disk.raw']
@@ -311,6 +299,4 @@ timeout: '3000s'

 options:
   dynamic_substitutions: true
-  pool:
-    name: 'projects/confidential-space-images-dev/locations/us-west1/workerPools/cs-image-build-vpc'
```

To apply the patch (fix-build.patch, in this example), run the following
command:

```
patch -p1 < fix-build.patch
```

After applying the patch, run the following command to compile the workload OS:

```html
sed -i -e '/VERSION=/i \        gcloud storage cp gs://<GCS_BUCKET>/vmlinux .' image/cloudbuild.yaml
sed -i -e '/VERSION=/i \        exit 0' image/cloudbuild.yaml
gcloud builds submit --config launcher/image/bc_cloudbuild.yaml --substitutions _BASE_IMAGE=cos-r125-cchost-base,_BASE_IMAGE_PROJECT=<PROJECT_ID>,_BUCKET_NAME=<GCS_BUCKET>,_IMAGE_ENV=debug,_OUTPUT_IMAGE_NAME=cos-r125-cchost-workload,_OUTPUT_IMAGE_FAMILY=cos-r125-cchost-workload,_WSD_CONTAINER_IMAGE_REF=gcr.io/<PROJECT_ID>/key-protection-module:latest,_ZONE=<ZONE> .
```

Replace the following:

*   ***GCS_BUCKET:*** The name of your Cloud Storage bucket.
*   ***PROJECT_ID***: The ID of your project
*   ***ZONE:*** The selected location for image export To export the workload OS
    image archive to GCS, run the following command:

```html
gcloud compute images export --image cos-r125-cchost-workload --destination-uri gs://<GCS_BUCKET>/cos-r125-cchost-workload.tar.gz
```

Replace ***GCS_BUCKET*** with the name of your Cloud Storage bucket.

## 3.4 Assemble the final custom debug OS image

Perform the following steps to create the custom debug OS image—which combines
the baseline host, Key Protection OS, and workload guest OS you created in
preceding sections—and export it to GCS.

### 3.4.1 Download the host aCOS source code

To get the host aCOS source code, run the following command to clone the
`host-acos` Git repository:

```html
git clone https://cos.googlesource.com/confidential-space/host-acos
```

### 3.4.2 Compile the host OS

To compile the host OS, you must modify the `image_config_debug.env` file to
include references to the baseline host OS, Key Protection OS, and workload
guest OS:

```html
cat <<EOF > image_config_debug.env
BASE_IMAGE_DIR=gs://<GCS_BUCKET>
GUEST_KEY_ORACLE_ACOS_GS_URL=gs://<GCS_BUCKET>/cos-r125-cchost-kps.tar.gz
GUEST_WORKLOAD_ACOS_GS_URL=gs://<GCS_BUCKET>/cos-r125-cchost-workload.tar.gz
EOF
```

Replace ***GCS_BUCKET*** with the name of your Cloud Storage bucket. After
modifying `image_config_debug.env`, run the following command to build the
image:

```html
IMAGE_ENV=debug OUTPUT_IMAGE_PREFIX=<IMAGE_PREFIX> OUTPUT_IMAGE_PROJECT=<PROJECT_ID> OUTPUT_IMAGE_GCS_BUCKET=gs://<GCS_BUCKET> ./build-acos-host-image.sh
```

Replace the following:

*   ***IMAGE_PREFIX:*** Your chosen prefix string.
*   ***PROJECT_ID:*** The ID of your project
*   ***GCS_BUCKET:*** The name of your Cloud Storage bucket

This process creates a GCE image in your project and exports it to GCS. The
image name and GCS location should be included in the script output.

# 4. Deploy and run host image on GCE

To run your custom image on C3 bare metal hardware in GCE, upload the compiled
disk tarball to GCS, register it as an image project artifact, create VPC
networks, and launch debug instances.

## 4.1 Register the host image

To register the host image, run the following command:

```html
gcloud compute images create <IMAGE_NAME> --source-uri="gs://<GCS_BUCKET>/<IMAGE_ARCHIVE>" --project <PROJECT_ID>  --guest-os-features=GVNIC,IDPF,VIRTIO_SCSI_MULTIQUEUE,UEFI_COMPATIBLE,TDX_CAPABLE,SEV_CAPABLE,SEV_LIVE_MIGRATABLE_V2,SEV_SNP_CAPABLE,SEV_LIVE_MIGRATABLE
```

Replace the following:

*   ***IMAGE_NAME:*** The name of the GCE image
*   ***PROJECT_ID:*** The ID of the your project
*   ***GCS_BUCKET:*** The name of your Cloud Storage bucket
*   ***IMAGE_ARCHIVE:*** The name of the host OS archive you created in
    [Compile the host OS](#342-compile-the-host-os)
    
The following list defines the configuration parameters in the preceding gcloud
command:

*   **TDX_CAPABLE:** Enables **Intel TDX** (Trust Domain Extensions).
*   **SEV_SNP_CAPABLE:** Enables **AMD SEV-SNP** (Secure Nested Paging), which
    adds strong memory integrity protection to prevent hypervisor-based
    side-channel attacks.
*   **SEV_CAPABLE:** Enables **AMD SEV** (Secure Encrypted Virtualization),
    which encrypts VM memory so the hypervisor cannot access it.
*   **SNP_SVSM_CAPABLE:** Indicates the guest supports **Secure VM Service
    Module** (SVSM), which is required for running services like a virtual TPM
    (vTPM) within an SEV-SNP environment.
*   **GVNIC:** Required to use the **Google Virtual NIC**.
*   **IDPF:** Enables the **Infrastructure Data Path Function** driver.
*   **VIRTIO_SCSI_MULTIQUEUE:** Allows the guest to use multiple "queues" for
    disk I/O.
*   **UEFI_COMPATIBLE:** Tells GCE to boot the image using **UEFI** instead of
    Legacy BIOS.
*   **SEV_LIVE_MIGRATABLE:** Indicates the guest kernel supports live migration
    while SEV is active.
*   **SEV_LIVE_MIGRATABLE_V2:** An updated version of the live migration tag. It
    generally requires a more recent kernel (6.1+ or 6.6+) and provides more
    robust migration for confidential VMs.

## 4.2 Create VPCs and subnetworks

These confidential instances use [VPCs](https://docs.cloud.google.com/vpc/docs/overview)
and [subnetworks](https://docs.cloud.google.com/vpc/docs/subnets) (subnets) for
secure connectivity and isolation. VPCs are global, logically isolated
virtual networks that provide connectivity for cloud resources. VPCs contain
subnets, which are regional partitions that define specific ranges of IP
addresses. To manage and configure advanced networking capabilities within
VPC networks, [network profiles](https://docs.cloud.google.com/vpc/docs/network-profiles)
are required. Because these instances feature two physical NICs on the host
machine, you must create two VPCs as follows:

*   Two Infrastructure Data Plane Function (IDPF) networks, each containing a
    subnet, are used for communication between hosts. For more information about
    IDPF, see
    [Using the IDPF network interface](https://docs.cloud.google.com/compute/docs/networking/using-idpf).

To configure the networking environment for your confidential instances, run the
following commands. The commands set up two VPC networks that let you manually
define subnets, create a subnet in each VPC, and create two firewall rules—one
that allows SSH access and another for dedicated communication between instance
hosts.

```html
PROJECT=<PROJECT_ID>
IDPF_NETWORK_PREFIX="c3-metal-idpf"
IDPF_MTU=8896
REGION=<GCE_REGION>

gcloud compute --project=${PROJECT?} \
  networks create \
  ${IDPF_NETWORK_PREFIX?}-mgmt-net \
  --subnet-mode=custom \
  --mtu=8896

gcloud compute --project=${PROJECT?} \
  networks subnets create \
  ${IDPF_NETWORK_PREFIX?}-mgmt-sub \
  --network=${IDPF_NETWORK_PREFIX?}-mgmt-net \
  --region=${REGION?} \
  --range=10.10.0.0/24

gcloud compute --project=${PROJECT?} \
  firewall-rules create \
  ${IDPF_NETWORK_PREFIX?}-mgmt-allow-ssh \
  --network=${IDPF_NETWORK_PREFIX?}-mgmt-net \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges=0.0.0.0/0

gcloud compute --project=${PROJECT?} \
  networks create \
  ${IDPF_NETWORK_PREFIX?}-net \
  --subnet-mode=custom \
  --mtu=${IDPF_MTU} \
  --enable-ula-internal-ipv6

gcloud compute --project=${PROJECT?} \
  networks subnets create \
  ${IDPF_NETWORK_PREFIX?}-sub-1 \
  --network=${IDPF_NETWORK_PREFIX?}-net \
  --region=${REGION?} \
  --stack-type=IPV6_ONLY \
  --ipv6-access-type=INTERNAL

gcloud compute --project=${PROJECT?} \
  firewall-rules create \
  ${IDPF_NETWORK_PREFIX?}-internal \
  --network=${IDPF_NETWORK_PREFIX?}-net \
  --action=ALLOW \
  --rules=tcp:0-65535,udp:0-65535,58 \
  --source-ranges=::/0
```

Replace the following:

*   ***PROJECT_ID:*** The ID of the your project
*   ***GCE_REGION:*** The selected region

> **Warning:** While using
    --source-ranges=0.0.0.0/0 in firewall settings is suitable for testing,
    don’t use it in production. This configuration permits any user to ping your
    instances. You should define a more limited range when feasible. For more
    information, see the
    [API reference](http://cloud/sdk/gcloud/reference/compute/firewall-rules/create)
    on firewall rules and
    [best practices](https://cloud.google.com/compute/docs/connect/ssh-best-practices/network-access#use-firewall-policies)
    on controlling network access. For optimal performance, IDPF_MTU sets the
    Maximum Transmission Unit (MTU) to an 8896 jumbo frame size. For details,
    see
    [MTU settings and GPU machine types](https://cloud.google.com/compute/docs/gpus/gpu-network-bandwidth#mtu-gpu).
    
## 4.3 Provision confidential C3 instances in GCE

Set environment variables and launch confidential C3 instances in GCE. The total
duration from creating the instance to the workload starting in the instance is
about 40 minutes. The workload instance will have approximately 3840 GB memory
and a disk size of about 100 GB.

### 4.3.1 Set environment variables

To set environment variables, run the following command:

```html
PROJECT=<PROJECT_ID>
IDPF_NETWORK_PREFIX="c3-metal-idpf"
ZONE=<ZONE>
MACHINE_TYPE=<C3_MACHINE>

IMAGE=<IMAGE_NAME>
IMAGE_PROJECT=<PROJECT_ID>

BM_NAME=<BM_INSTANCE_NAME>
BOOT_DISK_SIZE=100GB
```

Replace the following:

*   ***PROJECT_ID:*** The ID of your project
*   ***ZONE:*** The zone where you want the instance to be located (see
    [Regional availability for bare metalinstances](https://docs.cloud.google.com/compute/docs/instances/bare-metal-instances#regions-zones))
*   ***C3_MACHINE:*** The selected
    [machine type](https://docs.cloud.google.com/compute/docs/general-purpose-machines#c3_machine_types);
    C3 bare metal instances support **c3-highmem-192-metal**,
    **c3-standard-192-metal**, and **c3-highcpu-192-metal**
*   ***IMAGE_NAME:*** The name of the image
*   ***BM_INSTANCE_NAME:*** The name you want to assign to your instance

### 4.3.2 Launch C3 bare metal instances

C3 bare metal machines only support debug images and are intended for use
solely for debugging and testing machines. They aren’t suitable for
production workloads. For those reasons, C3 Bare Metal instances can be
created on-demand and don’t require future reservations. Before proceeding,
review the following caveats:

*   C3 machines don’t support host attestation
*   **Metadata variables:** Don’t include the **`tee-install-gpu-driver=true`**
    metadata variable in C3 instance creation commands; if the variable is
    included, the guest might crash after failing to find NVIDIA GPUs

To launch a C3 Bare Metal instance, run the following command:

```html
gcloud compute --project=${PROJECT?} instances create \
  ${BM_NAME?} \
  --machine-type=${MACHINE_TYPE?} \
  --zone=${ZONE?} \
  --image={IMAGE?} \
  --image-project={IMAGE_PROJECT?} \
  --maintenance-policy=TERMINATE \
  --boot-disk-type=hyperdisk-balanced \
  --boot-disk-size=${BOOT_DISK_SIZE} \
  --metadata=guest-memory-size-gib=<GUEST_MEMORY>,tee-debug-ssh-enable=true,on-guest-termination=debug-pause,enable-oslogin=true,tee-disable-gca-refresh=true,tee-image-reference=docker.io/library/nginx:latest,test-fake-verifier=true \
  --scopes=cloud-platform \
  --network-interface=nic-type=IDPF
```

Replace ***GUEST_MEMORY*** with the required size for your selected machine
type:

*   ***1024*** for **c3-highmem-192-metal** machines
*   **512** for **c3-standard-192-metal** machines
*   **256** for **c3-highcpu-192-metal** machines

The following list defines the metadata variables in the gcloud command:

*   **guest-memory-size-gib:** The amount of memory allocated to the guest
*   **tee-debug-ssh-enable=true:** Enables host to guest SSH access in debug
    instances
*   **on-guest-termination=debug-pause:** Pauses the instance on termination for
    debugging
*   **enable-oslogin=true:** Enables SSH key management on your project
*   **tee-disable-gca-refresh=true:** Disables the GCA refresh mechanism
*   **tee-image-reference:** The location of the workload container

To SSH into debug instances, follow the instructions in
[SSH into debug instances](#443-SSH-into-debug-instances).

The output of instance creation resembles the following:

```
Created [https://www.googleapis.com/compute/v1/projects/exampleproject/zones/europe-west4-b/instances/exampleinstance].

NAME               ZONE            MACHINE_TYPE            PREEMPTIBLE  INTERNAL_IP    EXTERNAL_IP     STATUS
exampleinstance  europe-west4-b  c3-highmem-192-metal               1.2.3.4  34.111.222.333  RUNNING
```

During instance creation, the physical machine is power-cycled, which erases
volatile memory and sends a reset signal to connected peripherals. Booting from
a power cycle takes about 20 minutes.

## 4.4 Manage instances

Perform lifecycle and data management operations on instances.

### 4.4.1 Use SCP to transfer files into debug instances

To perform inference, benchmark tests, and other tasks, you’ll need to transfer
files, such as model weights, performance testing scripts, datasets, and
configuration files, into your debug instances. This workflow isn’t possible
using hardened instances, which don’t allow SSH access. To securely transfer
files, use GCE’s
[`gcloud compute scp`](https://cloud.google.com/sdk/gcloud/reference/compute/scp)
command to copy files from your machine to the selected directory on the
instance.

```html
PROJECT=<PROJECT_ID>
BM_NAME=<BM_INSTANCE_NAME>
ZONE=<ZONE>
gcloud compute scp --project $PROJECT --zone $ZONE <LOCAL_FILE_PATH> $BM_NAME:<BM_PATH>
```

Replace the following:

*   ***PROJECT_ID:*** The ID of your project
*   ***BM_INSTANCE_NAME:*** The name of the target instance
*   ***ZONE:*** The zone where the instance is located
*   ***LOCAL_FILE_PATH:*** The location of the file you want to upload (for
    example, `~/etc/nvidia/custom_config.json`)
*   ***BM_PATH:*** The target destination on the instance (for example,
    `~/custom_config.json`).
    
### 4.4.2 Move instances to a different host machine

To move an instance to a different host machine, you must delete the existing 
instance from the current host and recreate it on the target host.

**Delete instances**

```html
gcloud compute instances delete <BM_INSTANCE_NAME>
  --zone=<ZONE>
```

Replace the following:

*   ***BM_INSTANCE_NAME:*** The name of the target instance
*   ***ZONE:*** The zone where the instance is located **Recreate instances** To
    recreate the instance on a target host, see
    [Launch C3 bare metal instances](#432-Launch-C3-bare-metal-instances) and
    use a different host resource.

### 4.4.3 SSH into debug instances

To manage,configure, test, and verify resources you can SSH into guest and host
instances. SSH access is supported only on instances created with a debug
image.

#### 4.4.3.1 SSH into guest

To SSH into a guest instance, run the following command after the guest instance
is started:

```html
gcloud compute ssh <BM_INSTANCE_NAME> --project <PROJECT_ID> --zone <ZONE>
```

Replace the following:

*   ***BM_INSTANCE_NAME:*** The name of the instance you want to access
*   ***PROJECT:*** The ID of your project
*   ***ZONE:*** The zone where the instance is located You should now be in the
    guest instance. To verify your location, run the following command to view
    dmesg logs:

```
sudo dmesg | grep -i tdx
```

The output should resemble the following:

```
[    0.000000] tdx: Guest detected
[    0.000000] tdx: Attributes: SEPT_VE_DISABLE
[    0.000000] tdx: TD_CTLS: PENDING_VE_DISABLE ENUM_TOPOLOGY VIRT_CPUID2 REDUCE_VE
[  742.821296] systemd[1]: Detected confidential virtualization tdx.
```

**Note:** The output also verifies that Intel TDX is active.

#### 4.4.3.2 SSH into host

There are two options for accessing the host: going through the guest while it
remains active or entering the host directly by shutting down the guest.

**Option 1: SSH hopping to host from guest (guest running, NIC assigned to the
guest)**

While the guest is active, you can SSH into the host machine. To access
a host with a running guest, do the following:

During instance creation or before a reboot, add the metadata variable
`tee-debug-ssh-enable=true`. This variable instructs the host service to
generate an ephemeral SSH keypair and securely share the key with the guest.
While connected to the guest, use the key provided within the guest to SSH into
the host:

```
[guest] $ sudo ssh -i /sys/firmware/qemu_fw_cfg/by_name/opt/tee_debug_ssh/id_rsa/raw root@192.168.100.1
```

You should now be inside the host. To see active guests running on the host,
execute the following command:

```
[host] $ ps aux | grep -i /usr/local/bin/qemu-system-x86_64
```

If the QEMU is running, the output should resemble the following:

```
root       13647 6033  0.9 6177257284 38093988 ? Sl   06:57 5470:32 /usr/local/bin/qemu-system-x86_64 -name guest=WorkloadVM,debug-threads=on -S -object {"qom-type":"secret","id":"masterKey0","format":"raw","file":"/var/lib/libvirt/qemu/domain-1-WorkloadVM/master-key.aes"} -machine pc-q35-11.0,usb=off,kernel_irqchip=split,dump-guest-core=off,acpi=on -accel kvm -cpu host,migratable=on -m size=4026531840k -overcommit mem-lock=off -smp 224,sockets=2,dies=1,clusters=1,cores=56,threads...
```

**Option 2: SSH directly into the host (guest shutdown, NIC assigned to the
host)**

When the guest isn’t running, the host claims the NIC, letting you SSH
directly into it. There are two ways to do this: During instance creation, you
can set the instance metadata variable `breakpoint=before_vm` which stops the
guest VM from booting and lets you SSH into the host. You can also shutdown the
guest VM. The following command stops the guest VM and disconnects active SSH
sessions. To ensure the host isn’t automatically terminated, when you create
instances, set the instance metadata variable
`on-guest-termination=debug-pause`.

```
[Guest] $ sudo shutdown now
```

Wait a few moments for the guest VM shutdown process to complete, and then run
the following command to reconnect to the host:

```html
gcloud compute ssh <BM_INSTANCE_NAME> --project <PROJECT_ID> --zone <ZONE>
```

Replace the following:

*   ***BM_INSTANCE_NAME:*** The name of the instance you want to access
*   ***PROJECT:*** The ID of your project
*   ***ZONE:*** The zone where the instance is located You should now be inside
    of the host. Reconnecting to the machine after a guest shutdown often
    triggers a warning about a potential “man in the middle” attack. This
    warning is expected. To reset SSH keys and clear the warning, run the
    following command:

```html
ssh-keygen -R <HOST_ID> -f ~/.ssh/google_compute_known_hosts
s-
# e.g. ssh-keygen -R compute.2858590262266178091 -f /usr/local/google/home/user-name/.ssh/google_compute_known_hosts
```

Replace ***HOST_ID*** with the hostname of the machine.

The output resembles the following:

```
# Host compute.2858590262266178091 found: line 55
/usr/local/google/home/user-name/.ssh/google_compute_known_hosts updated.
Original contents retained as /usr/local/google/home/user-name/.ssh/google_compute_known_hosts.old
```

### 4.4.4 Reboot instances

[Rebooting an instance](https://docs.cloud.google.com/compute/docs/instances/reset-instance)
forces a hard physical power cycle of the dedicated server, erasing all memory
contents, clearing CPU performance counters, and bypassing the guest OS's
standard shutdown procedures. To reboot an instance, run the following command
from the instance:

```
sudo reboot
```

### 4.4.5 Reset instances

[Resetting an instance](https://docs.cloud.google.com/compute/docs/instances/reset-instance)
prevents a clean shutdown of the guest OS and should be used as a last resort
when the system is crashed or unresponsive. To reset an instance, run the
following command:

```html
PROJECT=<PROJECT_ID>
BM_NAME=<BM_INSTANCE_NAME>
ZONE=<ZONE>

gcloud compute --project=${PROJECT?} instances reset ${BM_NAME?} --zone={ZONE?}
```

Replace the following:

*   ***PROJECT_ID:*** The ID of your project
*   ***BM_INSTANCE_NAME:*** The name of the target instance
*   ***ZONE:*** The zone where the instance is located

### 4.4.6 Delete instances

Deleting an instance terminates the physical hardware allocation
and the local operating system, and drops network connectivity. For more
information, see
[Delete instances](https://docs.cloud.google.com/compute/docs/instances/deleting-instance#delete_an_instance)
and
[Billing implications](https://docs.cloud.google.com/compute/docs/instances/deleting-instance#billing_implications).

To delete an instance, run the following command:

```html
PROJECT=<PROJECT_ID>
BM_NAME=<BM_INSTANCE_NAME>
ZONE=<ZONE>

gcloud compute --project=$PROJECT instances delete $BM_NAME --zone=$ZONE
```

Replace the following:

*   ***PROJECT_ID:*** The ID of your project
*   ***BM_INSTANCE_NAME:*** The name of the target instance
*   ***ZONE:*** The zone where the instance is located

### 4.4.7 List all instances in a project

To list all instances in a project, run the following command:

```html
PROJECT=<PROJECT_ID>
gcloud compute instances list --project=${PROJECT?} --filter=machine_type~<C3_MACHINE>
```

Replace the following:

*   ***PROJECT_ID:*** The ID of your project.
*   ***C3_MACHINE:*** The selected machine type (c3-highmem-192-metal,
    c3-standard-192-metal, or c3-highcpu-192-metal)

# 5. Clean up resources

To adhere to security best practices and control cloud costs, when you’re
done with your evaluation or no longer need the resources you created, you
should either delete the project that contains the resources (recommended)
or keep the project and delete the individual resources. The following links
provide instructions for deleting resources, managing access, and disabling
billing.

*   [Delete and restore projects](https://docs.cloud.google.com/resource-manager/docs/delete-restore-projects)
*   [Delete a Compute Engine instance](https://docs.cloud.google.com/compute/docs/instances/deleting-instance)
*   [Delete a custom image](https://docs.cloud.google.com/compute/docs/images/delete-custom)
*   [Delete a network](https://docs.cloud.google.com/vpc/docs/create-modify-vpc-networks#deleting_a_network)
*   [Delete a subnetwork](https://docs.cloud.google.com/vpc/docs/create-modify-vpc-networks#deleting_subnets)
*   [Delete GCS buckets](https://docs.cloud.google.com/storage/docs/deleting-buckets)
or
[delete objects in buckets](https://docs.cloud.google.com/storage/docs/deleting-objects)
*   [Manage access to projects, folders, and organizations](https://docs.cloud.google.com/iam/docs/granting-changing-revoking-access)
*   [Enable, disable, or change billing for a project](https://docs.cloud.google.com/billing/docs/how-to/modify-project)

# 6. Limitations and known issues

* All known
[limitations on Confidential VMs](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations#limitations)
apply to this offering.
* All known
[C3 machine limitations](https://docs.cloud.google.com/compute/docs/general-purpose-machines#c3_series)
apply to these Confidential VM instances.
* These instances don't support thecreation of clusters for multi-node workloads.
* Other [known issues](https://docs.cloud.google.com/compute/docs/troubleshooting/known-issues)
for GCE might apply. *ConnectX-7 (CX7) NICs, which typically provide RDMA
capabilities, shouldn’t be used and are disabled.

# 7. Troubleshooting

This section compiles links to troubleshooting guides. The guides show you
common errors and potential fixes for components and processes.

### 7.1 Cloud Billing errors

Billing and cost issues can occur if your projects and resources are not
properly set up or maintained. To resolve these issues:

*   Be sure projects are
    [linked to an active billing account](https://docs.cloud.google.com/billing/docs/how-to/modify-project).
*   [Optimize cloud costs](https://cloud.google.com/blog/topics/cost-management/best-practices-for-optimizing-your-cloud-costs)
    by deleting or turning off unused resources, including idle or underutilized
    instance instances, unattached disks, and unused static IP address.
*   For questions or concerns related to billing, try the
    [Google Cloud Billing Troubleshooter](https://support.google.com/cloud/troubleshooter/7279311?hl=en).

### 7.2 Confidential VM errors

* Networking:
    [I/O operation timeouts](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/troubleshoot-io-operation-timeouts)
    [Disk performance](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/troubleshoot-disk-performance)

### 7.3 Compute Engine errors

  *  [General troubleshooting tips](https://docs.cloud.google.com/compute/docs/troubleshooting/general-tips)
  *  [Troubleshoot SSH](https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshooting-ssh-errors)
  *  [Troubleshoot instance creation](https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshooting-vm-creation)
  *  [Troubleshoot resource availability errors](https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshooting-resource-availability)
  *  [Troubleshoot instance reboots and shutdowns](https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshooting-reboots)
  *  [Viewing serial port output](https://docs.cloud.google.com/compute/docs/troubleshooting/viewing-serial-port-output)
  *  [Troubleshoot common networking issues](https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshooting-networking)
  *  [Networking performance](https://docs.cloud.google.com/compute/docs/troubleshooting/performance#network_performance)
  *  [Storage performance](https://docs.cloud.google.com/compute/docs/troubleshooting/performance#storage_performance)
  *  [Troubleshoot concurrent operation quota errors](https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshoot-operation-limits)
