import base64
import os
from flask import Flask, jsonify, request
from google.auth import identity_pool
from google.cloud import kms
from google.cloud import storage
import torch
from transformers import AutoModelForCausalLM, GemmaTokenizer
from cryptography.fernet import Fernet

# Bucket that holds Codegemma model
MODEL_BUCKET_NAME = "vertex-model-garden-public-us"
MODEL_GCS_FOLDER = "codegemma/codegemma-2b"
LOCAL_MODEL_DIR = "./codegemma-2b"
_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
]

os.environ["PRIMUS_PROJECT_ID"] = "PRIMUS_PROJECT_ID_VALUE"
os.environ["PRIMUS_PROJECT_NUMBER"] = "PRIMUS_PROJECT_NUMBER_VALUE"
os.environ["PRIMUS_PROJECT_LOCATION"] = "PRIMUS_PROJECT_LOCATION_VALUE"
os.environ["PRIMUS_MODEL_STORAGE_BUCKET"] = "PRIMUS_MODEL_STORAGE_BUCKET_VALUE"
os.environ["PRIMUS_KEY_ID"] = "PRIMUS_KEY_ID_VALUE"
os.environ["PRIMUS_KEYRING"] = "PRIMUS_KEYRING_VALUE"
os.environ["PRIMUS_WORKLOAD_IDENTITY_POOL"] = (
    "PRIMUS_WORKLOAD_IDENTITY_POOL_VALUE"
)
os.environ["PRIMUS_WIP_PROVIDER"] = "PRIMUS_WIP_PROVIDER_VALUE"
os.environ["PRIMUS_SERVICEACCOUNT"] = "PRIMUS_SERVICEACCOUNT_VALUE"

wip_provider_name = f"projects/{os.environ['PRIMUS_PROJECT_NUMBER']}/locations/global/workloadIdentityPools/{os.environ['PRIMUS_WORKLOAD_IDENTITY_POOL']}/providers/{os.environ['PRIMUS_WIP_PROVIDER']}"

credentials_config = {
    "type": "external_account",
    "audience": f"//iam.googleapis.com/{wip_provider_name}",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "token_url": "https://sts.googleapis.com/v1/token",
    "credential_source": {
        "file": "/run/container_launcher/attestation_verifier_claims_token"
    },
    "service_account_impersonation_url": f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{os.environ['PRIMUS_SERVICEACCOUNT']}@{os.environ['PRIMUS_PROJECT_ID']}.iam.gserviceaccount.com:generateAccessToken",
}

app = Flask(__name__)


# Function for downloading files from GCS bucket
def download_from_gcs(gcs_folder, local_dir):
  blobs = bucket.list_blobs(prefix=gcs_folder)
  for blob in blobs:
    file_name = os.path.basename(blob.name)
    local_path = os.path.join(local_dir, file_name)
    blob.download_to_filename(local_path)


# Credentials for authenticating via Workload Identity Pool.
credentials = identity_pool.Credentials.from_info(
    credentials_config
).with_scopes(_SCOPES)

# Initialising KMS Client.
kms_client = kms.KeyManagementServiceClient(credentials=credentials)
key_name = kms_client.crypto_key_path(
    os.environ["PRIMUS_PROJECT_ID"],
    os.environ["PRIMUS_PROJECT_LOCATION"],
    os.environ["PRIMUS_KEYRING"],
    os.environ["PRIMUS_KEY_ID"],
)

# Initialising Storage Client.
storage_client = storage.Client()
bucket = storage_client.bucket(MODEL_BUCKET_NAME)
os.makedirs(LOCAL_MODEL_DIR, exist_ok=True)
download_from_gcs(MODEL_GCS_FOLDER, LOCAL_MODEL_DIR)

# Loading Codegemma model from local directory.
model = AutoModelForCausalLM.from_pretrained(LOCAL_MODEL_DIR)
tokenizer = GemmaTokenizer.from_pretrained(LOCAL_MODEL_DIR)


# Handler for /generate API for genearting the code for given encrypted prompt.
@app.route("/generate", methods=["POST"])
def generate():
  try:
    data = request.get_json()
    ciphertext = base64.b64decode(data["ciphertext"])
    wrapped_dek = base64.b64decode(data["wrapped_dek"])
    unwrapped_dek_response = kms_client.decrypt(
        request={"name": key_name, "ciphertext": wrapped_dek}
    )
    unwrapped_dek = unwrapped_dek_response.plaintext
    f = Fernet(unwrapped_dek)
    plaintext = f.decrypt(ciphertext)
    prompt = plaintext.decode("utf-8")
    tokens = tokenizer(prompt, return_tensors="pt")
    outputs = model.generate(**tokens, max_new_tokens=128)
    generated_code = tokenizer.decode(outputs[0])
    generated_code_bytes = generated_code.encode("utf-8")

    response = f.encrypt(generated_code_bytes)
    ciphertext_base64 = base64.b64encode(response).decode("utf-8")
    response = {"generated_code_ciphertext": ciphertext_base64}
    return jsonify(response)

  except (ValueError, TypeError, KeyError) as e:
    return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
  app.run(debug=True, host="0.0.0.0", port=8080)
