"""Sample workload for Attesting Confidential Space Workloads with ITA."""

import json
import os
import socket
from google.auth import identity_pool
from google.cloud import storage

os.environ["PRIMUS_PROJECT_ID"] = "PRIMUS_PROJECT_ID_VALUE"
os.environ["PRIMUS_PROJECT_NUMBER"] = "PRIMUS_PROJECT_NUMBER_VALUE"
os.environ["PRIMUS_WORKLOAD_IDENTITY_POOL"] = (
    "PRIMUS_WORKLOAD_IDENTITY_POOL_VALUE"
)
os.environ["PRIMUS_WIP_PROVIDER"] = "PRIMUS_WIP_PROVIDER_VALUE"
os.environ["PRIMUS_INPUT_STORAGE_BUCKET"] = "PRIMUS_INPUT_STORAGE_BUCKET_VALUE"
os.environ["SECUNDUS_PROJECT_ID"] = "SECUNDUS_PROJECT_ID_VALUE"
os.environ["SECUNDUS_PROJECT_NUMBER"] = "SECUNDUS_PROJECT_NUMBER_VALUE"
os.environ["SECUNDUS_RESULT_STORAGE_BUCKET"] = (
    "SECUNDUS_RESULT_STORAGE_BUCKET_VALUE"
)

# Scope helps to control which GCP services and APIs
# workload VM instance can access. Here we allow access to Cloud Platform APIs.
_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def get_ita_token(audience: str) -> str:
  """Fetches the ITA token from the local teeserver Unix socket."""
  s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  s.connect("/run/container_launcher/teeserver.sock")

  body = json.dumps({"audience": audience, "token_type": "OIDC"})

  request = (
      "POST /v1/intel/token HTTP/1.1\r\n"
      "Host: localhost\r\n"
      "Content-Type: application/json\r\n"
      f"Content-Length: {len(body)}\r\n"
      "Connection: close\r\n\r\n"
      f"{body}"
  )
  s.sendall(request.encode("utf-8"))

  response = b""
  while True:
    chunk = s.recv(4096)
    if not chunk:
      break
    response += chunk
  s.close()

  parts = response.split(b"\r\n\r\n", 1)
  if len(parts) < 2:
    raise RuntimeError("Invalid HTTP response from teeserver")

  header, body_bytes = parts
  status_line = header.split(b"\r\n")[0].decode("utf-8")
  if "200 OK" not in status_line:
    raise RuntimeError(
        f"Failed to get token: {status_line}\n{body_bytes.decode('utf-8')}"
    )

  return body_bytes.decode("utf-8")


def main():
  result_storage_client = storage.Client()
  result_storage_bucket = os.environ["SECUNDUS_RESULT_STORAGE_BUCKET"]
  result_bucket = result_storage_client.bucket(result_storage_bucket)
  result_blob = result_bucket.blob("result")

  try:
    # 1. Fetch the Intel Trust Authority token from the local teeserver socket.
    # The audience is the Google STS audience for Workload Identity Federation.
    wip_provider_name = (
        f"projects/{os.environ['PRIMUS_PROJECT_NUMBER']}/locations/global/"
        f"workloadIdentityPools/{os.environ['PRIMUS_WORKLOAD_IDENTITY_POOL']}/"
        f"providers/{os.environ['PRIMUS_WIP_PROVIDER']}"
    )
    audience = f"//iam.googleapis.com/{wip_provider_name}"
    ita_token = get_ita_token(audience)

    # Write the ITA token to a temporary file for google-auth library.
    token_file_path = "/tmp/ita_token"
    with open(token_file_path, "w") as f:
      f.write(ita_token)

    # 2. Configure credentials to exchange the ITA token and Google STS
    # using Direct Resource Access.
    credentials_config = {
        "type": "external_account",
        "audience": audience,
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": "https://sts.googleapis.com/v1/token",
        "credential_source": {"file": token_file_path},
    }

    credentials = identity_pool.Credentials.from_info(
        credentials_config
    ).with_scopes(_SCOPES)

    # 3. Access the protected GCS bucket owned by Primus using the federated
    # credentials.
    primus_storage_client = storage.Client(credentials=credentials)
    primus_bucket = primus_storage_client.bucket(
        os.environ["PRIMUS_INPUT_STORAGE_BUCKET"]
    )
    blobs = list(primus_bucket.list_blobs())
    file_names = [blob.name for blob in blobs]

    data_summary = []
    for blob in blobs:
      content = blob.download_as_text()
      data_summary.append(f"{blob.name}: {content.strip()}")

    # 4. Write the results to the Secundus result bucket.
    result_content = (
        f"Status: SUCCESS, GCP Bucket data: Files found {file_names}. "
        f"Contents: {', '.join(data_summary)}"
    )
    with result_blob.open("w") as f:
      f.write(result_content)

    print("Workload executed successfully!")

  except Exception as e:  # pylint: disable=broad-exception-caught
    error_msg = f"Status: FAILED, Error: {e}"
    print(error_msg)
    try:
      with result_blob.open("w") as f:
        f.write(error_msg)
    except Exception as inner_e:  # pylint: disable=broad-exception-caught
      print(f"Failed to write error to result bucket: {inner_e}")


if __name__ == "__main__":
  main()
