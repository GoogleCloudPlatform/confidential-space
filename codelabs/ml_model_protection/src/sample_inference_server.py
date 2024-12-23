import os
from google.auth import identity_pool
from google.cloud import kms_v1
from google.cloud import storage
import numpy as np
import tensorflow as tf
import tensorflow_hub as hub
import tarfile


os.environ["PRIMUS_PROJECT_ID"] = "PRIMUS_PROJECT_ID_VALUE"
os.environ["PRIMUS_PROJECT_NUMBER"] = "PRIMUS_PROJECT_NUMBER_VALUE"
os.environ["PRIMUS_WORKLOAD_IDENTITY_POOL"] = "PRIMUS_WORKLOAD_IDENTITY_POOL_VALUE"
os.environ["PRIMUS_WIP_PROVIDER"] = "PRIMUS_WIP_PROVIDER_VALUE"
os.environ["PRIMUS_SERVICEACCOUNT"] = "PRIMUS_SERVICEACCOUNT_VALUE"
os.environ["SECUNDUS_PROJECT_ID"] = "SECUNDUS_PROJECT_ID_VALUE"
os.environ["SECUNDUS_PROJECT_NUMBER"] = "SECUNDUS_PROJECT_NUMBER_VALUE"
os.environ["SECUNDUS_INPUT_STORAGE_BUCKET"] = "SECUNDUS_INPUT_STORAGE_BUCKET_VALUE"
os.environ["SECUNDUS_RESULT_STORAGE_BUCKET"] = "SECUNDUS_RESULT_STORAGE_BUCKET_VALUE"
os.environ["PRIMUS_INPUT_STORAGE_BUCKET"] = "PRIMUS_INPUT_STORAGE_BUCKET_VALUE"

wip_provider_name = (
    f"projects/{os.environ['PRIMUS_PROJECT_NUMBER']}/locations/global/workloadIdentityPools/{os.environ['PRIMUS_WORKLOAD_IDENTITY_POOL']}/providers/{os.environ['PRIMUS_WIP_PROVIDER']}"
)
credentials_config = {
    "type": "external_account",
    "audience": f"//iam.googleapis.com/{wip_provider_name}",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "token_url": "https://sts.googleapis.com/v1/token",
    "credential_source": {
        "file": "/run/container_launcher/attestation_verifier_claims_token"
    },
    "service_account_impersonation_url": (
        f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{os.environ['PRIMUS_SERVICEACCOUNT']}@{os.environ['PRIMUS_PROJECT_ID']}.iam.gserviceaccount.com:generateAccessToken"
    ),
}

# Scope helps to control which GCP services and APIs
# workload VM instance can access. here we are allowing
# an access to all GCP APIs.
_SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
]


def run_inference(image_path, model):
  try:
    # Read and preprocess the image
    image = tf.image.decode_image(tf.io.read_file(image_path), channels=3)
    image = tf.image.resize(image, (128, 128))
    image = tf.image.convert_image_dtype(image, tf.float32)
    image = tf.expand_dims(image, axis=0)

    # Get predictions from the model
    predictions = model(image)
    predicted_class = np.argmax(predictions)

    top_k = 5
    top_indices = np.argsort(predictions[0])[-top_k:][::-1]

    # Convert top_indices to a TensorFlow tensor
    top_indices_tensor = tf.convert_to_tensor(top_indices, dtype=tf.int32)

    # Use TensorFlow tensor for indexing
    top_scores = tf.gather(predictions[0], top_indices_tensor)

    return {
        "predicted_class": int(predicted_class),
        "top_k_predictions": [
            {"class_index": int(idx), "score": float(score)}
            for idx, score in zip(top_indices, top_scores)
        ],
    }
  except Exception as e:
    return {"error": str(e)}


# This workload inpersonates the service-account of Primus via
# workload identity pool. It pulls the ML model from the cloud
# storage bucket of the Primus and also downloads the sample images
# from the cloud storage bucket of Secundus. ML model used as part
# as part of the workload is image classification model trained on
# ILSVRC-2012-CLS dataset. Workload runs an inference on sample
# images using this model and it provides top 5 predictions with
# prediction classes and score. Result of the workload will be
# uploaded to result storage bucket of Secundus.
def main():

  credentials = identity_pool.Credentials.from_info(credentials_config).with_scopes(_SCOPES)
  storage_client = storage.Client(credentials=credentials)
  bucket = storage_client.bucket(os.environ["PRIMUS_INPUT_STORAGE_BUCKET"])

  result_storage_client = storage.Client()
  result_storage_bucket = os.environ["SECUNDUS_RESULT_STORAGE_BUCKET"]
  result_bucket = result_storage_client.bucket(result_storage_bucket)
  images_storage_bucket = os.environ["SECUNDUS_INPUT_STORAGE_BUCKET"]
  images_bucket = result_storage_client.bucket(images_storage_bucket)
  result_blob = result_bucket.blob("result")

  blob = bucket.blob("model.tar.gz")
  current_directory = os.getcwd()
  local_tarfile = os.path.join(current_directory, "model.tar.gz")
  try:
    blob.download_to_filename(local_tarfile)
    with tarfile.open(local_tarfile, "r") as tar:
      tar.extractall(path=f"{current_directory}")
    model = hub.load(f"{current_directory}")
  except Exception as e:
    with result_blob.open("w") as f:
      f.write(f"Error: {e}")
    return

  results = []
  try:
    blobs = images_bucket.list_blobs()
  except Exception as e:
    with result_blob.open("w") as f:
      f.write(f"Error: {e}")
    return
  for blb in blobs:
    if blb.name.endswith((".jpg", ".jpeg", ".png", ".JPG", ".JPEG", ".PNG")):
      # Construct the full GCS path to the image file
      image_path = f"gs://{images_storage_bucket}/{blb.name}"
      # Run image classification on the current image
      response = run_inference(image_path, model)
      results.append(f"Image: {blb.name}, Response: {response}")
  with result_blob.open("w") as f:
    f.write("\n".join(results))


if __name__ == "__main__":
  main()
