import base64
import os
import sys
from google.cloud import kms
import requests
from cryptography.fernet import Fernet

os.environ["PRIMUS_PROJECT_ID"] = "PRIMUS_PROJECT_ID_VALUE"
os.environ["PRIMUS_PROJECT_LOCATION"] = "PRIMUS_PROJECT_LOCATION_VALUE"
os.environ["PRIMUS_KEY_ID"] = "PRIMUS_KEY_ID_VALUE"
os.environ["PRIMUS_KEYRING"] = "PRIMUS_KEYRING_VALUE"
os.environ["INFERENCE_SERVER_URL"] = "http://INFERENCE_SERVER_IP_VALUE:8080/generate"

# Initialising KMS Client.
kms_client = kms.KeyManagementServiceClient()
key_name = kms_client.crypto_key_path(
    os.environ["PRIMUS_PROJECT_ID"],
    os.environ["PRIMUS_PROJECT_LOCATION"],
    os.environ["PRIMUS_KEYRING"],
    os.environ["PRIMUS_KEY_ID"],
)


def data_exchange():
  text = input("Enter your prompt: ")
  data_key = Fernet.generate_key()
  f = Fernet(data_key)
  encrypted_message = f.encrypt(bytes(text, "utf-8"))
  wrapped_dek_response = kms_client.encrypt(request={"name": key_name, "plaintext": data_key})
  wrapped_dek = base64.b64encode(wrapped_dek_response.ciphertext).decode("utf-8")
  ciphertext = base64.b64encode(encrypted_message).decode("utf-8")
  payload = {
      "ciphertext": ciphertext,
      "wrapped_dek": wrapped_dek,
  }
  print("sending encrypted payload: ", payload)
  response = requests.post(os.environ["INFERENCE_SERVER_URL"], json=payload)
  data = response.json()
  print("received encrypted response", data)
  ciphertext = base64.b64decode(data["generated_code_ciphertext"])
  decrypted_message = f.decrypt(ciphertext)
  print("decrypted response: ", decrypted_message)


def main():
  data_exchange()


if __name__ == "__main__":
  main()
