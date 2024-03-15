import {KeyManagementServiceClient} from '@google-cloud/kms';
import crc32c from 'fast-crc32c';

import {credentialConfig} from './credential-config.js';

const projectId = process.env.PRIMUS_PROJECT_ID;
const locationId = process.env.PRIMUS_PROJECT_LOCATION;
const keyRingId = process.env.PRIMUS_KEYRING;
const keyId = process.env.PRIMUS_KEY;

// Instantiates a client
const client = new KeyManagementServiceClient({
  credentials: credentialConfig,
});

// Build the key name
const keyName = client.cryptoKeyPath(projectId, locationId, keyRingId, keyId);

export const decryptSymmetric = async (ciphertext) => {
  const ciphertextCrc32c = crc32c.calculate(ciphertext);
  const [decryptResponse] = await client.decrypt({
    name: keyName,
    ciphertext,
    ciphertextCrc32c: {
      value: ciphertextCrc32c,
    },
  });

  // Optional, but recommended: perform integrity verification on
  // decryptResponse. For more details on ensuring E2E in-transit integrity to
  // and from Cloud KMS visit:
  // https://cloud.google.com/kms/docs/data-integrity-guidelines
  if (crc32c.calculate(decryptResponse.plaintext) !==
      Number(decryptResponse.plaintextCrc32c.value)) {
    throw new Error('Decrypt: response corrupted in-transit');
  }

  const plaintext = decryptResponse.plaintext.toString();

  return plaintext;
};