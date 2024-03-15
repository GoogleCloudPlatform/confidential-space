export const credentialConfig = {
  type: 'external_account',
  audience: `//iam.googleapis.com/projects/${process.env.PRIMUS_PROJECT_NUMBER}/locations/global/workloadIdentityPools/${process.env.PRIMUS_WORKLOAD_IDENTITY_POOL}/providers/${process.env.PRIMUS_WIP_PROVIDER}`,
  subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
  token_url: 'https://sts.googleapis.com/v1/token',
  credential_source: {
    file: '/run/container_launcher/attestation_verifier_claims_token',
  },
  service_account_impersonation_url:
      `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${process.env.PRIMUS_SERVICEACCOUNT}@${process.env.PRIMUS_PROJECT_ID}.iam.gserviceaccount.com:generateAccessToken`,
};