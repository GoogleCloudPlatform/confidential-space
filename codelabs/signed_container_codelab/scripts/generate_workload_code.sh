#!/bin/bash

PARENT_DIR=$(dirname ${PWD})

cat << 'EOF' > ${PARENT_DIR}/src/workload.go
// second_workload performs queries on the (imaginary) Primus Bank dataset.
//
// This package expects all data to be passed in as part of the subcommand arguments.
// Supported subcommands are:
//
//	count-location
package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	storage "cloud.google.com/go/storage"
	"github.com/google/logger"
	"github.com/google/subcommands"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	primusBucketName          = "PRIMUS_INPUT_STORAGE_BUCKET"
	primusInputFile           = "primus_enc_customer_list.csv"
	primusKeyName             = "projects/PRIMUS_PROJECT_ID/locations/global/keyRings/PRIMUS_ENC_KEYRING/cryptoKeys/PRIMUS_ENC_KEY"
	primusWipProviderName     = "projects/PRIMUS_PROJECT_NUMBER/locations/global/workloadIdentityPools/PRIMUS_WORKLOAD_IDENTITY_POOL/providers/PRIMUS_WIP_PROVIDER"
	primusServiceaccountEmail = "PRIMUS_SERVICEACCOUNT@PRIMUS_PROJECT_ID.iam.gserviceaccount.com"
)

const credentialConfig = `{
	"type": "external_account",
	"audience": "//iam.googleapis.com/%s",
	"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
	"token_url": "https://sts.googleapis.com/v1/token",
	"credential_source": {
  	"file": "/run/container_launcher/attestation_verifier_claims_token"
	},
	"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
}`

func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

func decryptData(ctx context.Context, keyName, trustedServiceAccountEmail, wipProviderName string, encryptedData []byte) ([]byte, error) {
	cc := fmt.Sprintf(credentialConfig, wipProviderName, trustedServiceAccountEmail)
	kmsClient, err := kms.NewKeyManagementClient(ctx, option.WithCredentialsJSON([]byte(cc)))
	if err != nil {
		return nil, fmt.Errorf("creating a new KMS client with federated credentials: %w", err)
	}
	decryptRequest := &kmspb.DecryptRequest{
		Name:             keyName,
		Ciphertext:       encryptedData,
		CiphertextCrc32C: wrapperspb.Int64(int64(crc32c(encryptedData))),
	}
	decryptResponse, err := kmsClient.Decrypt(ctx, decryptRequest)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt ciphertext: %v", err)
	}
	if int64(crc32c(decryptResponse.Plaintext)) != decryptResponse.PlaintextCrc32C.Value {
		return nil, fmt.Errorf("decrypt response corrupted in-transit")
	}
	return decryptResponse.Plaintext, nil
}

func getEncryptedData(ctx context.Context, c *storage.Client, bucketName string, objPath string) ([]byte, error) {
	bucketHandle := c.Bucket(bucketName)
	objectHandle := bucketHandle.Object(objPath)

	objectReader, err := objectHandle.NewReader(ctx)
	if err != nil {
		return nil, err
	}
	defer objectReader.Close()

	s, err := ioutil.ReadAll(objectReader)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func getPrimusCustomerData(ctx context.Context) ([][]string, error) {
	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not create storage client: %w", err)
	}
	encryptedData, err := getEncryptedData(ctx, storageClient, primusBucketName, primusInputFile)
	if err != nil {
		return nil, fmt.Errorf("could not read in gs://%v/%v: %w", primusBucketName, primusInputFile, err)
	}
	decryptedData, err := decryptData(ctx, primusKeyName, primusServiceaccountEmail, primusWipProviderName, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt gs://%v/%v: %w", primusBucketName, primusInputFile, err)
	}
	csvReader := csv.NewReader(bytes.NewReader(decryptedData))
	customerData, err := csvReader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("could not read in gs://%v/%v: %w", primusBucketName, primusInputFile, err)
	}
	return customerData, nil
}

type countLocationCmd struct{}

func (*countLocationCmd) Name() string     { return "count-location" }
func (*countLocationCmd) Synopsis() string { return "counts the number of users at the given location" }
func (*countLocationCmd) Usage() string {
	return "Usage: second_workload count-location <location> <output_storage_bucket>"
}
func (*countLocationCmd) SetFlags(_ *flag.FlagSet) {}
func (*countLocationCmd) Execute(ctx context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if f.NArg() != 2 {
		logger.Errorf("Not enough arguments (expected location and output object URI)")
		return subcommands.ExitUsageError
	}
	outputURI := f.Arg(1)
	re := regexp.MustCompile("gs://([^/]*)/(.*)")
	matches := re.FindStringSubmatch(outputURI)
	if matches == nil || matches[0] != outputURI || len(matches) != 3 {
		logger.Errorf("Second argument should be in the format gs://bucket/object")
		return subcommands.ExitUsageError
	}
	outputBucket := matches[1]
	outputPath := matches[2]
	client, err := storage.NewClient(ctx)
	outputWriter := client.Bucket(outputBucket).Object(outputPath).NewWriter(ctx)
	if err != nil {
		logger.Errorf("Error creating storage client with application default credentials: %v", err)
		return subcommands.ExitFailure
	}

	customerData, err := getPrimusCustomerData(ctx)
	if err != nil {
		_, err = outputWriter.Write([]byte(fmt.Sprintf("Error reading in Primus Bank data: %v", err)))
		if err != nil {
			logger.Errorf("Could not write to %v: %v", outputURI, err)
		}
		if err = outputWriter.Close(); err != nil {
			logger.Errorf("Could not write to %v: %v", outputURI, err)
		}
		return subcommands.ExitFailure
	}

	location := strings.ToLower(f.Arg(0))
	var count int
	if location == "-" {
		count = len(customerData)
	} else {
		for _, line := range customerData {
			if strings.ToLower(line[2]) == location {
				count++
			}
		}
	}

	_, err = outputWriter.Write([]byte(fmt.Sprintf("%d", count)))
	if err != nil {
		logger.Errorf("Could not write to %v: %v", outputURI, err)
		return subcommands.ExitFailure
	}
	if err = outputWriter.Close(); err != nil {
		logger.Errorf("Could not write to %v: %v", outputURI, err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func main() {
	flag.Parse()
	ctx := context.Background()
	subcommands.Register(&countLocationCmd{}, "")
	os.Exit(int(subcommands.Execute(ctx)))
}
EOF