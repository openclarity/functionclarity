// Copyright © 2022 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package test

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/openclarity/function-clarity/pkg/clients"
	i "github.com/openclarity/function-clarity/pkg/init"
	"github.com/openclarity/function-clarity/pkg/integrity"
	o "github.com/openclarity/function-clarity/pkg/options"
	"github.com/openclarity/function-clarity/pkg/sign"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	s "github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	zipName              = "test-function.zip"
	codeFuncName         = "e2eTestCode"
	imageFuncName        = "e2eTestImage"
	role                 = "arn:aws:iam::813189926740:role/e2eTest"
	imageUri             = "813189926740.dkr.ecr.us-east-2.amazonaws.com/securecn/serverless-scanner:busybox"
	publicKey            = "cosign.pub"
	privateKey           = "cosign.key"
	pass                 = "pass"
	verifierFunctionName = "FunctionClarityLambdaVerifier"
)

var awsClient *clients.AwsClient
var lambdaClient *lambda.Client
var formationClient *cloudformation.Client
var s3Client *s3.Client

var keyPass = []byte(pass)

var passFunc = func(_ bool) ([]byte, error) {
	return keyPass, nil
}

var accessKey, secretKey, bucket, region, lambdaRegion string

var ro = &options.RootOptions{Timeout: options.DefaultTimeout}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	//shutdown()
	os.Exit(code)
}

func setup() {
	accessKey = getEnvVar("ACCESS_KEY", "access key")
	secretKey = getEnvVar("SECRET_KEY", "secret key")
	bucket = getEnvVar("BUCKET", "bucket")
	region = getEnvVar("REGION", "region")
	lambdaRegion = getEnvVar("FUNCTION_REGION", "function region")

	awsClient = clients.NewAwsClient(accessKey, secretKey, bucket, region, lambdaRegion)

	cfg := createConfig(region)
	lambdaClient = lambda.NewFromConfig(*createConfig(lambdaRegion))
	formationClient = cloudformation.NewFromConfig(*cfg)
	s3Client = s3.NewFromConfig(*cfg)

	if err := integrity.InitDocker(awsClient); err != nil {
		log.Fatal(err)
	}

	//var configForDeployment i.AWSInput
	//configForDeployment.Bucket = bucket
	//configForDeployment.Action = "detect"
	//configForDeployment.Region = region
	//configForDeployment.IsKeyless = false
	//configForDeployment.SnsTopicArn = ""
	//configForDeployment.IncludedFuncRegions = []string{"us-east-2"}
	//if err := awsClient.DeployFunctionClarity("", publicKey, configForDeployment); err != nil {
	//	log.Fatal(err)
	//}
	//time.Sleep(2 * time.Minute)
}

func shutdown() {
	deleteS3TrailBucketContent()
	deleteStack()
	deleteS3Bucket(bucket)
}

func TestCodeImageAndVerifyKeyless(t *testing.T) {
	viper.Set("privatekey", "")
	//os.Setenv(integrity.ExperimentalEnv, "1")
	log.Printf("privateKey: %v\n", privateKey)
	log.Printf("publicKey: %v\n", viper.GetString("publickey"))
	log.Printf("IsExperimentalEnv: %v\n", integrity.IsExperimentalEnv())

	switchConfiguration(true, "")

	jwt := getEnvVar("jwt_token", "token ID")

	ko := options.KeyOpts{
		SkipConfirmation: true,
		FulcioURL:        options.DefaultFulcioURL,
		IDToken:          jwt,
		RekorURL:         options.DefaultRekorURL,
	}
	err := s.SignCmd(ro, ko, options.RegistryOptions{}, nil, []string{imageUri}, "", "", true, "", "", "", false, false, "", false)
	if err != nil {
		t.Fatal(err)
	}

	functionArn, err := createImageLambda(t)
	if err != nil {
		t.Fatal(err)
	}

	successTagValue := "Function signed and verified"
	success, timeout := findTag(t, functionArn, lambdaClient, "Function clarity result", successTagValue)
	if timeout {
		t.Fatal("test failed on timout, the required tag not added in the time period")
	}
	if !success {
		t.Fatal("test failure: no " + successTagValue + " tag in the signed function")
	}
	fmt.Println(successTagValue + " tag found in the signed function")
	deleteLambda(imageFuncName)
}

func TestCodeSignAndVerifyKeyless(t *testing.T) {
	os.Setenv(integrity.ExperimentalEnv, "1")
	switchConfiguration(true, "")
	time.Sleep(2 * time.Minute)

	jwt := getEnvVar("jwt_token", "token ID")
	sbo := o.SignBlobOptions{
		SignBlobOptions: options.SignBlobOptions{
			Base64Output:     true,
			Registry:         options.RegistryOptions{},
			SkipConfirmation: true,
			Fulcio:           options.FulcioOptions{URL: options.DefaultFulcioURL, IdentityToken: jwt},
			Rekor:            options.RekorOptions{URL: options.DefaultRekorURL},
		},
	}

	err := sign.SignAndUploadCode(awsClient, "utils/testing_lambda", &sbo, ro)
	if err != nil {
		t.Fatal(err)
	}

	functionArn := initCodeLambda(t)

	successTagValue := "Function signed and verified"
	success, timeout := findTag(t, functionArn, lambdaClient, "Function clarity result", successTagValue)
	if timeout {
		t.Fatal("test failed on timout, the required tag not added in the time period")
	}
	if !success {
		t.Fatal("test failure: no " + successTagValue + " tag in the signed function")
	}
	fmt.Println(successTagValue + " tag found in the signed function")
	deleteLambda(codeFuncName)
	deleteS3BucketContent(&bucket, []string{"function-clarity.zip"})
}

func TestCodeSignAndVerify(t *testing.T) {
	os.Setenv(integrity.ExperimentalEnv, "0")
	viper.Set("privatekey", privateKey)
	switchConfiguration(false, publicKey)

	funcDefer, err := mockStdin(t, pass)
	if err != nil {
		t.Fatal(err)
	}
	defer funcDefer()

	sbo := o.SignBlobOptions{
		SignBlobOptions: options.SignBlobOptions{
			Base64Output: true,
			Registry:     options.RegistryOptions{},
		},
	}
	err = sign.SignAndUploadCode(awsClient, "utils/testing_lambda", &sbo, ro)
	if err != nil {
		t.Fatal(err)
	}

	functionArn := initCodeLambda(t)

	successTagValue := "Function signed and verified"
	success, timeout := findTag(t, functionArn, lambdaClient, "Function clarity result", successTagValue)
	if timeout {
		t.Fatal("test failed on timout, the required tag not added in the time period")
	}
	if !success {
		t.Fatal("test failure: no " + successTagValue + " tag in the signed function")
	}
	fmt.Println(successTagValue + " tag found in the signed function")
	deleteLambda(codeFuncName)
	deleteS3BucketContent(&bucket, []string{"function-clarity.zip"})
}

func TestImageSignAndVerify(t *testing.T) {
	os.Setenv(integrity.ExperimentalEnv, "0")
	switchConfiguration(false, publicKey)

	funcDefer, err := mockStdin(t, pass)
	if err != nil {
		t.Fatal(err)
	}
	defer funcDefer()

	ko := options.KeyOpts{KeyRef: privateKey, PassFunc: passFunc}
	err = s.SignCmd(ro, ko, options.RegistryOptions{}, nil, []string{imageUri}, "", "", true, "", "", "", false, false, "", false)
	if err != nil {
		t.Fatal(err)
	}

	functionArn, err := createImageLambda(t)
	if err != nil {
		t.Fatal(err)
	}

	successTagValue := "Function signed and verified"
	success, timeout := findTag(t, functionArn, lambdaClient, "Function clarity result", successTagValue)
	if timeout {
		t.Fatal("test failed on timout, the required tag not added in the time period")
	}
	if !success {
		t.Fatal("test failure: no " + successTagValue + " tag in the signed function")
	}
	fmt.Println(successTagValue + " tag found in the signed function")
	deleteLambda(imageFuncName)
}

func findTag(t *testing.T, functionArn string, lambdaClient *lambda.Client, successTagKey string, successTagValue string) (bool, bool) {
	t.Helper()
	var timeout bool
	timer := time.NewTimer(10 * time.Minute)
	go func() {
		<-timer.C
		timeout = true
	}()
	defer func() {
		timer.Stop()
	}()

	var result *lambda.ListTagsOutput
	var err error
	for {
		result, err = lambdaClient.ListTags(context.TODO(), &lambda.ListTagsInput{Resource: &functionArn})
		if err != nil {
			t.Fatal("failed to get functions tags")
		}
		if len(result.Tags) == 0 {
			time.Sleep(10 * time.Second)
			continue
		}
		if timeout {
			return false, true
		}
		break
	}
	var success bool
	for key, value := range result.Tags {
		if key == successTagKey && value == successTagValue {
			success = true
		}
	}
	return success, false
}

func switchConfiguration(isKeyless bool, publicKey string) {
	funcCfg, err := lambdaClient.GetFunctionConfiguration(context.TODO(), &lambda.GetFunctionConfigurationInput{FunctionName: aws.String(verifierFunctionName)})
	if err != nil {
		log.Fatal("failed to get function configuration")
	}
	cfg := funcCfg.Environment.Variables["CONFIGURATION"]
	decodedConfig, err := base64.StdEncoding.DecodeString(cfg)
	if err != nil {
		log.Fatal("failed to decode config from base64")
	}
	var config *i.AWSInput = nil
	err = yaml.Unmarshal(decodedConfig, &config)
	if err != nil {
		log.Fatal("failed to unmarshal config from yaml")
	}
	config.IsKeyless = isKeyless
	config.PublicKey = publicKey

	cfgYaml, err := yaml.Marshal(&config)
	if err != nil {
		log.Fatal("failed to marshal config to yaml")
	}
	encodedConfig := base64.StdEncoding.EncodeToString(cfgYaml)
	funcCfg.Environment.Variables["CONFIGURATION"] = encodedConfig
	params := &lambda.UpdateFunctionConfigurationInput{
		FunctionName: funcCfg.FunctionName,
		Environment:  &types.Environment{Variables: funcCfg.Environment.Variables},
	}
	_, err = lambdaClient.UpdateFunctionConfiguration(context.TODO(), params)
	if err != nil {
		log.Fatalf("failed to update function configuration: %v", err)
	}
	time.Sleep(30 * time.Second)
}

func createConfig(region string) *aws.Config {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")))
	if err != nil {
		panic(fmt.Sprintf("failed loading config: %v", err))
	}
	return &cfg
}

func getEnvVar(key string, name string) string {
	v, b := os.LookupEnv(key)
	if !b {
		log.Fatal(name + " not found in the environment")
	}
	return v
}

func deleteS3TrailBucketContent() {
	result, err := s3Client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err != nil {
		fmt.Println("Got an error retrieving buckets:")
		fmt.Println(err)
		return
	}
	for _, bucket := range result.Buckets {
		if strings.HasPrefix(*bucket.Name, "function-clarity-stack-functionclaritytrailbucket") {
			bl, err := s3Client.GetBucketLocation(context.TODO(), &s3.GetBucketLocationInput{Bucket: bucket.Name})
			if err != nil {
				continue
			}
			if string(bl.LocationConstraint) == region {
				deleteS3BucketContent(bucket.Name, []string{})
			}
		}
	}
}

func deleteS3BucketContent(name *string, except []string) {
	listObjectsV2Response, err := s3Client.ListObjectsV2(context.TODO(),
		&s3.ListObjectsV2Input{
			Bucket: name,
		})

	for {

		if err != nil {
			log.Fatalf("Couldn't list objects... delete all objects in bucket: %s failed", *name)
		}
		for _, item := range listObjectsV2Response.Contents {
			if !contains(except, *item.Key) {
				_, err = s3Client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
					Bucket: name,
					Key:    item.Key,
				})

				if err != nil {
					log.Fatalf("delete all objects in bucket: %s failed", *name)
				}
			}
		}

		if listObjectsV2Response.IsTruncated {
			listObjectsV2Response, err = s3Client.ListObjectsV2(context.TODO(),
				&s3.ListObjectsV2Input{
					Bucket:            name,
					ContinuationToken: listObjectsV2Response.ContinuationToken,
				})
		} else {
			break
		}
	}
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func deleteS3Bucket(name string) {
	if _, err := s3Client.HeadBucket(context.TODO(), &s3.HeadBucketInput{Bucket: aws.String(name)}); err != nil {
		return
	}
	deleteS3BucketContent(&name, []string{})
	if _, err := s3Client.DeleteBucket(context.TODO(), &s3.DeleteBucketInput{Bucket: aws.String(name)}); err != nil {
		log.Fatalf("delete bucket: %s failed", name)
	}
}

func deleteStack() {
	stackName := "function-clarity-stack"
	_, err := formationClient.DeleteStack(context.TODO(), &cloudformation.DeleteStackInput{
		StackName: &stackName,
	})
	if err != nil {
		fmt.Println("Got an error deleting stack " + stackName)
		return
	}

	var timeout bool
	timer := time.NewTimer(5 * time.Minute)
	go func() {
		<-timer.C
		timeout = true
	}()
	defer func() {
		timer.Stop()
	}()

	for {
		var gae *smithy.GenericAPIError
		if _, err := formationClient.DescribeStacks(context.TODO(), &cloudformation.DescribeStacksInput{StackName: aws.String(stackName)}); err != nil {
			if errors.As(err, &gae) && gae.ErrorMessage() == "Stack with id function-clarity-stack does not exist" {
				log.Println("Deleted stack " + stackName)
				return
			}
			log.Println("Got an error waiting for stack to be deleted")
			return
		}
		if timeout {
			log.Fatal("timout on waiting for stack to delete")
		}
		time.Sleep(15 * time.Second)
	}
}

func deleteLambda(name string) {
	deleteArgs := &lambda.DeleteFunctionInput{
		FunctionName: &name,
	}
	_, err := lambdaClient.DeleteFunction(context.TODO(), deleteArgs)
	if err != nil {
		log.Fatal("failed to delete function")
	}
}

func initCodeLambda(t *testing.T) string {
	t.Helper()

	if err := createCodeZip(t); err != nil {
		t.Fatal(err)
	}
	functionArn, err := createCodeLambda(t)
	if err != nil {
		t.Fatal(err)
	}
	return functionArn
}

func createCodeLambda(t *testing.T) (string, error) {
	t.Helper()

	contents, err := os.ReadFile(zipName)
	if err != nil {
		fmt.Println("Got error trying to read " + zipName)
		return "", err
	}

	handler := "testing_lambda"
	createArgs := &lambda.CreateFunctionInput{
		Code:         &types.FunctionCode{ZipFile: contents},
		FunctionName: aws.String(codeFuncName),
		Handler:      aws.String(handler),
		Role:         aws.String(role),
		Runtime:      types.RuntimeGo1x,
	}
	result, err := lambdaClient.CreateFunction(context.TODO(), createArgs)
	if err != nil {
		fmt.Println("Cannot create function")
		return "", err
	}
	return *result.FunctionArn, nil
}

func createImageLambda(t *testing.T) (string, error) {
	t.Helper()

	createArgs := &lambda.CreateFunctionInput{
		Code:         &types.FunctionCode{ImageUri: aws.String(imageUri)},
		FunctionName: aws.String(imageFuncName),
		Role:         aws.String(role),
		PackageType:  types.PackageTypeImage,
	}
	result, err := lambdaClient.CreateFunction(context.TODO(), createArgs)
	if err != nil {
		fmt.Println("Cannot create function")
		return "", err
	}
	return *result.FunctionArn, nil
}

func createCodeZip(t *testing.T) error {
	t.Helper()

	archive, err := os.Create(zipName)
	if err != nil {
		return err
	}
	defer archive.Close()
	zipWriter := zip.NewWriter(archive)
	binaryFile, err := os.Open("utils/testing_lambda")
	if err != nil {
		return err
	}
	defer binaryFile.Close()

	w1, err := zipWriter.Create("testing_lambda")
	if err != nil {
		return err
	}
	if _, err := io.Copy(w1, binaryFile); err != nil {
		return err
	}
	zipWriter.Close()
	return nil
}

func mockStdin(t *testing.T, dummyInput string) (funcDefer func(), err error) {
	t.Helper()

	tmpfile, err := os.CreateTemp(t.TempDir(), t.Name())

	if err != nil {
		return nil, err
	}

	content := []byte(dummyInput)

	if _, err := tmpfile.Write(content); err != nil {
		return nil, err
	}

	if _, err := tmpfile.Seek(0, 0); err != nil {
		return nil, err
	}

	oldOsStdin := os.Stdin
	os.Stdin = tmpfile

	return func() {
		os.Stdin = oldOsStdin
		os.Remove(tmpfile.Name())
	}, nil
}
