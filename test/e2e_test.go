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
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/openclarity/function-clarity/pkg/clients"
	i "github.com/openclarity/function-clarity/pkg/init"
	"github.com/openclarity/function-clarity/pkg/integrity"
	o "github.com/openclarity/function-clarity/pkg/options"
	"github.com/openclarity/function-clarity/pkg/sign"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	s "github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/spf13/viper"
	"io"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	zipName       = "test-function.zip"
	codeFuncName  = "e2eTestCode"
	imageFuncName = "e2eTestImage"
	role          = "arn:aws:iam::813189926740:role/e2eTest"
	imageUri      = "813189926740.dkr.ecr.us-east-2.amazonaws.com/securecn/serverless-scanner:busybox"
	publicKey     = "cosign.pub"
	privateKey    = "cosign.key"
	pass          = "pass"
)

var awsClient *clients.AwsClient
var lambdaSess *lambda.Lambda
var formationSess *cloudformation.CloudFormation
var s3Sess *s3.S3

var keyPass = []byte(pass)

var passFunc = func(_ bool) ([]byte, error) {
	return keyPass, nil
}

var accessKey, secretKey, bucket, region, lambdaRegion string

var ro = &options.RootOptions{Timeout: options.DefaultTimeout}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}

func setup() {
	accessKey = getEnvVar("ACCESS_KEY", "access key")
	secretKey = getEnvVar("SECRET_KEY", "secret key")
	bucket = getEnvVar("BUCKET", "bucket")
	region = getEnvVar("REGION", "region")
	lambdaRegion = getEnvVar("FUNCTION_REGION", "function region")

	awsClient = clients.NewAwsClient(accessKey, secretKey, bucket, region, lambdaRegion)

	sess := createSession(region)
	lambdaSess = lambda.New(createSession(lambdaRegion))
	formationSess = cloudformation.New(sess)
	s3Sess = s3.New(sess)

	if err := integrity.InitDocker(awsClient); err != nil {
		log.Fatal(err)
	}

	var configForDeployment i.AWSInput
	configForDeployment.Bucket = bucket
	configForDeployment.Action = "detect"
	configForDeployment.Region = region
	configForDeployment.IsKeyless = false
	configForDeployment.SnsTopicArn = ""
	if err := awsClient.DeployFunctionClarity("", publicKey, configForDeployment); err != nil {
		log.Fatal(err)
	}
	time.Sleep(2 * time.Minute)
}

func shutdown() {
	deleteS3()
	deleteStack()
}

func TestCodeSignAndVerify(t *testing.T) {
	viper.Set("privatekey", privateKey)
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
	success, timeout := findTag(t, functionArn, lambdaSess, "Function clarity result", successTagValue)
	if timeout {
		t.Fatal("test failed on timout, the required tag not added in the time period")
	}
	if !success {
		t.Fatal("test failure: no " + successTagValue + " tag in the signed function")
	}
	fmt.Println(successTagValue + " tag found in the signed function")
	deleteLambda(codeFuncName)
}

func TestImageSignAndVerify(t *testing.T) {
	viper.Set("privatekey", privateKey)
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
	success, timeout := findTag(t, functionArn, lambdaSess, "Function clarity result", successTagValue)
	if timeout {
		t.Fatal("test failed on timout, the required tag not added in the time period")
	}
	if !success {
		t.Fatal("test failure: no " + successTagValue + " tag in the signed function")
	}
	fmt.Println(successTagValue + " tag found in the signed function")
	deleteLambda(imageFuncName)
}

func findTag(t *testing.T, functionArn string, lambdaSess *lambda.Lambda, successTagKey string, successTagValue string) (bool, bool) {
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
		result, err = lambdaSess.ListTags(&lambda.ListTagsInput{
			Resource: &functionArn,
		})
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
		if key == successTagKey && *value == successTagValue {
			success = true
		}
	}
	return success, false
}

func createSession(region string) *session.Session {
	cfgs := &aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(accessKey, secretKey, ""),
	}
	return session.Must(session.NewSession(cfgs))
}

func getEnvVar(key string, name string) string {
	v, b := os.LookupEnv(key)
	if !b {
		log.Fatal(name + " not found in the environment")
	}
	return v
}

func deleteS3() {
	result, err := s3Sess.ListBuckets(&s3.ListBucketsInput{})
	if err != nil {
		fmt.Println("Got an error retrieving buckets:")
		fmt.Println(err)
		return
	}
	for _, bucket := range result.Buckets {
		if strings.HasPrefix(*bucket.Name, "function-clarity-stack-functionclaritytrailbucket") {
			bl, err := s3Sess.GetBucketLocation(&s3.GetBucketLocationInput{Bucket: bucket.Name})
			if err != nil {
				continue
			}
			if bl.LocationConstraint != nil && *bl.LocationConstraint == region {
				iter := s3manager.NewDeleteListIterator(s3Sess, &s3.ListObjectsInput{
					Bucket: bucket.Name,
				})

				err := s3manager.NewBatchDeleteWithClient(s3Sess).Delete(aws.BackgroundContext(), iter)
				if err != nil {
					log.Fatal("delete all objects in bucket failed")
				}
			}
		}
	}
}

func deleteStack() {
	stackName := "function-clarity-stack"
	_, err := formationSess.DeleteStack(&cloudformation.DeleteStackInput{
		StackName: &stackName,
	})
	if err != nil {
		fmt.Println("Got an error deleting stack " + stackName)
		return
	}

	err = formationSess.WaitUntilStackDeleteComplete(&cloudformation.DescribeStacksInput{
		StackName: &stackName,
	})
	if err != nil {
		fmt.Println("Got an error waiting for stack to be deleted")
		return
	}
	fmt.Println("Deleted stack " + stackName)
}

func deleteLambda(name string) {
	deleteArgs := &lambda.DeleteFunctionInput{
		FunctionName: &name,
	}
	_, err := lambdaSess.DeleteFunction(deleteArgs)
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
	createCode := &lambda.FunctionCode{
		ZipFile: contents,
	}
	handler := "testing_lambda"
	runtime := "go1.x"
	createArgs := &lambda.CreateFunctionInput{
		Code:         createCode,
		FunctionName: aws.String(codeFuncName),
		Handler:      aws.String(handler),
		Role:         aws.String(role),
		Runtime:      aws.String(runtime),
	}
	result, err := lambdaSess.CreateFunction(createArgs)
	if err != nil {
		fmt.Println("Cannot create function")
		return "", err
	}
	return *result.FunctionArn, nil
}

func createImageLambda(t *testing.T) (string, error) {
	t.Helper()

	createArgs := &lambda.CreateFunctionInput{
		Code:         &lambda.FunctionCode{ImageUri: aws.String(imageUri)},
		FunctionName: aws.String(imageFuncName),
		Role:         aws.String(role),
		PackageType:  aws.String("Image"),
	}
	result, err := lambdaSess.CreateFunction(createArgs)
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
