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

package clients

import (
	"archive/zip"
	"bytes"
	"context"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdaTypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/google/uuid"
	i "github.com/openclarity/function-clarity/pkg/init"
	"github.com/openclarity/function-clarity/pkg/utils"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"
)

const FunctionClarityBucketName = "functionclarity"
const FunctionClarityLambdaVerierName = "FunctionClarityLambdaVerifier"

type AwsClient struct {
	accessKey    string
	secretKey    string
	s3           string
	region       string
	lambdaRegion string
}

func NewAwsClient(accessKey string, secretKey string, s3 string, region string, lambdaRegion string) *AwsClient {
	p := new(AwsClient)
	p.accessKey = accessKey
	p.secretKey = secretKey
	p.s3 = s3
	p.region = region
	p.lambdaRegion = lambdaRegion
	return p
}

func NewAwsClientInit(accessKey string, secretKey string, region string) *AwsClient {
	p := new(AwsClient)
	p.accessKey = accessKey
	p.secretKey = secretKey
	p.region = region
	return p
}

func (o *AwsClient) ResolvePackageType(funcIdentifier string) (string, error) {
	cfg := o.getConfigForLambda()
	lambdaClient := lambda.NewFromConfig(*cfg)
	input := &lambda.GetFunctionInput{
		FunctionName: aws.String(funcIdentifier),
	}
	result, err := lambdaClient.GetFunction(context.TODO(), input)
	if err != nil {
		return "", err
	}
	return string(result.Configuration.PackageType), nil
}

func (o *AwsClient) Upload(signature string, identity string, isKeyless bool) error {
	cfg := o.getConfig()

	uploader := manager.NewUploader(s3.NewFromConfig(*cfg))
	// Upload the file to S3.
	_, err := uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(o.s3),
		Key:    aws.String(identity + ".sig"),
		Body:   strings.NewReader(signature),
	})
	if err != nil {
		return err
	}

	if isKeyless {
		certificatePath := "/tmp/" + identity + ".crt.base64"
		f, err := os.Open(certificatePath)
		if err != nil {
			return err
		}

		result, err := uploader.Upload(context.TODO(), &s3.PutObjectInput{
			Bucket: aws.String(o.s3),
			Key:    aws.String(identity + ".crt.base64"),
			Body:   f,
		})
		if err != nil {
			return err
		}
		fmt.Printf("\ncertificate file uploaded to, %s\n", aws.ToString(&result.Location))
	}
	return nil
}

func (o *AwsClient) Download(fileName string, outputType string) error {
	cfg := o.getConfig()
	downloader := manager.NewDownloader(s3.NewFromConfig(*cfg))

	outputFile := "/tmp/" + fileName + "." + outputType
	f, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = downloader.Download(context.TODO(), f, &s3.GetObjectInput{
		Bucket: aws.String(o.s3),
		Key:    aws.String(fileName + "." + outputType),
	})

	if err != nil {
		return err
	}
	return nil
}

func (o *AwsClient) GetFuncCode(funcIdentifier string) (string, error) {
	cfg := o.getConfigForLambda()
	lambdaClient := lambda.NewFromConfig(*cfg)
	input := &lambda.GetFunctionInput{
		FunctionName: aws.String(funcIdentifier),
	}
	result, err := lambdaClient.GetFunction(context.TODO(), input)
	if err != nil {
		return "", err
	}
	contentName := uuid.New().String()
	zipFileName := contentName + ".zip"
	if err := DownloadFile(contentName+".zip", result.Code.Location); err != nil {
		return "", err
	}
	if err := ExtractZip("/tmp/"+zipFileName, "/tmp/"+contentName); err != nil {
		return "", err
	}
	return "/tmp/" + contentName, nil
}

func (o *AwsClient) IsFuncInRegions(regions []string) bool {
	for _, value := range regions {
		if o.lambdaRegion == value {
			return true
		}
	}
	return false
}
func (o *AwsClient) FuncContainsTags(funcIdentifier string, tagKes []string) (bool, error) {
	cfg := o.getConfigForLambda()
	lambdaClient := lambda.NewFromConfig(*cfg)
	err := o.convertToArnIfNeeded(&funcIdentifier)
	if err != nil {
		return false, err
	}
	input := &lambda.ListTagsInput{
		Resource: aws.String(funcIdentifier),
	}
	resp, err := lambdaClient.ListTags(context.TODO(), input)
	if err != nil {
		return false, err
	}
	for _, tag := range tagKes {
		if _, exist := resp.Tags[tag]; exist {
			return true, nil
		}
	}
	return false, nil
}

func (o *AwsClient) Notify(msg string, topicARN string) error {
	cfg := o.getConfig()
	snsClient := sns.NewFromConfig(*cfg)
	result, err := snsClient.Publish(context.TODO(), &sns.PublishInput{
		Message:  &msg,
		TopicArn: &topicARN,
	})
	if err != nil {
		return fmt.Errorf("error publishing the message: %s to topic: %s", msg, topicARN)
	}

	fmt.Println("Message ID: " + *result.MessageId)
	return nil
}

func (o *AwsClient) GetFuncImageURI(funcIdentifier string) (string, error) {
	cfg := o.getConfigForLambda()
	lambdaClient := lambda.NewFromConfig(*cfg)
	input := &lambda.GetFunctionInput{
		FunctionName: aws.String(funcIdentifier),
	}
	result, err := lambdaClient.GetFunction(context.TODO(), input)
	if err != nil {
		return "", err
	}
	return *result.Code.ImageUri, nil
}

func (o *AwsClient) HandleDetect(funcIdentifier *string, failed bool) error {
	if err := o.convertToArnIfNeeded(funcIdentifier); err != nil {
		return err
	}
	var tagVerificationString string
	if failed {
		tagVerificationString = utils.FunctionNotSignedTagValue
	} else {
		tagVerificationString = utils.FunctionSignedTagValue
	}
	return o.tagFunction(*funcIdentifier, "Function clarity result", tagVerificationString)
}

func (o *AwsClient) tagFunction(funcIdentifier string, tag string, tagValue string) error {
	cfg := o.getConfigForLambda()
	lambdaClient := lambda.NewFromConfig(*cfg)
	input := &lambda.TagResourceInput{
		Resource: aws.String(funcIdentifier),
		Tags: map[string]string{
			tag: tagValue,
		},
	}
	_, err := lambdaClient.TagResource(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to tag function. %v", err)
	}
	return nil
}

func (o *AwsClient) HandleBlock(funcIdentifier *string, failed bool) error {
	if err := o.convertToArnIfNeeded(funcIdentifier); err != nil {
		return err
	}
	if failed {
		return o.BlockFunction(funcIdentifier)
	}
	return o.UnblockFunction(funcIdentifier)
}

func (o *AwsClient) BlockFunction(funcIdentifier *string) error {
	currentConcurrencyLevel, err := o.GetConcurrencyLevel(*funcIdentifier)
	if err != nil {
		return fmt.Errorf("failed to get current concurrency level of function. %v", err)
	}
	currentConcurrencyLevelString := ""
	if currentConcurrencyLevel == nil {
		currentConcurrencyLevelString = "nil"
	} else {
		currentConcurrencyLevelString = strconv.FormatInt(int64(*currentConcurrencyLevel), 10)
	}
	if err = o.tagFunction(*funcIdentifier, utils.FunctionClarityConcurrencyTagKey, currentConcurrencyLevelString); err != nil {
		return fmt.Errorf("failed to tag function with current concurrency level. %v", err)
	}
	var zeroConcurrencyLevel = int32(0)
	if err = o.updateConcurrencyLevel(*funcIdentifier, &zeroConcurrencyLevel); err != nil {
		return fmt.Errorf("failed to set concurrency level to 0. %v", err)
	}
	return nil
}

func (o *AwsClient) updateConcurrencyLevel(funcIdentifier string, concurrencyLevel *int32) error {
	cfg := o.getConfig()
	lambdaClient := lambda.NewFromConfig(*cfg)
	input := &lambda.PutFunctionConcurrencyInput{
		FunctionName:                 &funcIdentifier,
		ReservedConcurrentExecutions: concurrencyLevel,
	}
	result, err := lambdaClient.PutFunctionConcurrency(context.TODO(), input)
	if *result.ReservedConcurrentExecutions != *concurrencyLevel {
		return fmt.Errorf("failed to update function concurrency to %d. %v", *concurrencyLevel, err)
	}
	return nil
}

func (o *AwsClient) DeleteConcurrencyLevel(funcIdentifier string) error {
	cfg := o.getConfig()
	lambdaClient := lambda.NewFromConfig(*cfg)
	input := &lambda.DeleteFunctionConcurrencyInput{
		FunctionName: &funcIdentifier,
	}
	_, err := lambdaClient.DeleteFunctionConcurrency(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to update function concurrency to 0. %v", err)
	}
	return nil
}

func (o *AwsClient) GetConcurrencyLevel(funcIdentifier string) (*int32, error) {
	cfg := o.getConfigForLambda()
	lambdaClient := lambda.NewFromConfig(*cfg)
	input := &lambda.GetFunctionConcurrencyInput{
		FunctionName: &funcIdentifier,
	}
	result, err := lambdaClient.GetFunctionConcurrency(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch func concurrencly level. %v", err)
	}
	return result.ReservedConcurrentExecutions, nil
}

func (o *AwsClient) UnblockFunction(funcIdentifier *string) error {
	if err := o.tagFunction(*funcIdentifier, utils.FunctionVerifyResultTagKey, utils.FunctionSignedTagValue); err != nil {
		return fmt.Errorf("failed to tag function with success result: %s. %v", *funcIdentifier, err)
	}
	err, concurrencyLevel := o.GetConcurrencyLevelTag(*funcIdentifier, utils.FunctionClarityConcurrencyTagKey)
	if err != nil {
		return fmt.Errorf("failed to get function tag with prev concurrency level for func: %s. %v", *funcIdentifier, err)
	}
	if concurrencyLevel == nil {
		if err = o.DeleteConcurrencyLevel(*funcIdentifier); err != nil {
			return fmt.Errorf("failed to unblock function (set concurrency level to prev value): %s. %v", *funcIdentifier, err)
		}
	} else if *concurrencyLevel != -1 {
		if err = o.updateConcurrencyLevel(*funcIdentifier, concurrencyLevel); err != nil {
			return fmt.Errorf("failed to unblock function (set concurrency level to prev value): %s. %v", *funcIdentifier, err)
		}
	} else {
		log.Printf("function not blocked by func clarity, not changing concurrency level")
		return nil
	}
	concurrencyLevelTagName := utils.FunctionClarityConcurrencyTagKey
	untagKeyArray := []string{concurrencyLevelTagName}
	cfg := o.getConfig()
	lambdaClient := lambda.NewFromConfig(*cfg)
	untagFunctionInput := &lambda.UntagResourceInput{
		Resource: funcIdentifier,
		TagKeys:  untagKeyArray}
	_, err = lambdaClient.UntagResource(context.TODO(), untagFunctionInput)
	if err != nil {
		return fmt.Errorf("failed to untag func clarity concurrency level tag for func: %s. %v", *funcIdentifier, err)
	}
	return nil
}

func (o *AwsClient) convertToArnIfNeeded(funcIdentifier *string) error {
	if !arn.IsARN(*funcIdentifier) {
		cfg := o.getConfigForLambda()
		lambdaClient := lambda.NewFromConfig(*cfg)
		input := &lambda.GetFunctionInput{
			FunctionName: aws.String(*funcIdentifier),
		}
		result, err := lambdaClient.GetFunction(context.TODO(), input)
		if err != nil {
			return fmt.Errorf("failed to get function by name: %s", *funcIdentifier)
		}
		*funcIdentifier = *result.Configuration.FunctionArn
	}
	return nil
}

func (o *AwsClient) GetConcurrencyLevelTag(funcIdentifier string, tag string) (error, *int32) {
	cfg := o.getConfig()
	lambdaClient := lambda.NewFromConfig(*cfg)
	input := &lambda.ListTagsInput{
		Resource: aws.String(funcIdentifier),
	}
	resp, err := lambdaClient.ListTags(context.TODO(), input)
	if err != nil {
		return err, nil
	}
	concurrencyLevel, exist := resp.Tags[tag]
	if !exist {
		log.Printf("function not blocked by function-clarity, nothing to do")
		noConcurrency := int32(-1)
		return nil, &noConcurrency
	}
	if concurrencyLevel == "nil" {
		return nil, nil
	}
	concurrencyLevelInt, err := strconv.ParseInt(concurrencyLevel, 10, 32)
	concurrencyLevelInt32 := int32(concurrencyLevelInt)
	return err, &concurrencyLevelInt32
}

func (o *AwsClient) GetEcrToken() (*ecr.GetAuthorizationTokenOutput, error) {
	cfg := o.getConfig()
	ecrClient := ecr.NewFromConfig(*cfg)
	output, err := ecrClient.GetAuthorizationToken(context.TODO(), &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (o *AwsClient) DeployFunctionClarity(trailName string, keyPath string, deploymentConfig i.AWSInput) error {
	cfg := o.getConfig()
	if err := uploadFuncClarityCode(cfg, keyPath, deploymentConfig.Bucket); err != nil {
		return fmt.Errorf("failed to upload function clarity code: %w", err)
	}
	cloudformationClient := cloudformation.NewFromConfig(*cfg)
	const funcClarityStackName = "function-clarity-stack"
	stackExists, err := stackExists(funcClarityStackName, cloudformationClient)
	if err != nil {
		return fmt.Errorf("failed to check if stack exists: %w", err)
	}
	if stackExists {
		return fmt.Errorf("function clarity already deployed, please delete stack before you dpeloy")
	}

	err, stackCalculatedTemplate := calculateStackTemplate(trailName, cfg, deploymentConfig)
	if err != nil {
		return err
	}
	stackName := funcClarityStackName
	_, err = cloudformationClient.CreateStack(context.TODO(), &cloudformation.CreateStackInput{
		TemplateBody: &stackCalculatedTemplate,
		StackName:    &stackName,
		Capabilities: []types.Capability{types.CapabilityCapabilityIam},
	})
	fmt.Println("deployment request sent to provider")
	if err != nil {
		return fmt.Errorf("failed to create stack: %w", err)
	}
	fmt.Println("waiting for deployment to complete")

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
		stacks, err := cloudformationClient.DescribeStacks(context.TODO(), &cloudformation.DescribeStacksInput{StackName: aws.String(stackName)})
		if err != nil {
			return fmt.Errorf("failed to create stack: %w", err)
		}
		if len(stacks.Stacks) == 1 && stacks.Stacks[0].StackStatus == types.StackStatusCreateComplete {
			break
		}
		if timeout {
			return fmt.Errorf("timout on waiting for stack to create")
		}
		time.Sleep(30 * time.Second)
	}

	fmt.Println("deployment finished successfully")
	return nil
}

func (o *AwsClient) UpdateVerifierFucConfig(action *string, includedFuncTagKeys *[]string, includedFuncRegions *[]string, topic *string) error {
	cfg := o.getConfig()
	lambdaClient := lambda.NewFromConfig(*cfg)
	input := &lambda.GetFunctionConfigurationInput{
		FunctionName: aws.String(FunctionClarityLambdaVerierName),
	}
	functionConfiguration, err := lambdaClient.GetFunctionConfiguration(context.TODO(), input)
	if err != nil {
		return fmt.Errorf("failed to update configuration: %w", err)
	}
	funcConfigEnvEncoded := functionConfiguration.Environment.Variables[ConfigEnvVariableName]
	funcConfigEnvDecoded, err := b64.StdEncoding.DecodeString(funcConfigEnvEncoded)
	if err != nil {
		return fmt.Errorf("failed to update configuration: %w", err)
	}
	config := i.AWSInput{}
	err = yaml.Unmarshal(funcConfigEnvDecoded, &config)
	if err != nil {
		return fmt.Errorf("failed to update configuration: %w", err)
	}
	if action != nil {
		config.Action = *action
	}
	if includedFuncTagKeys != nil {
		config.IncludedFuncTagKeys = *includedFuncTagKeys
	}
	if includedFuncRegions != nil {
		config.IncludedFuncRegions = *includedFuncRegions
	}
	if topic != nil {
		config.SnsTopicArn = *topic
	}
	var environment = lambdaTypes.Environment{}
	configMarshal, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to update configuration: %w", err)
	}
	configEncoded := b64.StdEncoding.EncodeToString(configMarshal)
	environment.Variables = functionConfiguration.Environment.Variables
	environment.Variables[ConfigEnvVariableName] = configEncoded
	updateFunctionEnvInput := lambda.UpdateFunctionConfigurationInput{FunctionName: aws.String(FunctionClarityLambdaVerierName), Environment: &environment}
	_, err = lambdaClient.UpdateFunctionConfiguration(context.TODO(), &updateFunctionEnvInput)
	if err != nil {
		return fmt.Errorf("failed to update configuration: %w", err)
	}
	return nil
}

func (o *AwsClient) FillNotificationDetails(notification *Notification, functionIdentifier string) error {
	if err := o.convertToArnIfNeeded(&functionIdentifier); err != nil {
		return fmt.Errorf("failed to fill notification details: %w", err)
	}
	funcArn, err := arn.Parse(functionIdentifier)
	if err != nil {
		return fmt.Errorf("failed to fill notification details: %w", err)
	}
	notification.AccountId = funcArn.AccountID
	notification.FunctionIdentifier = funcArn.String()
	notification.FunctionName = funcArn.Resource
	notification.Region = o.lambdaRegion
	return nil
}

func calculateStackTemplate(trailName string, cfg *aws.Config, config i.AWSInput) (error, string) {
	templateFile := "utils/unified-template.template"
	content, err := os.ReadFile(templateFile)
	if err != nil {
		return err, ""
	}
	templateBody := string(content)
	data := make(map[string]interface{}, 4)
	data["bucketName"] = FunctionClarityBucketName
	if config.Bucket != "" {
		data["bucketName"] = config.Bucket
	}

	serConfig, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to create template. %v", err), ""
	}
	encodedConfig := b64.StdEncoding.EncodeToString(serConfig)
	data["config"] = encodedConfig
	if trailName == "" {
		data["withTrail"] = "True"
	} else {
		svt := cloudtrail.NewFromConfig(*cfg)
		trail, err := svt.GetTrail(context.TODO(), &cloudtrail.GetTrailInput{Name: &trailName})
		if err != nil {
			return err, ""
		}
		if err = trailValid(trail); err != nil {
			return err, ""
		}
		cloudWatchArn, err := arn.Parse(*trail.Trail.CloudWatchLogsLogGroupArn)
		if err != nil {
			return err, ""
		}
		data["logGroupArn"] = *trail.Trail.CloudWatchLogsLogGroupArn
		data["logGroupName"] = strings.Split(cloudWatchArn.Resource, ":")[1]
	}
	tmpl := template.Must(template.New("template.json").Parse(templateBody))
	buf := &bytes.Buffer{}
	if err = tmpl.Execute(buf, data); err != nil {
		return err, ""
	}
	stackCalculatedTemplate := buf.String()
	return err, stackCalculatedTemplate
}

func trailValid(trail *cloudtrail.GetTrailOutput) error {
	if *trail.Trail.CloudWatchLogsLogGroupArn == "" {
		return fmt.Errorf("trail doesn't have cloudwatch logs defined")
	}
	return nil
}

func (o *AwsClient) getConfig() *aws.Config {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(o.region))
	if o.accessKey != "" && o.secretKey != "" {
		cfg, err = config.LoadDefaultConfig(context.TODO(),
			config.WithRegion(o.region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(o.accessKey, o.secretKey, "")))
	}
	if err != nil {
		panic(fmt.Sprintf("failed loading config, %v", err))
	}
	return &cfg
}

func (o *AwsClient) getConfigForLambda() *aws.Config {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(o.lambdaRegion))
	if o.accessKey != "" && o.secretKey != "" {
		cfg, err = config.LoadDefaultConfig(context.TODO(),
			config.WithRegion(o.lambdaRegion),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(o.accessKey, o.secretKey, "")))
	}
	if err != nil {
		panic(fmt.Sprintf("failed loading config, %v", err))
	}
	return &cfg
}

func uploadFuncClarityCode(cfg *aws.Config, keyPath string, bucket string) error {
	s3Client := s3.NewFromConfig(*cfg)
	_, err := s3Client.CreateBucket(context.TODO(), &s3.CreateBucketInput{
		Bucket:                    aws.String(bucket),
		CreateBucketConfiguration: &s3types.CreateBucketConfiguration{LocationConstraint: s3types.BucketLocationConstraint(cfg.Region)},
	})
	var bne *s3types.BucketAlreadyOwnedByYou
	if err != nil && !errors.As(err, &bne) {
		return err
	}
	archive, err := os.Create("function-clarity.zip")
	if err != nil {
		return err
	}
	defer archive.Close()
	zipWriter := zip.NewWriter(archive)
	binaryFile, err := os.Open("aws_function")
	if err != nil {
		return err
	}
	defer binaryFile.Close()

	w1, err := zipWriter.Create("function-clarity")
	if err != nil {
		return err
	}
	if _, err := io.Copy(w1, binaryFile); err != nil {
		return err
	}

	if keyPath != "" {
		publicKey, err := os.Open(keyPath)
		if err != nil {
			return err
		}
		defer publicKey.Close()

		w2, err := zipWriter.Create("cosign.pub")
		if err != nil {
			return err
		}
		if _, err := io.Copy(w2, publicKey); err != nil {
			return err
		}
	}
	zipWriter.Close()
	uploader := manager.NewUploader(s3.NewFromConfig(*cfg))
	// Upload the file to S3.
	//p := mpb.New()
	file, err := os.Open("function-clarity.zip")
	//fileInfo, err := file.Stat()
	//reader := &utils.ProgressBarReader{
	//	Fp:      file,
	//	Size:    fileInfo.Size(),
	//	SignMap: map[int64]struct{}{},
	//	Bar: p.AddBar(fileInfo.Size(),
	//		mpb.PrependDecorators(
	//			decor.Name("uploading..."),
	//			decor.Percentage(decor.WCSyncSpace),
	//		),
	//	),
	//}

	if err != nil {
		return err
	}
	fmt.Println("Uploading function-clarity function code to s3 bucket, this may take a few minutes")
	_, err = uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String("function-clarity.zip"),
		Body:   file,
	})
	if err != nil {
		return err
	}
	fmt.Println("function-clarity function code upload successfully")
	return nil
}

func ExtractZip(zipPath string, dstToExtract string) error {

	archive, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open archive file : %s. %v", zipPath, err)
	}
	defer archive.Close()

	for _, f := range archive.File {
		filePath := filepath.Join(dstToExtract, f.Name)

		if !strings.HasPrefix(filePath, filepath.Clean(dstToExtract)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path")
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
				return fmt.Errorf("failed to create directory for path: %s. %v", filePath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(filePath), os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directories for path: %s. %v", filePath, err)
		}

		dstFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return fmt.Errorf("failed to open destination file for writing: %s. %v", filePath, err)
		}

		fileInArchive, err := f.Open()
		if err != nil {
			return fmt.Errorf("failed to open file in archive : %s. %v", f.Name, err)
		}

		if _, err := io.Copy(dstFile, fileInArchive); err != nil {
			return fmt.Errorf("failed to copy file: %s from archive to local path: %s. %v", f.Name, dstFile.Name(), err)
		}

		dstFile.Close()
		fileInArchive.Close()
	}
	return nil
}

func stackExists(stackNameOrID string, cfClient *cloudformation.Client) (bool, error) {
	describeStacksInput := &cloudformation.DescribeStacksInput{
		StackName: aws.String(stackNameOrID),
	}
	_, err := cfClient.DescribeStacks(context.TODO(), describeStacksInput)

	if err != nil {
		// If the stack doesn't exist, then no worries
		if strings.Contains(err.Error(), "does not exist") {
			return false, nil
		}
		return false, err

	}
	return true, nil
}

func DownloadFile(fileName string, url *string) error {

	// Get the data
	resp, err := http.Get(*url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create("/tmp/" + fileName)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}
