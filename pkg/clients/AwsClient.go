package clients

import (
	"archive/zip"
	"bytes"
	b64 "encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/sns"
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
)

const FunctionClarityBucketName = "functionclarity"

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
	sess := o.getSessionForLambda()
	svc := lambda.New(sess)
	input := &lambda.GetFunctionInput{
		FunctionName: aws.String(funcIdentifier),
	}
	result, err := svc.GetFunction(input)
	if err != nil {
		return "", err
	}
	return *result.Configuration.PackageType, nil
}

func (o *AwsClient) Upload(signature string, identity string, isKeyless bool) error {
	sess := o.getSession()

	uploader := s3manager.NewUploader(sess)
	// Upload the file to S3.
	_, err := uploader.Upload(&s3manager.UploadInput{
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

		result, err := uploader.Upload(&s3manager.UploadInput{
			Bucket: aws.String(o.s3),
			Key:    aws.String(identity + ".crt.base64"),
			Body:   f,
		})
		if err != nil {
			return err
		}
		fmt.Printf("\ncertificate file uploaded to, %s\n", aws.StringValue(&result.Location))
	}
	return nil
}

func (o *AwsClient) Download(fileName string, outputType string) error {
	sess := o.getSession()
	downloader := s3manager.NewDownloader(sess)

	outputFile := "/tmp/" + fileName + "." + outputType
	f, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = downloader.Download(f, &s3.GetObjectInput{
		Bucket: aws.String(o.s3),
		Key:    aws.String(fileName + "." + outputType),
	})

	if err != nil {
		return err
	}
	return nil
}

func (o *AwsClient) GetFuncCode(funcIdentifier string) (string, error) {
	sess := o.getSessionForLambda()
	svc := lambda.New(sess)
	input := &lambda.GetFunctionInput{
		FunctionName: aws.String(funcIdentifier),
	}
	result, err := svc.GetFunction(input)
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
	sess := o.getSession()
	svc := lambda.New(sess)
	o.convertToArnIfNeeded(&funcIdentifier)
	input := &lambda.ListTagsInput{
		Resource: aws.String(funcIdentifier),
	}
	req, resp := svc.ListTagsRequest(input)
	if err := req.Send(); err != nil {
		return false, err
	}
	for _, tag := range tagKes {
		if resp.Tags[tag] != nil {
			return true, nil
		}
	}
	return false, nil
}

func (o *AwsClient) Notify(msg string, topicARN string) error {
	sess := o.getSession()
	svc := sns.New(sess)
	result, err := svc.Publish(&sns.PublishInput{
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
	sess := o.getSessionForLambda()
	svc := lambda.New(sess)
	input := &lambda.GetFunctionInput{
		FunctionName: aws.String(funcIdentifier),
	}
	result, err := svc.GetFunction(input)
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
	sess := o.getSessionForLambda()
	svc := lambda.New(sess)
	input := &lambda.TagResourceInput{
		Resource: aws.String(funcIdentifier),
		Tags: map[string]*string{
			tag: aws.String(tagValue),
		},
	}
	_, err := svc.TagResource(input)
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
		currentConcurrencyLevelString = strconv.FormatInt(*currentConcurrencyLevel, 10)
	}
	if err = o.tagFunction(*funcIdentifier, utils.FunctionClarityConcurrencyTagKey, currentConcurrencyLevelString); err != nil {
		return fmt.Errorf("failed to tag function with current concurrency level. %v", err)
	}
	var zeroConcurrencyLevel = int64(0)
	if err = o.updateConcurrencyLevel(*funcIdentifier, &zeroConcurrencyLevel); err != nil {
		return fmt.Errorf("failed to set concurrency level to 0. %v", err)
	}
	return nil
}

func (o *AwsClient) updateConcurrencyLevel(funcIdentifier string, concurrencyLevel *int64) error {
	sess := o.getSession()
	svc := lambda.New(sess)
	input := &lambda.PutFunctionConcurrencyInput{
		FunctionName:                 &funcIdentifier,
		ReservedConcurrentExecutions: concurrencyLevel,
	}
	result, err := svc.PutFunctionConcurrency(input)
	if *result.ReservedConcurrentExecutions != *concurrencyLevel {
		return fmt.Errorf("failed to update function concurrency to %d. %v", *concurrencyLevel, err)
	}
	return nil
}

func (o *AwsClient) DeleteConcurrencyLevel(funcIdentifier string) error {
	sess := o.getSession()
	svc := lambda.New(sess)
	input := &lambda.DeleteFunctionConcurrencyInput{
		FunctionName: &funcIdentifier,
	}
	_, err := svc.DeleteFunctionConcurrency(input)
	if err != nil {
		return fmt.Errorf("failed to update function concurrency to 0. %v", err)
	}
	return nil
}

func (o *AwsClient) GetConcurrencyLevel(funcIdentifier string) (*int64, error) {
	sess := o.getSession()
	svc := lambda.New(sess)
	input := &lambda.GetFunctionConcurrencyInput{
		FunctionName: &funcIdentifier,
	}
	result, err := svc.GetFunctionConcurrency(input)
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
	untagKeyArray := []*string{&concurrencyLevelTagName}
	sess := o.getSession()
	svc := lambda.New(sess)
	untagFunctionInput := &lambda.UntagResourceInput{
		Resource: funcIdentifier,
		TagKeys:  untagKeyArray}
	_, err = svc.UntagResource(untagFunctionInput)
	if err != nil {
		return fmt.Errorf("failed to untag func clarity concurrency level tag for func: %s. %v", *funcIdentifier, err)
	}
	return nil
}

func (o *AwsClient) convertToArnIfNeeded(funcIdentifier *string) error {
	if !arn.IsARN(*funcIdentifier) {
		sess := o.getSessionForLambda()
		svc := lambda.New(sess)
		input := &lambda.GetFunctionInput{
			FunctionName: aws.String(*funcIdentifier),
		}
		result, err := svc.GetFunction(input)
		if err != nil {
			return fmt.Errorf("failed to get function by name: %s", *funcIdentifier)
		}
		*funcIdentifier = *result.Configuration.FunctionArn
	}
	return nil
}

func (o *AwsClient) GetConcurrencyLevelTag(funcIdentifier string, tag string) (error, *int64) {
	sess := o.getSession()
	svc := lambda.New(sess)
	input := &lambda.ListTagsInput{
		Resource: aws.String(funcIdentifier),
	}
	req, resp := svc.ListTagsRequest(input)
	if err := req.Send(); err != nil {
		return err, nil
	}
	concurrencyLevel := resp.Tags[tag]
	var result *int64
	if concurrencyLevel == nil {
		log.Printf("function not blocked by function-clarity, nothing to do")
		*result = -1
		return nil, result
	}
	if *concurrencyLevel == "nil" {
		return nil, nil
	}
	concurrencyLevelInt, err := strconv.ParseInt(*concurrencyLevel, 10, 64)
	return err, &concurrencyLevelInt
}

func (o *AwsClient) GetEcrToken() (*ecr.GetAuthorizationTokenOutput, error) {
	sess := o.getSession()
	ecrClient := ecr.New(sess)
	output, err := ecrClient.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (o *AwsClient) DeployFunctionClarity(trailName string, keyPath string, deploymentConfig i.AWSInput) error {
	sess := o.getSession()
	if err := uploadFuncClarityCode(sess, keyPath, deploymentConfig.Bucket); err != nil {
		return fmt.Errorf("failed to upload function clarity code: %w", err)
	}
	svc := cloudformation.New(sess)
	const funcClarityStackName = "function-clarity-stack"
	stackExists, err := stackExists(funcClarityStackName, svc)
	if err != nil {
		return fmt.Errorf("failed to check if stack exists: %w", err)
	}
	if stackExists {
		return fmt.Errorf("function clarity already deployed, please delete stack before you dpeloy")
	}

	err, stackCalculatedTemplate := calculateStackTemplate(trailName, sess, deploymentConfig)
	if err != nil {
		return err
	}
	stackName := funcClarityStackName
	_, err = svc.CreateStack(&cloudformation.CreateStackInput{
		TemplateBody: &stackCalculatedTemplate,
		StackName:    &stackName,
		Capabilities: []*string{aws.String(cloudformation.CapabilityCapabilityIam)},
	})
	fmt.Println("deployment request sent to provider")
	if err != nil {
		return fmt.Errorf("failed to create stack: %w", err)
	}
	fmt.Println("waiting for deployment to complete")
	if err = svc.WaitUntilStackCreateComplete(&cloudformation.DescribeStacksInput{
		StackName: &stackName,
	}); err != nil {
		return fmt.Errorf("failed to create stack: %w", err)
	}
	fmt.Println("deployment finished successfully")
	return nil
}
func calculateStackTemplate(trailName string, sess *session.Session, config i.AWSInput) (error, string) {
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
		svt := cloudtrail.New(sess)
		trail, err := svt.GetTrail(&cloudtrail.GetTrailInput{Name: &trailName})
		if err != nil {
			return err, ""
		}
		if err = trailValid(trail); err != nil {
			return err, ""
		}
		cloudWatchArn, err := arn.Parse(*trail.Trail.CloudWatchLogsLogGroupArn)
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

func (o *AwsClient) getSession() *session.Session {
	cfgs := &aws.Config{
		Region: aws.String(o.region)}
	if o.accessKey != "" && o.secretKey != "" {
		cfgs = &aws.Config{
			Region:      aws.String(o.region),
			Credentials: credentials.NewStaticCredentials(o.accessKey, o.secretKey, ""),
		}
	}
	result := session.Must(session.NewSession(cfgs))
	return result
}

func (o *AwsClient) getSessionForLambda() *session.Session {
	cfgs := &aws.Config{
		Region: aws.String(o.lambdaRegion)}
	if o.accessKey != "" && o.secretKey != "" {
		cfgs = &aws.Config{
			Region:      aws.String(o.lambdaRegion),
			Credentials: credentials.NewStaticCredentials(o.accessKey, o.secretKey, ""),
		}
	}
	result := session.Must(session.NewSession(cfgs))
	return result
}

func uploadFuncClarityCode(sess *session.Session, keyPath string, bucket string) error {
	s3svc := s3.New(sess)
	_, err := s3svc.CreateBucket(&s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() != "BucketAlreadyOwnedByYou" {
				return err
			}
		} else {
			return err
		}
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
	uploader := s3manager.NewUploader(sess)
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
	_, err = uploader.Upload(&s3manager.UploadInput{
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
			os.MkdirAll(filePath, os.ModePerm)
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

func stackExists(stackNameOrID string, cf *cloudformation.CloudFormation) (bool, error) {
	describeStacksInput := &cloudformation.DescribeStacksInput{
		StackName: aws.String(stackNameOrID),
	}
	_, err := cf.DescribeStacks(describeStacksInput)

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
