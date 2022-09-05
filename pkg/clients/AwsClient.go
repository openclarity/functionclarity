package clients

import (
	"archive/zip"
	"bytes"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/google/uuid"
	"github.com/openclarity/function-clarity/pkg/utils"
	"github.com/vbauerster/mpb/v5"
	"github.com/vbauerster/mpb/v5/decor"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

const FunctionClarityBucketName = "functionclarity"

type AwsClient struct {
	accessKey string
	secretKey string
	s3        string
	region    string
}

func NewAwsClient(accessKey string, secretKey string, s3 string, region string) *AwsClient {
	p := new(AwsClient)
	p.accessKey = accessKey
	p.secretKey = secretKey
	p.s3 = s3
	p.region = region
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
	sess := o.getSession()
	svc := lambda.New(sess)
	input := &lambda.GetFunctionInput{
		FunctionName: aws.String(funcIdentifier),
	}
	result, err := svc.GetFunction(input)
	if err != nil {
		return "", fmt.Errorf("failed to download function: %s from region: %s, %v", funcIdentifier, o.region, err)
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
		return fmt.Errorf("failed to upload key: %s, value: %s to bucket: %s %v", identity, signature, o.s3, err)
	}

	if isKeyless {
		certificatePath := "/tmp/" + identity + ".crt.base64"
		f, err := os.Open(certificatePath)
		if err != nil {
			return fmt.Errorf("failed to open file %q, %v", certificatePath, err)
		}

		result, err := uploader.Upload(&s3manager.UploadInput{
			Bucket: aws.String(o.s3),
			Key:    aws.String(identity + ".crt.base64"),
			Body:   f,
		})
		if err != nil {
			return fmt.Errorf("failed to upload key: %s, value: %s to bucket: %s %v", identity, certificatePath, o.s3, err)
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
		return fmt.Errorf("failed to create file %q, %v", outputFile, err)
	}
	defer f.Close()

	_, err = downloader.Download(f, &s3.GetObjectInput{
		Bucket: aws.String(o.s3),
		Key:    aws.String(fileName + "." + outputType),
	})

	if err != nil {
		return fmt.Errorf("failed to download file: %s from bucket: %s, %v", fileName, o.s3, err)
	}
	return nil
}

func (o *AwsClient) GetFuncCode(funcIdentifier string) (string, error) {
	sess := o.getSession()
	svc := lambda.New(sess)
	input := &lambda.GetFunctionInput{
		FunctionName: aws.String(funcIdentifier),
	}
	result, err := svc.GetFunction(input)
	if err != nil {
		return "", fmt.Errorf("failed to download function: %s from region: %s, %v", funcIdentifier, o.region, err)
	}
	contentName := uuid.New().String()
	zipFileName := contentName + ".zip"
	if err := DownloadFile(contentName+".zip", result.Code.Location); err != nil {
		return "", fmt.Errorf("failed to download function code for function: %s, from location: %s. %v", funcIdentifier, result.Code.String(), err)
	}
	if err := ExtractZip("/tmp/"+zipFileName, "/tmp/"+contentName); err != nil {
		return "", fmt.Errorf("failed to extract code for function: %s. %v", funcIdentifier, err)
	}
	return "/tmp/" + contentName, nil
}

func (o *AwsClient) GetFuncImageURI(funcIdentifier string) (string, error) {
	sess := o.getSession()
	svc := lambda.New(sess)
	input := &lambda.GetFunctionInput{
		FunctionName: aws.String(funcIdentifier),
	}
	result, err := svc.GetFunction(input)
	if err != nil {
		return "", fmt.Errorf("failed to download function: %s from region: %s, %v", funcIdentifier, o.region, err)
	}
	return *result.Code.ImageUri, nil
}

func (o *AwsClient) TagFunction(funcIdentifier string, tag string, tagValue string) (string, error) {
	sess := o.getSession()
	svc := lambda.New(sess)
	input := &lambda.TagResourceInput{
		Resource: aws.String(funcIdentifier),
		Tags: map[string]*string{
			tag: aws.String(tagValue),
		},
	}
	result, err := svc.TagResource(input)
	if err != nil {
		return "", err
	}
	return result.GoString(), nil
}

func (o *AwsClient) DeployFunctionClarity(trailName string, keyPath string) error {
	sess := o.getSession()
	err := uploadFuncClarityCode(sess, keyPath)
	if err != nil {
		return err
	}
	svc := cloudformation.New(sess)
	const funcClarityStackName = "function-clarity-stack"
	stackExists, err := stackExists(funcClarityStackName, svc)
	if err != nil {
		return err
	}
	if stackExists {
		return fmt.Errorf("function clarity already deployed, please delete stack before you dpeloy")
	}

	err, stackCalculatedTemplate := calculateStackTemplate(trailName, sess)
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
		return err
	}
	fmt.Println("waiting for deployment to complete")
	err = svc.WaitUntilStackCreateComplete(&cloudformation.DescribeStacksInput{
		StackName: &stackName,
	})
	if err != nil {
		fmt.Println("Got an error waiting for stack to be created")
		return err
	}
	return nil
}

func calculateStackTemplate(trailName string, sess *session.Session) (error, string) {
	templateFile := "utils/unified-template.template"
	content, err := os.ReadFile(templateFile)
	if err != nil {
		return err, ""
	}
	templateBody := string(content)
	data := make(map[string]interface{}, 4)
	data["bucketName"] = FunctionClarityBucketName
	if trailName == "" {
		data["withTrail"] = "True"
	} else {
		svt := cloudtrail.New(sess)
		trail, err := svt.GetTrail(&cloudtrail.GetTrailInput{Name: &trailName})
		if err != nil {
			return err, ""
		}
		err = trailValid(trail)
		if err != nil {
			return err, ""
		}
		cloudWatchArn, err := arn.Parse(*trail.Trail.CloudWatchLogsLogGroupArn)
		data["logGroupArn"] = *trail.Trail.CloudWatchLogsLogGroupArn
		data["logGroupName"] = strings.Split(cloudWatchArn.Resource, ":")[1]
	}
	tmpl := template.Must(template.New("template.json").Parse(templateBody))
	buf := &bytes.Buffer{}
	err = tmpl.Execute(buf, data)
	if err != nil {
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

func uploadFuncClarityCode(sess *session.Session, keyPath string) error {
	s3svc := s3.New(sess)

	_, err := s3svc.CreateBucket(&s3.CreateBucketInput{
		Bucket: aws.String(FunctionClarityBucketName),
	})
	if err != nil {
		return nil
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
	zipWriter.Close()
	uploader := s3manager.NewUploader(sess)
	// Upload the file to S3.
	p := mpb.New()
	file, err := os.Open("function-clarity.zip")
	fileInfo, err := file.Stat()
	reader := &utils.ProgressBarReader{
		Fp:      file,
		Size:    fileInfo.Size(),
		SignMap: map[int64]struct{}{},
		Bar: p.AddBar(fileInfo.Size(),
			mpb.PrependDecorators(
				decor.Name("uploading..."),
				decor.Percentage(decor.WCSyncSpace),
			),
		),
	}

	if err != nil {
		return err
	}
	fmt.Println("Uploading function-clarity function code to s3 bucket, this may take a few minutes")
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(FunctionClarityBucketName),
		Key:    aws.String("function-clarity.zip"),
		Body:   reader,
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
			fmt.Println("creating directory...")
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
