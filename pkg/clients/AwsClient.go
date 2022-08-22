package clients

import (
	"archive/zip"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/google/uuid"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

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

func (o *AwsClient) Upload(signature string, identity string) error {
	sess := o.getSession()

	uploader := s3manager.NewUploader(sess)
	// Upload the file to S3.
	result, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(o.s3),
		Key:    aws.String(identity),
		Body:   strings.NewReader(signature),
	})
	if err != nil {
		return fmt.Errorf("failed to upload key: %s, value: %s to bucket: %s %v", identity, signature, o.s3, err)
	}
	fmt.Printf("file uploaded to, %s\n", aws.StringValue(&result.Location))
	return nil
}

func (o *AwsClient) Download(identity string) (string, error) {
	sess := o.getSession()
	downloader := s3manager.NewDownloader(sess)

	w := aws.NewWriteAtBuffer(make([]byte, 256))
	_, err := downloader.Download(w, &s3.GetObjectInput{
		Bucket: aws.String(o.s3),
		Key:    aws.String(identity),
	})

	if err != nil {
		return "", fmt.Errorf("failed to download content: %s from bucket: %s, %v", identity, o.s3, err)
	}
	return fmt.Sprintf("%s", string(w.Bytes())), nil
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
	//fmt.Printf(result.Code.GoString())
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

func (o *AwsClient) getSession() *session.Session {
	cfgs := &aws.Config{
		Region: aws.String(o.region)}
	if o.accessKey != "" && o.secretKey != "" {
		cfgs = &aws.Config{
			Region:      aws.String(o.region),
			Credentials: credentials.NewStaticCredentials(o.accessKey, o.secretKey, ""),
		}
	}
	session := session.Must(session.NewSession(cfgs))
	return session
}

func ExtractZip(zipPath string, dstToExtract string) error {

	archive, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open archive file : %s. %v", zipPath, err)
	}
	defer archive.Close()

	for _, f := range archive.File {
		filePath := filepath.Join(dstToExtract, f.Name)
		fmt.Println("unzipping file ", filePath)

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
