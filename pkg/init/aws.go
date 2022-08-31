package init

import (
	"bufio"
	"context"
	"fmt"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
	"os"
	"strings"
)

type AWSInput struct {
	AccessKey     string
	SecretKey     string
	Region        string
	PublicKeyPath string
	CloudTrail    CloudTrail
}

type CloudTrail struct {
	Name string
}

func (i *AWSInput) digestParameters() error {
	if i.PublicKeyPath == "" {
		if err := generate.GenerateKeyPairCmd(context.Background(), "", []string{}); err != nil {
			return err
		}
	}
	return nil
}

func (i *AWSInput) ReceiveParameters() error {
	if err := inputParameter("enter Access Key: ", &i.AccessKey, false); err != nil {
		return err
	}
	if err := inputParameter("enter Secret Key: ", &i.SecretKey, false); err != nil {
		return err
	}
	if err := inputParameter("enter region: ", &i.Region, false); err != nil {
		return err
	}
	if err := inputParameter("is there existing trail in CloudTrail which you would like to use? (if no, please press enter): ", &i.CloudTrail.Name, true); err != nil {
		return err
	}
	if err := inputParameter("enter path to custom public key for code signing? (if you want us to generate key pair, please press enter): ", &i.PublicKeyPath, true); err != nil {
		return err
	}

	if err := i.digestParameters(); err != nil {
		return err
	}
	return nil
}

func inputParameter(q string, p *string, em bool) error {
	fmt.Print(q)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	input = strings.TrimSuffix(input, "\n")
	if !em && input == "" {
		return fmt.Errorf("this is a compulsory parameter")
	}
	*p = strings.TrimSuffix(input, "\n")
	return err
}
