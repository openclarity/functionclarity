package init

import "fmt"

type AWSInput struct {
	AccessKey  string
	SecretKey  string
	Region     string
	CloudTrail CloudTrail
}

type CloudTrail struct {
	Name string
}

func (i *AWSInput) RecieveParameters() error {
	if err := inputParameter("Enter Access Key: ", &i.AccessKey); err != nil {
		return err
	}
	if err := inputParameter("Enter Secret Key: ", &i.SecretKey); err != nil {
		return err
	}
	if err := inputParameter("Enter region: ", &i.Region); err != nil {
		return err
	}

	if err := inputParameter("is there existing trail in CloudTrail which you would like to use (if no please press enter): ", &i.CloudTrail.Name); err != nil {
		return err
	}
	return nil
}

func inputParameter(q string, p *string) error {
	fmt.Print(q)
	_, err := fmt.Scanln(p)
	return err
}
