package init

import "fmt"

type Input struct {
	AccessKey string
	SecretKey string
	Region    string
}

func (i *Input) RecieveParameters() error {
	if err := inputParameter("Enter Access Key: ", &i.AccessKey); err != nil {
		return err
	}
	if err := inputParameter("Enter Secret Key: ", &i.SecretKey); err != nil {
		return err
	}
	if err := inputParameter("Enter region: ", &i.Region); err != nil {
		return err
	}
	return nil
}

func inputParameter(q string, p *string) error {
	fmt.Print(q)
	_, err := fmt.Scanln(p)
	return err
}
