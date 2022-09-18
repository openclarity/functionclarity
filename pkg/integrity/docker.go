package integrity

import (
	"encoding/base64"
	"encoding/json"
	"github.com/openclarity/function-clarity/pkg/clients"
	"os"
	"strings"
)

type Auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DockerAuth struct {
	Auths map[string]Auth `json:"auths"`
}

func InitDocker(awsClient *clients.AwsClient) error {
	ecrToken, err := awsClient.GetEcrToken()
	if err != nil {
		return err
	}
	dockerAuth := DockerAuth{Auths: map[string]Auth{}}
	for _, ad := range ecrToken.AuthorizationData {
		usernamePassword, err := base64.StdEncoding.DecodeString(*ad.AuthorizationToken)
		if err != nil {
			return err
		}
		split := strings.Split(string(usernamePassword), ":")
		dockerAuth.Auths[*ad.ProxyEndpoint] = Auth{
			Username: split[0],
			Password: split[1],
		}
	}
	if err != nil {
		return err
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	dockerConfigDir := homeDir + "/.docker"
	err = os.MkdirAll(dockerConfigDir, 0700)
	if err != nil {
		return err
	}

	dockerConfigJson, err := json.Marshal(dockerAuth)
	if err != nil {
		return err
	}

	err = os.WriteFile(dockerConfigDir+"/config.json", dockerConfigJson, 0600)
	return nil
}
