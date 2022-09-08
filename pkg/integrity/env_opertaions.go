package integrity

import (
	"fmt"
	"github.com/spf13/viper"
	"os"
	"strconv"
)

const ExperimentalEnv = "COSIGN_EXPERIMENTAL"

func IsExperimentalEnv() bool {
	env, err := strconv.ParseBool(os.Getenv(ExperimentalEnv))
	if err != nil {
		fmt.Errorf("can't read env variable")
	}
	config := viper.GetBool("isKeyless")
	if env || config {
		return true
	}
	return false
}
