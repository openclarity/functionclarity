package integrity

import (
	"os"
	"strconv"
)

const ExperimentalEnv = "COSIGN_EXPERIMENTAL"

func IsExperimentalEnv() bool {
	parseBool, _ := strconv.ParseBool(os.Getenv(ExperimentalEnv))
	return parseBool
}
