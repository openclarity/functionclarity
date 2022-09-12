package options

import (
	"fmt"
	"github.com/spf13/viper"
	"log"
	"os"
)

var Config string = ""

func CobraInit() {
	if Config != "" {
		viper.SetConfigFile(Config)
		viper.SetConfigType("yaml")
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}
		viper.AddConfigPath(home)
		viper.SetConfigName(".fc")
		viper.SetConfigType("yaml")
	}
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("Error loading config file: %s\n", err)
	}
	if viper.ConfigFileUsed() != "" {
		fmt.Printf("using config file: %s\n", viper.ConfigFileUsed())
	}
}
