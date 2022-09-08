package options

import (
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
		log.Println("Error loading config file.", err)
	}
	if viper.ConfigFileUsed() != "" {
		log.Println("Using config file:", viper.ConfigFileUsed())
	}
}
