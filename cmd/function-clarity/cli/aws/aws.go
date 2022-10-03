// Copyright © 2022 Cisco Systems, Inc. and its affiliates.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aws

import (
	"fmt"
	opt "github.com/openclarity/function-clarity/cmd/function-clarity/cli/options"
	"github.com/openclarity/function-clarity/pkg/clients"
	i "github.com/openclarity/function-clarity/pkg/init"
	"github.com/openclarity/function-clarity/pkg/options"
	"github.com/openclarity/function-clarity/pkg/verify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"os"
)

func AwsSign() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "sign code/image and upload to aws",
	}
	cmd.AddCommand(AwsSignCode())
	cmd.AddCommand(AwsSignImage())
	return cmd
}

func AwsVerify() *cobra.Command {
	o := &options.VerifyOpts{}
	var lambdaRegion string
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "verify function identity",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlag("accessKey", cmd.Flags().Lookup("aws-access-key")); err != nil {
				return fmt.Errorf("error binding accessKey: %w", err)
			}
			if err := viper.BindPFlag("secretKey", cmd.Flags().Lookup("aws-secret-key")); err != nil {
				return fmt.Errorf("error binding secretKey: %w", err)
			}
			if err := viper.BindPFlag("region", cmd.Flags().Lookup("region")); err != nil {
				return fmt.Errorf("error binding region: %w", err)
			}
			if err := viper.BindPFlag("bucket", cmd.Flags().Lookup("bucket")); err != nil {
				return fmt.Errorf("error binding bucket: %w", err)
			}
			if err := viper.BindPFlag("publickey", cmd.Flags().Lookup("key")); err != nil {
				return fmt.Errorf("error binding publickey: %w", err)
			}
			if err := viper.BindPFlag("action", cmd.Flags().Lookup("action")); err != nil {
				return fmt.Errorf("error binding action: %w", err)
			}
			if err := viper.BindPFlag("includedfunctagkeys", cmd.Flags().Lookup("included-func-tags")); err != nil {
				return fmt.Errorf("error binding action: %w", err)
			}
			if err := viper.BindPFlag("includedfuncregions", cmd.Flags().Lookup("included-func-regions")); err != nil {
				return fmt.Errorf("error binding action: %w", err)
			}
			if err := viper.BindPFlag("snsTopicArn", cmd.Flags().Lookup("sns-topic-arn")); err != nil {
				return fmt.Errorf("error binding snsTopicArn: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Key = viper.GetString("publickey")
			awsClient := clients.NewAwsClient(viper.GetString("accesskey"), viper.GetString("secretkey"), viper.GetString("bucket"), viper.GetString("region"), lambdaRegion)
			return verify.Verify(awsClient, args[0], o, cmd.Context(), viper.GetString("action"), viper.GetString("snsTopicArn"), viper.GetString("region"),
				viper.GetStringSlice("includedfunctagkeys"), viper.GetStringSlice("includedfuncregions"))
		},
	}
	cmd.Flags().StringVar(&lambdaRegion, "function-region", "", "aws region where the verified lambda runs")
	cmd.MarkFlagRequired("function-region") //nolint:errcheck
	o.AddFlags(cmd)
	initAwsVerifyFlags(cmd)
	return cmd
}

func initAwsVerifyFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&opt.Config, "config", "", "config file (default: $HOME/.fs)")
	cmd.Flags().String("aws-access-key", "", "aws access key")
	cmd.Flags().String("aws-secret-key", "", "aws secret key")
	cmd.Flags().String("region", "", "aws region to perform the operation against")
	cmd.Flags().String("bucket", "", "s3 bucket to work against")
	cmd.Flags().String("key", "", "public key")
	cmd.Flags().String("action", "", "action to perform upon validation result")
	cmd.Flags().StringSlice("included-func-tags", []string{}, "function tags to include when verifying")
	cmd.Flags().StringSlice("included-func-regions", []string{}, "function regions to include when verifying")
	cmd.Flags().String("sns-topic-arn", "", "SNS topic ARN for notifications")
}

func AwsInit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "initialize configuration and deploy to aws",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var input i.AWSInput
			if err := input.ReceiveParameters(); err != nil {
				return err
			}
			if input.Bucket == "" {
				input.Bucket = clients.FunctionClarityBucketName
			}
			var configForDeployment i.AWSInput
			configForDeployment.Bucket = input.Bucket
			configForDeployment.Action = input.Action
			configForDeployment.Region = input.Region
			configForDeployment.IsKeyless = input.IsKeyless
			configForDeployment.SnsTopicArn = input.SnsTopicArn
			configForDeployment.IncludedFuncTagKeys = input.IncludedFuncTagKeys
			configForDeployment.IncludedFuncRegions = input.IncludedFuncRegions
			onlyCreateConfig, err := cmd.Flags().GetBool("only-create-config")
			if err != nil {
				return err
			}
			if !onlyCreateConfig {
				awsClient := clients.NewAwsClientInit(input.AccessKey, input.SecretKey, input.Region)
				err = awsClient.DeployFunctionClarity(input.CloudTrail.Name, input.PublicKey, configForDeployment)
				if err != nil {
					return fmt.Errorf("failed to deploy function clarity: %w", err)
				}
			}
			d, err := yaml.Marshal(&input)
			if err != nil {
				return fmt.Errorf("init command fail: %w", err)
			}

			h, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("init command fail: %w", err)
			}
			f, err := os.Create(h + "/.fc")
			if err != nil {
				return fmt.Errorf("init command fail: %w", err)
			}
			defer f.Close()
			if _, err = f.Write(d); err != nil {
				return fmt.Errorf("init command fail: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().Bool("only-create-config", false, "determine whether to only create config file without deployment")
	return cmd
}

func AwsDeploy() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "deploy to aws using config file",
		Long:  "deploy to aws, this command relies on a configuration file to exist under ~/.fc, to create a config file run the command: 'init aws --only-create-config'",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var configForDeployment i.AWSInput
			configForDeployment.Bucket = viper.GetString("bucket")
			configForDeployment.Action = viper.GetString("action")
			configForDeployment.Region = viper.GetString("region")
			configForDeployment.IsKeyless = viper.GetBool("iskeyless")
			configForDeployment.SnsTopicArn = viper.GetString("snsTopicArn")
			configForDeployment.IncludedFuncTagKeys = viper.GetStringSlice("includedfunctagkeys")
			configForDeployment.IncludedFuncRegions = viper.GetStringSlice("includedfuncregions")
			awsClient := clients.NewAwsClientInit(viper.GetString("accesskey"), viper.GetString("secretkey"), viper.GetString("region"))
			err := awsClient.DeployFunctionClarity(viper.GetString("cloudtrail.name"), viper.GetString("publickey"), configForDeployment)
			if err != nil {
				return fmt.Errorf("failed to deploy function clarity: %w", err)
			}
			return nil
		},
	}
	return cmd
}

func AwsUpdateFuncConfig() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "update verifier function runtime configuration",
		Long: "update verifier function runtime configuration, the following configurations can be updated:\n" +
			"- included functions tags\n" +
			"- included functions regions\n" +
			"- sns topic arn\n" +
			"- action",
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := viper.BindPFlag("accessKey", cmd.Flags().Lookup("aws-access-key")); err != nil {
				return fmt.Errorf("error binding accessKey: %w", err)
			}
			if err := viper.BindPFlag("secretKey", cmd.Flags().Lookup("aws-secret-key")); err != nil {
				return fmt.Errorf("error binding secretKey: %w", err)
			}
			if err := viper.BindPFlag("region", cmd.Flags().Lookup("region")); err != nil {
				return fmt.Errorf("error binding region: %w", err)
			}
			if err := viper.BindPFlag("action", cmd.Flags().Lookup("action")); err != nil {
				return fmt.Errorf("error binding action: %w", err)
			}
			if err := viper.BindPFlag("includedfunctagkeys", cmd.Flags().Lookup("included-func-tags")); err != nil {
				return fmt.Errorf("error binding action: %w", err)
			}
			if err := viper.BindPFlag("includedfuncregions", cmd.Flags().Lookup("included-func-regions")); err != nil {
				return fmt.Errorf("error binding action: %w", err)
			}
			if err := viper.BindPFlag("snsTopicArn", cmd.Flags().Lookup("sns-topic-arn")); err != nil {
				return fmt.Errorf("error binding snsTopicArn: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			awsClient := clients.NewAwsClientInit(viper.GetString("accesskey"), viper.GetString("secretkey"), viper.GetString("region"))
			includedFuncTagKeysStringArray := viper.GetStringSlice("includedfunctagkeys")
			includedFuncTagKeys := &includedFuncTagKeysStringArray
			if !viper.IsSet("includedfunctagkeys") && !cmd.Flags().Lookup("included-func-tags").Changed {
				includedFuncTagKeys = nil
			}
			actionString := viper.GetString("action")
			action := &actionString
			if !viper.IsSet("action") && !cmd.Flags().Lookup("action").Changed {
				action = nil
			}
			includedFuncRegionsStringArray := viper.GetStringSlice("includedfuncregions")
			includedFuncRegions := &includedFuncRegionsStringArray
			if !viper.IsSet("includedfuncregions") && !cmd.Flags().Lookup("included-func-regions").Changed {
				includedFuncRegions = nil
			}
			topicString := viper.GetString("snsTopicArn")
			topic := &topicString
			if !viper.IsSet("snsTopicArn") && !cmd.Flags().Lookup("sns-topic-arn").Changed {
				topic = nil
			}
			return awsClient.UpdateVerifierFucConfig(action, includedFuncTagKeys,
				includedFuncRegions, topic)
		},
	}
	initAwsUpdateConfigFlags(cmd)
	return cmd
}

func initAwsUpdateConfigFlags(cmd *cobra.Command) {
	cmd.Flags().String("aws-access-key", "", "aws access key")
	cmd.Flags().String("aws-secret-key", "", "aws secret key")
	cmd.Flags().String("region", "", "aws region where function clarity is deployed")
	cmd.Flags().String("action", "", "action to perform upon validation result")
	cmd.Flags().StringSlice("included-func-tags", []string{}, "function tags to include when verifying")
	cmd.Flags().StringSlice("included-func-regions", []string{}, "function regions to include when verifying")
	cmd.Flags().String("sns-topic-arn", "", "SNS topic ARN for notifications")
}
