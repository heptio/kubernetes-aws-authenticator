//go:build !no_verify

/*
Copyright 2017 by the contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"sigs.k8s.io/aws-iam-authenticator/pkg/regions"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"

	aws_config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a token for debugging purpose",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		tok := viper.GetString("token")
		output := viper.GetString("output")
		clusterID := viper.GetString("clusterID")
		partition := viper.GetString("partition")
		endpointValidationMode := viper.GetString("server.endpointValidationMode")
		endpointValidationFile := viper.GetString("server.endpointValidationFile")

		if tok == "" {
			fmt.Fprintf(os.Stderr, "error: token not specified\n")
			cmd.Usage()
			os.Exit(1)
		}

		if clusterID == "" {
			fmt.Fprintf(os.Stderr, "error: cluster ID not specified\n")
			cmd.Usage()
			os.Exit(1)
		}

		var discoverer regions.Discoverer
		switch endpointValidationMode {
		case "Legacy", "":
			// TODO: get region?
			discoverer = regions.NewSdkV1Discoverer(partition, "")
		case "API":
			awscfg, err := aws_config.LoadDefaultConfig(context.TODO())
			if err != nil {
				logrus.WithError(err).Fatal("unable to create AWS config")
			}
			client := account.NewFromConfig(awscfg)
			discoverer = regions.NewAPIDiscoverer(client, partition)
		case "File":
			discoverer = regions.NewFileDiscoverer(endpointValidationFile)
		default:
			// Defensive check here in case the cmd validation fails
			logrus.WithField("server.endpointValidationMode", endpointValidationMode).Fatalf(
				`invalid EndpointValidationMode, must be one of "Legacy", "API", or "File"`)
		}
		endpointVerifier, err := regions.NewEndpointVerifier(discoverer)
		if err != nil {
			logrus.WithError(err).Fatal("could not create endpoint verifier")
		}

		id, err := token.NewVerifier(clusterID, endpointVerifier).Verify(tok)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not verify token: %v\n", err)
			os.Exit(1)
		}

		if output == "json" {
			value, err := json.MarshalIndent(id, "", "    ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "could not unmarshal token: %v\n", err)
			}
			fmt.Printf("%s\n", value)
		} else {
			fmt.Printf("%+v\n", id)
		}
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringP("token", "t", "", "Token to verify")
	verifyCmd.Flags().StringP("output", "o", "", "Output format. Only `json` is supported currently.")
	viper.BindPFlag("token", verifyCmd.Flags().Lookup("token"))
	viper.BindPFlag("output", verifyCmd.Flags().Lookup("output"))

	partitionKeys := []string{
		"aws",
		"aws-cn",
		"aws-us-gov",
		"aws-iso",
		"aws-iso-b",
		"aws-iso-e",
		"aws-iso-f",
	}
	verifyCmd.Flags().String("partition",
		"aws",
		fmt.Sprintf("The AWS partition. Must be one of: %v", partitionKeys))
	viper.BindPFlag("partition", verifyCmd.Flags().Lookup("partition"))

	verifyCmd.Flags().String("endpoint-validation-mode",
		"Legacy",
		`The method for discovering valid regions. Must be one of "Legacy", "File", or "API"`)
	viper.BindPFlag("server.endpointValidationMode", verifyCmd.Flags().Lookup("endpoint-validation-mode"))

	verifyCmd.Flags().String("endpoint-validation-file", "",
		`The file to use for endpoint validation. Only used if endpoint-validation-mode is "File"`)
	viper.BindPFlag("server.endpointValidationFile", verifyCmd.Flags().Lookup("endpoint-validation-file"))

}
