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

package server

import (
	"net"
	"net/http"

	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
	"sigs.k8s.io/aws-iam-authenticator/pkg/regions"
)

// Server for the authentication webhook.
type Server struct {
	// Config is the whole configuration of aws-iam-authenticator used for valid keys and certs, kubeconfig, and so on
	config.Config
	httpServer       http.Server
	listener         net.Listener
	internalHandler  *handler
	endpointVerifier regions.EndpointVerifier
}

type BackendMapper struct {
	mappers      []mapper.Mapper
	mapperStopCh chan struct{}
	currentModes string
}

// AccessConfig represents the configuration format for cluster access config via backend mode.
type BackendModeConfig struct {
	// Time that the object takes from update time to load time
	LastUpdatedDateTime string `json:"LastUpdatedDateTime"`
	// Version is the version number of the update
	Version     string `json:"Version"`
	BackendMode string `json:"backendMode"`
}
