/*
Copyright 2017-2020 by the contributors.

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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"sigs.k8s.io/aws-iam-authenticator/pkg/config"
	"sigs.k8s.io/aws-iam-authenticator/pkg/ec2provider"
	"sigs.k8s.io/aws-iam-authenticator/pkg/errutil"
	"sigs.k8s.io/aws-iam-authenticator/pkg/fileutil"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper/configmap"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper/crd"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper/dynamicfile"
	"sigs.k8s.io/aws-iam-authenticator/pkg/mapper/file"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"

	awsarn "github.com/aws/aws-sdk-go/aws/arn"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
)

// tokenReviewDenyJSON is a static encoding (at init time) of the 'deny' TokenReview
var tokenReviewDenyJSON = func() []byte {
	res, err := json.Marshal(authenticationv1beta1.TokenReview{
		Status: authenticationv1beta1.TokenReviewStatus{
			Authenticated: false,
		},
	})
	if err != nil {
		logrus.WithError(err).Fatal("could not create static 'deny' JSON response")
	}
	return res
}()

// Pattern to match EC2 instance IDs
var (
	instanceIDPattern = regexp.MustCompile("^i-(\\w{8}|\\w{17})$")
)

// server state (internal)
type handler struct {
	http.ServeMux
	mutex                     sync.RWMutex
	verifier                  token.Verifier
	ec2Provider               ec2provider.EC2Provider
	clusterID                 string
	backendMapper             BackendMapper
	backendModeConfigInitDone bool
	scrubbedAccounts          []string
	cfg                       config.Config
}

// New authentication webhook server.
func New(cfg config.Config, stopCh <-chan struct{}) *Server {
	c := &Server{
		Config: cfg,
	}

	backendMapper, err := BuildMapperChain(cfg, cfg.BackendMode)
	if err != nil {
		logrus.Fatalf("failed to build mapper chain: %v", err)
	}

	for _, mapping := range c.RoleMappings {
		if mapping.RoleARN != "" {
			logrus.WithFields(logrus.Fields{
				"role":     mapping.RoleARN,
				"username": mapping.Username,
				"groups":   mapping.Groups,
			}).Infof("mapping IAM role")
		} else if mapping.SSO != nil {
			logrus.WithFields(logrus.Fields{
				"sso":      *mapping.SSO,
				"username": mapping.Username,
				"groups":   mapping.Groups,
			}).Infof("mapping IAM role")
		}
	}
	for _, mapping := range c.UserMappings {
		logrus.WithFields(logrus.Fields{
			"user":     mapping.UserARN,
			"username": mapping.Username,
			"groups":   mapping.Groups,
		}).Infof("mapping IAM user")
	}

	for _, account := range c.AutoMappedAWSAccounts {
		logrus.WithField("accountID", account).Infof("mapping IAM Account")
	}

	cert, err := c.GetOrCreateX509KeyPair()
	if err != nil {
		logrus.WithError(err).Fatalf("could not load/generate a certificate")
	}

	if !c.KubeconfigPregenerated {
		if err := c.GenerateWebhookKubeconfig(); err != nil {
			logrus.WithError(err).Fatalf("could not create webhook kubeconfig")
		}
	}

	// start a TLS listener with our custom certs
	listener, err := tls.Listen("tcp", c.ListenAddr(), &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		logrus.WithError(err).Fatal("could not open TLS listener")
	}

	// create a logrus logger for HTTP error logs
	errLog := logrus.WithField("http", "error").Writer()
	defer errLog.Close()

	logrus.Infof("listening on %s", listener.Addr())
	logrus.Infof("reconfigure your apiserver with `--authentication-token-webhook-config-file=%s` to enable (assuming default hostPath mounts)", c.GenerateKubeconfigPath)
	internalHandler := c.getHandler(backendMapper, c.EC2DescribeInstancesQps, c.EC2DescribeInstancesBurst, stopCh)
	c.httpServer = http.Server{
		ErrorLog: log.New(errLog, "", 0),
		Handler:  internalHandler,
	}
	c.listener = listener
	c.internalHandler = internalHandler
	return c
}

// Run will run the server closing the connection if there is a struct on the channel
func (c *Server) Run(stopCh <-chan struct{}) {

	defer c.listener.Close()

	go func() {
		http.ListenAndServe(":21363", &healthzHandler{})
	}()
	go func() {
		for {
			select {
			case <-stopCh:
				logrus.Info("shut down mapper before return from Run")
				close(c.internalHandler.backendMapper.mapperStopCh)
				return
			}
		}
	}()
	if err := c.httpServer.Serve(c.listener); err != nil {
		logrus.WithError(err).Warning("http server exited")
	}
}

func (c *Server) Close() {
	c.listener.Close()

	ctxTimeout, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	c.httpServer.Shutdown(ctxTimeout)
}

type healthzHandler struct{}

func (m *healthzHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "ok")
}
func (c *Server) getHandler(backendMapper BackendMapper, ec2DescribeQps int, ec2DescribeBurst int, stopCh <-chan struct{}) *handler {
	if c.ServerEC2DescribeInstancesRoleARN != "" {
		_, err := awsarn.Parse(c.ServerEC2DescribeInstancesRoleARN)
		if err != nil {
			panic(fmt.Sprintf("describeinstancesrole %s is not a valid arn", c.ServerEC2DescribeInstancesRoleARN))
		}
	}
	sess := session.Must(session.NewSession())
	ec2metadata := ec2metadata.New(sess)
	instanceRegion, err := ec2metadata.Region()
	if err != nil {
		logrus.WithError(err).Errorln("Region not found in instance metadata.")
	}

	h := &handler{
		verifier:                  token.NewVerifier(c.ClusterID, c.PartitionID, instanceRegion),
		ec2Provider:               ec2provider.New(c.ServerEC2DescribeInstancesRoleARN, c.SourceARN, instanceRegion, ec2DescribeQps, ec2DescribeBurst),
		clusterID:                 c.ClusterID,
		backendMapper:             backendMapper,
		scrubbedAccounts:          c.Config.ScrubbedAWSAccounts,
		cfg:                       c.Config,
		backendModeConfigInitDone: false,
	}

	h.HandleFunc("/authenticate", h.authenticateEndpoint)
	h.Handle("/metrics", promhttp.Handler())
	h.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	})
	logrus.Infof("Starting the h.ec2Provider.startEc2DescribeBatchProcessing ")
	go h.ec2Provider.StartEc2DescribeBatchProcessing()
	if strings.TrimSpace(c.DynamicBackendModePath) != "" {
		fileutil.StartLoadDynamicFile(c.DynamicBackendModePath, h, stopCh)
	}

	return h
}

func BuildMapperChain(cfg config.Config, modes []string) (BackendMapper, error) {
	backendMapper := BackendMapper{
		mappers:      []mapper.Mapper{},
		mapperStopCh: make(chan struct{}),
	}
	for _, mode := range modes {
		switch mode {
		case mapper.ModeFile:
			fallthrough
		case mapper.ModeMountedFile:
			fileMapper, err := file.NewFileMapper(cfg)
			if err != nil {
				return BackendMapper{}, fmt.Errorf("backend-mode %q creation failed: %v", mode, err)
			}
			backendMapper.mappers = append(backendMapper.mappers, fileMapper)
		case mapper.ModeConfigMap:
			fallthrough
		case mapper.ModeEKSConfigMap:
			configMapMapper, err := configmap.NewConfigMapMapper(cfg)
			if err != nil {
				return BackendMapper{}, fmt.Errorf("backend-mode %q creation failed: %v", mode, err)
			}
			backendMapper.mappers = append(backendMapper.mappers, configMapMapper)
		case mapper.ModeCRD:
			crdMapper, err := crd.NewCRDMapper(cfg)
			if err != nil {
				return BackendMapper{}, fmt.Errorf("backend-mode %q creation failed: %v", mode, err)
			}
			backendMapper.mappers = append(backendMapper.mappers, crdMapper)
		case mapper.ModeDynamicFile:
			dynamicFileMapper, err := dynamicfile.NewDynamicFileMapper(cfg)
			if err != nil {
				return BackendMapper{}, fmt.Errorf("backend-mode %q creation failed: %v", mode, err)
			}
			backendMapper.mappers = append(backendMapper.mappers, dynamicFileMapper)
		default:
			return BackendMapper{}, fmt.Errorf("backend-mode %q is not a valid mode", mode)
		}
	}
	for _, m := range backendMapper.mappers {
		logrus.Infof("starting mapper %q", m.Name())
		if err := m.Start(backendMapper.mapperStopCh); err != nil {
			logrus.Fatalf("start mapper %q failed", m.Name())
		}
		if backendMapper.currentModes != "" {
			backendMapper.currentModes = backendMapper.currentModes + " " + m.Name()
		} else {
			backendMapper.currentModes = m.Name()
		}
	}
	return backendMapper, nil
}

func duration(start time.Time) float64 {
	return time.Since(start).Seconds()
}

func (h *handler) isLoggableIdentity(identity *token.Identity) bool {
	for _, account := range h.scrubbedAccounts {
		if identity.AccountID == account {
			return false
		}
	}
	return true
}

func (h *handler) authenticateEndpoint(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	log := logrus.WithFields(logrus.Fields{
		"path":   req.URL.Path,
		"client": req.RemoteAddr,
		"method": req.Method,
	})

	if req.Method != http.MethodPost {
		log.Error("unexpected request method")
		http.Error(w, "expected POST", http.StatusMethodNotAllowed)
		metrics.Get().Latency.WithLabelValues(metrics.Malformed).Observe(duration(start))
		return
	}
	if req.Body == nil {
		log.Error("empty request body")
		http.Error(w, "expected a request body", http.StatusBadRequest)
		metrics.Get().Latency.WithLabelValues(metrics.Malformed).Observe(duration(start))
		return
	}
	defer req.Body.Close()

	var tokenReview authenticationv1beta1.TokenReview
	if err := json.NewDecoder(req.Body).Decode(&tokenReview); err != nil {
		log.WithError(err).Error("could not parse request body")
		http.Error(w, "expected a request body to be a TokenReview", http.StatusBadRequest)
		metrics.Get().Latency.WithLabelValues(metrics.Malformed).Observe(duration(start))
		return
	}

	// TODO: rate limit here so we can't be tricked into spamming AWS

	// all responses from here down have JSON bodies
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	// if the token is invalid, reject with a 403
	identity, err := h.verifier.Verify(tokenReview.Spec.Token)
	if err != nil {
		if throttleErr, ok := err.(token.STSThrottling); ok {
			metrics.Get().Latency.WithLabelValues(metrics.STSThrottling).Observe(duration(start))
			log.WithError(throttleErr).WithField("accountID", throttleErr.AccountID()).Warn("access denied")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write(tokenReviewDenyJSON)
			return
		} else if _, ok := err.(token.STSError); ok {
			metrics.Get().Latency.WithLabelValues(metrics.STSError).Observe(duration(start))
		} else {
			metrics.Get().Latency.WithLabelValues(metrics.Invalid).Observe(duration(start))
		}
		log.WithError(err).Warn("access denied")
		w.WriteHeader(http.StatusForbidden)
		w.Write(tokenReviewDenyJSON)
		return
	}

	if h.isLoggableIdentity(identity) {
		log.WithFields(logrus.Fields{
			"accesskeyid": identity.AccessKeyID,
			"arn":         identity.ARN,
			"accountid":   identity.AccountID,
			"userid":      identity.UserID,
			"session":     identity.SessionName,
		}).Info("STS response")

		// look up the ARN in each of our mappings to fill in the username and groups
		log = log.WithField("arn", identity.CanonicalARN)
	}

	username, groups, err := h.doMapping(identity)
	if err != nil {
		metrics.Get().Latency.WithLabelValues(metrics.Unknown).Observe(duration(start))
		log.WithError(err).Warn("access denied")
		w.WriteHeader(http.StatusForbidden)
		w.Write(tokenReviewDenyJSON)
		return
	}

	uid := fmt.Sprintf("aws-iam-authenticator:administrative:%s", username)
	if h.isLoggableIdentity(identity) {
		// use a prefixed UID that includes the AWS account ID and AWS user ID ("AROAAAAAAAAAAAAAAAAAA")
		uid = fmt.Sprintf("aws-iam-authenticator:%s:%s", identity.AccountID, identity.UserID)
	}

	// the token is valid and the role is mapped, return success!
	log.WithFields(logrus.Fields{
		"username": username,
		"uid":      uid,
		"groups":   groups,
	}).Info("access granted")
	metrics.Get().Latency.WithLabelValues(metrics.Success).Observe(duration(start))
	w.WriteHeader(http.StatusOK)

	userExtra := map[string]authenticationv1beta1.ExtraValue{}
	if h.isLoggableIdentity(identity) {
		userExtra["arn"] = authenticationv1beta1.ExtraValue{identity.ARN}
		userExtra["canonicalArn"] = authenticationv1beta1.ExtraValue{identity.CanonicalARN}
		userExtra["sessionName"] = authenticationv1beta1.ExtraValue{identity.SessionName}
		userExtra["accessKeyId"] = authenticationv1beta1.ExtraValue{identity.AccessKeyID}
		userExtra["principalId"] = authenticationv1beta1.ExtraValue{identity.UserID}
		userExtra["sigs.k8s.io/aws-iam-authenticator/principalId"] = authenticationv1beta1.ExtraValue{identity.UserID}
	}

	json.NewEncoder(w).Encode(authenticationv1beta1.TokenReview{
		Status: authenticationv1beta1.TokenReviewStatus{
			Authenticated: true,
			User: authenticationv1beta1.UserInfo{
				Username: username,
				UID:      uid,
				Groups:   groups,
				Extra:    userExtra,
			},
		},
	})
}

func ReservedPrefixExists(username string, reservedList []string) bool {
	for _, prefix := range reservedList {
		if len(prefix) > 0 && strings.HasPrefix(username, prefix) {
			return true
		}
	}
	return false
}

func (h *handler) doMapping(identity *token.Identity) (string, []string, error) {
	var errs []error

	for _, m := range h.backendMapper.mappers {
		mapping, err := m.Map(identity)
		if err == nil {
			// Mapping found, try to render any templates like {{EC2PrivateDNSName}}
			username, groups, err := h.renderTemplates(*mapping, identity)
			if err != nil {
				return "", nil, fmt.Errorf("mapper %s renderTemplates error: %v", m.Name(), err)
			}
			if len(m.UsernamePrefixReserveList()) > 0 && ReservedPrefixExists(username, m.UsernamePrefixReserveList()) {
				return "", nil, fmt.Errorf("invalid username '%s' for mapper %s: username must not begin with with the following prefixes: %v", username, m.Name(), m.UsernamePrefixReserveList())
			}
			return username, groups, nil
		} else {
			if err != errutil.ErrNotMapped {
				errs = append(errs, fmt.Errorf("mapper %s Map error: %v", m.Name(), err))
			}

			if m.IsAccountAllowed(identity.AccountID) {
				return identity.CanonicalARN, []string{}, nil
			}
		}
	}

	if len(errs) > 0 {
		return "", nil, utilerrors.NewAggregate(errs)
	}
	return "", nil, errutil.ErrNotMapped
}

func (h *handler) renderTemplates(mapping config.IdentityMapping, identity *token.Identity) (string, []string, error) {
	var username string
	groups := []string{}
	var err error

	userPattern := mapping.Username
	username, err = h.renderTemplate(userPattern, identity)
	if err != nil {
		return "", nil, fmt.Errorf("error rendering username template %q: %s", userPattern, err.Error())
	}

	for _, groupPattern := range mapping.Groups {
		group, err := h.renderTemplate(groupPattern, identity)
		if err != nil {
			return "", nil, fmt.Errorf("error rendering group template %q: %s", groupPattern, err.Error())
		}
		groups = append(groups, group)
	}

	return username, groups, nil
}

func (h *handler) renderTemplate(template string, identity *token.Identity) (string, error) {
	// Private DNS requires EC2 API call
	if strings.Contains(template, "{{EC2PrivateDNSName}}") {
		if !instanceIDPattern.MatchString(identity.SessionName) {
			return "", fmt.Errorf("SessionName did not contain an instance id")
		}
		privateDNSName, err := h.ec2Provider.GetPrivateDNSName(identity.SessionName)
		if err != nil {
			return "", err
		}
		template = strings.Replace(template, "{{EC2PrivateDNSName}}", privateDNSName, -1)
	}

	template = strings.Replace(template, "{{AccountID}}", identity.AccountID, -1)
	sessionName := strings.Replace(identity.SessionName, "@", "-", -1)
	template = strings.Replace(template, "{{SessionName}}", sessionName, -1)
	template = strings.Replace(template, "{{SessionNameRaw}}", identity.SessionName, -1)
	template = strings.Replace(template, "{{AccessKeyID}}", identity.AccessKeyID, -1)

	return template, nil
}

func (h *handler) CallBackForFileLoad(dynamicContent []byte) error {
	var backendModes BackendModeConfig
	logrus.Infof("BackendMode dynamic file got changed to %s", string(dynamicContent))
	err := json.Unmarshal(dynamicContent, &backendModes)
	if err != nil {
		logrus.Infof("CallBackForFileLoad: could not unmarshal dynamic file.")
		return err
	}
	if h.backendMapper.currentModes != backendModes.BackendMode {
		logrus.Infof("BackendMode dynamic file got changed, %s different from current mode %s, rebuild mapper", backendModes.BackendMode, h.backendMapper.currentModes)
		newMapper, err := BuildMapperChain(h.cfg, strings.Split(backendModes.BackendMode, " "))
		if err == nil && len(newMapper.mappers) > 0 {
			// replace the mapper
			close(h.backendMapper.mapperStopCh)
			h.backendMapper = newMapper
		} else {
			return err
		}
	} else {
		logrus.Infof("BackendMode dynamic file got changed, but same with current mode, skip rebuild mapper")
	}

	// when instance or container restarts, the backendend mode config is (re)loaded and the latency metric is calculated
	// regardless if there was a change upstream, and thus can emit an incorrect latency value
	// so a workaround is to skip the first time the metric is calculated, and only emit metris after
	// as we know any subsequent calculations are from a valid change upstream
	if h.backendModeConfigInitDone {
		latency, err := fileutil.CalculateTimeDeltaFromUnixInSeconds(backendModes.LastUpdatedDateTime)
		if err != nil {
			logrus.Errorf("error parsing latency for dynamic backend mode file: %v", err)
		} else {
			metrics.Get().E2ELatency.WithLabelValues("dynamic_backend_mode").Observe(float64(latency))
			logrus.WithFields(logrus.Fields{
				"Version": backendModes.Version,
				"Type":    "dynamic_backend_mode",
				"Latency": latency,
			}).Infof("logging latency metric")
		}
	}
	h.backendModeConfigInitDone = true

	if h.backendMapper.currentModes == mapper.ModeDynamicFile {
		metrics.Get().DynamicFileOnly.Set(1)
	} else if strings.Contains(h.backendMapper.currentModes, mapper.ModeDynamicFile) {
		metrics.Get().DynamicFileEnabled.Set(1)
	}

	return nil
}

func (h *handler) CallBackForFileDeletion() error {
	logrus.Infof("BackendMode dynamic file got deleted")
	backendMapper, err := BuildMapperChain(h.cfg, h.cfg.BackendMode)
	if err == nil && len(backendMapper.mappers) > 0 {
		// replace the mapper
		close(h.backendMapper.mapperStopCh)
		h.backendMapper = backendMapper
	} else {
		return err
	}
	return nil
}
