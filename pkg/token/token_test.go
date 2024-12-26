package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication"
	clientauthv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
)

func TestMain(m *testing.M) {
	metrics.InitMetrics(prometheus.NewRegistry())
	m.Run()
}

type testEndpointVerifier struct {
	resp bool
}

func (v *testEndpointVerifier) Verify(string) bool {
	return v.resp
}

func (v *testEndpointVerifier) Stop() error { return nil }

func validationErrorTest(t *testing.T, token string, expectedErr string) {
	t.Helper()

	_, err := NewVerifier("", &testEndpointVerifier{true}).(tokenVerifier).Verify(token)
	errorContains(t, err, expectedErr)
}

func validationSuccessTest(t *testing.T, token string) {
	t.Helper()
	arn := "arn:aws:iam::123456789012:user/Alice"
	account := "123456789012"
	userID := "Alice"
	_, err := newVerifier(true, 200, jsonResponse(arn, account, userID), nil).Verify(token)
	if err != nil {
		t.Errorf("received unexpected error: %s", err)
	}
}

func errorContains(t *testing.T, err error, expectedErr string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("err should have contained '%s' was '%s'", expectedErr, err)
	}
}

func assertSTSError(t *testing.T, err error) {
	t.Helper()
	if _, ok := err.(STSError); !ok {
		t.Errorf("Expected err %v to be an STSError but was not", err)
	}
}

func assertSTSThrottling(t *testing.T, err error) {
	t.Helper()
	if _, ok := err.(STSThrottling); !ok {
		t.Errorf("Expected err %v to be an STSThrottling but was not", err)
	}
}

var (
	now        = time.Now()
	timeStr    = now.UTC().Format("20060102T150405Z")
	validURL   = fmt.Sprintf("https://sts.amazonaws.com/?action=GetCallerIdentity&X-Amz-Credential=ASIABCDEFGHIJKLMNOPQ%%2F20191216%%2Fus-west-2%%2Fs3%%2Faws4_request&x-amz-signedheaders=x-k8s-aws-id&x-amz-expires=60&x-amz-date=%s", timeStr)
	validToken = toToken(validURL)
)

func toToken(url string) string {
	return v1Prefix + base64.RawURLEncoding.EncodeToString([]byte(url))
}

func newVerifier(validRegion bool, statusCode int, body string, err error) Verifier {
	var rc io.ReadCloser
	if body != "" {
		rc = io.NopCloser(bytes.NewReader([]byte(body)))
	}
	return tokenVerifier{
		client: &http.Client{
			Transport: &roundTripper{
				err: err,
				resp: &http.Response{
					StatusCode: statusCode,
					Body:       rc,
				},
			},
		},
		endpointVerifier: &testEndpointVerifier{validRegion},
	}
}

type roundTripper struct {
	err  error
	resp *http.Response
}

type errorReadCloser struct {
}

func (r errorReadCloser) Read(b []byte) (int, error) {
	return 0, errors.New("An Error")
}

func (r errorReadCloser) Close() error {
	return nil
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return rt.resp, rt.err
}

func jsonResponse(arn, account, userid string) string {
	response := getCallerIdentityWrapper{}
	response.GetCallerIdentityResponse.GetCallerIdentityResult.Account = account
	response.GetCallerIdentityResponse.GetCallerIdentityResult.Arn = arn
	response.GetCallerIdentityResponse.GetCallerIdentityResult.UserID = userid
	data, _ := json.Marshal(response)
	return string(data)
}

func TestVerifyTokenPreSTSValidations(t *testing.T) {
	b := make([]byte, maxTokenLenBytes+1)
	s := string(b)
	validationErrorTest(t, s, "token is too large")
	validationErrorTest(t, "k8s-aws-v2.asdfasdfa", "token is missing expected \"k8s-aws-v1.\" prefix")
	validationErrorTest(t, "k8s-aws-v1.decodingerror", "illegal base64 data")

	validationErrorTest(t, toToken(":ab:cd.af:/asda"), "missing protocol scheme")
	validationErrorTest(t, toToken("http://"), "unexpected scheme")

	_, err := NewVerifier("", &testEndpointVerifier{false}).(tokenVerifier).Verify(toToken("https://google.com"))
	errorContains(t, err, fmt.Sprintf("unexpected hostname %q in pre-signed URL", "google.com"))

	validationErrorTest(t, toToken("https://sts.cn-north-1.amazonaws.com.cn/abc"), "unexpected path in pre-signed URL")
	validationErrorTest(t, toToken("https://sts.amazonaws.com/abc"), "unexpected path in pre-signed URL")
	validationErrorTest(t, toToken("https://sts.amazonaws.com/?NoInWhiteList=abc"), "non-whitelisted query parameter")
	validationErrorTest(t, toToken("https://sts.amazonaws.com/?action=get&action=post"), "query parameter with multiple values not supported")
	validationErrorTest(t, toToken("https://sts.amazonaws.com/?action=NotGetCallerIdenity"), "unexpected action parameter in pre-signed URL")
	validationErrorTest(t, toToken("https://sts.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=abc%3bx-k8s-aws-i%3bdef"), "client did not sign the x-k8s-aws-id header in the pre-signed URL")
	validationErrorTest(t, toToken(fmt.Sprintf("https://sts.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=9999999", timeStr)), "invalid X-Amz-Expires parameter in pre-signed URL")
	validationErrorTest(t, toToken("https://sts.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=xxxxxxx&x-amz-expires=60"), "error parsing X-Amz-Date parameter")
	validationErrorTest(t, toToken("https://sts.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=19900422T010203Z&x-amz-expires=60"), "X-Amz-Date parameter is expired")
	validationErrorTest(t, toToken(fmt.Sprintf("https://sts.sa-east-1.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=60%%gh", timeStr)), "input token was not properly formatted: malformed query parameter")
	validationSuccessTest(t, toToken(fmt.Sprintf("https://sts.us-east-2.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=60", timeStr)))
	validationSuccessTest(t, toToken(fmt.Sprintf("https://sts.ap-northeast-2.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=60", timeStr)))
	validationSuccessTest(t, toToken(fmt.Sprintf("https://sts.ca-central-1.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=60", timeStr)))
	validationSuccessTest(t, toToken(fmt.Sprintf("https://sts.eu-west-1.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=60", timeStr)))
	validationSuccessTest(t, toToken(fmt.Sprintf("https://sts.sa-east-1.amazonaws.com/?action=GetCallerIdentity&x-amz-signedheaders=x-k8s-aws-id&x-amz-date=%s&x-amz-expires=60", timeStr)))
	validationErrorTest(t, toToken(fmt.Sprintf("https://sts.us-west-2.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIAAAAAAAAAAAAAAAAA%%2F20220601%%2Fus-west-2%%2Fsts%%2Faws4_request&X-Amz-Date=%s&X-Amz-Expires=900&X-Amz-Security-Token=XXXXXXXXXXXXX&X-Amz-SignedHeaders=host%%3Bx-k8s-aws-id&x-amz-credential=eve&X-Amz-Signature=999999999999999999", timeStr)), "input token was not properly formatted: duplicate query parameter found:")
}

func TestVerifyHTTPThrottling(t *testing.T) {
	testVerifier := newVerifier(true, 400, "{\\\"Error\\\":{\\\"Code\\\":\\\"Throttling\\\",\\\"Message\\\":\\\"Rate exceeded\\\",\\\"Type\\\":\\\"Sender\\\"},\\\"RequestId\\\":\\\"8c2d3520-24e1-4d5c-ac55-7e226335f447\\\"}", nil)
	_, err := testVerifier.Verify(validToken)
	errorContains(t, err, "sts getCallerIdentity was throttled")
	assertSTSThrottling(t, err)
}

func TestVerifyHTTPError(t *testing.T) {
	_, err := newVerifier(true, 0, "", errors.New("an error")).Verify(validToken)
	errorContains(t, err, "error during GET: an error")
	assertSTSError(t, err)
}

func TestVerifyHTTP403(t *testing.T) {
	_, err := newVerifier(true, 403, " ", nil).Verify(validToken)
	errorContains(t, err, "error from AWS (expected 200, got")
	assertSTSError(t, err)
}

func TestVerifyNoRedirectsFollowed(t *testing.T) {
	ts2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"UserId":"AROAIIRR6I5NDJBWMIRQQ:admin-session","Account":"111122223333","Arn":"arn:aws:sts::111122223333:assumed-role/Admin/admin-session"}`)
	}))
	defer ts2.Close()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ts2.URL, http.StatusFound)
	}))
	defer ts.Close()

	tokVerifier := NewVerifier("", &testEndpointVerifier{true}).(tokenVerifier)

	resp, err := tokVerifier.client.Get(ts.URL)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.Header.Get("Location") != ts2.URL && resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("%#v\n", resp)
		fmt.Println(string(body))
		t.Error("Unexpectedly followed redirect")
	}
}

func TestVerifyBodyReadError(t *testing.T) {
	verifier := tokenVerifier{
		client: &http.Client{
			Transport: &roundTripper{
				err: nil,
				resp: &http.Response{
					StatusCode: 200,
					Body:       errorReadCloser{},
				},
			},
		},
		endpointVerifier: &testEndpointVerifier{true},
	}
	_, err := verifier.Verify(validToken)
	errorContains(t, err, "error reading HTTP result")
	assertSTSError(t, err)
}

func TestVerifyUnmarshalJSONError(t *testing.T) {
	_, err := newVerifier(true, 200, "xxxx", nil).Verify(validToken)
	errorContains(t, err, "invalid character")
	assertSTSError(t, err)
}

func TestVerifyInvalidCanonicalARNError(t *testing.T) {
	_, err := newVerifier(true, 200, jsonResponse("arn", "1000", "userid"), nil).Verify(validToken)
	errorContains(t, err, "arn 'arn' is invalid:")
	assertSTSError(t, err)
}

func TestVerifyInvalidUserIDError(t *testing.T) {
	_, err := newVerifier(true, 200, jsonResponse("arn:aws:iam::123456789012:role/Alice", "123456789012", "not:vailid:userid"), nil).Verify(validToken)
	errorContains(t, err, "malformed UserID")
	assertSTSError(t, err)
}

func TestVerifyNoSession(t *testing.T) {
	arn := "arn:aws:iam::123456789012:user/Alice"
	account := "123456789012"
	userID := "Alice"
	accessKeyID := "ASIABCDEFGHIJKLMNOPQ"
	identity, err := newVerifier(true, 200, jsonResponse(arn, account, userID), nil).Verify(validToken)
	if err != nil {
		t.Errorf("expected error to be nil was %q", err)
	}
	if identity.AccessKeyID != accessKeyID {
		t.Errorf("expected AccessKeyID to be %q but was %q", accessKeyID, identity.AccessKeyID)
	}
	if identity.ARN != arn {
		t.Errorf("expected ARN to be %q but was %q", arn, identity.ARN)
	}
	if identity.CanonicalARN != arn {
		t.Errorf("expected CanonicalARN to be %q but was %q", arn, identity.CanonicalARN)
	}
	if identity.UserID != userID {
		t.Errorf("expected Username to be %q but was %q", userID, identity.UserID)
	}
}

func TestVerifySessionName(t *testing.T) {
	arn := "arn:aws:iam::123456789012:role/Alice"
	account := "123456789012"
	userID := "Alice"
	session := "session-name"
	identity, err := newVerifier(true, 200, jsonResponse(arn, account, userID+":"+session), nil).Verify(validToken)
	if err != nil {
		t.Errorf("expected error to be nil was %q", err)
	}
	if identity.UserID != userID {
		t.Errorf("expected Username to be %q but was %q", userID, identity.UserID)
	}
	if identity.SessionName != session {
		t.Errorf("expected Session to be %q but was %q", session, identity.SessionName)
	}
}

func TestVerifyCanonicalARN(t *testing.T) {
	arn := "arn:aws:sts::123456789012:assumed-role/Alice/extra"
	canonicalARN := "arn:aws:iam::123456789012:role/Alice"
	account := "123456789012"
	userID := "Alice"
	session := "session-name"
	identity, err := newVerifier(true, 200, jsonResponse(arn, account, userID+":"+session), nil).Verify(validToken)
	if err != nil {
		t.Errorf("expected error to be nil was %q", err)
	}
	if identity.ARN != arn {
		t.Errorf("expected ARN to be %q but was %q", arn, identity.ARN)
	}
	if identity.CanonicalARN != canonicalARN {
		t.Errorf("expected CannonicalARN to be %q but was %q", canonicalARN, identity.CanonicalARN)
	}
}

func TestFormatJson(t *testing.T) {
	cases := []struct {
		Name             string
		EnvKey           string
		ExpectApiVersion string
		IsMalformedEnv   bool
	}{
		{
			Name:             "Default",
			ExpectApiVersion: clientauthv1beta1.SchemeGroupVersion.String(),
		},
		{
			Name:             "Malformed KUBERNETES_EXEC_INFO",
			EnvKey:           "KUBERNETES_EXEC_INFO",
			IsMalformedEnv:   true,
			ExpectApiVersion: clientauthv1beta1.SchemeGroupVersion.String(),
		},
		{
			Name:             "KUBERNETES_EXEC_INFO with v1beta1",
			EnvKey:           "KUBERNETES_EXEC_INFO",
			ExpectApiVersion: clientauthv1beta1.SchemeGroupVersion.String(),
		},
		{
			Name:             "KUBERNETES_EXEC_INFO with v1",
			EnvKey:           "KUBERNETES_EXEC_INFO",
			ExpectApiVersion: clientauthv1.SchemeGroupVersion.String(),
		},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			expiry, _ := time.Parse(time.RFC3339, "2012-11-01T22:08:41+00:00")
			token := "token"
			g, _ := NewGenerator(true, true)

			if c.EnvKey != "" {
				marshal := make([]byte, 0)
				if !c.IsMalformedEnv {
					marshal, _ = json.Marshal(clientauthentication.ExecCredential{
						TypeMeta: v1.TypeMeta{
							Kind:       "ExecCredential",
							APIVersion: c.ExpectApiVersion,
						},
					})
				}

				os.Setenv(c.EnvKey, string(marshal))
			}

			jsonResponse := g.FormatJSON(Token{Token: token, Expiration: expiry})
			output := &clientauthentication.ExecCredential{}
			json.Unmarshal([]byte(jsonResponse), output)

			if output.TypeMeta.Kind != kindExecCredential {
				t.Errorf("expected Kind to be %s but was %s", kindExecCredential, output.TypeMeta.Kind)
			}

			if output.TypeMeta.APIVersion != c.ExpectApiVersion {
				t.Errorf("expected APIVersion to be %s but was %s", c.ExpectApiVersion, output.TypeMeta.APIVersion)
			}

			if output.Status.Token != token {
				t.Errorf("expected token to be %s but was %s", token, output.Status.Token)
			}

			if !output.Status.ExpirationTimestamp.Time.Equal(expiry) {
				t.Errorf("expected expiration to be %s but was %s", expiry, output.Status.ExpirationTimestamp)
			}

			os.Unsetenv(c.EnvKey)
		})
	}
}

func TestGetIdentityFromSTSResponse(t *testing.T) {
	var (
		accessKeyID = "AKIAVVVVVVVVVVVAGAVA"
		defaultID   = Identity{
			AccessKeyID: accessKeyID,
		}
		defaultAccount = "123456789012"
		rootUserARN    = "arn:aws:iam::123456789012:root"
		userARN        = "arn:aws:iam::123456789012:user/Alice"
		userID         = "AIDAIYCCCMMMMMMMMGGDA"
		fedUserID      = "123456789012:Alice"
		fedUserARN     = "arn:aws:sts::123456789012:federated-user/Alice"
		roleARN        = "arn:aws:iam::123456789012:role/Alice"
		roleID         = "AROAZZCCCNNNNNNNNFFFA"
	)

	cases := []struct {
		name          string
		inputID       Identity
		inputResponse getCallerIdentityWrapper
		expectedErr   bool
		want          Identity
	}{
		{
			name:          "Root User",
			inputID:       defaultID,
			inputResponse: response(defaultAccount, defaultAccount, rootUserARN),
			expectedErr:   false,
			want: Identity{
				ARN:          rootUserARN,
				CanonicalARN: rootUserARN,
				AccountID:    defaultAccount,
				UserID:       defaultAccount,
				AccessKeyID:  accessKeyID,
			},
		},
		{
			name:          "User",
			inputID:       defaultID,
			inputResponse: response(defaultAccount, userID, userARN),
			expectedErr:   false,
			want: Identity{
				ARN:          userARN,
				CanonicalARN: userARN,
				AccountID:    defaultAccount,
				UserID:       userID,
				AccessKeyID:  accessKeyID,
			},
		},
		{
			name:          "Role",
			inputID:       defaultID,
			inputResponse: response(defaultAccount, roleID, roleARN),
			expectedErr:   false,
			want: Identity{
				ARN:          roleARN,
				CanonicalARN: roleARN,
				AccountID:    defaultAccount,
				UserID:       roleID,
				AccessKeyID:  accessKeyID,
			},
		},
		{
			name:          "Federated User",
			inputID:       defaultID,
			inputResponse: response(defaultAccount, fedUserID, fedUserARN),
			expectedErr:   false,
			want: Identity{
				ARN:          fedUserARN,
				CanonicalARN: fedUserARN,
				AccountID:    defaultAccount,
				UserID:       fedUserID,
				AccessKeyID:  accessKeyID,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {

			if got, err := getIdentityFromSTSResponse(&c.inputID, c.inputResponse); err == nil {
				if c.expectedErr {
					t.Errorf("expected err to be nil but was %s", err)
				}

				if diff := cmp.Diff(c.want, *got); diff != "" {
					t.Errorf("getIdentityFromSTSResponse() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func response(account, userID, arn string) getCallerIdentityWrapper {
	wrapper := getCallerIdentityWrapper{}
	wrapper.GetCallerIdentityResponse.GetCallerIdentityResult.Account = account
	wrapper.GetCallerIdentityResponse.GetCallerIdentityResult.Arn = arn
	wrapper.GetCallerIdentityResponse.GetCallerIdentityResult.UserID = userID
	wrapper.GetCallerIdentityResponse.ResponseMetadata.RequestID = "id1234"
	return wrapper
}

func TestGetWithSTS(t *testing.T) {
	clusterID := "test-cluster"

	cases := []struct {
		name    string
		creds   *credentials.Credentials
		nowTime time.Time
		want    Token
		wantErr error
	}{
		{
			"Non-zero time",
			// Example non-real credentials
			func() *credentials.Credentials {
				decodedAkid, _ := base64.StdEncoding.DecodeString("QVNJQVIyVEc0NFY2QVMzWlpFN0M=")
				decodedSk, _ := base64.StdEncoding.DecodeString("NEtENWNudEdjVm1MV1JkRjV3dk5SdXpOTDVReG1wNk9LVlk2RnovUQ==")
				return credentials.NewStaticCredentials(
					string(decodedAkid),
					string(decodedSk),
					"",
				)
			}(),
			time.Unix(1682640000, 0),
			Token{
				Token:      "k8s-aws-v1.aHR0cHM6Ly9zdHMudXMtd2VzdC0yLmFtYXpvbmF3cy5jb20vP0FjdGlvbj1HZXRDYWxsZXJJZGVudGl0eSZWZXJzaW9uPTIwMTEtMDYtMTUmWC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BU0lBUjJURzQ0VjZBUzNaWkU3QyUyRjIwMjMwNDI4JTJGdXMtd2VzdC0yJTJGc3RzJTJGYXdzNF9yZXF1ZXN0JlgtQW16LURhdGU9MjAyMzA0MjhUMDAwMDAwWiZYLUFtei1FeHBpcmVzPTYwJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCUzQngtazhzLWF3cy1pZCZYLUFtei1TaWduYXR1cmU9ZTIxMWRiYTc3YWJhOWRjNDRiMGI2YmUzOGI4ZWFhZDA5MjU5OWM1MTU3ZjYzMTQ0NDRjNWI5ZDg1NzQ3ZjVjZQ",
				Expiration: time.Unix(1682640000, 0).Local().Add(time.Minute * 14),
			},
			nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := sts.New(session.Must(session.NewSession(
				&aws.Config{
					Credentials:         tc.creds,
					Region:              aws.String("us-west-2"),
					STSRegionalEndpoint: endpoints.RegionalSTSEndpoint,
				},
			)))

			gen := &generator{
				forwardSessionName: false,
				cache:              false,
				nowFunc:            func() time.Time { return tc.nowTime },
			}

			got, err := gen.GetWithSTS(clusterID, svc)
			if diff := cmp.Diff(err, tc.wantErr); diff != "" {
				t.Errorf("Unexpected error: %s", diff)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				fmt.Printf("Want: %s\n", tc.want)
				fmt.Printf("Got: %s\n", got)
				t.Errorf("Got unexpected token: %s", diff)
			}
		})
	}
}

func TestGetStsRegion(t *testing.T) {
	tests := []struct {
		host     string
		expected string
		wantErr  bool
	}{
		{"sts.amazonaws.com", "global", false},                    // Global endpoint
		{"sts.us-west-2.amazonaws.com", "us-west-2", false},       // Valid regional endpoint
		{"sts.eu-central-1.amazonaws.com", "eu-central-1", false}, // Another valid regional endpoint
		{"", "", true},                // Empty input (expect error)
		{"sts", "", true},             // Malformed input (expect error)
		{"sts.wrongformat", "", true}, // Malformed input (expect error)
	}

	for _, test := range tests {
		result, err := getStsRegion(test.host)
		if (err != nil) != test.wantErr {
			t.Errorf("getStsRegion(%q) error = %v, wantErr %v", test.host, err, test.wantErr)
		}
		if result != test.expected {
			t.Errorf("getStsRegion(%q) = %q; expected %q", test.host, result, test.expected)
		}
	}
}
