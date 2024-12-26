package regions

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestStsHostsForPartition(t *testing.T) {

	testCases := []struct {
		name              string
		partition, region string
		want              map[string]bool
		wantErr           error
	}{
		{
			name:      "aws-cn",
			partition: "aws-cn",
			region:    "cn-north-1",
			want: map[string]bool{
				"sts.cn-northwest-1.amazonaws.com.cn": true,
				"sts.cn-north-1.amazonaws.com.cn":     true,
			},
		},
		{
			name:      "aws-us-gov",
			partition: "aws-us-gov",
			region:    "us-gov-west-1",
			want: map[string]bool{
				"sts.us-gov-east-1.amazonaws.com": true,
				"sts.us-gov-west-1.amazonaws.com": true,
			},
		},
		{
			name:      "aws",
			partition: "aws",
			region:    "us-west-1",
			want: map[string]bool{
				"sts-fips.us-east-1.amazonaws.com": true,
				"sts-fips.us-east-2.amazonaws.com": true,
				"sts-fips.us-west-1.amazonaws.com": true,
				"sts-fips.us-west-2.amazonaws.com": true,
				"sts.af-south-1.amazonaws.com":     true,
				"sts.amazonaws.com":                true,
				"sts.ap-east-1.amazonaws.com":      true,
				"sts.ap-northeast-1.amazonaws.com": true,
				"sts.ap-northeast-2.amazonaws.com": true,
				"sts.ap-northeast-3.amazonaws.com": true,
				"sts.ap-south-1.amazonaws.com":     true,
				"sts.ap-south-2.amazonaws.com":     true,
				"sts.ap-southeast-1.amazonaws.com": true,
				"sts.ap-southeast-2.amazonaws.com": true,
				"sts.ap-southeast-3.amazonaws.com": true,
				"sts.ap-southeast-4.amazonaws.com": true,
				"sts.ca-central-1.amazonaws.com":   true,
				"sts.ca-west-1.amazonaws.com":      true,
				"sts.eu-central-1.amazonaws.com":   true,
				"sts.eu-central-2.amazonaws.com":   true,
				"sts.eu-north-1.amazonaws.com":     true,
				"sts.eu-south-1.amazonaws.com":     true,
				"sts.eu-south-2.amazonaws.com":     true,
				"sts.eu-west-1.amazonaws.com":      true,
				"sts.eu-west-2.amazonaws.com":      true,
				"sts.eu-west-3.amazonaws.com":      true,
				"sts.il-central-1.amazonaws.com":   true,
				"sts.me-central-1.amazonaws.com":   true,
				"sts.me-south-1.amazonaws.com":     true,
				"sts.sa-east-1.amazonaws.com":      true,
				"sts.us-east-1.amazonaws.com":      true,
				"sts.us-east-2.amazonaws.com":      true,
				"sts.us-west-1.amazonaws.com":      true,
				"sts.us-west-2.amazonaws.com":      true,
			},
		},
		{
			name:      "unknown partition",
			partition: "aws-eu-gov",
			region:    "eu-gov-west-1",
			want:      nil,
			wantErr:   errors.New("partition aws-eu-gov not found"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := stsHostsForPartition(tc.partition, tc.region)
			if err != nil && tc.wantErr == nil {
				t.Errorf("unexpected error: got '%v', wanted nil", err)
				return
			}
			if err == nil && tc.wantErr != nil {
				t.Errorf("missing expected error '%v', got nil", tc.wantErr)
				return
			}
			if err != nil && tc.wantErr != nil && !(err.Error() == tc.wantErr.Error() ||
				errors.Is(err, tc.wantErr)) {
				t.Errorf("stsHostsForPartition() error = '%v', wantErr '%v'", err, tc.wantErr)
				return
			}

			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("got unexpected result\n%s", diff)
			}
		})
	}
}
