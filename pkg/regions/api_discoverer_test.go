package regions

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/account"
	account_types "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/google/go-cmp/cmp"
)

type fakeRegionsClient struct {
	resp account.ListRegionsOutput
	err  error
}

func (c *fakeRegionsClient) ListRegions(context.Context, *account.ListRegionsInput, ...func(*account.Options)) (*account.ListRegionsOutput, error) {
	return &c.resp, c.err
}

func TestAPIDiscoverer(t *testing.T) {
	testCases := []struct {
		name       string
		discoverer apiDiscoverer
		want       map[string]bool
		wantErr    error
	}{
		{
			name: "aws partition",
			discoverer: apiDiscoverer{
				partition: "aws",
				client: &fakeRegionsClient{
					resp: account.ListRegionsOutput{
						Regions: []account_types.Region{
							{RegionName: aws.String("us-east-1")},
							{RegionName: aws.String("us-west-2")},
						},
					},
				},
			},
			want: map[string]bool{
				"sts-fips.us-east-1.amazonaws.com": true,
				"sts-fips.us-east-1.api.aws":       true,
				"sts.us-east-1.amazonaws.com":      true,
				"sts.us-east-1.api.aws":            true,
				"sts.amazonaws.com":                true,
				"sts-fips.us-west-2.amazonaws.com": true,
				"sts-fips.us-west-2.api.aws":       true,
				"sts.us-west-2.amazonaws.com":      true,
				"sts.us-west-2.api.aws":            true,
			},
		},
		{
			name: "aws-us-gov partition",
			discoverer: apiDiscoverer{
				partition: "aws-us-gov",
				client: &fakeRegionsClient{
					resp: account.ListRegionsOutput{
						Regions: []account_types.Region{
							{RegionName: aws.String("us-gov-east-1")},
							{RegionName: aws.String("us-gov-west-1")},
						},
					},
				},
			},
			want: map[string]bool{
				"sts-fips.us-gov-east-1.amazonaws.com": true,
				"sts-fips.us-gov-east-1.api.aws":       true,
				"sts.us-gov-east-1.amazonaws.com":      true,
				"sts.us-gov-east-1.api.aws":            true,
				"sts-fips.us-gov-west-1.amazonaws.com": true,
				"sts-fips.us-gov-west-1.api.aws":       true,
				"sts.us-gov-west-1.amazonaws.com":      true,
				"sts.us-gov-west-1.api.aws":            true,
			},
		},
		{
			name: "aws-cn partition",
			discoverer: apiDiscoverer{
				partition: "aws-cn",
				client: &fakeRegionsClient{
					resp: account.ListRegionsOutput{
						Regions: []account_types.Region{
							{RegionName: aws.String("cn-north-1")},
							{RegionName: aws.String("cn-northwest-1")},
						},
					},
				},
			},
			want: map[string]bool{
				"sts.cn-northwest-1.amazonaws.com.cn": true,
				"sts.cn-north-1.amazonaws.com.cn":     true,
			},
		},
		{
			name: "error",
			discoverer: apiDiscoverer{
				partition: "aws",
				client: &fakeRegionsClient{
					err: errors.New("some error"),
				},
			},
			wantErr: errors.New("failed to get regions: some error"),
		},
		{
			name: "empty response",
			discoverer: apiDiscoverer{
				partition: "aws",
				client: &fakeRegionsClient{
					resp: account.ListRegionsOutput{
						Regions: []account_types.Region{},
					},
				},
			},
			want: map[string]bool{
				"sts.amazonaws.com": true,
			},
		},
		{
			name: "nil response",
			discoverer: apiDiscoverer{
				partition: "aws",
				client: &fakeRegionsClient{
					resp: account.ListRegionsOutput{
						Regions: nil,
					},
				},
			},
			want: map[string]bool{
				"sts.amazonaws.com": true,
			},
		},
		{
			name: "duplicate regions",
			discoverer: apiDiscoverer{
				partition: "aws",
				client: &fakeRegionsClient{
					resp: account.ListRegionsOutput{
						Regions: []account_types.Region{
							{RegionName: aws.String("us-east-1")},
							{RegionName: aws.String("us-east-1")},
						},
					},
				},
			},
			want: map[string]bool{
				"sts-fips.us-east-1.amazonaws.com": true,
				"sts-fips.us-east-1.api.aws":       true,
				"sts.us-east-1.amazonaws.com":      true,
				"sts.us-east-1.api.aws":            true,
				"sts.amazonaws.com":                true,
			},
		},
		{
			name: "invalid partition",
			discoverer: apiDiscoverer{
				partition: "aws-eu",
				client:    &fakeRegionsClient{},
			},
			wantErr: errors.New("unrecognized partition aws-eu"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.discoverer.Find(context.Background())
			if err != nil && tc.wantErr == nil {
				t.Errorf("unexpected error: got '%v', wanted nil", err)
				return
			}
			if err == nil && tc.wantErr != nil {
				t.Errorf("missing expected error '%v', got nil", tc.wantErr)
				return
			}
			if err != nil && tc.wantErr != nil && err.Error() != tc.wantErr.Error() {
				t.Errorf("apiDiscoverer.Hostnames() error = '%v', wantErr '%v'", err, tc.wantErr)
				return
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("got unexpected result\n%s", diff)
			}
		})
	}
}
