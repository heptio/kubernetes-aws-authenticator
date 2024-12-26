package regions

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
)

// NewAPIDiscoverer returns a new Discoverer for the given partition. Hostname
// discovery uses the `account:ListRegions` API call to identifiy
//
// The partition is used to determine the correct hostnames for the STS endpoints
// The supported partitions are "aws", "aws-us-gov", and "aws-cn". Future partitions
// will need to be added manually, or use a different Discoverer
func NewAPIDiscoverer(c account.ListRegionsAPIClient, partition string) Discoverer {
	return &apiDiscoverer{
		client:    c,
		partition: partition,
	}
}

type apiDiscoverer struct {
	client    account.ListRegionsAPIClient
	partition string
}

func (d *apiDiscoverer) Find(ctx context.Context) (map[string]bool, error) {
	stsHostnames := map[string]bool{}

	var tlds []string
	serviceNames := []string{"sts", "sts-fips"}
	switch d.partition {
	case "aws":
		tlds = []string{"amazonaws.com", "api.aws"}
		stsHostnames["sts.amazonaws.com"] = true
	case "aws-us-gov":
		tlds = []string{"amazonaws.com", "api.aws"}
	case "aws-cn":
		serviceNames = []string{"sts"}
		tlds = []string{"amazonaws.com.cn"}
	case "aws-iso":
		tlds = []string{"c2s.ic.gov"}
	case "aws-iso-b":
		tlds = []string{"sc2s.sgov.gov"}
	case "aws-iso-e":
		tlds = []string{"cloud.adc-e.uk"}
	case "aws-iso-f":
		tlds = []string{"csp.hci.ic.gov"}
	default:
		return nil, fmt.Errorf("unrecognized partition %s", d.partition)
	}

	result, err := d.client.ListRegions(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get regions: %w", err)
	}

	for _, region := range result.Regions {
		// TODO: We could assess if a region is opted in, but we may need to
		// increase the frequency of Verifier's ticker or make it configurable
		// so clients don't have to wait up to 24h to trust tokens from a
		// recently opted-in region.
		for _, serviceName := range serviceNames {
			for _, tld := range tlds {
				hostname := fmt.Sprintf("%s.%s.%s", serviceName, aws.ToString(region.RegionName), tld)
				stsHostnames[hostname] = true
			}
		}
	}

	return stsHostnames, nil
}
