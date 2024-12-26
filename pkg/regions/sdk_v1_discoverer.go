package regions

import (
	"context"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/sirupsen/logrus"
)

func NewSdkV1Discoverer(partition, region string) Discoverer {
	return &sdkV1Discoverer{
		partition: partition,
		region:    region,
	}
}

type sdkV1Discoverer struct {
	partition string
	region    string
}

func (d *sdkV1Discoverer) Find(context.Context) (map[string]bool, error) {
	return stsHostsForPartition(d.partition, d.region)
}

func stsHostsForPartition(partitionID, region string) (map[string]bool, error) {
	validSTShostnames := map[string]bool{}

	var partition *endpoints.Partition
	for _, p := range endpoints.DefaultPartitions() {
		if partitionID == p.ID() {
			partition = &p
			break
		}
	}
	if partition == nil {
		return nil, fmt.Errorf("partition %s not found", partitionID)
	}

	stsSvc, ok := partition.Services()[stsServiceID]
	if !ok {
		logrus.Errorf("STS service not found in partition %s", partitionID)
		// Add the host of the current instances region if the service doesn't already exists in the partition
		// so we don't fail if the service is not present in the go sdk but matches the instances region.
		stsHostName, err := getDefaultHostNameForRegion(partition, region, stsServiceID)
		if err != nil {
			return nil, err
		} else {
			validSTShostnames[stsHostName] = true
		}
		return validSTShostnames, nil
	}
	stsSvcEndPoints := stsSvc.Endpoints()
	for _, ep := range stsSvcEndPoints {
		rep, err := ep.ResolveEndpoint(endpoints.STSRegionalEndpointOption)
		if err != nil {
			return nil, err
		}
		parsedURL, err := url.Parse(rep.URL)
		if err != nil {
			return nil, err
		}
		validSTShostnames[parsedURL.Hostname()] = true
	}

	// Add the host of the current instances region if not already exists so we don't fail if the region is not
	// present in the go sdk but matches the instances region.
	if _, ok := stsSvcEndPoints[region]; !ok {
		stsHostName, err := getDefaultHostNameForRegion(partition, region, stsServiceID)
		if err != nil {
			logrus.WithError(err).Error("Error getting default hostname")
			return nil, err
		}
		validSTShostnames[stsHostName] = true
	}

	return validSTShostnames, nil
}

func getDefaultHostNameForRegion(partition *endpoints.Partition, region, service string) (string, error) {
	rep, err := partition.EndpointFor(service, region, endpoints.STSRegionalEndpointOption, endpoints.ResolveUnknownServiceOption)
	if err != nil {
		return "", fmt.Errorf("error resolving endpoint for %s in partition %s. err: %v", region, partition.ID(), err)
	}
	parsedURL, err := url.Parse(rep.URL)
	if err != nil {
		return "", fmt.Errorf("error parsing STS URL %s. err: %v", rep.URL, err)
	}
	return parsedURL.Hostname(), nil
}
