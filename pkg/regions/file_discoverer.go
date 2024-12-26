package regions

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
)

// NewFileDiscoverer creates a Discoverer that reads hostnames from a JSON file
// containing a list of strings.
func NewFileDiscoverer(filename string) Discoverer {
	return &fileDiscoverer{
		fs:       os.DirFS("."),
		filename: filename,
	}
}

type fileDiscoverer struct {
	fs       fs.FS
	filename string
}

// HostnameFileContent is a type to decode STS hostnames into
type HostnameFileContent []string

func (d *fileDiscoverer) Find(ctx context.Context) (map[string]bool, error) {
	f, err := d.fs.Open(d.filename)
	if err != nil {
		return nil, err
	}
	hfc := &HostnameFileContent{}
	err = json.NewDecoder(f).Decode(hfc)
	if err != nil {
		return nil, err
	}
	resp := make(map[string]bool)
	for _, h := range *hfc {
		resp[h] = true
	}
	return resp, nil
}
