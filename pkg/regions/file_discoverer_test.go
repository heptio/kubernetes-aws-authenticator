package regions

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/afero"
)

const testFileName = "/test.json"

type aferoFSWrapper struct{ afero.Fs }

// Open satisfies the fs.Open interface with the afero implementation
func (a aferoFSWrapper) Open(name string) (fs.File, error) {
	return a.Fs.Open(name)
}

func TestFileDiscoverer(t *testing.T) {

	testCases := []struct {
		name    string
		fs      fs.FS
		want    map[string]bool
		wantErr error
	}{
		{
			name: "MissingFile",
			fs: func() fs.FS {
				return aferoFSWrapper{afero.NewMemMapFs()}
			}(),
			want:    nil,
			wantErr: fs.ErrNotExist,
		},
		{
			name: "InvalidJSON",
			fs: func() fs.FS {
				tmpfs := afero.NewMemMapFs()
				afero.WriteFile(tmpfs, testFileName, []byte(`["sts.us-east-1.amazonaws.com]`), 0644)
				return aferoFSWrapper{tmpfs}
			}(),
			want:    nil,
			wantErr: errors.New("unexpected EOF"),
		},
		{
			name: "ValidFile",
			fs: func() fs.FS {
				tmpfs := afero.NewMemMapFs()
				afero.WriteFile(tmpfs, testFileName, []byte(`["sts.us-east-1.amazonaws.com","sts.us-east-2.amazonaws.com"]`), 0644)
				return aferoFSWrapper{tmpfs}
			}(),
			want: map[string]bool{
				"sts.us-east-1.amazonaws.com": true,
				"sts.us-east-2.amazonaws.com": true,
			},
			wantErr: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fileDiscoverer{
				fs:       tc.fs,
				filename: testFileName,
			}
			got, err := f.Find(context.Background())
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
				t.Errorf("fileDiscoverer.Hostnames() error = '%v', wantErr '%v'", err, tc.wantErr)
				return
			}
			if diff := cmp.Diff(got, tc.want); diff != "" {
				t.Errorf("got unexpected result\n%s", diff)
			}
		})
	}

}
