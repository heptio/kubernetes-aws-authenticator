package filecache

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/gofrs/flock"
	"github.com/spf13/afero"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// env variable name for custom credential cache file location
const cacheFileNameEnv = "AWS_IAM_AUTHENTICATOR_CACHE_FILE"

// FileLocker is a subset of the methods exposed by *flock.Flock
type FileLocker interface {
	Unlock() error
	TryLockContext(ctx context.Context, retryDelay time.Duration) (bool, error)
	TryRLockContext(ctx context.Context, retryDelay time.Duration) (bool, error)
}

// NewFileLocker returns a *flock.Flock that satisfies FileLocker
func NewFileLocker(filename string) FileLocker {
	return flock.New(filename)
}

// cacheFile is a map of clusterID/roleARNs to cached credentials
type cacheFile struct {
	// a map of clusterIDs/profiles/roleARNs to cachedCredentials
	ClusterMap map[string]map[string]map[string]aws.Credentials `yaml:"clusters"`
}

// a utility type for dealing with compound cache keys
type cacheKey struct {
	clusterID string
	profile   string
	roleARN   string
}

func (c *cacheFile) Put(key cacheKey, credential aws.Credentials) {
	if _, ok := c.ClusterMap[key.clusterID]; !ok {
		// first use of this cluster id
		c.ClusterMap[key.clusterID] = map[string]map[string]aws.Credentials{}
	}
	if _, ok := c.ClusterMap[key.clusterID][key.profile]; !ok {
		// first use of this profile
		c.ClusterMap[key.clusterID][key.profile] = map[string]aws.Credentials{}
	}
	c.ClusterMap[key.clusterID][key.profile][key.roleARN] = credential
}

func (c *cacheFile) Get(key cacheKey) (credential aws.Credentials) {
	if _, ok := c.ClusterMap[key.clusterID]; ok {
		if _, ok := c.ClusterMap[key.clusterID][key.profile]; ok {
			// we at least have this cluster and profile combo in the map, if no matching roleARN, map will
			// return the zero-value for cachedCredential, which expired a long time ago.
			credential = c.ClusterMap[key.clusterID][key.profile][key.roleARN]
		}
	}
	return
}

// readCacheWhileLocked reads the contents of the credential cache and returns the
// parsed yaml as a cacheFile object.  This method must be called while a shared
// lock is held on the filename.
func readCacheWhileLocked(fs afero.Fs, filename string) (cache cacheFile, err error) {
	cache = cacheFile{
		map[string]map[string]map[string]aws.Credentials{},
	}
	data, err := afero.ReadFile(fs, filename)
	if err != nil {
		err = fmt.Errorf("unable to open file %s: %v", filename, err)
		return
	}

	err = yaml.Unmarshal(data, &cache)
	if err != nil {
		err = fmt.Errorf("unable to parse file %s: %v", filename, err)
	}
	return
}

// writeCacheWhileLocked writes the contents of the credential cache using the
// yaml marshaled form of the passed cacheFile object.  This method must be
// called while an exclusive lock is held on the filename.
func writeCacheWhileLocked(fs afero.Fs, filename string, cache cacheFile) error {
	data, err := yaml.Marshal(cache)
	if err == nil {
		// write privately owned by the user
		err = afero.WriteFile(fs, filename, data, 0600)
	}
	return err
}

type FileCacheOpt func(*FileCacheProvider)

// WithFs returns a FileCacheOpt that sets the cache's filesystem
func WithFs(fs afero.Fs) FileCacheOpt {
	return func(p *FileCacheProvider) {
		p.fs = fs
	}
}

// WithFilename returns a FileCacheOpt that sets the cache's file
func WithFilename(filename string) FileCacheOpt {
	return func(p *FileCacheProvider) {
		p.filename = filename
	}
}

// WithFileLockCreator returns a FileCacheOpt that sets the cache's FileLocker
// creation function
func WithFileLockerCreator(f func(string) FileLocker) FileCacheOpt {
	return func(p *FileCacheProvider) {
		p.filelockCreator = f
	}
}

// FileCacheProvider is a credentials.Provider implementation that wraps an underlying Provider
// (contained in Credentials) and provides caching support for credentials for the
// specified clusterID, profile, and roleARN (contained in cacheKey)
type FileCacheProvider struct {
	fs               afero.Fs
	filelockCreator  func(string) FileLocker
	filename         string
	provider         aws.CredentialsProvider // the underlying implementation that has the *real* Provider
	cacheKey         cacheKey                // cache key parameters used to create Provider
	cachedCredential aws.Credentials         // the cached credential, if it exists
}

var _ credentials.Provider = &FileCacheProvider{}

// NewFileCacheProvider creates a new Provider implementation that wraps a provided Credentials,
// and works with an on disk cache to speed up credential usage when the cached copy is not expired.
// If there are any problems accessing or initializing the cache, an error will be returned, and
// callers should just use the existing credentials provider.
func NewFileCacheProvider(clusterID, profile, roleARN string, provider aws.CredentialsProvider, opts ...FileCacheOpt) (*FileCacheProvider, error) {
	if provider == nil {
		return nil, errors.New("no underlying Credentials object provided")
	}

	resp := &FileCacheProvider{
		fs:               afero.NewOsFs(),
		filelockCreator:  NewFileLocker,
		filename:         defaultCacheFilename(),
		provider:         provider,
		cacheKey:         cacheKey{clusterID, profile, roleARN},
		cachedCredential: aws.Credentials{},
	}

	// override defaults
	for _, opt := range opts {
		opt(resp)
	}

	// ensure path to cache file exists
	_ = resp.fs.MkdirAll(filepath.Dir(resp.filename), 0700)
	if info, err := resp.fs.Stat(resp.filename); err == nil {
		if info.Mode()&0077 != 0 {
			// cache file has secret credentials and should only be accessible to the user, refuse to use it.
			return nil, fmt.Errorf("cache file %s is not private", resp.filename)
		}

		// do file locking on cache to prevent inconsistent reads
		lock := resp.filelockCreator(resp.filename)
		defer lock.Unlock()
		// wait up to a second for the file to lock
		ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()
		ok, err := lock.TryRLockContext(ctx, 250*time.Millisecond) // try to lock every 1/4 second
		if !ok {
			// unable to lock the cache, something is wrong, refuse to use it.
			return nil, fmt.Errorf("unable to read lock file %s: %v", resp.filename, err)
		}

		cache, err := readCacheWhileLocked(resp.fs, resp.filename)
		if err != nil {
			// can't read or parse cache, refuse to use it.
			return nil, err
		}

		resp.cachedCredential = cache.Get(resp.cacheKey)
	} else {
		if errors.Is(err, fs.ErrNotExist) {
			// cache file is missing.  maybe this is the very first run?  continue to use cache.
			_, _ = fmt.Fprintf(os.Stderr, "Cache file %s does not exist.\n", resp.filename)
		} else {
			return nil, fmt.Errorf("couldn't stat cache file: %w", err)
		}
	}

	return resp, nil
}

// Retrieve() implements the Provider interface, returning the cached credential if is not expired,
// otherwise fetching the credential from the underlying Provider and caching the results on disk
// with an expiration time.
func (f *FileCacheProvider) Retrieve() (credentials.Value, error) {
	return f.RetrieveWithContext(context.Background())
}

// Retrieve() implements the Provider interface, returning the cached credential if is not expired,
// otherwise fetching the credential from the underlying Provider and caching the results on disk
// with an expiration time.
func (f *FileCacheProvider) RetrieveWithContext(ctx context.Context) (credentials.Value, error) {
	var quiet bool = viper.GetBool("quiet")

	if !f.cachedCredential.Expired() && f.cachedCredential.HasKeys() {
		// use the cached credential
		return V2CredentialToV1Value(f.cachedCredential), nil
	} else {
		if !quiet {
			_, _ = fmt.Fprintf(os.Stderr, "No cached credential available.  Refreshing...\n")
		}
		// fetch the credentials from the underlying Provider
		credential, err := f.provider.Retrieve(ctx)
		if err != nil {
			return V2CredentialToV1Value(credential), err
		}

		if credential.CanExpire {
			// Credential supports expiration, so we can cache

			// do file locking on cache to prevent inconsistent writes
			lock := f.filelockCreator(f.filename)
			defer lock.Unlock()
			// wait up to a second for the file to lock
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			ok, err := lock.TryLockContext(ctx, 250*time.Millisecond) // try to lock every 1/4 second
			if !ok {
				// can't get write lock to create/update cache, but still return the credential
				_, _ = fmt.Fprintf(os.Stderr, "Unable to write lock file %s: %v\n", f.filename, err)
				return V2CredentialToV1Value(credential), nil
			}
			f.cachedCredential = credential
			// don't really care about read error.  Either read the cache, or we create a new cache.
			cache, _ := readCacheWhileLocked(f.fs, f.filename)
			cache.Put(f.cacheKey, f.cachedCredential)
			err = writeCacheWhileLocked(f.fs, f.filename, cache)
			if err != nil {
				// can't write cache, but still return the credential
				_, _ = fmt.Fprintf(os.Stderr, "Unable to update credential cache %s: %v\n", f.filename, err)
				err = nil
			} else if !quiet {
				_, _ = fmt.Fprintf(os.Stderr, "Updated cached credential\n")
			}
		} else {
			// credential doesn't support expiration time, so can't cache, but still return the credential
			_, _ = fmt.Fprint(os.Stderr, "Unable to cache credential: credential doesn't support expiration\n")
		}
		return V2CredentialToV1Value(credential), err
	}
}

// IsExpired() implements the Provider interface, deferring to the cached credential first,
// but fall back to the underlying Provider if it is expired.
func (f *FileCacheProvider) IsExpired() bool {
	return f.cachedCredential.CanExpire && f.cachedCredential.Expired()
}

// ExpiresAt implements the Expirer interface, and gives access to the expiration time of the credential
func (f *FileCacheProvider) ExpiresAt() time.Time {
	return f.cachedCredential.Expires
}

// defaultCacheFilename returns the name of the credential cache file, which can either be
// set by environment variable, or use the default of ~/.kube/cache/aws-iam-authenticator/credentials.yaml
func defaultCacheFilename() string {
	if filename := os.Getenv(cacheFileNameEnv); filename != "" {
		return filename
	} else {
		return filepath.Join(userHomeDir(), ".kube", "cache", "aws-iam-authenticator", "credentials.yaml")
	}
}

// userHomeDir returns the home directory for the user the process is
// running under.
func userHomeDir() string {
	if runtime.GOOS == "windows" { // Windows
		return os.Getenv("USERPROFILE")
	}

	// *nix
	return os.Getenv("HOME")
}
