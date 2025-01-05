// Package alist implements an rclone backend for AList
package alist

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/rest"
)

const (
	minSleep      = 10 * time.Millisecond
	maxSleep      = 2 * time.Second
	decayConstant = 2 // bigger for slower decay, exponential

	// Define API endpoint constants
	apiLogin  = "/api/auth/login/hash"
	apiList   = "/api/fs/list"
	apiPut    = "/api/fs/put"
	apiMkdir  = "/api/fs/mkdir"
	apiRemove = "/api/fs/remove"
	apiGet    = "/api/fs/get"
)

func init() {
	fs.Register(&fs.RegInfo{
		Name:        "alist",
		Description: "AList",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:     "url",
			Help:     "URL of the AList server",
			Required: true,
		}, {
			Name:     "username",
			Help:     "Username for AList",
			Required: false,
		}, {
			Name:       "password",
			Help:       "Password for AList",
			Required:   false,
			IsPassword: true,
		}, {
			Name:     "root_path",
			Help:     "Root path within the AList server",
			Required: false,
			Default:  "/",
		}, {
			Name:     "otp_code",
			Help:     "Two-factor authentication code",
			Default:  "",
			Advanced: true,
		}, {
			Name:     "meta_pass",
			Help:     "Meta password for listing",
			Default:  "",
			Advanced: true,
		}, {
			Name:     config.ConfigEncoding,
			Help:     config.ConfigEncodingHelp,
			Advanced: true,
			Default: (encoder.EncodeLtGt |
				encoder.EncodeLeftSpace |
				encoder.EncodeCtl |
				encoder.EncodeSlash |
				encoder.EncodeRightSpace |
				encoder.EncodeInvalidUtf8),
		}},
	})
}

// Options defines the configuration for this backend
type Options struct {
	URL      string `config:"url"`
	Username string `config:"username"`
	Password string `config:"password"`
	OTPCode  string `config:"otp_code"`
	// meta_pass is used as a password parameter in listing
	MetaPass string `config:"meta_pass"`
	// root_path specifies the root path within the AList server
	RootPath string `config:"root_path"`
}

// Fs represents a remote AList server
type Fs struct {
	name            string
	root            string
	opt             Options
	features        *fs.Features
	token           string
	tokenMu         sync.Mutex
	srv             *rest.Client
	pacer           *fs.Pacer
	fileListCacheMu sync.Mutex
	fileListCache   map[string]listResponse
}

// API response structures
type loginResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Token string `json:"token"`
	} `json:"data"`
}

type fileInfo struct {
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	IsDir    bool      `json:"is_dir"`
	Modified time.Time `json:"modified"`
	HashInfo *struct {
		MD5    string `json:"md5,omitempty"`
		SHA1   string `json:"sha1,omitempty"`
		SHA256 string `json:"sha256,omitempty"`
	} `json:"hash_info"`
	RawURL string `json:"raw_url"`
}

type listResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Content []fileInfo `json:"content"`
		Total   int        `json:"total"`
	} `json:"data"`
}

type requestResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Object describes an AList object
type Object struct {
	fs        *Fs
	remote    string
	size      int64
	modTime   time.Time
	md5sum    string
	sha1sum   string
	sha256sum string
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// Features returns the Fs features
func (f *Fs) Features() *fs.Features {
	return f.features
}

func (o *Object) Fs() fs.Info {
	return o.fs
}

// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	// Ensure root starts with '/'
	if !strings.HasPrefix(root, "/") {
		root = "/" + root
	}

	// Incorporate root_path if provided
	if opt.RootPath != "" && opt.RootPath != "/" {
		root = path.Join(root, opt.RootPath)
	}

	client := fshttp.NewClient(ctx)
	f := &Fs{
		name:            name,
		root:            root,
		opt:             *opt,
		srv:             rest.NewClient(client).SetRoot(opt.URL),
		pacer:           fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
		fileListCacheMu: sync.Mutex{},
		fileListCache:   make(map[string]listResponse),
	}

	// Login and get token only if username and password are provided
	if f.opt.Username != "" && f.opt.Password != "" {
		err = f.login(ctx)
		if err != nil {
			return nil, err
		}
	} else {
		// Proceed as guest
		f.token = ""
	}

	// Set supported hash types
	f.features = (&fs.Features{
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f)

	return f, nil
}

// func make password to hash
func (f *Fs) makePasswordHash(password string) string {
	// add -https://github.com/alist-org/alist at the end of the password
	password += "-https://github.com/alist-org/alist"
	// hash the password with sha256
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// login performs authentication and stores the token
func (f *Fs) login(ctx context.Context) error {
	if f.opt.Username == "" || f.opt.Password == "" {
		// Skip login for guest access
		return nil
	}
	pw, err := obscure.Reveal(f.opt.Password)
	if err != nil {
		return fmt.Errorf("password decode failed - did you obscure it?: %w", err)
	}
	loginURL := "/api/auth/login/hash"

	data := map[string]string{
		"username": f.opt.Username,
		"password": f.makePasswordHash(pw),
		"otpcode":  f.opt.OTPCode,
	}

	var loginResp loginResponse
	err = f.makeRequest(ctx, "POST", loginURL, data, &loginResp)
	if err != nil {
		return err
	}

	f.token = loginResp.Data.Token
	return nil
}

// doRequest performs an HTTP request, handles token renewal, and ensures the response body can be read by the caller.
func (f *Fs) doRequest(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	if f.token != "" {
		req.Header.Set("Authorization", f.token)
	}

	resp, err := f.srv.Do(req)
	if err != nil {
		return nil, err
	}

	// Read the entire response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		// Start of Selection
		if err := resp.Body.Close(); err != nil {
			fs.Errorf(ctx, "Failed to close response body: %v", err)
		}
		return nil, err
	}
	// Handle the error returned by resp.Body.Close()
	if err := resp.Body.Close(); err != nil {
		fs.Errorf(ctx, "Failed to close response body: %v", err)
	}

	// Parse the response to check the Code
	var respBody requestResponse
	err = json.Unmarshal(bodyBytes, &respBody)
	if err != nil {
		return nil, err
	}

	if respBody.Code != 200 {
		if respBody.Code == 401 {
			// Renew token
			f.tokenMu.Lock()
			err = f.login(req.Context())
			f.tokenMu.Unlock()
			if err != nil {
				return nil, fmt.Errorf("token renewal failed: %w", err)
			}
			return f.doRequest(req)
		}
		return nil, fmt.Errorf("request failed: %s", respBody.Message)
	}

	// Reconstruct the response body so the caller can read it
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	return resp, nil
}

// makeRequest is a helper method to create and process HTTP requests.
func (f *Fs) makeRequest(ctx context.Context, method, endpoint string, data interface{}, response interface{}) error {
	// Marshal the data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, method, f.opt.URL+endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	// Set common headers
	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, text/plain, */*",
	}
	f.setCommonHeaders(req, headers)

	// Perform the request using doRequest
	resp, err := f.doRequest(req)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fs.Errorf(ctx, "Failed to close response body: %v", closeErr)
		}
	}()

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Unmarshal the response into the provided response interface
	err = json.Unmarshal(bodyBytes, response)
	if err != nil {
		return err
	}

	// Handle response codes
	err = f.handleResponse(response)
	if err != nil {
		if err.Error() == "unauthorized access" {
			// Renew token if unauthorized
			f.tokenMu.Lock()
			defer f.tokenMu.Unlock()
			if err := f.login(ctx); err != nil {
				return fmt.Errorf("token renewal failed: %w", err)
			}
			// Retry the request after renewing token
			return f.makeRequest(ctx, method, endpoint, data, response)
		}
		return err
	}

	return nil
}

// fileInfoToDirEntry converts a fileInfo instance to a fs.DirEntry
func (f *Fs) fileInfoToDirEntry(item fileInfo, dir string) fs.DirEntry {
	remote := path.Join(dir, item.Name)
	if item.IsDir {
		return fs.NewDir(remote, item.Modified)
	}

	var md5sum, sha1sum, sha256sum string
	if item.HashInfo != nil {
		md5sum = item.HashInfo.MD5
		sha1sum = item.HashInfo.SHA1
		sha256sum = item.HashInfo.SHA256
	}

	return &Object{
		fs:        f,
		remote:    remote,
		size:      item.Size,
		modTime:   item.Modified,
		md5sum:    md5sum,
		sha1sum:   sha1sum,
		sha256sum: sha256sum,
	}
}

// List the objects and directories in dir into entries
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	if cached, ok := f.getCachedList(dir); ok {
		// Use cached data
		for _, item := range cached.Data.Content {
			entries = append(entries, f.fileInfoToDirEntry(item, dir))
		}
		return entries, nil
	}

	// existing listing logic...
	data := map[string]interface{}{
		"path":     path.Join(f.root, dir),
		"per_page": 1000,
		"page":     1,
		"refresh":  true,
		"password": f.opt.MetaPass,
	}

	var listResp listResponse
	err = f.makeRequest(ctx, "POST", apiList, data, &listResp)
	if err != nil {
		return nil, err
	}

	// Cache the list response
	f.setCachedList(dir, listResp)

	for _, item := range listResp.Data.Content {
		entries = append(entries, f.fileInfoToDirEntry(item, dir))
	}

	return entries, nil
}

// Put in to the remote path with the modTime given of the given size
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	remote := src.Remote()
	size := src.Size()
	modTime := src.ModTime(ctx)

	putURL := f.opt.URL + "/api/fs/put"
	req, err := http.NewRequestWithContext(ctx, "PUT", putURL, in)
	if err != nil {
		return nil, err
	}

	encodedFilePath := url.PathEscape(path.Join(f.root, remote))
	req.Header.Set("File-Path", encodedFilePath)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", size))
	req.Header.Set("last-modified", fmt.Sprintf("%d", modTime.UnixMilli()))
	req.ContentLength = size

	resp, err := f.doRequest(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fs.Errorf(ctx, "Failed to close response body: %v", closeErr)
		}
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var uploadResp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	err = json.Unmarshal(bodyBytes, &uploadResp)
	if err != nil {
		return nil, err
	}

	if uploadResp.Code != 200 {
		return nil, fmt.Errorf("upload failed: %s", uploadResp.Message)
	}

	// Invalidate cache for the parent directory using helper
	parentDir := path.Dir(src.Remote())
	f.invalidateCache(parentDir)

	return &Object{
		fs:      f,
		remote:  remote,
		size:    size,
		modTime: modTime,
	}, nil
}

// Mkdir creates a directory if it doesn't exist
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	mkdirURL := "/api/fs/mkdir"

	data := map[string]string{
		"path": path.Join(f.root, dir),
	}

	var mkdirResp requestResponse
	err := f.makeRequest(ctx, "POST", mkdirURL, data, &mkdirResp)
	if err != nil {
		return err
	}

	return nil
}

// Rmdir removes the directory if empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return f.purgeDir(ctx, dir, false)
}

// purgeDir removes the directory and optionally all of its contents
func (f *Fs) purgeDir(ctx context.Context, dir string, recursive bool) error {
	removeURL := "/api/fs/remove"

	names := []string{"."}

	data := map[string]interface{}{
		"dir":   path.Join(f.root, dir),
		"names": names,
	}

	var removeResp requestResponse
	err := f.makeRequest(ctx, "POST", removeURL, data, &removeResp)
	if err != nil {
		return err
	}

	// Optionally, clear the file list cache for the directory
	f.fileListCacheMu.Lock()
	delete(f.fileListCache, dir)
	f.fileListCacheMu.Unlock()

	return nil
}

// Object implementation
func (o *Object) Remote() string {
	return o.remote
}

func (o *Object) Size() int64 {
	return o.size
}

func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

func (o *Object) SetModTime(ctx context.Context, t time.Time) error {
	return fs.ErrorCantSetModTime
}

func (o *Object) Hashes() hash.Set {
	return hash.NewHashSet(hash.MD5, hash.SHA1, hash.SHA256)
}

func (o *Object) Storable() bool {
	return true
}

func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	getURL := "/api/fs/get"

	data := map[string]string{
		"path": path.Join(o.fs.root, o.remote),
	}

	var getResp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			RawURL string `json:"raw_url"`
		} `json:"data"`
	}

	err := o.fs.makeRequest(ctx, "POST", getURL, data, &getResp)
	if err != nil {
		return nil, err
	}

	// Download from raw URL
	resp, err := http.NewRequestWithContext(ctx, "GET", getResp.Data.RawURL, nil)
	if err != nil {
		return nil, err
	}
	fs.FixRangeOption(options, o.size)
	fs.OpenOptionAddHTTPHeaders(resp.Header, options)
	if o.size == 0 {
		// Don't supply range requests for 0 length objects as they always fail
		delete(resp.Header, "Range")
	}
	client := &http.Client{}
	response, err := client.Do(resp)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 && response.StatusCode != 206 {
		response.Body.Close()
		return nil, fmt.Errorf("failed to open object: status code %d", response.StatusCode)
	}
	return response.Body, nil
}

func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	_, err := o.fs.Put(ctx, in, src, options...)
	return err
}

func (o *Object) Remove(ctx context.Context) error {
	removeURL := "/api/fs/remove"

	data := map[string]interface{}{
		"dir":   path.Dir(path.Join(o.fs.root, o.remote)),
		"names": []string{path.Base(o.remote)},
	}

	var removeResp requestResponse
	err := o.fs.makeRequest(ctx, "POST", removeURL, data, &removeResp)
	if err != nil {
		return err
	}

	// Invalidate cache for the directory using helper
	o.fs.invalidateCache(path.Dir(o.remote))

	return nil
}

// Hash returns the hash for the given type
func (o *Object) Hash(ctx context.Context, ty hash.Type) (string, error) {
	switch ty {
	case hash.MD5:
		return o.md5sum, nil
	case hash.SHA1:
		return o.sha1sum, nil
	case hash.SHA256:
		return o.sha256sum, nil
	default:
		return "", hash.ErrUnsupported
	}
}

// String returns a descriptive string for the object
func (o *Object) String() string {
	return fmt.Sprintf("AList Object: %s", o.remote)
}

// Hashes returns the supported hash types
func (f *Fs) Hashes() hash.Set {
	return hash.NewHashSet(hash.MD5, hash.SHA1, hash.SHA256)
}

// Precision returns the precision of the filesystem
func (f *Fs) Precision() time.Duration {
	return time.Second // Adjust as needed
}

// NewObject creates a new Object
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	// Split the remote path into directory and file name
	dir := path.Dir(remote)

	// List the contents of the directory
	entries, err := f.List(ctx, dir)
	if err != nil {
		return nil, err
	}

	// Iterate through the directory entries to find the specific object
	for _, entry := range entries {
		if entry.Remote() == remote {
			obj, ok := entry.(*Object)
			if ok {
				return obj, nil
			}
		}
	}

	// If the object is not found, return an appropriate error
	return nil, fs.ErrorObjectNotFound
}

// String returns a descriptive string for the filesystem
func (f *Fs) String() string {
	return f.name
}

// Add a helper function to handle response codes
func (f *Fs) handleResponse(response interface{}) error {
	switch response.(type) {
	case *loginResponse, *listResponse, *requestResponse:
		v := reflect.ValueOf(response).Elem()
		code := v.FieldByName("Code").Int()
		message := v.FieldByName("Message").String()
		if code != 200 {
			if code == 401 {
				return fmt.Errorf("unauthorized access")
			}
			return fmt.Errorf("request failed: %s", message)
		}
	default:
		// No action needed for other types
	}
	return nil
}

// Add helper functions for cache access
func (f *Fs) getCachedList(dir string) (listResponse, bool) {
	f.fileListCacheMu.Lock()
	defer f.fileListCacheMu.Unlock()
	cached, ok := f.fileListCache[dir]
	return cached, ok
}

func (f *Fs) setCachedList(dir string, resp listResponse) {
	f.fileListCacheMu.Lock()
	defer f.fileListCacheMu.Unlock()
	f.fileListCache[dir] = resp
}

func (f *Fs) invalidateCache(dir string) {
	f.fileListCacheMu.Lock()
	defer f.fileListCacheMu.Unlock()
	delete(f.fileListCache, dir)
}

// Add a helper function to set common headers
func (f *Fs) setCommonHeaders(req *http.Request, headers map[string]string) {
	for key, value := range headers {
		req.Header.Set(key, value)
	}
}
