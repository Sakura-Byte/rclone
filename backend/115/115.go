package _115

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rclone/rclone/backend/115/api"
	"github.com/rclone/rclone/backend/115/crypto" // Keep for traditional calls
	"github.com/rclone/rclone/backend/115/dircache"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/oauthutil"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/rest"
	"golang.org/x/oauth2"
)

// Constants
const (
	domain             = "www.115.com"
	traditionalRootURL = "https://webapi.115.com"
	openAPIRootURL     = "https://proapi.115.com"
	passportRootURL    = "https://passportapi.115.com"
	qrCodeAPIRootURL   = "https://qrcodeapi.115.com"
	hnQrCodeAPIRootURL = "https://hnqrcodeapi.115.com"     // For confirm step
	appID              = "100195993"                       // Provided App ID
	tradUserAgent      = "Mozilla/5.0 115Browser/27.0.7.5" // Keep for traditional login mimicry?
	defaultUserAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"

	defaultGlobalMinSleep = fs.Duration(200 * time.Millisecond)  // 5 QPS default for global
	traditionalMinSleep   = fs.Duration(1112 * time.Millisecond) // ~0.9 QPS for traditional
	maxSleep              = 2 * time.Second
	decayConstant         = 2 // bigger for slower decay, exponential

	defaultConTimeout = fs.Duration(10 * time.Second)
	defaultTimeout    = fs.Duration(45 * time.Second)

	maxUploadSize       = 115 * fs.Gibi // 115 GiB from https://proapi.115.com/app/uploadinfo (or OpenAPI equivalent)
	maxUploadParts      = 10000         // Part number must be an integer between 1 and 10000, inclusive.
	defaultChunkSize    = 5 * fs.Mebi   // Part size should be in [100KB, 5GB]
	minChunkSize        = 100 * fs.Kibi
	maxChunkSize        = 5 * fs.Gibi // Max part size for OSS
	defaultUploadCutoff = 200 * fs.Mebi
	defaultNohashSize   = 100 * fs.Mebi
	StreamUploadLimit   = 5 * fs.Gibi // Max size for sample/streamed upload (traditional)
	maxUploadCutoff     = 5 * fs.Gibi // maximum allowed size for singlepart uploads (OSS PutObject limit)

	tokenRefreshWindow = 10 * time.Minute // Refresh token 10 minutes before expiry
	pkceVerifierLength = 64               // Length for PKCE code verifier
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "115",
		Description: "115 drive (supports Open API)",
		NewFs:       NewFs,
		CommandHelp: commandHelp,
		Options: []fs.Option{{
			Name: "cookie",
			Help: `Provide the login cookie in the format "UID=...; CID=...; SEID=...;".
Required for initial login to obtain API tokens.
Example: "UID=123; CID=abc; SEID=def;"`,
			Required:  true,
			Sensitive: true,
		}, {
			Name:      "share_code",
			Help:      "Share code from share link (for accessing shared files via traditional API).",
			Sensitive: true,
		}, {
			Name:      "receive_code",
			Help:      "Password from share link (for accessing shared files via traditional API).",
			Sensitive: true,
		}, {
			Name:     "user_agent",
			Default:  defaultUserAgent,
			Advanced: true,
			Help: fmt.Sprintf(`HTTP user agent. Primarily used for initial login mimicry.
Defaults to "%s".`, defaultUserAgent),
		}, {
			Name: "root_folder_id",
			Help: `ID of the root folder.
Leave blank normally (uses the drive root '0').
Fill in for rclone to use a non root folder as its starting point.`,
			Advanced:  true,
			Sensitive: true,
		}, {
			Name:     "list_chunk",
			Default:  1150, // Max limit for OpenAPI file list
			Help:     "Size of listing chunk.",
			Advanced: true,
		}, {
			Name:     "censored_only",
			Default:  false,
			Help:     "Only show files that are censored (only applies to traditional API calls).",
			Advanced: true,
		}, {
			Name:     "pacer_min_sleep",
			Default:  defaultGlobalMinSleep,
			Help:     "Minimum time to sleep between API calls (controls global QPS, default 5 QPS).",
			Advanced: true,
		}, {
			Name:     "contimeout",
			Default:  defaultConTimeout,
			Help:     "Connect timeout.",
			Advanced: true,
		}, {
			Name:     "timeout",
			Default:  defaultTimeout,
			Help:     "IO idle timeout.",
			Advanced: true,
		}, {
			Name:     "upload_hash_only",
			Default:  false,
			Advanced: true,
			Help: `Attempt hash-based upload (秒传) only. Skip uploading if the server doesn't have the file.
Requires SHA1 hash to be available or calculable.`,
		}, {
			Name:     "only_stream",
			Default:  false,
			Advanced: true,
			Help:     `Use traditional streamed upload (sample upload) for all files up to 5GiB. Fails for larger files.`,
		}, {
			Name:     "fast_upload",
			Default:  false,
			Advanced: true,
			Help: `Upload strategy:
- Files <= nohash_size: Use traditional streamed upload.
- Files > nohash_size: Attempt hash-based upload (秒传).
- If 秒传 fails and size <= 5GiB: Use traditional streamed upload.
- If 秒传 fails and size > 5GiB: Use multipart upload.`,
		}, {
			Name:     "hash_memory_limit",
			Help:     "Files bigger than this will be cached on disk to calculate hash if required.",
			Default:  fs.SizeSuffix(10 * 1024 * 1024),
			Advanced: true,
		}, {
			Name: "upload_cutoff",
			Help: `Cutoff for switching to multipart upload.
Any files larger than this will be uploaded in chunks using the OSS multipart API.
Minimum is 0, maximum is 5 GiB.`,
			Default:  defaultUploadCutoff,
			Advanced: true,
		}, {
			Name:     "nohash_size",
			Help:     `Files smaller than this size will use traditional streamed upload if fast_upload is enabled or if hash upload is not attempted/fails. Max is 5GiB.`,
			Default:  defaultNohashSize,
			Advanced: true,
		}, {
			Name: "chunk_size",
			Help: `Chunk size for multipart uploads.
Rclone will automatically increase the chunk size for large files to stay below the 10,000 parts limit.
Minimum is 100 KiB, maximum is 5 GiB.`,
			Default:  defaultChunkSize,
			Advanced: true,
		}, {
			Name:     "max_upload_parts",
			Help:     `Maximum number of parts in a multipart upload.`,
			Default:  maxUploadParts,
			Advanced: true,
		}, {
			Name:     "internal",
			Help:     `Use the internal OSS endpoint for uploads (requires appropriate network access).`,
			Default:  false,
			Advanced: true,
		}, {
			Name:     "dual_stack",
			Help:     `Use a dual-stack (IPv4/IPv6) OSS endpoint for uploads.`,
			Default:  false,
			Advanced: true,
		}, {
			Name:     "no_check",
			Default:  false,
			Advanced: true,
			Help:     "Disable post-upload check (avoids extra API call but reduces certainty).",
		}, {
			Name:     config.ConfigEncoding,
			Help:     config.ConfigEncodingHelp,
			Advanced: true,
			Default: (encoder.EncodeLtGt |
				encoder.EncodeDoubleQuote |
				encoder.EncodeLeftSpace |
				encoder.EncodeCtl |
				encoder.EncodeRightSpace |
				encoder.EncodeInvalidUtf8),
		}},
	})
}

func checkUploadChunkSize(cs fs.SizeSuffix) error {
	if cs < minChunkSize {
		return fmt.Errorf("%s is less than %s", cs, minChunkSize)
	}
	if cs > maxChunkSize {
		return fmt.Errorf("%s is greater than %s", cs, maxChunkSize)
	}
	return nil
}

func (f *Fs) setUploadChunkSize(cs fs.SizeSuffix) (old fs.SizeSuffix, err error) {
	err = checkUploadChunkSize(cs)
	if err == nil {
		old, f.opt.ChunkSize = f.opt.ChunkSize, cs
	}
	return
}

func checkUploadCutoff(cs fs.SizeSuffix) error {
	if cs > maxUploadCutoff {
		return fmt.Errorf("%s is greater than %s", cs, maxUploadCutoff)
	}
	return nil
}

func (f *Fs) setUploadCutoff(cs fs.SizeSuffix) (old fs.SizeSuffix, err error) {
	err = checkUploadCutoff(cs)
	if err == nil {
		old, f.opt.UploadCutoff = f.opt.UploadCutoff, cs
	}
	return
}

// Options defines the configuration of this backend
type Options struct {
	Cookie              string               `config:"cookie"` // Single cookie string now
	ShareCode           string               `config:"share_code"`
	ReceiveCode         string               `config:"receive_code"`
	UserAgent           string               `config:"user_agent"`
	RootFolderID        string               `config:"root_folder_id"`
	ListChunk           int                  `config:"list_chunk"`
	CensoredOnly        bool                 `config:"censored_only"`
	PacerMinSleep       fs.Duration          `config:"pacer_min_sleep"` // Global pacer setting
	ConTimeout          fs.Duration          `config:"contimeout"`
	Timeout             fs.Duration          `config:"timeout"`
	HashMemoryThreshold fs.SizeSuffix        `config:"hash_memory_limit"`
	UploadHashOnly      bool                 `config:"upload_hash_only"`
	OnlyStream          bool                 `config:"only_stream"`
	FastUpload          bool                 `config:"fast_upload"`
	UploadCutoff        fs.SizeSuffix        `config:"upload_cutoff"`
	NohashSize          fs.SizeSuffix        `config:"nohash_size"`
	ChunkSize           fs.SizeSuffix        `config:"chunk_size"`
	MaxUploadParts      int                  `config:"max_upload_parts"`
	Internal            bool                 `config:"internal"`
	DualStack           bool                 `config:"dual_stack"`
	NoCheck             bool                 `config:"no_check"`
	Enc                 encoder.MultiEncoder `config:"encoding"`
}

// Fs represents a remote 115 drive
type Fs struct {
	name          string
	root          string
	opt           Options
	features      *fs.Features
	tradClient    *rest.Client // Client for traditional (cookie, encrypted) API calls
	openAPIClient *rest.Client // Client for OpenAPI (token) calls
	dirCache      *dircache.DirCache
	globalPacer   *fs.Pacer // Controls overall QPS
	tradPacer     *fs.Pacer // Controls QPS for traditional calls only (subset of global)
	rootFolder    string    // path of the absolute root
	rootFolderID  string
	appVer        string // parsed from user-agent; used in traditional calls
	userID        string // User ID from cookie/token
	userkey       string // User key from traditional uploadinfo (needed for traditional upload init signature)
	isShare       bool   // mark it is from shared or not
	fileObj       *fs.Object

	// Token management
	tokenMu      sync.Mutex
	accessToken  string
	refreshToken string
	tokenExpiry  time.Time
	codeVerifier string // For PKCE
	tokenRenewer *oauthutil.Renew
}

// Object describes a 115 object
type Object struct {
	fs          *Fs
	remote      string
	hasMetaData bool
	id          string
	parent      string
	size        int64
	sha1sum     string
	pickCode    string
	modTime     time.Time
	durl        *api.DownloadURL // link to download the object
	durlMu      *sync.Mutex
}

// retryErrorCodes is a slice of HTTP status codes that we will retry
var retryErrorCodes = []int{
	429, // Too Many Requests.
	500, // Internal Server Error
	502, // Bad Gateway
	503, // Service Unavailable
	504, // Gateway Timeout
	509, // Bandwidth Limit Exceeded
}

// shouldRetry checks if a request should be retried based on the response, error, and API type.
func shouldRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}

	// Check for specific API errors that indicate retry
	// Note: Error parsing is now handled within Call* methods based on API type
	var apiErr *api.TokenError
	if errors.As(err, &apiErr) {
		// Token errors are handled by refreshTokenIfNecessary, don't retry here
		return false, err
	}

	// Standard rclone retry logic
	if fserrors.ShouldRetry(err) {
		return true, err
	}

	// HTTP status code based retry
	return fserrors.ShouldRetryHTTP(resp, retryErrorCodes), err
}

// ------------------------------------------------------------
// Authentication and Client Setup
// ------------------------------------------------------------

// Credential holds the parsed cookie values needed for initial login
type Credential struct {
	UID  string
	CID  string
	SEID string
	KID  string // Keep KID as it might be used implicitly by the web API calls
}

// Valid reports whether the credential is valid.
func (cr *Credential) Valid() error {
	if cr == nil {
		return errors.New("nil credential")
	}
	// KID is optional/sometimes empty, SEID seems required for login mimicry
	if cr.UID == "" || cr.CID == "" || cr.SEID == "" {
		return errors.New("missing UID, CID, or SEID in cookie")
	}
	return nil
}

// FromCookie loads credential from cookie string
func (cr *Credential) FromCookie(cookieStr string) *Credential {
	for _, item := range strings.Split(cookieStr, ";") {
		kv := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToUpper(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "UID":
			cr.UID = val
		case "CID":
			cr.CID = val
		case "SEID":
			cr.SEID = val
		case "KID":
			cr.KID = val
		}
	}
	return cr
}

// Cookie turns the credential into a list of http cookie for the traditional client
func (cr *Credential) Cookie() []*http.Cookie {
	cookies := []*http.Cookie{
		{Name: "UID", Value: cr.UID, Domain: domain, Path: "/", HttpOnly: true},
		{Name: "CID", Value: cr.CID, Domain: domain, Path: "/", HttpOnly: true},
		{Name: "SEID", Value: cr.SEID, Domain: domain, Path: "/", HttpOnly: true},
	}
	// Add KID only if it's present
	if cr.KID != "" {
		cookies = append(cookies, &http.Cookie{Name: "KID", Value: cr.KID, Domain: domain, Path: "/", HttpOnly: true})
	}
	return cookies
}

// UserID parses userID from UID field
func (cr *Credential) UserID() string {
	userID, _, _ := strings.Cut(cr.UID, "_")
	return userID
}

// getHTTPClient makes an http client according to the options
func getHTTPClient(ctx context.Context, opt *Options) *http.Client {
	t := fshttp.NewTransportCustom(ctx, func(t *http.Transport) {
		t.TLSHandshakeTimeout = time.Duration(opt.ConTimeout)
		t.ResponseHeaderTimeout = time.Duration(opt.Timeout)
		// Removed download_no_proxy logic
	})
	return &http.Client{
		Transport: t,
	}
}

// getTradHTTPClient creates an HTTP client with traditional UserAgent
func getTradHTTPClient(ctx context.Context, opt *Options) *http.Client {
	// Create a new context with the traditional UserAgent
	newCtx, ci := fs.AddConfig(ctx)
	ci.UserAgent = tradUserAgent
	return getHTTPClient(newCtx, opt)
}

// getOpenAPIHTTPClient creates an HTTP client with default UserAgent
func getOpenAPIHTTPClient(ctx context.Context, opt *Options) *http.Client {
	// Create a new context with the default UserAgent
	newCtx, ci := fs.AddConfig(ctx)
	ci.UserAgent = defaultUserAgent
	return getHTTPClient(newCtx, opt)
}

// errorHandler parses a non 2xx error response into an error (Generic, might need adjustment per API)
func errorHandler(resp *http.Response) error {
	// Attempt to decode as OpenAPI error first
	openAPIErr := new(api.OpenAPIBase)
	bodyBytes, readErr := rest.ReadBody(resp) // Read body once
	if readErr != nil {
		fs.Debugf(nil, "Couldn't read error response body: %v", readErr)
		// Fallback to status code if body read fails
		return api.NewTokenError(fmt.Sprintf("HTTP error %d (%s)", resp.StatusCode, resp.Status))
	}

	decodeErr := json.Unmarshal(bodyBytes, &openAPIErr)
	if decodeErr == nil && !openAPIErr.State {
		// Successfully decoded as OpenAPI error
		err := openAPIErr.Err()
		// Check for specific token-related errors
		if openAPIErr.ErrCode() == 401 || openAPIErr.ErrCode() == 100001 || strings.Contains(openAPIErr.ErrMsg(), "token") { // Example codes
			return api.NewTokenError(err.Error(), true) // Assume token error needs refresh/relogin
		}
		return err
	}

	// Attempt to decode as Traditional error
	tradErr := new(api.TraditionalBase)
	decodeErr = json.Unmarshal(bodyBytes, &tradErr)
	if decodeErr == nil && !tradErr.State {
		// Successfully decoded as Traditional error
		return tradErr.Err()
	}

	// Fallback if JSON decoding fails or state is true (but status code != 2xx)
	fs.Debugf(nil, "Couldn't decode error response: %v. Body: %s", decodeErr, string(bodyBytes))
	return api.NewTokenError(fmt.Sprintf("HTTP error %d (%s): %s", resp.StatusCode, resp.Status, string(bodyBytes)))
}

// generatePKCE generates a code_verifier and code_challenge
func generatePKCE() (verifier, challenge string, err error) {
	verifierBytes := make([]byte, pkceVerifierLength)
	_, err = rand.Read(verifierBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate random verifier: %w", err)
	}
	// Use URL-safe base64 encoding without padding
	verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)
	// Calculate SHA256 hash
	hash := sha256.Sum256([]byte(verifier))
	// Base64 encode the hash
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}

// login performs the initial authentication flow to get tokens
func (f *Fs) login(ctx context.Context) error {
	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()

	// 1. Parse cookie
	cred := (&Credential{}).FromCookie(f.opt.Cookie)
	if err := cred.Valid(); err != nil {
		return fmt.Errorf("invalid cookie provided: %w", err)
	}
	f.userID = cred.UserID() // Set userID early

	// 2. Setup clients (needed for the login calls)
	// Create separate clients for each API type with different User-Agents
	tradHTTPClient := getTradHTTPClient(ctx, &f.opt)
	openAPIHTTPClient := getOpenAPIHTTPClient(ctx, &f.opt)

	// Traditional client (uses cookie)
	f.tradClient = rest.NewClient(tradHTTPClient).
		SetRoot(traditionalRootURL).
		SetCookie(cred.Cookie()...).
		SetErrorHandler(errorHandler)

	// OpenAPI client (will have token set later)
	f.openAPIClient = rest.NewClient(openAPIHTTPClient).
		SetRoot(openAPIRootURL).
		SetErrorHandler(errorHandler)

	fs.Debugf(f, "Starting login process for user %s", f.userID)

	// 3. Generate PKCE
	var challenge string
	var err error
	f.codeVerifier, challenge, err = generatePKCE()
	if err != nil {
		return fmt.Errorf("failed to generate PKCE codes: %w", err)
	}
	fs.Debugf(f, "Generated PKCE challenge")

	// 4. Call open/authDeviceCode (using traditional client)
	authData := url.Values{
		"client_id":             {appID},
		"code_challenge":        {challenge},
		"code_challenge_method": {"sha256"}, // Use SHA256
	}
	authOpts := rest.Opts{
		Method:       "POST",
		RootURL:      passportRootURL, // Use passport API domain
		Path:         "/open/authDeviceCode",
		Parameters:   authData, // Send as query parameters for POST? Docs say body, let's try body.
		Body:         strings.NewReader(authData.Encode()),
		ExtraHeaders: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	var authResp api.AuthDeviceCodeResp
	// This initial call uses the traditional client *but doesn't need encryption*
	// It still needs the cookie and pacing.
	err = f.CallTraditionalAPI(ctx, &authOpts, nil, &authResp, true) // Pass skipEncrypt=true
	if err != nil {
		return fmt.Errorf("authDeviceCode failed: %w", err)
	}
	if authResp.Data == nil || authResp.Data.UID == "" {
		return fmt.Errorf("authDeviceCode returned empty data: %v", authResp)
	}
	loginUID := authResp.Data.UID
	fs.Debugf(f, "authDeviceCode successful, login UID: %s", loginUID)

	// 5. Mimic QR Scan/Confirm (using traditional client and endpoints)
	// These calls seem necessary based on user request, even if OpenAPI docs differ.
	// They use the *old* QR API endpoints and require the cookie.
	scanPayload := map[string]string{"uid": loginUID}
	scanOpts := rest.Opts{
		Method:     "GET",
		RootURL:    qrCodeAPIRootURL,
		Path:       "/api/2.0/prompt.php",
		Parameters: url.Values{"uid": []string{loginUID}}, // Send as query params
	}
	var scanResp api.TraditionalBase // Use base struct, don't care about response data much
	fs.Debugf(f, "Calling login_qrcode_scan...")
	err = f.CallTraditionalAPI(ctx, &scanOpts, scanPayload, &scanResp, true) // Needs encryption? Assume yes for old API.
	if err != nil {
		// Log error but continue, maybe it's not strictly required?
		fs.Logf(f, "login_qrcode_scan failed (continuing anyway): %v", err)
		// return fmt.Errorf("login_qrcode_scan failed: %w", err)
	} else {
		fs.Debugf(f, "login_qrcode_scan call successful (State: %v)", scanResp.State)
	}

	confirmPayload := map[string]string{"uid": loginUID, "key": loginUID, "client": "0"} // Key seems to be same as uid?
	confirmOpts := rest.Opts{
		Method:     "GET",
		RootURL:    hnQrCodeAPIRootURL,
		Path:       "/api/2.0/slogin.php",
		Parameters: url.Values{"uid": []string{loginUID}, "key": []string{loginUID}, "client": []string{"0"}}, // Send as query params
	}
	var confirmResp api.TraditionalBase
	fs.Debugf(f, "Calling login_qrcode_scan_confirm...")
	err = f.CallTraditionalAPI(ctx, &confirmOpts, confirmPayload, &confirmResp, true) // Needs encryption? Assume yes.
	if err != nil {
		// Log error but continue
		fs.Logf(f, "login_qrcode_scan_confirm failed (continuing anyway): %v", err)
		// return fmt.Errorf("login_qrcode_scan_confirm failed: %w", err)
	} else {
		fs.Debugf(f, "login_qrcode_scan_confirm call successful (State: %v)", confirmResp.State)
	}

	// Add a small delay after mimic steps, just in case
	time.Sleep(1 * time.Second)

	// 6. Call open/deviceCodeToToken (using traditional client)
	tokenData := url.Values{
		"uid":           {loginUID},
		"code_verifier": {f.codeVerifier},
	}
	tokenOpts := rest.Opts{
		Method:       "POST",
		RootURL:      passportRootURL,
		Path:         "/open/deviceCodeToToken",
		Body:         strings.NewReader(tokenData.Encode()),
		ExtraHeaders: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}
	var tokenResp api.DeviceCodeTokenResp
	// This call also uses traditional client but no encryption needed.
	err = f.CallTraditionalAPI(ctx, &tokenOpts, nil, &tokenResp, true) // skipEncrypt=true
	if err != nil {
		return fmt.Errorf("deviceCodeToToken failed: %w", err)
	}
	if tokenResp.Data == nil || tokenResp.Data.AccessToken == "" {
		return fmt.Errorf("deviceCodeToToken returned empty data: %v", tokenResp)
	}

	// 7. Store tokens
	f.accessToken = tokenResp.Data.AccessToken
	f.refreshToken = tokenResp.Data.RefreshToken
	f.tokenExpiry = time.Now().Add(time.Duration(tokenResp.Data.ExpiresIn) * time.Second)
	fs.Debugf(f, "Successfully obtained access token, expires at %v", f.tokenExpiry)

	// 8. Get userkey (needed for traditional upload init signature)
	// This uses the old /app/uploadinfo endpoint with the cookie.
	if f.userkey == "" {
		fs.Debugf(f, "Fetching userkey using traditional API...")
		if err := f.getUploadBasicInfo(ctx); err != nil {
			// Log error but don't fail login, userkey is only for traditional upload init
			fs.Logf(f, "Failed to get userkey (needed for some traditional uploads): %v", err)
		} else {
			fs.Debugf(f, "Successfully fetched userkey.")
		}
	}

	return nil
}

// refreshTokenIfNecessary checks token expiry and refreshes if needed.
// This function handles its own locking.
func (f *Fs) refreshTokenIfNecessary(ctx context.Context) error {
	f.tokenMu.Lock()

	// Common check for token validity
	if f.accessToken == "" || f.refreshToken == "" {
		fs.Debugf(f, "No token found, attempting initial login.")
		// Drop lock before calling login, as login acquires the lock
		f.tokenMu.Unlock()
		err := f.login(ctx)
		return err // login handles its own locking
	}

	if time.Now().Before(f.tokenExpiry.Add(-tokenRefreshWindow)) {
		f.tokenMu.Unlock() // Unlock before returning since token is valid
		return nil         // Token is still valid
	}

	// Prepare for token refresh
	fs.Debugf(f, "Access token expired or nearing expiry, attempting refresh.")
	refreshToken := f.refreshToken // Store locally before unlocking
	f.tokenMu.Unlock()             // Unlock before making API call

	// Check if openAPIClient is initialized
	if f.openAPIClient == nil {
		// Setup client if it doesn't exist
		newCtx, ci := fs.AddConfig(ctx)
		ci.UserAgent = f.opt.UserAgent
		httpClient := getHTTPClient(newCtx, &f.opt)
		f.openAPIClient = rest.NewClient(httpClient).
			SetRoot(openAPIRootURL).
			SetErrorHandler(errorHandler)
	}

	// Set up refresh request
	refreshData := url.Values{
		"refresh_token": {refreshToken},
	}
	opts := rest.Opts{
		Method:       "POST",
		RootURL:      passportRootURL,
		Path:         "/open/refreshToken",
		Body:         strings.NewReader(refreshData.Encode()),
		ExtraHeaders: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}

	// Make API call without the lock
	var refreshResp api.RefreshTokenResp
	_, err := f.openAPIClient.CallJSON(ctx, &opts, nil, &refreshResp)

	// Handle the response
	if err != nil {
		fs.Errorf(f, "Refresh token failed: %v", err)
		// Check if the error indicates the refresh token itself is expired
		var tokenErr *api.TokenError
		if errors.As(err, &tokenErr) && tokenErr.IsRefreshTokenExpired || strings.Contains(err.Error(), "refresh token expired") {
			fs.Debugf(f, "Refresh token seems expired, attempting full re-login.")
			loginErr := f.login(ctx) // login handles its own locking
			if loginErr != nil {
				return fmt.Errorf("re-login failed after refresh token expired: %w", loginErr)
			}
			fs.Debugf(f, "Re-login successful after refresh token expiry.")
			return nil // Re-login successful
		}
		// Return the original refresh error if it wasn't an expiry issue or re-login failed
		return fmt.Errorf("token refresh failed: %w", err)
	}

	if refreshResp.Data == nil || refreshResp.Data.AccessToken == "" {
		fs.Errorf(f, "Refresh token response empty, attempting re-login.")
		loginErr := f.login(ctx) // login handles its own locking
		if loginErr != nil {
			return fmt.Errorf("re-login failed after empty refresh response: %w", loginErr)
		}
		fs.Debugf(f, "Re-login successful after empty refresh response.")
		return nil // Re-login successful
	}

	// Update tokens
	f.accessToken = refreshResp.Data.AccessToken
	// OpenAPI spec says refresh_token might be updated, so store the new one
	if refreshResp.Data.RefreshToken != "" {
		f.refreshToken = refreshResp.Data.RefreshToken
	}
	f.tokenExpiry = time.Now().Add(time.Duration(refreshResp.Data.ExpiresIn) * time.Second)
	fs.Debugf(f, "Token refreshed successfully, new expiry: %v", f.tokenExpiry)
	return nil
}

// saveToken saves the current token to the config
func (f *Fs) saveToken(ctx context.Context, m configmap.Mapper) {
	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()

	if f.accessToken == "" || f.refreshToken == "" || f.tokenExpiry.IsZero() {
		fs.Debugf(f, "Not saving tokens - incomplete token information")
		return
	}

	// Create the token structure
	token := map[string]string{
		"access_token":  f.accessToken,
		"token_type":    "Bearer",
		"refresh_token": f.refreshToken,
		"expiry":        f.tokenExpiry.Format(time.RFC3339Nano),
	}

	// Convert to JSON
	tokenBytes, err := json.Marshal(token)
	if err != nil {
		fs.Errorf(f, "Failed to marshal token: %v", err)
		return
	}
	tokenString := string(tokenBytes)

	// Save to config
	err = config.SetValueAndSave(f.name, "token", tokenString)
	if err != nil {
		fs.Errorf(f, "Failed to save token to config: %v", err)
		return
	}

	fs.Debugf(f, "Saved token to config file")
}

// setupTokenRenewer initializes the token renewer to automatically refresh tokens
func (f *Fs) setupTokenRenewer(ctx context.Context, m configmap.Mapper) {
	// Only set up renewer if we have valid tokens
	if f.accessToken == "" || f.refreshToken == "" || f.tokenExpiry.IsZero() {
		return
	}

	// Create a renewal transaction function
	transaction := func() error {
		f.tokenMu.Lock()
		defer f.tokenMu.Unlock()

		// Check if token needs refresh
		if time.Now().Before(f.tokenExpiry.Add(-tokenRefreshWindow)) {
			return nil // Token is still valid
		}

		// Perform refresh without lock to avoid deadlock
		f.tokenMu.Unlock()
		// Use the direct method to refresh instead of calling refreshTokenIfNecessary to avoid deadlocks
		refreshData := url.Values{
			"refresh_token": {f.refreshToken},
		}
		opts := rest.Opts{
			Method:       "POST",
			RootURL:      passportRootURL,
			Path:         "/open/refreshToken",
			Body:         strings.NewReader(refreshData.Encode()),
			ExtraHeaders: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		}

		var refreshResp api.RefreshTokenResp
		_, err := f.openAPIClient.CallJSON(ctx, &opts, nil, &refreshResp)

		// Reacquire lock
		f.tokenMu.Lock()

		if err == nil && refreshResp.Data != nil && refreshResp.Data.AccessToken != "" {
			// Update tokens
			f.accessToken = refreshResp.Data.AccessToken
			if refreshResp.Data.RefreshToken != "" {
				f.refreshToken = refreshResp.Data.RefreshToken
			}
			f.tokenExpiry = time.Now().Add(time.Duration(refreshResp.Data.ExpiresIn) * time.Second)
			fs.Debugf(f, "Token refreshed successfully via renewer, new expiry: %v", f.tokenExpiry)

			// Save the refreshed token back to config
			f.saveToken(ctx, m)
		} else if err != nil {
			fs.Errorf(f, "Failed to refresh token in renewer: %v", err)
		}

		return err
	}

	// Create actual OAuth2 token from our fields
	token := &oauth2.Token{
		AccessToken:  f.accessToken,
		RefreshToken: f.refreshToken,
		Expiry:       f.tokenExpiry,
		TokenType:    "Bearer",
	}

	// Save token to config so it can be accessed by TokenSource
	err := oauthutil.PutToken(f.name, m, token, false)
	if err != nil {
		fs.Logf(f, "Failed to save token for renewer: %v", err)
		return
	}

	// Create a minimal config for token handling
	config := &oauthutil.Config{
		TokenURL: "https://115.com/oauth/token", // The actual URL doesn't matter for refresh operation
	}

	// Create a client with the token source
	_, ts, err := oauthutil.NewClientWithBaseClient(ctx, f.name, m, config, fshttp.NewClient(ctx))
	if err != nil {
		fs.Logf(f, "Failed to create token source for renewer: %v", err)
		return
	}

	// Create token renewer that will trigger when the token is about to expire
	f.tokenRenewer = oauthutil.NewRenew(f.String(), ts, transaction)
	fs.Debugf(f, "Token renewer initialized")
}

// CallOpenAPI performs a call to the OpenAPI endpoint.
// It handles token refresh and sets the Authorization header.
// If skipToken is true, it skips adding the Authorization header (used for refresh itself).
func (f *Fs) CallOpenAPI(ctx context.Context, opts *rest.Opts, request any, response any, skipToken bool) error {
	// Ensure root URL is set if not provided in opts
	if opts.RootURL == "" {
		opts.RootURL = openAPIRootURL
	}

	// Wrap the entire attempt sequence with the global pacer, returning proper retry signals
	err := f.globalPacer.Call(func() (shouldRetryGlobal bool, errGlobal error) {
		// Check if we need to refresh the token first
		if !skipToken {
			// Token refresh is needed - refreshTokenIfNecessary handles its own locking
			refreshErr := f.refreshTokenIfNecessary(ctx)
			if refreshErr != nil {
				fs.Debugf(f, "Token refresh check failed: %v", refreshErr)
				return false, backoff.Permanent(fmt.Errorf("token refresh check failed: %w", refreshErr))
			}

			// Get the current token
			f.tokenMu.Lock()
			token := f.accessToken
			f.tokenMu.Unlock()

			// Set the Authorization header
			if opts.ExtraHeaders == nil {
				opts.ExtraHeaders = make(map[string]string)
			}
			opts.ExtraHeaders["Authorization"] = "Bearer " + token
		}

		// Make the call using the OpenAPI client
		var resp *http.Response
		var apiErr error
		if request != nil && response != nil {
			// Assume standard JSON request/response
			resp, apiErr = f.openAPIClient.CallJSON(ctx, opts, request, response)
		} else if response != nil {
			// Assume GET request with JSON response
			resp, apiErr = f.openAPIClient.CallJSON(ctx, opts, nil, response)
		} else {
			// Assume call without specific request/response body
			var baseResp api.OpenAPIBase
			resp, apiErr = f.openAPIClient.CallJSON(ctx, opts, nil, &baseResp)
			if apiErr == nil {
				apiErr = baseResp.Err() // Check for API-level errors
			}
		}

		// Check for retryable errors
		retryNeeded, retryErr := shouldRetry(ctx, resp, apiErr)
		if retryNeeded {
			fs.Debugf(f, "pacer: low level retry required for OpenAPI call (error: %v)", retryErr)
			return true, retryErr // Signal globalPacer to retry
		}

		// If error occurred and it's not retryable according to shouldRetry
		if apiErr != nil {
			// Check if it's a token error that might need re-login
			var tokenErr *api.TokenError
			if errors.As(apiErr, &tokenErr) && tokenErr.IsRefreshTokenExpired {
				// Signal that re-login is needed by returning the specific error
				fs.Debugf(f, "Token error detected, needs re-login: %v", tokenErr)
				return false, tokenErr // Special case handled outside the pacer
			}

			// Non-retryable error
			fs.Debugf(f, "pacer: permanent error encountered in OpenAPI call: %v", apiErr)
			return false, backoff.Permanent(apiErr)
		}

		// Check for API-level errors in the response struct if applicable
		if response != nil {
			// Use reflection to check for and call an Err() method
			val := reflect.ValueOf(response)
			if val.Kind() == reflect.Ptr && !val.IsNil() {
				method := val.MethodByName("Err")
				if method.IsValid() && method.Type().NumIn() == 0 && method.Type().NumOut() == 1 && method.Type().Out(0).Implements(reflect.TypeOf((*error)(nil)).Elem()) {
					result := method.Call(nil)
					if !result[0].IsNil() {
						apiErr = result[0].Interface().(error)
						// Check if this specific API error is a token error
						var tokenErr *api.TokenError
						if errors.As(apiErr, &tokenErr) && tokenErr.IsRefreshTokenExpired {
							fs.Debugf(f, "Token error detected in API response, needs re-login: %v", tokenErr)
							return false, tokenErr
						}
						fs.Debugf(f, "pacer: permanent API error encountered in API response: %v", apiErr)
						return false, backoff.Permanent(apiErr) // Treat API error as permanent
					}
				}
			}
		}

		fs.Debugf(f, "pacer: OpenAPI call successful")
		return false, nil // Success, don't retry
	})

	// The re-login logic is handled outside the pacer.Call like before
	var tokenErr *api.TokenError
	if errors.As(err, &tokenErr) && tokenErr.IsRefreshTokenExpired {
		fs.Debugf(f, "Token error detected after API call, attempting re-login.")
		f.tokenMu.Lock()
		loginErr := f.login(ctx) // Attempt re-login
		f.tokenMu.Unlock()
		if loginErr != nil {
			return fmt.Errorf("re-login failed after token error: %w (original error: %s)", loginErr, err)
		}
		// Re-login successful, retry the original call *once*
		fs.Debugf(f, "Re-login successful, retrying original OpenAPI call.")

		// Retry once with the same pacer pattern
		err = f.globalPacer.Call(func() (shouldRetryGlobal bool, errGlobal error) {
			// Prepare request again
			if !skipToken {
				if opts.ExtraHeaders == nil {
					opts.ExtraHeaders = make(map[string]string)
				}
				// Use the newly acquired token from re-login
				f.tokenMu.Lock()
				opts.ExtraHeaders["Authorization"] = "Bearer " + f.accessToken
				f.tokenMu.Unlock()
			}

			// Make the call using the OpenAPI client
			var resp *http.Response
			var apiErr error
			if request != nil && response != nil {
				resp, apiErr = f.openAPIClient.CallJSON(ctx, opts, request, response)
			} else if response != nil {
				resp, apiErr = f.openAPIClient.CallJSON(ctx, opts, nil, response)
			} else {
				var baseResp api.OpenAPIBase
				resp, apiErr = f.openAPIClient.CallJSON(ctx, opts, nil, &baseResp)
				if apiErr == nil {
					apiErr = baseResp.Err()
				}
			}

			// Check for retryable errors
			retryNeeded, retryErr := shouldRetry(ctx, resp, apiErr)
			if retryNeeded {
				fs.Debugf(f, "pacer: low level retry required for OpenAPI call after re-login (error: %v)", retryErr)
				return true, retryErr // Signal globalPacer to retry
			}

			if apiErr != nil {
				fs.Debugf(f, "pacer: permanent error encountered in OpenAPI call after re-login: %v", apiErr)
				return false, backoff.Permanent(apiErr)
			}

			// Check API response errors like before
			if response != nil {
				val := reflect.ValueOf(response)
				if val.Kind() == reflect.Ptr && !val.IsNil() {
					method := val.MethodByName("Err")
					if method.IsValid() && method.Type().NumIn() == 0 && method.Type().NumOut() == 1 && method.Type().Out(0).Implements(reflect.TypeOf((*error)(nil)).Elem()) {
						result := method.Call(nil)
						if !result[0].IsNil() {
							apiErr = result[0].Interface().(error)
							fs.Debugf(f, "pacer: permanent API error encountered in API response after re-login: %v", apiErr)
							return false, backoff.Permanent(apiErr)
						}
					}
				}
			}

			fs.Debugf(f, "pacer: OpenAPI call successful after re-login")
			return false, nil // Success after re-login
		})
	}

	return err
}

// CallTraditionalAPI performs a call to the traditional (cookie, encrypted) API.
// It uses both the traditional and global pacers.
// If skipEncrypt is true, it skips the request/response encryption (used for some login steps).
func (f *Fs) CallTraditionalAPI(ctx context.Context, opts *rest.Opts, request any, response any, skipEncrypt bool) error {
	// Ensure root URL is set if not provided in opts
	if opts.RootURL == "" {
		opts.RootURL = traditionalRootURL
	}

	// Wrap the entire attempt sequence with the global pacer
	return f.globalPacer.Call(func() (shouldRetryGlobal bool, errGlobal error) {

		// --- Enforce traditional pacer delay ---
		// Use tradPacer.Call with a dummy function that always succeeds immediately
		// and doesn't retry. This effectively just waits for the pacer's internal timer.
		tradPaceErr := f.tradPacer.Call(func() (bool, error) {
			return false, nil // Dummy call: Success, don't retry this dummy op.
		})
		if tradPaceErr != nil {
			// If waiting for tradPacer was interrupted (e.g., context cancelled)
			fs.Debugf(f, "Context cancelled or error while waiting for traditional pacer: %v", tradPaceErr)
			// Treat this as a permanent failure for the global pacer's attempt.
			return false, backoff.Permanent(tradPaceErr)
		}
		// --- End of traditional pacer delay enforcement ---

		// Prepare and make the actual API call using the traditional client
		var resp *http.Response
		var apiErr error // Renamed from 'err' to avoid shadowing tradPaceErr
		if skipEncrypt {
			// Call without encryption (used for some login steps)
			if request != nil && response != nil {
				resp, apiErr = f.tradClient.CallJSON(ctx, opts, request, response)
			} else if response != nil {
				resp, apiErr = f.tradClient.CallJSON(ctx, opts, nil, response)
			} else {
				var baseResp api.TraditionalBase
				resp, apiErr = f.tradClient.CallJSON(ctx, opts, nil, &baseResp)
				if apiErr == nil {
					apiErr = baseResp.Err()
				}
			}
		} else {
			// Call with standard encryption
			if request != nil && response != nil {
				// Encode request data
				input, marshalErr := json.Marshal(request)
				if marshalErr != nil {
					// Permanent error on marshal failure
					return false, backoff.Permanent(fmt.Errorf("failed to marshal traditional request: %w", marshalErr))
				}
				key := crypto.GenerateKey()
				// Check if opts.MultipartParams exists, if not create it
				if opts.MultipartParams == nil {
					opts.MultipartParams = url.Values{}
				}
				opts.MultipartParams.Set("data", crypto.Encode(input, key))
				opts.Body = nil // Clear body if using multipart params

				var info api.StringInfo // Expect encrypted string response
				resp, apiErr = f.tradClient.CallJSON(ctx, opts, nil, &info)
				if apiErr == nil {
					if apiErr = info.Err(); apiErr != nil {
						// API level error before decryption
					} else if info.Data == "" {
						apiErr = errors.New("no data received in traditional response")
					} else {
						// Decode and unmarshal response
						key := crypto.GenerateKey()
						output, decodeErr := crypto.Decode(string(info.Data), key)
						if decodeErr != nil {
							apiErr = fmt.Errorf("failed to decode traditional data: %w", decodeErr)
						} else if unmarshalErr := json.Unmarshal(output, response); unmarshalErr != nil {
							apiErr = fmt.Errorf("failed to unmarshal traditional response %q: %w", string(output), unmarshalErr)
						}
					}
				}
			} else if response != nil {
				// Call expecting encrypted response, no request body needed (e.g., GET)
				var info api.StringInfo
				resp, apiErr = f.tradClient.CallJSON(ctx, opts, nil, &info)
				if apiErr == nil {
					if apiErr = info.Err(); apiErr != nil {
						// API level error before decryption
					} else if info.Data == "" {
						apiErr = errors.New("no data received in traditional response")
					} else {
						key := crypto.GenerateKey()
						output, decodeErr := crypto.Decode(string(info.Data), key)
						if decodeErr != nil {
							apiErr = fmt.Errorf("failed to decode traditional data: %w", decodeErr)
						} else if unmarshalErr := json.Unmarshal(output, response); unmarshalErr != nil {
							apiErr = fmt.Errorf("failed to unmarshal traditional response %q: %w", string(output), unmarshalErr)
						}
					}
				}
			} else {
				// Call expecting simple base response (e.g., delete, move)
				var baseResp api.TraditionalBase
				resp, apiErr = f.tradClient.CallJSON(ctx, opts, nil, &baseResp)
				if apiErr == nil {
					apiErr = baseResp.Err()
				}
			}
		}

		// Check the result of the actual API call for retryability by the *global* pacer
		retryNeeded, retryErr := shouldRetry(ctx, resp, apiErr)
		if retryNeeded {
			fs.Debugf(f, "pacer: low level retry required for traditional call (error: %v)", retryErr)
		} else if apiErr != nil {
			// Error occurred, but shouldRetry decided it's permanent
			fs.Debugf(f, "pacer: permanent error encountered in traditional call: %v", apiErr)
			// Ensure the error returned to globalPacer is marked permanent if it isn't already.
			var permanentErr *backoff.PermanentError
			if !errors.As(apiErr, &permanentErr) {
				retryErr = backoff.Permanent(apiErr)
			} else {
				retryErr = apiErr // Already permanent
			}
		} else {
			// Success
			fs.Debugf(f, "pacer: traditional call successful")
			retryErr = nil
		}

		// Return the retry status and error to the *global* pacer
		return retryNeeded, retryErr

	}) // End of globalPacer.Call
}

// newFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	// Validate incompatible options
	if opt.FastUpload && opt.OnlyStream {
		return nil, errors.New("fast_upload and only_stream cannot be set simultaneously")
	}
	if opt.FastUpload && opt.UploadHashOnly {
		return nil, errors.New("fast_upload and upload_hash_only cannot be set simultaneously")
	}
	if opt.OnlyStream && opt.UploadHashOnly {
		return nil, errors.New("only_stream and upload_hash_only cannot be set simultaneously")
	}

	// Validate upload parameters
	err = checkUploadChunkSize(opt.ChunkSize)
	if err != nil {
		return nil, fmt.Errorf("115: chunk size: %w", err)
	}
	err = checkUploadCutoff(opt.UploadCutoff)
	if err != nil {
		return nil, fmt.Errorf("115: upload cutoff: %w", err)
	}
	if opt.NohashSize > StreamUploadLimit {
		fs.Logf(name, "nohash_size (%v) reduced to stream upload limit (%v)", opt.NohashSize, StreamUploadLimit)
		opt.NohashSize = StreamUploadLimit
	}

	// Parse root ID from path if present
	if rootID, _, _ := parseRootID(root); rootID != "" {
		name += rootID // Append ID to name for uniqueness?
		root = root[strings.Index(root, "}")+1:]
	}

	root = strings.Trim(root, "/")

	f := &Fs{
		name: name,
		root: root,
		opt:  *opt,
	}
	f.features = (&fs.Features{
		DuplicateFiles:          false,
		CanHaveEmptyDirectories: true,
		NoMultiThreading:        true, // Keep true as downloads might still use traditional API? Or set based on API used? Let's keep it for now.
	}).Fill(ctx, f)

	// Setting appVer (might only be needed for traditional calls)
	re := regexp.MustCompile(`\d+\.\d+\.\d+(\.\d+)?$`)
	if m := re.FindStringSubmatch(tradUserAgent); m == nil {
		// Don't fail, just use a default or log a warning if UserAgent is critical
		fs.Logf(f, "Could not parse app version from User-Agent %q. Using default.", tradUserAgent)
		f.appVer = "27.0.7.5" // Default fallback
	} else {
		f.appVer = m[0]
		fs.Debugf(f, "Using App Version %q from User-Agent %q", f.appVer, tradUserAgent)
	}

	// Initialize pacers
	f.globalPacer = fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(time.Duration(opt.PacerMinSleep)), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant)))
	f.tradPacer = fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(traditionalMinSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant)))

	// Check if we have saved token in config file
	tokenString, found := m.Get("token")
	if found && tokenString != "" {
		// Parse the token
		token := make(map[string]interface{})
		err = json.Unmarshal([]byte(tokenString), &token)
		if err == nil {
			// Extract token components
			if accessToken, ok := token["access_token"].(string); ok {
				f.accessToken = accessToken
			}
			if refreshToken, ok := token["refresh_token"].(string); ok {
				f.refreshToken = refreshToken
			}
			if expiryStr, ok := token["expiry"].(string); ok {
				f.tokenExpiry, _ = time.Parse(time.RFC3339Nano, expiryStr)
			}

			fs.Debugf(f, "Loaded token from config file, expires at %v", f.tokenExpiry)

			// Only attempt to validate/refresh if we have both tokens
			if f.accessToken != "" && f.refreshToken != "" {
				// Check if the token needs refreshing now
				if time.Now().After(f.tokenExpiry.Add(-tokenRefreshWindow)) {
					fs.Debugf(f, "Token expired or will expire soon, refreshing now")
					// refreshTokenIfNecessary handles its own locking
					err = f.refreshTokenIfNecessary(ctx)
					if err != nil {
						fs.Logf(f, "Failed to refresh token from config: %v", err)
						// Continue with login below
					} else {
						// Token refreshed successfully, save it back to config
						f.saveToken(ctx, m)
					}
				}
			}
		} else {
			fs.Logf(f, "Failed to parse token from config: %v", err)
		}
	}

	// Perform initial login if needed (no token or token refresh failed)
	if f.accessToken == "" || f.refreshToken == "" {
		if err = f.login(ctx); err != nil {
			return nil, fmt.Errorf("initial login failed: %w", err)
		}
		// Save token to config after successful login
		f.saveToken(ctx, m)
	}

	// Setup clients (needed in case login above didn't initialize them)
	if f.tradClient == nil || f.openAPIClient == nil {
		// Create separate clients for each API type with different User-Agents
		tradHTTPClient := getTradHTTPClient(ctx, &f.opt)
		openAPIHTTPClient := getOpenAPIHTTPClient(ctx, &f.opt)

		// Traditional client (uses cookie)
		if f.tradClient == nil {
			cred := (&Credential{}).FromCookie(f.opt.Cookie)
			f.tradClient = rest.NewClient(tradHTTPClient).
				SetRoot(traditionalRootURL).
				SetCookie(cred.Cookie()...).
				SetErrorHandler(errorHandler)
		}

		// OpenAPI client
		if f.openAPIClient == nil {
			f.openAPIClient = rest.NewClient(openAPIHTTPClient).
				SetRoot(openAPIRootURL).
				SetErrorHandler(errorHandler)
		}
	}

	// Setup token renewer
	f.setupTokenRenewer(ctx, m)

	// --- Root Folder Logic ---
	// mod - parse object id from path remote:{ID}
	if rootID, receiveCode, _ := parseRootID(f.root); len(rootID) == 19 { // Check if root looks like a file/folder ID
		info, err := f.getFile(ctx, rootID, "") // Use getFile which now uses OpenAPI
		if err != nil {
			// Check if it's a directory not found error vs file not found
			if errors.Is(err, fs.ErrorDirNotFound) || errors.Is(err, fs.ErrorObjectNotFound) {
				return nil, fmt.Errorf("root ID %s not found: %w", rootID, err)
			}
			return nil, fmt.Errorf("failed to get info for root ID %s: %w", rootID, err)
		}
		if !info.IsDir() {
			// Root is a file
			f.dirCache = dircache.New("", info.ParentID(), f)
			_ = f.dirCache.FindRoot(ctx, false) // Populate parent info
			obj, _ := f.newObjectWithInfo(ctx, info.FileNameBest(), info)
			f.root = "isFile:" + info.FileNameBest() // Mark root as special case
			f.fileObj = &obj
			return f, fs.ErrorIsFile
		}
		// Root is a directory ID
		f.opt.RootFolderID = rootID
		f.root = "" // Reset root path as we are using RootFolderID
	} else if len(rootID) == 11 { // Check if root looks like a share code
		f.opt.ShareCode = rootID
		f.opt.ReceiveCode = receiveCode
		f.root = "" // Reset root path for shares
	}

	// Mark if it's a share based on options (needed for traditional share API)
	f.isShare = f.opt.ShareCode != "" && f.opt.ReceiveCode != ""

	// Set the root folder ID
	if f.isShare {
		// Shares use traditional API, root ID determined during listing/copying
		f.rootFolderID = ""
	} else if f.opt.RootFolderID != "" {
		f.rootFolderID = f.opt.RootFolderID
	} else {
		f.rootFolderID = "0" // Default root
	}

	// Features related to sharing (only possible via traditional API)
	f.features.ServerSideAcrossConfigs = f.isShare

	// Set the root folder path if it is not the absolute root "0"
	if f.rootFolderID != "" && f.rootFolderID != "0" {
		// Use getDirPath which now uses OpenAPI
		f.rootFolder, err = f.getDirPath(ctx, f.rootFolderID)
		if err != nil {
			// Check if the error is dir not found
			if errors.Is(err, fs.ErrorDirNotFound) {
				return nil, fmt.Errorf("configured root folder ID %q not found: %w", f.rootFolderID, err)
			}
			return nil, fmt.Errorf("failed to get path for root folder ID %q: %w", f.rootFolderID, err)
		}
	}

	f.dirCache = dircache.New(f.root, f.rootFolderID, f)

	// Find the current root directory in the cache
	err = f.dirCache.FindRoot(ctx, false)
	if err != nil {
		// If root is not found, check if it's a file path
		newRoot, remote := dircache.SplitPath(f.root)
		if remote != "" { // Only check if there's a leaf part
			tempF := *f // Create a temporary Fs pointing to the parent
			tempF.dirCache = dircache.New(newRoot, f.rootFolderID, &tempF)
			tempF.root = newRoot
			// Don't fill cache, FindRoot needs to run on the parent
			errRoot := tempF.dirCache.FindRoot(ctx, false)
			if errRoot == nil {
				// Parent exists, try to find the leaf as an object
				_, errFile := tempF.NewObject(ctx, remote)
				if errFile == nil {
					// It's a file! Update the original Fs instance
					f.dirCache = tempF.dirCache
					f.root = tempF.root
					f.features.Fill(ctx, &tempF) // Fill features based on the parent Fs
					return f, fs.ErrorIsFile
				}
				// If leaf is not an object, maybe it's a non-existent path?
				if errors.Is(errFile, fs.ErrorObjectNotFound) {
					// Instead of returning an error, create the missing directory if it's not a share
					if !f.isShare {
						fs.Debugf(f, "Directory %q not found, creating it", f.root)
						// Recreate the dirCache with create=true to auto-create parent directories
						f.dirCache = dircache.New(f.root, f.rootFolderID, f)
						err = f.dirCache.FindRoot(ctx, true)
						if err != nil {
							return nil, fmt.Errorf("failed to create directory %q: %w", f.root, err)
						}
						return f, nil
					}
					return f, fmt.Errorf("path not found: %s", f.root) // Return original error for shares
				}
				// Return other errors from NewObject
				return nil, errFile
			}
		}

		// If root is not a file path, check if we should create the directory
		if !f.isShare && errors.Is(err, fs.ErrorDirNotFound) {
			fs.Debugf(f, "Root directory %q not found, creating it", f.root)
			// Recreate dirCache with create=true to auto-create the directory structure
			f.dirCache = dircache.New(f.root, f.rootFolderID, f)
			err = f.dirCache.FindRoot(ctx, true)
			if err != nil {
				return nil, fmt.Errorf("failed to create root directory %q: %w", f.root, err)
			}
			return f, nil
		}

		// If FindRoot failed for other reasons, or it was a share that doesn't exist
		return f, err // Return the original error from FindRoot
	}

	return f, nil
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String returns a description of the FS
func (f *Fs) String() string {
	return fmt.Sprintf("115 %s", f.root)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// Precision of the ModTimes in this Fs
func (f *Fs) Precision() time.Duration {
	// OpenAPI might allow setting modtime, but let's assume not for now
	return fs.ModTimeNotSupported
}

// DirCacheFlush resets the directory cache
func (f *Fs) DirCacheFlush() {
	f.dirCache.ResetRoot()
}

// Hashes returns the supported hash types of the filesystem
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.SHA1)
}

// NewObject finds the Object at remote.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	if f.fileObj != nil { // Handle case where Fs points to a single file
		obj := *f.fileObj
		if obj.Remote() == remote || obj.Remote() == "isFile:"+remote {
			return obj, nil
		}
		return nil, fs.ErrorObjectNotFound // If remote doesn't match the single file
	}
	return f.newObjectWithInfo(ctx, remote, nil)
}

// FindLeaf finds a directory or file leaf in the parent folder pathID.
// Used by dircache.
func (f *Fs) FindLeaf(ctx context.Context, pathID, leaf string) (foundID string, found bool, err error) {
	// Use listAll which now uses OpenAPI
	found, err = f.listAll(ctx, pathID, f.opt.ListChunk, false, false, func(item *api.File) bool {
		if item.FileNameBest() == leaf {
			foundID = item.ID()
			// Cache the found item's path/ID mapping
			parentPath, ok := f.dirCache.GetInv(pathID)
			if ok {
				itemPath := path.Join(parentPath, leaf)
				f.dirCache.Put(itemPath, foundID)
			}
			return true // Stop searching
		}
		return false // Continue searching
	})
	return foundID, found, err
}

// GetDirID finds a directory ID by its absolute path. Used by dircache.
// This implementation uses the OpenAPI list endpoint iteratively, which might be slow.
// The traditional /files/getid is faster but less reliable. We prioritize OpenAPI.
func (f *Fs) GetDirID(ctx context.Context, dir string) (string, error) {
	// Start from the filesystem's root ID
	currentID := f.rootFolderID
	if dir == "" || dir == "/" {
		return currentID, nil
	}

	parts := strings.Split(strings.Trim(dir, "/"), "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		encodedPart := f.opt.Enc.FromStandardName(part) // Encode each part
		foundID, found, err := f.FindLeaf(ctx, currentID, encodedPart)
		if err != nil {
			return "", fmt.Errorf("error searching for %q in %q: %w", encodedPart, currentID, err)
		}
		if !found {
			return "", fs.ErrorDirNotFound
		}
		// Check if the found item is actually a directory
		// Need a way to confirm type without full listing again. Assume FindLeaf returns correct type for now.
		// If FindLeaf could return the *api.File, we could check item.IsDir() here.
		// For now, assume FindLeaf only finds directories when called by GetDirID context.
		currentID = foundID
	}
	return currentID, nil
}

// List the objects and directories in dir into entries.
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	dirID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return nil, err
	}
	var iErr error
	_, err = f.listAll(ctx, dirID, f.opt.ListChunk, false, false, func(item *api.File) bool {
		entry, err := f.itemToDirEntry(ctx, path.Join(dir, item.FileNameBest()), item)
		if err != nil {
			iErr = err // Capture error but continue listing
			return false
		}
		if entry != nil {
			entries = append(entries, entry)
		}
		return false
	})
	if err != nil {
		return nil, err // Return listing error
	}
	if iErr != nil {
		return nil, iErr // Return item processing error
	}
	return entries, nil
}

// CreateDir makes a directory with pathID as parent and name leaf. Used by dircache.
func (f *Fs) CreateDir(ctx context.Context, pathID, leaf string) (newID string, err error) {
	if f.isShare {
		return "", errors.New("unsupported operation: Mkdir on shared filesystem")
	}
	// Use makeDir which now uses OpenAPI
	info, err := f.makeDir(ctx, pathID, leaf)
	if err != nil {
		return "", err
	}
	if info.Data == nil || info.Data.FileID == "" {
		return "", errors.New("Mkdir response did not contain a file ID")
	}
	return info.Data.FileID, nil
}

// Put uploads the object.
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	// Check if destination exists. If not, use PutUnchecked. If yes, use Update.
	existingObj, err := f.NewObject(ctx, src.Remote())
	if err == fs.ErrorObjectNotFound {
		// Not found, so create it using PutUnchecked
		return f.PutUnchecked(ctx, in, src, options...)
	} else if err != nil {
		// An error other than not found
		return nil, err
	}
	// Object exists, so update it
	return existingObj, existingObj.Update(ctx, in, src, options...)
}

// PutUnchecked uploads the object without checking for existence first.
func (f *Fs) PutUnchecked(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.putUnchecked(ctx, in, src, src.Remote(), options...)
}

// putUnchecked uploads the object
func (f *Fs) putUnchecked(ctx context.Context, in io.Reader, src fs.ObjectInfo, remote string, options ...fs.OpenOption) (fs.Object, error) {
	if f.isShare {
		return nil, errors.New("unsupported operation: Put on shared filesystem")
	}

	// Call the main upload function which handles different strategies
	newObj, err := f.upload(ctx, in, src, remote, options...)
	if err != nil {
		return nil, err
	}
	if newObj == nil {
		return nil, errors.New("internal error: upload returned nil object without error")
	}

	o := newObj.(*Object)

	// Post-upload check (optional)
	if !f.opt.NoCheck && !o.hasMetaData {
		fs.Debugf(o, "Running post-upload check...")
		// Attempt to read metadata for the uploaded object to confirm
		err = o.readMetaData(ctx) // This will list the parent directory
		if err != nil {
			// Don't fail the upload, just log a warning
			fs.Logf(o, "Post-upload check failed to read metadata: %v", err)
			// Mark as having metadata anyway to avoid repeated checks
			o.hasMetaData = true
		} else {
			fs.Debugf(o, "Post-upload check successful.")
		}
	}

	return newObj, nil
}

// MergeDirs merges multiple source directories into the first one.
func (f *Fs) MergeDirs(ctx context.Context, dirs []fs.Directory) (err error) {
	if f.isShare {
		return errors.New("unsupported operation: MergeDirs on shared filesystem")
	}
	if len(dirs) < 2 {
		return nil
	}
	dstDir := dirs[0]
	dstDirID := dstDir.ID()

	for _, srcDir := range dirs[1:] {
		srcDirID := srcDir.ID()
		fs.Debugf(srcDir, "Merging contents into %v", dstDir)

		// List all items in the source directory
		var itemsToMove []*api.File
		_, err = f.listAll(ctx, srcDirID, f.opt.ListChunk, false, false, func(item *api.File) bool {
			itemsToMove = append(itemsToMove, item)
			return false // Collect all items
		})
		if err != nil {
			return fmt.Errorf("MergeDirs list failed on %v: %w", srcDir, err)
		}

		// Move items in chunks
		chunkSize := f.opt.ListChunk // Use list chunk size for move chunks
		for i := 0; i < len(itemsToMove); i += chunkSize {
			end := i + chunkSize
			if end > len(itemsToMove) {
				end = len(itemsToMove)
			}
			chunk := itemsToMove[i:end]
			if len(chunk) == 0 {
				continue
			}

			var idsToMove []string
			for _, item := range chunk {
				idsToMove = append(idsToMove, item.ID())
			}

			fs.Debugf(srcDir, "Moving %d items to %v", len(idsToMove), dstDir)
			if err = f.moveFiles(ctx, idsToMove, dstDirID); err != nil {
				return fmt.Errorf("MergeDirs move failed for %v: %w", srcDir, err)
			}
		}
	}

	// Remove the source directories (now empty)
	var dirsToDelete []string
	for _, srcDir := range dirs[1:] {
		dirsToDelete = append(dirsToDelete, srcDir.ID())
	}

	// Delete directories in chunks
	chunkSize := f.opt.ListChunk
	for i := 0; i < len(dirsToDelete); i += chunkSize {
		end := i + chunkSize
		if end > len(dirsToDelete) {
			end = len(dirsToDelete)
		}
		chunkIDs := dirsToDelete[i:end]
		if len(chunkIDs) == 0 {
			continue
		}

		fs.Debugf(f, "Removing merged source directories: %v", chunkIDs)
		if err = f.deleteFiles(ctx, chunkIDs); err != nil {
			// Log error but continue trying to delete others
			fs.Errorf(f, "MergeDirs failed to rmdir chunk %v: %v", chunkIDs, err)
		}
	}

	// Flush the cache for the source directories
	for _, srcDir := range dirs[1:] {
		f.dirCache.FlushDir(srcDir.Remote())
	}

	return nil // Return nil even if some deletions failed, as merge likely succeeded partially
}

// Mkdir makes the directory.
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	if f.isShare {
		return errors.New("unsupported operation: Mkdir on shared filesystem")
	}
	_, err := f.dirCache.FindDir(ctx, dir, true) // create = true
	return err
}

// Move server-side moves a file.
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	if f.isShare {
		return nil, fs.ErrorCantMove
	}
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't move - not same remote type")
		return nil, fs.ErrorCantMove
	}
	// Ensure metadata is read for srcObj.id
	err := srcObj.readMetaData(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read source metadata for move: %w", err)
	}
	if srcObj.id == "" {
		return nil, errors.New("cannot move object with empty ID")
	}

	// Find destination parent directory ID, creating if necessary
	dstLeaf, dstParentID, err := f.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return nil, fmt.Errorf("failed to find destination directory for move: %w", err)
	}

	// Find source parent directory ID
	srcLeaf, srcParentID, err := srcObj.fs.dirCache.FindPath(ctx, srcObj.remote, false)
	if err != nil {
		// Log error but proceed, maybe parent doesn't exist in cache but file does
		fs.Logf(src, "Could not find source path in cache for move: %v", err)
		// Attempt to get parent ID from object if available
		if srcObj.parent != "" {
			srcParentID = srcObj.parent
		} else {
			return nil, fmt.Errorf("failed to find source directory for move and object has no parent ID: %w", err)
		}
	}

	// Perform the move if parents differ
	if srcParentID != dstParentID {
		fs.Debugf(srcObj, "Moving %q from %q to %q", srcObj.id, srcParentID, dstParentID)
		err = f.moveFiles(ctx, []string{srcObj.id}, dstParentID)
		if err != nil {
			return nil, fmt.Errorf("server-side move failed: %w", err)
		}
	}

	// Perform rename if names differ
	if srcLeaf != dstLeaf {
		fs.Debugf(srcObj, "Renaming %q to %q", srcLeaf, dstLeaf)
		err = f.renameFile(ctx, srcObj.id, dstLeaf)
		if err != nil {
			// Attempt to move back if rename fails? Or just return error?
			return nil, fmt.Errorf("failed to rename after move: %w", err)
		}
	}

	// Create new object representing the destination
	dstObj := &Object{
		fs:          f,
		remote:      remote,
		hasMetaData: false, // Mark metadata as stale
		id:          srcObj.id,
		parent:      dstParentID, // Update parent ID
		size:        srcObj.size,
		sha1sum:     srcObj.sha1sum,
		pickCode:    srcObj.pickCode,
		modTime:     srcObj.modTime, // Keep original modTime? Or update? Keep for now.
		durlMu:      new(sync.Mutex),
	}

	// Read metadata for the new object to confirm and update details
	err = dstObj.readMetaData(ctx)
	if err != nil {
		// Log error but return the object anyway, metadata might be eventually consistent
		fs.Logf(dstObj, "Failed to read metadata after move: %v", err)
	} else {
		dstObj.hasMetaData = true
	}

	// Flush source directory from cache
	dir, _ := dircache.SplitPath(srcObj.remote)
	srcObj.fs.dirCache.FlushDir(dir)

	return dstObj, nil
}

// DirMove server-side moves a directory.
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	if f.isShare {
		return fs.ErrorCantDirMove
	}
	srcFs, ok := src.(*Fs)
	if !ok {
		fs.Debugf(srcFs, "Can't move directory - not same remote type")
		return fs.ErrorCantDirMove
	}

	// Use dircache helper to prepare for move
	srcID, srcParentID, srcLeaf, dstParentID, dstLeaf, err := f.dirCache.DirMove(ctx, srcFs.dirCache, srcFs.root, srcRemote, f.root, dstRemote)
	if err != nil {
		return err // Errors like DirExists, CantMoveRoot handled by DirMove helper
	}

	// Perform the move if parents differ
	if srcParentID != dstParentID {
		fs.Debugf(srcFs, "Moving directory %q from %q to %q", srcID, srcParentID, dstParentID)
		err = f.moveFiles(ctx, []string{srcID}, dstParentID)
		if err != nil {
			return fmt.Errorf("server-side directory move failed: %w", err)
		}
	}

	// Perform rename if names differ
	if srcLeaf != dstLeaf {
		fs.Debugf(srcFs, "Renaming directory %q to %q", srcLeaf, dstLeaf)
		err = f.renameFile(ctx, srcID, dstLeaf)
		if err != nil {
			return fmt.Errorf("failed to rename directory after move: %w", err)
		}
	}

	// Flush source directory from cache
	srcFs.dirCache.FlushDir(srcRemote)
	return nil
}

// Copy server-side copies a file.
func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't copy - not same remote type")
		return nil, fs.ErrorCantCopy
	}

	// Special handling for copying *from* a shared remote (using traditional API)
	if srcObj.fs.isShare {
		if f.isShare {
			// Cannot copy from share to share directly? Assume not supported.
			return nil, errors.New("copying between shared remotes is not supported")
		}
		fs.Debugf(src, "Copying from shared remote using traditional API")
		// Find destination parent ID
		_, dstParentID, err := f.dirCache.FindPath(ctx, remote, true)
		if err != nil {
			return nil, fmt.Errorf("failed to find destination directory for copy: %w", err)
		}
		// Call traditional copyFromShare
		err = f.copyFromShare(ctx, srcObj.fs.opt.ShareCode, srcObj.fs.opt.ReceiveCode, srcObj.id, dstParentID)
		if err != nil {
			return nil, fmt.Errorf("copy from share failed: %w", err)
		}
		// Need to find the new object in the destination to return it
		// The name will be the same as the source object's name
		srcLeaf, _, _ := srcObj.fs.dirCache.FindPath(ctx, srcObj.remote, false) // Get original leaf name
		dir, _ := dircache.SplitPath(remote)
		dstPath := path.Join(dir, srcLeaf)       // Construct potential destination path
		newObj, err := f.NewObject(ctx, dstPath) // Find the newly copied object
		if err != nil {
			return nil, fmt.Errorf("failed to find copied object in destination after share copy: %w", err)
		}
		// If the target remote name is different, rename the copied object
		dstLeaf := path.Base(remote)
		if srcLeaf != dstLeaf {
			err = f.renameFile(ctx, newObj.(*Object).id, dstLeaf)
			if err != nil {
				return nil, fmt.Errorf("failed to rename after copy from share: %w", err)
			}
			// Re-fetch the object to get updated metadata/remote path
			finalObj, err := f.NewObject(ctx, remote)
			if err != nil {
				return nil, fmt.Errorf("failed to find renamed object after share copy: %w", err)
			}
			return finalObj, nil
		}
		return newObj, nil
	}

	// --- Standard Copy (Non-Share Source) ---
	if f.isShare {
		// Cannot copy *to* a shared remote
		return nil, errors.New("copying to a shared remote is not supported")
	}

	// Ensure metadata is read for srcObj.id
	err := srcObj.readMetaData(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read source metadata for copy: %w", err)
	}
	if srcObj.id == "" {
		return nil, errors.New("cannot copy object with empty ID")
	}

	// Find destination parent directory ID, creating if necessary
	dstLeaf, dstParentID, err := f.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return nil, fmt.Errorf("failed to find destination directory for copy: %w", err)
	}

	// Check if source and destination parent are the same
	srcParentID := srcObj.parent
	if srcParentID == "" { // Try to get from cache if not on object
		_, srcParentID, _ = srcObj.fs.dirCache.FindPath(ctx, srcObj.remote, false)
	}
	if srcParentID == dstParentID {
		// API restriction: cannot copy within the same directory
		// We could potentially handle this by copying to a temp dir and moving,
		// but for now, return ErrorCantCopy.
		fs.Debugf(src, "Can't copy - source and destination directory are the same (%q)", srcParentID)
		return nil, fs.ErrorCantCopy
	}

	// Perform the copy using OpenAPI
	fs.Debugf(srcObj, "Copying %q to %q", srcObj.id, dstParentID)
	err = f.copyFiles(ctx, []string{srcObj.id}, dstParentID)
	if err != nil {
		return nil, fmt.Errorf("server-side copy failed: %w", err)
	}

	// Find the newly created object in the destination directory
	// It will initially have the same name as the source object.
	srcLeaf, _, _ := srcObj.fs.dirCache.FindPath(ctx, srcObj.remote, false) // Get original leaf name
	dir, _ := dircache.SplitPath(remote)
	copiedObjPath := path.Join(dir, srcLeaf)       // Construct path where copied object should be
	newObj, err := f.NewObject(ctx, copiedObjPath) // Find the object at that path
	if err != nil {
		return nil, fmt.Errorf("failed to find copied object in destination: %w", err)
	}
	newObjConcrete := newObj.(*Object)

	// Rename the copied object if the target remote name is different
	if srcLeaf != dstLeaf {
		fs.Debugf(newObj, "Renaming copied object to %q", dstLeaf)
		err = f.renameFile(ctx, newObjConcrete.id, dstLeaf)
		if err != nil {
			// Attempt to delete the wrongly named copy? Or just return error?
			_ = f.deleteFiles(ctx, []string{newObjConcrete.id}) // Best effort cleanup
			return nil, fmt.Errorf("failed to rename after copy: %w", err)
		}
		// Update the object's remote path and mark metadata stale
		newObjConcrete.remote = remote
		newObjConcrete.hasMetaData = false
		// Read metadata again to confirm rename and get latest info
		err = newObjConcrete.readMetaData(ctx)
		if err != nil {
			fs.Logf(newObj, "Failed to read metadata after rename: %v", err)
		} else {
			newObjConcrete.hasMetaData = true
		}
	} else {
		// If no rename needed, ensure the returned object has the correct remote path
		newObjConcrete.remote = remote
	}

	return newObjConcrete, nil
}

// purgeCheck removes the root directory. Refuses if check=true and not empty.
func (f *Fs) purgeCheck(ctx context.Context, dir string, check bool) error {
	if f.isShare {
		return errors.New("unsupported operation: Purge/Rmdir on shared filesystem")
	}
	root := path.Join(f.root, dir)
	if root == "" && dir != "" { // Check if trying to delete the effective root specified in config
		// This case needs careful handling. If root_folder_id is set, `dir` might be ""
		// but `f.rootFolderID` is not "0".
		if f.rootFolderID == "0" {
			return errors.New("internal error: attempting to purge root directory")
		}
		// Allow purging the configured root folder ID
	} else if root == "" && dir == "" && f.rootFolderID == "0" {
		// Explicitly prevent purging the absolute root "0"
		return errors.New("refusing to purge the absolute root directory '0'")
	}

	// Find the ID of the directory to purge
	dirID, err := f.dirCache.FindDir(ctx, dir, false) // Don't create
	if err != nil {
		return err // Return DirNotFound or other errors
	}

	if check {
		// Check if directory is empty using listAll with limit 1
		found, listErr := f.listAll(ctx, dirID, 1, false, false, func(item *api.File) bool {
			fs.Debugf(f, "Rmdir check: directory %q contains %q", dir, item.FileNameBest())
			return true // Found an item, stop listing
		})
		if listErr != nil {
			return fmt.Errorf("failed to check if directory %q is empty: %w", dir, listErr)
		}
		if found {
			return fs.ErrorDirectoryNotEmpty
		}
	}

	// Perform the delete using OpenAPI
	fs.Debugf(f, "Purging directory %q (ID: %q)", dir, dirID)
	err = f.deleteFiles(ctx, []string{dirID})
	if err != nil {
		return fmt.Errorf("failed to delete directory %q (ID: %q): %w", dir, dirID, err)
	}

	// Flush the directory from cache
	f.dirCache.FlushDir(dir)
	return nil
}

// Rmdir removes an empty directory.
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return f.purgeCheck(ctx, dir, true) // check = true
}

// Purge removes a directory and all its contents.
func (f *Fs) Purge(ctx context.Context, dir string) error {
	return f.purgeCheck(ctx, dir, false) // check = false
}

// About gets quota information (currently uses traditional API).
// TODO: Check if OpenAPI provides a quota endpoint.
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	// Using traditional indexInfo for now
	info, err := f.indexInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage info: %w", err)
	}

	usage := &fs.Usage{}
	if totalInfo, ok := info.SpaceInfo["all_total"]; ok {
		usage.Total = fs.NewUsageValue(int64(totalInfo.Size))
	}
	if useInfo, ok := info.SpaceInfo["all_use"]; ok {
		usage.Used = fs.NewUsageValue(int64(useInfo.Size))
	}
	if remainInfo, ok := info.SpaceInfo["all_remain"]; ok {
		usage.Free = fs.NewUsageValue(int64(remainInfo.Size))
	}

	return usage, nil
}

// Shutdown shuts down the fs, closing any background tasks
func (f *Fs) Shutdown(ctx context.Context) error {
	if f.tokenRenewer != nil {
		f.tokenRenewer.Shutdown()
		f.tokenRenewer = nil
	}
	return nil
}

// itemToDirEntry converts an api.File to an fs.DirEntry
func (f *Fs) itemToDirEntry(ctx context.Context, remote string, item *api.File) (entry fs.DirEntry, err error) {
	if item.IsDir() {
		// Cache the directory ID
		f.dirCache.Put(remote, item.ID())
		d := fs.NewDir(remote, item.ModTime()).SetID(item.ID()).SetParentID(item.ParentID())
		return d, nil
	}
	// It's a file
	entry, err = f.newObjectWithInfo(ctx, remote, item)
	if err == fs.ErrorObjectNotFound {
		return nil, nil // Should not happen if item came from listing
	}
	return entry, err
}

// newObjectWithInfo creates an fs.Object from an api.File or by reading metadata.
func (f *Fs) newObjectWithInfo(ctx context.Context, remote string, info *api.File) (fs.Object, error) {
	o := &Object{
		fs:     f,
		remote: remote,
		durlMu: new(sync.Mutex),
	}
	var err error
	if info != nil {
		// Set metadata from provided info
		err = o.setMetaData(info)
	} else {
		// Read metadata from the backend
		err = o.readMetaData(ctx)
	}
	if err != nil {
		return nil, err
	}
	return o, nil
}

// readMetaDataForPath finds metadata for a specific file path.
func (f *Fs) readMetaDataForPath(ctx context.Context, path string) (info *api.File, err error) {
	leaf, dirID, err := f.dirCache.FindPath(ctx, path, false)
	if err != nil {
		if err == fs.ErrorDirNotFound {
			return nil, fs.ErrorObjectNotFound
		}
		return nil, err
	}

	// List the directory and find the leaf
	found, err := f.listAll(ctx, dirID, f.opt.ListChunk, true, false, func(item *api.File) bool {
		if item.FileNameBest() == leaf {
			info = item
			return true // Found it
		}
		return false // Keep looking
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list directory %q to find %q: %w", dirID, leaf, err)
	}
	if !found {
		return nil, fs.ErrorObjectNotFound
	}
	return info, nil
}

// createObject creates a placeholder Object struct before upload.
func (f *Fs) createObject(ctx context.Context, remote string, modTime time.Time, size int64) (o *Object, leaf string, dirID string, err error) {
	// Create the parent directory if it doesn't exist
	leaf, dirID, err = f.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return
	}
	// Temporary Object under construction
	o = &Object{
		fs:          f,
		remote:      remote,
		parent:      dirID,
		size:        size,
		modTime:     modTime,
		hasMetaData: false, // Metadata not set yet
		durlMu:      new(sync.Mutex),
	}
	return o, leaf, dirID, nil
}

// ------------------------------------------------------------
// Command Help & Execution
// ------------------------------------------------------------

var commandHelp = []fs.CommandHelp{{
	Name:  "addurls",
	Short: "Add offline download task for urls (uses traditional API)",
	Long: `This command adds offline download task for urls using the traditional API.

Usage:

    rclone backend addurls 115:dirpath url1 url2

Downloads are saved to the folder "dirpath". If omitted or non-existent,
it defaults to "云下载". Requires cookie authentication.
This command always exits with code 0; check output for errors.`,
}, {
	Name:  "getid",
	Short: "Get the ID of a file or directory",
	Long: `This command obtains the ID of a file or directory using the OpenAPI.

Usage:

    rclone backend getid 115:path/to/item

Returns the internal ID used by the 115 API.`,
}, {
	Name:  "addshare",
	Short: "Add shared files/dirs from a share link (uses traditional API)",
	Long: `This command adds shared files/dirs from a share link using the traditional API.

Usage:

    rclone backend addshare 115:dirpath share_link

Content from the link is copied to "dirpath". Requires cookie authentication.`,
}, {
	Name:  "stats",
	Short: "Get folder statistics (uses OpenAPI)",
	Long: `This command retrieves statistics for a folder using the OpenAPI.

Usage:

    rclone backend stats 115:path/to/folder

Returns information like total size, file count, folder count, etc.`,
}}

// Command executes backend-specific commands.
func (f *Fs) Command(ctx context.Context, name string, arg []string, opt map[string]string) (out any, err error) {
	switch name {
	case "addurls":
		if f.isShare {
			return nil, errors.New("addurls unsupported for shared filesystem")
		}
		dir := "" // Default to root or 云下载 handled by API
		if parentDir, ok := opt["dir"]; ok {
			dir = parentDir
		}
		return f.addURLs(ctx, dir, arg) // Uses traditional API
	case "getid":
		path := ""
		if len(arg) > 0 {
			path = arg[0]
		}
		return f.getID(ctx, path) // Uses OpenAPI via listAll/FindDir/NewObject
	case "addshare":
		if f.isShare {
			return nil, errors.New("addshare unsupported for shared filesystem")
		}
		if len(arg) < 1 {
			return nil, errors.New("addshare requires a share link argument")
		}
		shareCode, receiveCode, err := parseShareLink(arg[0])
		if err != nil {
			return nil, err
		}
		dirID, err := f.dirCache.FindDir(ctx, "", true) // Find target dir ID (create if needed)
		if err != nil {
			return nil, err
		}
		return nil, f.copyFromShare(ctx, shareCode, receiveCode, "", dirID) // Uses traditional API
	case "stats":
		path := ""
		if len(arg) > 0 {
			path = arg[0]
		}
		cid, err := f.getID(ctx, path) // Get ID first
		if err != nil {
			return nil, err
		}
		return f.getStats(ctx, cid) // Uses OpenAPI
	default:
		return nil, fs.ErrorCommandNotFound
	}
}

// ------------------------------------------------------------
// Object Methods
// ------------------------------------------------------------

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// String returns a description of the Object
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// ModTime returns the modification time
func (o *Object) ModTime(ctx context.Context) time.Time {
	err := o.readMetaData(ctx)
	if err != nil {
		fs.Logf(o, "failed to read metadata for ModTime: %v", err)
		// Return a zero time instead of Now() as Precision is NotSupported
		return time.Time{}
	}
	return o.modTime
}

// Size returns the size of the file
func (o *Object) Size() int64 {
	// Return size immediately if known, otherwise read metadata
	if o.hasMetaData || o.size > 0 { // Check if size is already populated
		return o.size
	}
	err := o.readMetaData(context.TODO()) // Use TODO context for simplicity here
	if err != nil {
		fs.Logf(o, "failed to read metadata for Size: %v", err)
		return -1 // Indicate error or unknown size
	}
	return o.size
}

// Hash returns the SHA1 checksum
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	if t != hash.SHA1 {
		return "", hash.ErrUnsupported
	}
	// Return hash immediately if known, otherwise read metadata
	if o.hasMetaData || o.sha1sum != "" {
		return o.sha1sum, nil
	}
	err := o.readMetaData(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to read metadata for Hash: %w", err)
	}
	return o.sha1sum, nil
}

// ID returns the ID of the Object
func (o *Object) ID() string {
	// Return ID immediately if known, otherwise read metadata
	if o.hasMetaData || o.id != "" {
		return o.id
	}
	// Reading metadata just for ID might be inefficient, but necessary if not cached
	err := o.readMetaData(context.TODO()) // Use TODO context
	if err != nil {
		fs.Logf(o, "failed to read metadata for ID: %v", err)
		return "" // Return empty string on error
	}
	return o.id
}

// ParentID returns the parent ID of the Object
func (o *Object) ParentID() string {
	// Return parent immediately if known, otherwise read metadata
	if o.hasMetaData || o.parent != "" {
		return o.parent
	}
	err := o.readMetaData(context.TODO()) // Use TODO context
	if err != nil {
		fs.Logf(o, "failed to read metadata for ParentID: %v", err)
		return "" // Return empty string on error
	}
	return o.parent
}

// SetModTime is not supported
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return fs.ErrorCantSetModTime
}

// Storable indicates this object can be stored
func (o *Object) Storable() bool {
	return true
}

// open opens the object for reading.
func (o *Object) open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	if !o.durl.Valid() {
		return nil, errors.New("download URL is invalid or expired")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", o.durl.URL, nil)
	if err != nil {
		return nil, err
	}
	fs.FixRangeOption(options, o.size)
	fs.OpenOptionAddHTTPHeaders(req.Header, options)
	if o.size == 0 {
		// Don't supply range requests for 0 length objects as they always fail
		delete(req.Header, "Range")
	}
	resp, err := o.fs.openAPIClient.Do(req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// Open the file for reading.
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	// Ensure metadata (specifically pickCode or ID) is available
	err := o.readMetaData(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata before open: %w", err)
	}

	if o.size == 0 {
		// No need for download URL for 0-byte files
		return io.NopCloser(bytes.NewReader(nil)), nil
	}

	// Get/refresh download URL
	err = o.setDownloadURL(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get download URL: %w", err)
	}
	if !o.durl.Valid() {
		// Attempt refresh again if invalid right after getting it
		fs.Debugf(o, "Download URL invalid immediately after fetching, retrying...")
		time.Sleep(500 * time.Millisecond) // Small delay before retry
		err = o.setDownloadURL(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get download URL on retry: %w", err)
		}
		if !o.durl.Valid() {
			return nil, errors.New("failed to obtain a valid download URL")
		}
	}

	// Open the URL
	return o.open(ctx, options...)
}

// Update the object with new content.
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	if o.fs.isShare {
		return errors.New("unsupported operation: Update on shared filesystem")
	}
	if src.Size() < 0 {
		return errors.New("refusing to update with unknown size")
	}

	// Start the token renewer if we have a valid one
	if o.fs.tokenRenewer != nil {
		o.fs.tokenRenewer.Start()
		defer o.fs.tokenRenewer.Stop()
	}

	// Ensure metadata is read for the existing object
	err := o.readMetaData(ctx)
	if err != nil {
		return fmt.Errorf("failed to read metadata of existing object for update: %w", err)
	}
	oldID := o.id // Keep track of the old ID

	// Upload the new content using putUnchecked (handles creation logic)
	// This will place the new file at the same remote path.
	newObj, err := o.fs.putUnchecked(ctx, in, src, o.remote, options...)
	if err != nil {
		return fmt.Errorf("upload during update failed: %w", err)
	}

	newO := newObj.(*Object)

	// If the upload resulted in a *new* file ID (not an overwrite), delete the old one.
	if oldID != "" && newO.id != oldID {
		fs.Debugf(o, "Update created new object %q, removing old object %q", newO.id, oldID)
		err = o.fs.deleteFiles(ctx, []string{oldID})
		if err != nil {
			// Log error but don't fail the update, the new file is there
			fs.Errorf(o, "Failed to remove old version %q after update: %v", oldID, err)
		}
	} else {
		fs.Debugf(o, "Update likely overwrote existing object %q", oldID)
	}

	// Replace the metadata of the original object `o` with the new object's data
	*o = *newO

	return nil
}

// Remove the object.
func (o *Object) Remove(ctx context.Context) error {
	if o.fs.isShare {
		return errors.New("unsupported operation: Remove on shared filesystem")
	}
	// Ensure metadata (ID) is read
	err := o.readMetaData(ctx)
	if err != nil {
		// If object not found, Remove should succeed
		if errors.Is(err, fs.ErrorObjectNotFound) {
			return nil
		}
		return fmt.Errorf("failed to read metadata before remove: %w", err)
	}
	if o.id == "" {
		return errors.New("cannot remove object with empty ID")
	}

	err = o.fs.deleteFiles(ctx, []string{o.id})
	if err != nil {
		return fmt.Errorf("failed to delete object %q: %w", o.id, err)
	}
	// Flush parent directory from cache? Might be too aggressive.
	// o.fs.dirCache.FlushDir(dircache.SplitPath(o.remote))
	return nil
}

// setMetaData updates the object's metadata from an api.File struct.
func (o *Object) setMetaData(info *api.File) error {
	if info == nil {
		return errors.New("cannot set metadata from nil info")
	}
	if info.IsDir() {
		// This indicates we tried to create an Object for a directory path
		return fs.ErrorIsDir
	}
	o.id = info.ID()
	o.parent = info.ParentID()
	o.size = info.FileSizeBest()
	o.sha1sum = strings.ToLower(info.Sha1Best())
	o.pickCode = info.PickCodeBest()
	o.modTime = info.ModTime()
	o.hasMetaData = true
	return nil
}

// setMetaDataFromCallBack updates metadata after an upload callback.
func (o *Object) setMetaDataFromCallBack(data *api.CallbackData) error {
	if data == nil {
		return errors.New("cannot set metadata from nil callback data")
	}
	// Assume size and modTime are already set from the source info
	o.id = data.FileID
	o.parent = data.CID // Callback provides parent CID
	o.pickCode = data.PickCode
	o.sha1sum = strings.ToLower(data.Sha)
	// Update size from callback if available and different?
	if data.FileSize > 0 {
		o.size = int64(data.FileSize)
	}
	// ModTime is usually the upload time, keep the original source ModTime
	o.hasMetaData = true
	return nil
}

// readMetaData gets the metadata if it hasn't already been fetched.
func (o *Object) readMetaData(ctx context.Context) error {
	if o.hasMetaData {
		return nil
	}
	// Use the path-based lookup
	info, err := o.fs.readMetaDataForPath(ctx, o.remote)
	if err != nil {
		return err // fs.ErrorObjectNotFound or other errors
	}
	return o.setMetaData(info)
}

// setDownloadURL ensures a valid download URL is available.
func (o *Object) setDownloadURL(ctx context.Context) error {
	o.durlMu.Lock()
	defer o.durlMu.Unlock()

	// Check if existing URL is valid
	if o.durl.Valid() {
		return nil
	}

	fs.Debugf(o, "Fetching download URL...")
	var err error
	var newURL *api.DownloadURL

	if o.fs.isShare {
		// Use traditional share download API
		if o.id == "" {
			return errors.New("cannot get share download URL without file ID")
		}
		newURL, err = o.fs.getDownloadURLFromShare(ctx, o.id)
	} else {
		// Use OpenAPI download URL endpoint
		if o.pickCode == "" {
			// If pickCode is missing, try getting it from metadata first
			metaErr := o.readMetaData(ctx)
			if metaErr != nil || o.pickCode == "" {
				return fmt.Errorf("cannot get download URL without pick code (metadata read error: %v)", metaErr)
			}
		}
		newURL, err = o.fs.getDownloadURL(ctx, o.pickCode)
	}

	if err != nil {
		o.durl = nil // Clear invalid URL
		return fmt.Errorf("failed to get download URL: %w", err)
	}

	o.durl = newURL
	if !o.durl.Valid() {
		// This might happen if the link expires immediately or is invalid
		fs.Logf(o, "Fetched download URL is invalid or expired immediately: %s", o.durl.URL)
		// Don't return error here, let the open call fail if it's truly invalid
	} else {
		fs.Debugf(o, "Successfully fetched download URL")
	}
	return nil
}

// Check the interfaces are satisfied
var (
	_ fs.Fs              = (*Fs)(nil)
	_ fs.Purger          = (*Fs)(nil)
	_ fs.Copier          = (*Fs)(nil)
	_ fs.Mover           = (*Fs)(nil)
	_ fs.DirMover        = (*Fs)(nil)
	_ fs.DirCacheFlusher = (*Fs)(nil)
	_ fs.MergeDirser     = (*Fs)(nil)
	_ fs.PutUncheckeder  = (*Fs)(nil)
	_ fs.Abouter         = (*Fs)(nil)
	_ fs.Commander       = (*Fs)(nil)
	_ fs.Object          = (*Object)(nil)
	_ fs.ObjectInfo      = (*Object)(nil)
	_ fs.IDer            = (*Object)(nil)
	_ fs.ParentIDer      = (*Object)(nil)
	_ fs.Shutdowner      = (*Fs)(nil)
)
