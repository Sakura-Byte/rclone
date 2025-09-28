package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Time represents date and time information
type Time time.Time

// MarshalJSON turns a Time into JSON (in UTC)
func (t *Time) MarshalJSON() (out []byte, err error) {
	s := strconv.Itoa(int((*time.Time)(t).Unix()))
	return []byte(s), nil
}

// UnmarshalJSON turns JSON into a Time
func (t *Time) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "null" || s == "" {
		return nil
	}
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		// Try parsing RFC3339 format for Expiration in OSSTokenData
		parsedTime, timeErr := time.Parse(time.RFC3339, s)
		if timeErr == nil {
			*t = Time(parsedTime)
			return nil
		}
		// Return original error if RFC3339 parsing also fails
		return err
	}
	newT := time.Unix(i, 0)
	*t = Time(newT)
	return nil
}

type Int int

func (e *Int) UnmarshalJSON(in []byte) (err error) {
	s := strings.Trim(string(in), `"`)
	if s == "" {
		s = "0"
	}
	if i, err := strconv.Atoi(s); err == nil {
		*e = Int(i)
	}
	return
}

type Int64 int64

func (e *Int64) UnmarshalJSON(in []byte) (err error) {
	s := strings.Trim(string(in), `"`)
	if s == "" {
		s = "0"
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		*e = Int64(i)
	}
	return
}

type BoolOrInt bool

func (b *BoolOrInt) UnmarshalJSON(in []byte) error {
	// if in is "true" or "false", unmarshal it as a bool
	// if in is 0 or 1, unmarshal it as an int
	// otherwise, return an error
	var boolVal bool
	err := json.Unmarshal(in, &boolVal)
	if err == nil {
		*b = BoolOrInt(boolVal)
		return nil
	}

	var intVal int
	err = json.Unmarshal(in, &intVal)
	if err == nil {
		*b = BoolOrInt(intVal == 1)
		return nil
	}

	return fmt.Errorf("cannot unmarshal %s into BoolOrInt", string(in))
}

// String ensures JSON unmarshals to a string, handling both quoted and unquoted inputs.
// Unquoted inputs are treated as raw bytes and converted directly to a string.
type String string

func (s *String) UnmarshalJSON(in []byte) error {
	if n := len(in); n > 1 && in[0] == '"' && in[n-1] == '"' {
		return json.Unmarshal(in, (*string)(s))
	}
	*s = String(in)
	return nil
}

// StringOrNumber handles API fields that can be either a string or a number
type StringOrNumber string

func (s *StringOrNumber) UnmarshalJSON(data []byte) error {
	// Try string first
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = StringOrNumber(str)
		return nil
	}

	// Try number (int)
	var intVal int
	if err := json.Unmarshal(data, &intVal); err == nil {
		*s = StringOrNumber(strconv.Itoa(intVal))
		return nil
	}

	// Try number (float)
	var floatVal float64
	if err := json.Unmarshal(data, &floatVal); err == nil {
		*s = StringOrNumber(strconv.FormatFloat(floatVal, 'f', -1, 64))
		return nil
	}

	// If it's null or empty
	if string(data) == "null" || string(data) == "" {
		*s = ""
		return nil
	}

	// Last resort: use the raw value
	*s = StringOrNumber(strings.Trim(string(data), "\""))
	return nil
}

// ------------------------------------------------------------
// Base response structures
// ------------------------------------------------------------

// TraditionalBase is for the old cookie/encrypted API
type TraditionalBase struct {
	Msg   string    `json:"msg,omitempty"`
	Errno Int       `json:"errno,omitempty"` // Base, NewDir, DirID, UploadBasicInfo, ShareSnap
	ErrNo Int       `json:"errNo,omitempty"` // FileList
	Error string    `json:"error,omitempty"` // Base, FileList, NewDir, DirID, UploadBasicInfo, ShareSnap
	State BoolOrInt `json:"state,omitempty"`
}

func (b *TraditionalBase) ErrCode() Int {
	if b.Errno != 0 {
		return b.Errno
	}
	return b.ErrNo
}

func (b *TraditionalBase) ErrMsg() string {
	if b.Error != "" {
		return b.Error
	}
	return b.Msg
}

// Err returns Error or Nil for TraditionalBase
func (b *TraditionalBase) Err() error {
	if b.State {
		return nil
	}
	out := fmt.Sprintf("Traditional API Error(%d)", b.ErrCode())
	if msg := b.ErrMsg(); msg != "" {
		out += fmt.Sprintf(": %q", msg)
	}
	return errors.New(out)
}

// OpenAPIBase is for the new Open API

type OpenAPIBase struct {
	State   BoolOrInt      `json:"state"` // Note: OpenAPI uses boolean state
	Code    Int            `json:"code,omitempty"`
	Message StringOrNumber `json:"message,omitempty"` // Can be either string or number
	Error   string         `json:"error,omitempty"`   // Some endpoints might still use this
	Errno   Int            `json:"errno,omitempty"`   // Some endpoints might still use this
}

func (b *OpenAPIBase) ErrCode() Int {
	if b.Code != 0 {
		return b.Code
	}
	return b.Errno
}

func (b *OpenAPIBase) ErrMsg() string {
	if string(b.Message) != "" {
		return string(b.Message)
	}
	return b.Error
}

// Err returns Error or Nil for OpenAPIBase
func (b *OpenAPIBase) Err() error {
	if b.State {
		return nil
	}
	out := fmt.Sprintf("OpenAPI Error(%d)", b.ErrCode())
	if msg := b.ErrMsg(); msg != "" {
		out += fmt.Sprintf(": %q", msg)
	}

	// Specific error codes to check based on API documentation
	code := b.ErrCode()
	// Check for rate limit error codes in multiple formats
	if code == 0 && (string(b.Message) == "770004" ||
		strings.Contains(b.ErrMsg(), "770004") ||
		strings.Contains(b.ErrMsg(), "已达到当前访问上限")) {
		// This is a rate limit error
		return fmt.Errorf("%s: rate limit exceeded", out)
	}

	switch code {
	// Codes that require re-login
	case 40140116: // refresh_token invalid (authorization revoked)
		return NewTokenError(out, true)
	case 40140117: // access_token refreshed too frequently
		return NewTokenError(out, true)
	case 40140119: // refresh_token expired
		return NewTokenError(out, true)
	case 40140120: // refresh_token verification failed (anti-tampering)
		// Check if local refresh token is updated; if not, re-login
		return NewTokenError(out, true)
	case 40140121: // access_token refresh failed
		// This should allow a retry of the refresh token operation
		return NewTokenError(out, false)
	case 40140125: // access_token invalid (expired or authorization revoked)
		// Try refreshing token first
		return NewTokenError(out, false)
	case 40140126: // access_token verification failed
		// Attempt to refresh the access token before forcing re-login
		return NewTokenError(out, false)
	}

	return errors.New(out)
}

// TokenError indicates an issue with the access or refresh token
type TokenError struct {
	msg                   string
	IsRefreshTokenExpired bool
}

// NewTokenError creates a new TokenError with the given message and refresh token status
func NewTokenError(msg string, isRefreshTokenExpired ...bool) *TokenError {
	expired := false
	if len(isRefreshTokenExpired) > 0 {
		expired = isRefreshTokenExpired[0]
	}
	return &TokenError{
		msg:                   msg,
		IsRefreshTokenExpired: expired,
	}
}

func (e *TokenError) Error() string {
	return e.msg
}

// ------------------------------------------------------------
// Authentication related structs
// ------------------------------------------------------------

type AuthDeviceCodeData struct {
	UID    string `json:"uid"`
	Time   int64  `json:"time"`
	Qrcode string `json:"qrcode"`
	Sign   string `json:"sign"`
}

type AuthDeviceCodeResp struct {
	OpenAPIBase
	Data *AuthDeviceCodeData `json:"data"`
}

type DeviceCodeTokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // seconds
}

type DeviceCodeTokenResp struct {
	OpenAPIBase
	Data *DeviceCodeTokenData `json:"data"`
}

type RefreshTokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // seconds
}

type RefreshTokenResp struct {
	OpenAPIBase
	Data *RefreshTokenData `json:"data"`
}

// ------------------------------------------------------------
// File and Directory related structs
// ------------------------------------------------------------

// File represents a file or folder object from either API
// Uses tags for both traditional and OpenAPI field names
type File struct {
	// Common fields (adapt names if needed)
	Name     string `json:"n,omitempty"`    // Traditional: n, OpenAPI: fn or file_name
	FileName string `json:"fn,omitempty"`   // OpenAPI: fn (in list), file_name (in details)
	Size     Int64  `json:"size,omitempty"` // Traditional: s, OpenAPI: file_size
	FileSize Int64  `json:"fs,omitempty"`   // OpenAPI: file_size
	PickCode string `json:"pc,omitempty"`   // Traditional: pc, OpenAPI: pick_code
	Sha      string `json:"sha,omitempty"`  // Traditional: sha, OpenAPI: sha1
	Sha1     string `json:"sha1,omitempty"` // OpenAPI: sha1

	// Identifiers
	FID string `json:"fid,omitempty"` // Traditional: fid (file), OpenAPI: fid (file), file_id (folder/file details)
	CID string `json:"cid,omitempty"` // Traditional: cid (folder), OpenAPI: cid (in list query param), file_id (folder details)
	PID string `json:"pid,omitempty"` // Traditional: pid (folder parent), OpenAPI: pid (folder parent)

	// Timestamps
	T   string `json:"t,omitempty"`    // Traditional: representative time? "2024-05-19 03:54" or "1715919337"
	Te  Time   `json:"te,omitempty"`   // Traditional: modify time
	Tp  Time   `json:"tp,omitempty"`   // Traditional: create time
	Tu  Time   `json:"tu,omitempty"`   // Traditional: update time?
	To  Time   `json:"to,omitempty"`   // Traditional: last opened 0 if never accessed or "1716165082"
	Upt Time   `json:"upt,omitempty"`  // OpenAPI: upt (update time)
	Uet Time   `json:"uet,omitempty"`  // OpenAPI: uet (update time alias?)
	Ppt Time   `json:"uppt,omitempty"` // OpenAPI: uppt (upload time)

	// Type/Category
	IsFolder Int    `json:"fc,omitempty"`    // OpenAPI: fc (0 folder, 1 file)
	Ico      string `json:"ico,omitempty"`   // Traditional icon
	Class    string `json:"class,omitempty"` // Traditional class

	// Status/Attributes
	IsMarked Int `json:"ism,omitempty"`  // OpenAPI: ism (starred, 1=yes)
	Star     Int `json:"star,omitempty"` // OpenAPI: star (in update response)
	IsHidden Int `json:"ih,omitempty"`   // OpenAPI: ih (hidden?)
	IsLocked Int `json:"lo,omitempty"`   // OpenAPI: lo (locked?)
	IsCrypt  Int `json:"isp,omitempty"`  // OpenAPI: isp (encrypted, 1=yes)
	Censored Int `json:"c,omitempty"`    // Traditional: censored flag

	// Other fields from OpenAPI list
	Aid   json.Number `json:"aid,omitempty"`   // OpenAPI: aid (area id?)
	Fco   string      `json:"fco,omitempty"`   // OpenAPI: fco (folder cover?)
	Cm    Int         `json:"cm,omitempty"`    // OpenAPI: cm (?)
	Fdesc string      `json:"fdesc,omitempty"` // OpenAPI: fdesc (description?)
	Ispl  Int         `json:"ispl,omitempty"`  // OpenAPI: ispl (play long related?)

	// Fields from traditional API (might be redundant or map differently)
	UID       json.Number `json:"uid,omitempty"` // Traditional user ID
	CheckCode int         `json:"check_code,omitempty"`
	CheckMsg  string      `json:"check_msg,omitempty"`
	Score     int         `json:"score,omitempty"`
	PlayLong  float64     `json:"play_long,omitempty"` // playback secs if media
}

// IsDir checks if the item represents a directory based on OpenAPI fields
func (f *File) IsDir() bool {
	// OpenAPI uses fc=0 for folder, file_category="0" in details
	// Traditional uses fid="" for folder
	return f.IsFolder == 0 || (f.FID == "" && f.CID != "")
}

// ID returns the best identifier (File ID or Category ID)
func (f *File) ID() string {
	if f.FID != "" { // Prefer FID if available (OpenAPI file, Traditional file)
		return f.FID
	}
	if f.CID != "" { // Use CID if FID is empty (OpenAPI folder, Traditional folder)
		return f.CID
	}
	// Fallback for folder details where file_id is used
	// This might need adjustment based on actual API responses for folder details via OpenAPI
	// if f.FileID != "" {
	// 	return f.FileID
	// }
	return "" // Should not happen for valid items
}

// ParentID returns the parent directory ID
func (f *File) ParentID() string {
	return f.PID // Both APIs seem to use 'pid'
}

// FileName returns the best name field
func (f *File) FileNameBest() string {
	if f.FileName != "" { // OpenAPI list 'fn', details 'file_name'
		return f.FileName
	}
	return f.Name // Traditional 'n'
}

// FileSizeBest returns the best size field
func (f *File) FileSizeBest() int64 {
	if f.FileSize > 0 { // OpenAPI 'file_size'
		return int64(f.FileSize)
	}
	return int64(f.Size) // Traditional 's'
}

// PickCodeBest returns the best pick code field
func (f *File) PickCodeBest() string {
	return f.PickCode // Both seem to use 'pc' or 'pick_code'
}

// Sha1Best returns the best SHA1 field
func (f *File) Sha1Best() string {
	if f.Sha1 != "" { // OpenAPI 'sha1'
		return f.Sha1
	}
	return f.Sha // Traditional 'sha'
}

// ModTime returns the best modification time
func (f *File) ModTime() time.Time {
	// Prefer OpenAPI update times
	if t := time.Time(f.Upt); !t.IsZero() {
		return t
	}
	if t := time.Time(f.Uet); !t.IsZero() {
		return t
	}
	// Fallback to traditional times
	if t := time.Time(f.Te); !t.IsZero() {
		return t
	}
	if t := time.Time(f.Tu); !t.IsZero() {
		return t
	}
	// Fallback for ShareSnap list items
	if ts, err := strconv.ParseInt(f.T, 10, 64); err == nil {
		return time.Unix(ts, 0)
	}
	return time.Time{}
}

// FilePath represents an item in the path hierarchy (used in traditional list)
type FilePath struct {
	Name string      `json:"name,omitempty"`
	AID  json.Number `json:"aid,omitempty"` // area
	CID  json.Number `json:"cid,omitempty"` // category
	PID  json.Number `json:"pid,omitempty"` // parent
	Isp  json.Number `json:"isp,omitempty"`
	PCid string      `json:"p_cid,omitempty"`
	Iss  string      `json:"iss,omitempty"`
	Fv   string      `json:"fv,omitempty"`
	Fvs  string      `json:"fvs,omitempty"`
}

// FileList represents the response from listing files (adaptable for both APIs)
type FileList struct {
	// Use OpenAPIBase for state/code/message
	OpenAPIBase

	// Data payload
	Files []*File `json:"data,omitempty"` // OpenAPI uses 'data', Traditional uses 'data'

	// Pagination and Counts (check OpenAPI names)
	Count       int         `json:"count,omitempty"`        // Traditional total count
	TotalCount  int         `json:"total_count,omitempty"`  // OpenAPI might use a different name
	FileCount   int         `json:"file_count,omitempty"`   // Traditional
	FolderCount int         `json:"folder_count,omitempty"` // Traditional
	PageSize    int         `json:"page_size,omitempty"`    // Traditional
	Limit       json.Number `json:"limit,omitempty"`        // OpenAPI uses 'limit' param, response might confirm
	Offset      json.Number `json:"offset,omitempty"`       // OpenAPI uses 'offset' param, response might confirm

	// Context/Query Info (check OpenAPI names)
	DataSource     string      `json:"data_source,omitempty"`      // Traditional
	SysCount       int         `json:"sys_count,omitempty"`        // Traditional
	AID            json.Number `json:"aid,omitempty"`              // Traditional
	CID            json.Number `json:"cid,omitempty"`              // Traditional context CID
	IsAsc          json.Number `json:"is_asc,omitempty"`           // Traditional sort order
	Star           int         `json:"star,omitempty"`             // Traditional star filter
	IsShare        int         `json:"is_share,omitempty"`         // Traditional
	Type           int         `json:"type,omitempty"`             // Traditional type filter
	IsQ            int         `json:"is_q,omitempty"`             // Traditional
	RAll           int         `json:"r_all,omitempty"`            // Traditional
	Stdir          int         `json:"stdir,omitempty"`            // Traditional
	Cur            int         `json:"cur,omitempty"`              // Traditional
	MinSize        int         `json:"min_size,omitempty"`         // Traditional
	MaxSize        int         `json:"max_size,omitempty"`         // Traditional
	RecordOpenTime string      `json:"record_open_time,omitempty"` // Traditional
	Path           []*FilePath `json:"path,omitempty"`             // Traditional path breadcrumbs
	Fields         string      `json:"fields,omitempty"`           // Traditional
	Order          string      `json:"order,omitempty"`            // Traditional sort field
	FcMix          int         `json:"fc_mix,omitempty"`           // Traditional
	Natsort        int         `json:"natsort,omitempty"`          // Traditional
	UID            json.Number `json:"uid,omitempty"`              // Traditional user ID
	Suffix         string      `json:"suffix,omitempty"`           // Traditional suffix filter
}

// FileInfo represents the response for getting single file info (Traditional)
// OpenAPI might use a different structure or just return a File object in 'data'
type FileInfo struct {
	TraditionalBase
	Data []*File `json:"data,omitempty"`
}
type NewDirData struct {
	FileName string `json:"file_name,omitempty"`
	FileID   string `json:"file_id,omitempty"`
}

// NewDir represents the response for creating a directory
type NewDir struct {
	OpenAPIBase
	Data *NewDirData `json:"data,omitempty"`
}

// DirID represents the response for getting a directory ID by path (Traditional)
type DirID struct {
	TraditionalBase
	ID        json.Number `json:"id,omitempty"`
	IsPrivate json.Number `json:"is_private,omitempty"`
}

// FileStats represents the response for getting folder stats (Traditional /category/get)
// OpenAPI has /open/folder/get_info
type FileStats struct {
	OpenAPIBase
	Data *FolderInfoData `json:"data"`
}

type FolderInfoData struct {
	Count        String `json:"count"`          // OpenAPI: string
	Size         String `json:"size"`           // OpenAPI: string
	FolderCount  String `json:"folder_count"`   // OpenAPI: string
	PlayLong     Int64  `json:"play_long"`      // OpenAPI: number (seconds), -1=calculating
	ShowPlayLong Int    `json:"show_play_long"` // OpenAPI: number (bool 0/1)
	Ptime        String `json:"ptime"`          // OpenAPI: string timestamp?
	Utime        String `json:"utime"`          // OpenAPI: string timestamp?
	FileName     string `json:"file_name"`      // OpenAPI: string
	PickCode     string `json:"pick_code"`      // OpenAPI: string
	Sha1         string `json:"sha1"`           // OpenAPI: string
	FileID       string `json:"file_id"`        // OpenAPI: string
	IsMark       String `json:"is_mark"`        // OpenAPI: string (bool 0/1)
	OpenTime     Int64  `json:"open_time"`      // OpenAPI: number timestamp?
	FileCategory String `json:"file_category"`  // OpenAPI: string (0=folder)
	Paths        []struct {
		FileID   String `json:"file_id"`   // OpenAPI: number (as string?)
		FileName string `json:"file_name"` // OpenAPI: string
	} `json:"paths"`
}

// StringInfo is a generic response where data is just a string (Traditional)
type StringInfo struct {
	TraditionalBase
	Data String `json:"data,omitempty"`
}

// IndexInfo represents user quota info (Traditional)
type IndexInfo struct {
	TraditionalBase
	Data *IndexData `json:"data,omitempty"`
}

type IndexData struct {
	SpaceInfo map[string]*SizeInfo `json:"space_info"`
}

type SizeInfo struct {
	Size       float64 `json:"size"`
	SizeFormat string  `json:"size_format"`
}

// ------------------------------------------------------------
// Download related structs
// ------------------------------------------------------------

// DownloadURL represents the URL structure from both APIs
type DownloadURL struct {
	URL     string         `json:"url"`              // Present in both
	Client  Int            `json:"client,omitempty"` // Traditional
	Desc    string         `json:"desc,omitempty"`   // Traditional
	OssID   string         `json:"oss_id,omitempty"` // Traditional
	Cookies []*http.Cookie // Added manually after request
}

func (u *DownloadURL) UnmarshalJSON(data []byte) error {
	if string(data) == "false" {
		*u = DownloadURL{}
		return nil
	}

	type Alias DownloadURL // Use type alias to avoid recursion
	aux := Alias{}
	if err := json.Unmarshal(data, &aux); err != nil {
		// Try unmarshalling just as a string if object fails (OpenAPI might simplify)
		var urlStr string
		if strErr := json.Unmarshal(data, &urlStr); strErr == nil {
			*u = DownloadURL{URL: urlStr}
			return nil
		}
		return err // Return original error if string unmarshal also fails
	}
	*u = DownloadURL(aux)
	return nil
}

// expiry parses expiry from URL parameter t (Traditional URL format)
func (u *DownloadURL) expiry() time.Time {
	if p, err := url.Parse(u.URL); err == nil {
		if q, err := url.ParseQuery(p.RawQuery); err == nil {
			if t := q.Get("t"); t != "" {
				if i, err := strconv.ParseInt(t, 10, 64); err == nil {
					return time.Unix(i, 0)
				}
			}
			// Check for OSS expiry parameter (might be different)
			if exp := q.Get("Expires"); exp != "" {
				if i, err := strconv.ParseInt(exp, 10, 64); err == nil {
					return time.Unix(i, 0)
				}
			}
		}
	}
	return time.Time{}
}

// expired reports whether the token is expired.
func (u *DownloadURL) expired() bool {
	expiry := u.expiry()
	if expiry.IsZero() {
		return false // Assume non-expiring if no expiry found
	}
	// Use a smaller delta as OSS links might be shorter-lived
	expiryDelta := time.Duration(60) * time.Second
	return expiry.Round(0).Add(-expiryDelta).Before(time.Now())
}

// Valid reports whether u is non-nil and is not expired.
func (u *DownloadURL) Valid() bool {
	return u != nil && u.URL != "" && !u.expired()
}

func (u *DownloadURL) Cookie() string {
	cookie := ""
	for _, ck := range u.Cookies {
		cookie += fmt.Sprintf("%s=%s;", ck.Name, ck.Value)
	}
	return cookie
}

// DownloadInfo represents the structure within the DownloadData map (Traditional)
type DownloadInfo struct {
	FileName string      `json:"file_name"`
	FileSize Int64       `json:"file_size"`
	PickCode string      `json:"pick_code"`
	URL      DownloadURL `json:"url"`
}

// DownloadData is the map returned by the traditional download URL endpoint
type DownloadData map[string]*DownloadInfo

// OpenAPI specific download response structure
type OpenAPIDownloadInfo struct {
	FileName string      `json:"file_name"`
	FileSize Int64       `json:"file_size"`
	PickCode string      `json:"pick_code"`
	Sha1     string      `json:"sha1"`
	URL      DownloadURL `json:"url"` // Assumes nested URL object like traditional
}

// OpenAPIDownloadResp represents the response from POST /open/ufile/downurl
type OpenAPIDownloadResp struct {
	OpenAPIBase
	// Data is a map where the key is the file ID
	Data map[string]*OpenAPIDownloadInfo `json:"data"`
}

// ------------------------------------------------------------
// Upload related structs
// ------------------------------------------------------------

// UploadBasicInfo (Traditional - /app/uploadinfo) - May become obsolete
type UploadBasicInfo struct {
	TraditionalBase
	Uploadinfo       string      `json:"uploadinfo,omitempty"`
	UserID           json.Number `json:"user_id,omitempty"`
	AppVersion       int         `json:"app_version,omitempty"`
	AppID            int         `json:"app_id,omitempty"`
	Userkey          string      `json:"userkey,omitempty"`
	SizeLimit        int64       `json:"size_limit,omitempty"`
	SizeLimitYun     int64       `json:"size_limit_yun,omitempty"`
	MaxDirLevel      int64       `json:"max_dir_level,omitempty"`
	MaxDirLevelYun   int64       `json:"max_dir_level_yun,omitempty"`
	MaxFileNum       int64       `json:"max_file_num,omitempty"`
	MaxFileNumYun    int64       `json:"max_file_num_yun,omitempty"`
	UploadAllowed    bool        `json:"upload_allowed,omitempty"`
	UploadAllowedMsg string      `json:"upload_allowed_msg,omitempty"`
}

// UploadInitInfo represents the response from upload init/resume (adaptable for both)
type UploadInitInfo struct {
	// Common Base - OpenAPI uses state/code/message, Traditional uses statuscode/statusmsg
	OpenAPIBase
	Request   string `json:"request,omitempty"`    // Traditional
	ErrorCode int    `json:"statuscode,omitempty"` // Traditional
	ErrorMsg  string `json:"statusmsg,omitempty"`  // Traditional

	// Data payload (nested under 'data' in OpenAPI)
	Data *UploadInitData `json:"data,omitempty"` // OpenAPI nests the main info

	// Traditional top-level fields (might be moved into Data for OpenAPI)
	Status   Int    `json:"status,omitempty"`   // Traditional: 1=need upload, 2=秒传; OpenAPI: 1=non-秒传, 2=秒传, 6/7/8=auth
	PickCode string `json:"pickcode,omitempty"` // Traditional: pickcode; OpenAPI: pick_code
	Target   string `json:"target,omitempty"`   // Both
	Version  string `json:"version,omitempty"`  // Both?

	// OSS upload fields (Traditional top-level, OpenAPI in 'data')
	Bucket   string          `json:"bucket,omitempty"`   // Both
	Object   string          `json:"object,omitempty"`   // Both
	Callback json.RawMessage `json:"callback,omitempty"` // Both (structure might differ)

	// Useless fields (Traditional)
	FileID   int    `json:"fileid,omitempty"`
	FileInfo string `json:"fileinfo,omitempty"`

	// New fields in upload v4.0 / OpenAPI
	SignKey   string `json:"sign_key,omitempty"`   // Both
	SignCheck string `json:"sign_check,omitempty"` // Both
	FileIDStr string `json:"file_id,omitempty"`    // OpenAPI: file_id (for 秒传 success)

	// Raw data for custom UnmarshalJSON
	rawData json.RawMessage
}

// UnmarshalJSON handles custom unmarshaling for UploadInitInfo
func (ui *UploadInitInfo) UnmarshalJSON(data []byte) error {
	// Define an alias type to avoid infinite recursion
	type Alias UploadInitInfo
	aux := &struct {
		Data json.RawMessage `json:"data"`
		*Alias
	}{
		Alias: (*Alias)(ui),
	}

	// Unmarshal into the auxiliary struct
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// Store raw data for later processing
	ui.rawData = aux.Data

	// Handle different formats for the data field
	if len(aux.Data) > 0 {
		// Try to unmarshal as an object first
		var objData UploadInitData
		if err := json.Unmarshal(aux.Data, &objData); err != nil {
			// If that fails, try as an array
			var arrData []map[string]interface{}
			if err := json.Unmarshal(aux.Data, &arrData); err != nil {
				return fmt.Errorf("data field is neither a valid object nor an array: %w", err)
			}

			// If it's an array and has at least one element, use the first element
			if len(arrData) > 0 {
				// Convert the first array element back to JSON
				firstElem, err := json.Marshal(arrData[0])
				if err != nil {
					return fmt.Errorf("failed to marshal first array element: %w", err)
				}

				// Then unmarshal it into the objData
				if err := json.Unmarshal(firstElem, &objData); err != nil {
					return fmt.Errorf("failed to unmarshal first array element: %w", err)
				}

				ui.Data = &objData
			}
		} else {
			// It was a valid object
			ui.Data = &objData
		}
	}

	return nil
}

// UploadInitData holds the nested data part of the OpenAPI upload init/resume response
type UploadInitData struct {
	PickCode  string          `json:"pick_code"`         // Upload task ID
	Status    Int             `json:"status"`            // 1: non-秒传, 2: 秒传, 6/7/8: auth needed
	SignKey   string          `json:"sign_key"`          // SHA1 ID for secondary auth
	SignCheck string          `json:"sign_check"`        // SHA1 range for secondary auth
	FileID    string          `json:"file_id"`           // File ID if 秒传 success (status=2)
	Target    string          `json:"target"`            // Upload target string
	Bucket    string          `json:"bucket"`            // OSS Bucket
	Object    string          `json:"object"`            // OSS Object ID
	Callback  json.RawMessage `json:"callback"`          // Can be either struct or array
	Version   string          `json:"version,omitempty"` // Optional version info
}

// GetCallback decodes and returns the callback string
func (ui *UploadInitInfo) GetCallback() string {
	// Get the raw callback data first
	var rawCallback string
	data := ui.Data
	if data == nil {
		// Fallback to traditional structure
		// Try to unmarshal as object first
		var callbackStruct struct {
			Callback    string `json:"callback"`
			CallbackVar string `json:"callback_var"`
		}

		if err := json.Unmarshal(ui.Callback, &callbackStruct); err == nil && callbackStruct.Callback != "" {
			rawCallback = callbackStruct.Callback
		} else {
			// Try to unmarshal as array if object failed
			var callbackArray []string
			if err := json.Unmarshal(ui.Callback, &callbackArray); err == nil && len(callbackArray) > 0 {
				rawCallback = callbackArray[0]
			} else {
				// Fall back to string representation if both fail
				rawCallback = string(ui.Callback)
			}
		}
	} else {
		// Try to unmarshal as object first
		var callbackStruct struct {
			Callback    string `json:"callback"`
			CallbackVar string `json:"callback_var"`
		}

		if err := json.Unmarshal(data.Callback, &callbackStruct); err == nil && callbackStruct.Callback != "" {
			rawCallback = callbackStruct.Callback
		} else {
			// Try to unmarshal as array if object failed
			var callbackArray []string
			if err := json.Unmarshal(data.Callback, &callbackArray); err == nil && len(callbackArray) > 0 {
				rawCallback = callbackArray[0]
			} else {
				// Fall back to string representation if both fail
				rawCallback = string(data.Callback)
			}
		}
	}

	// Check if the callback data is already base64 encoded
	if _, err := base64.StdEncoding.DecodeString(rawCallback); err != nil {
		// Not valid base64, so encode it
		return base64.StdEncoding.EncodeToString([]byte(rawCallback))
	}

	// Already base64 encoded, return as is
	return rawCallback
}

// GetCallbackVar decodes and returns the callback variables string
func (ui *UploadInitInfo) GetCallbackVar() string {
	// Get the raw callback var data first
	var rawCallbackVar string
	data := ui.Data
	if data == nil {
		// Fallback to traditional structure
		// Try to unmarshal as object first
		var callbackStruct struct {
			Callback    string `json:"callback"`
			CallbackVar string `json:"callback_var"`
		}

		if err := json.Unmarshal(ui.Callback, &callbackStruct); err == nil && callbackStruct.CallbackVar != "" {
			rawCallbackVar = callbackStruct.CallbackVar
		} else {
			// Try to unmarshal as array if object failed
			var callbackArray []string
			if err := json.Unmarshal(ui.Callback, &callbackArray); err == nil && len(callbackArray) > 1 {
				rawCallbackVar = callbackArray[1]
			} else {
				// No callback var found
				return ""
			}
		}
	} else {
		// Try to unmarshal as object first
		var callbackStruct struct {
			Callback    string `json:"callback"`
			CallbackVar string `json:"callback_var"`
		}

		if err := json.Unmarshal(data.Callback, &callbackStruct); err == nil && callbackStruct.CallbackVar != "" {
			rawCallbackVar = callbackStruct.CallbackVar
		} else {
			// Try to unmarshal as array if object failed
			var callbackArray []string
			if err := json.Unmarshal(data.Callback, &callbackArray); err == nil && len(callbackArray) > 1 {
				rawCallbackVar = callbackArray[1]
			} else {
				// No callback var found
				return ""
			}
		}
	}

	// If we have callback var data, check if it's already base64 encoded
	if rawCallbackVar != "" {
		if _, err := base64.StdEncoding.DecodeString(rawCallbackVar); err != nil {
			// Not valid base64, so encode it
			return base64.StdEncoding.EncodeToString([]byte(rawCallbackVar))
		}
	}

	// Already base64 encoded or empty, return as is
	return rawCallbackVar
}

// GetPickCode returns the pick code from the appropriate field
func (ui *UploadInitInfo) GetPickCode() string {
	if ui.Data != nil {
		return ui.Data.PickCode
	}
	return ui.PickCode
}

// GetStatus returns the status code from the appropriate field
func (ui *UploadInitInfo) GetStatus() Int {
	if ui.Data != nil {
		return ui.Data.Status
	}
	return ui.Status
}

// GetFileID returns the file ID (on 秒传) from the appropriate field
func (ui *UploadInitInfo) GetFileID() string {
	if ui.Data != nil {
		return ui.Data.FileID
	}
	return ui.FileIDStr
}

// GetSignKey returns the sign key from the appropriate field
func (ui *UploadInitInfo) GetSignKey() string {
	if ui.Data != nil {
		return ui.Data.SignKey
	}
	return ui.SignKey
}

// GetSignCheck returns the sign check range from the appropriate field
func (ui *UploadInitInfo) GetSignCheck() string {
	if ui.Data != nil {
		return ui.Data.SignCheck
	}
	return ui.SignCheck
}

// GetBucket returns the OSS bucket from the appropriate field
func (ui *UploadInitInfo) GetBucket() string {
	if ui.Data != nil {
		return ui.Data.Bucket
	}
	return ui.Bucket
}

// GetObject returns the OSS object key from the appropriate field
func (ui *UploadInitInfo) GetObject() string {
	if ui.Data != nil {
		return ui.Data.Object
	}
	return ui.Object
}

// CallbackInfo represents the structure of the callback response after OSS upload (Traditional)
type CallbackInfo struct {
	TraditionalBase
	Data *CallbackData `json:"data,omitempty"`
}

// CallbackData holds the details from the upload callback
type CallbackData struct {
	AID      json.Number `json:"aid"`
	CID      string      `json:"cid"`
	FileID   string      `json:"file_id"`
	FileName string      `json:"file_name"`
	FileSize Int64       `json:"file_size"`
	IsVideo  int         `json:"is_video"`
	PickCode string      `json:"pick_code"`
	Sha      string      `json:"sha1"`
	ThumbURL string      `json:"thumb_url,omitempty"`
}

// OSSToken represents the structure for OSS credentials (adaptable)
type OSSToken struct {
	AccessKeyID     string `json:"AccessKeyId"`     // OpenAPI uses AccessKeyId
	AccessKeySecret string `json:"AccessKeySecret"` // OpenAPI uses AccessKeySecrett (typo in docs?) -> Corrected to AccessKeySecret based on common usage
	Expiration      Time   `json:"Expiration"`      // OpenAPI uses Expiration (RFC3339 format)
	SecurityToken   string `json:"SecurityToken"`   // OpenAPI uses SecurityToken
	Endpoint        string `json:"endpoint"`        // OpenAPI provides endpoint

	// Traditional fields (might be redundant)
	StatusCode   string `json:"StatusCode,omitempty"`
	ErrorCode    string `json:"ErrorCode,omitempty"`
	ErrorMessage string `json:"ErrorMessage,omitempty"`
}

// OSSTokenResp represents the response from GET /open/upload/get_token
type OSSTokenResp struct {
	OpenAPIBase
	Data *OSSToken `json:"data"` // Assuming data holds a single OSSToken object
}

// TimeToExpiry calculates duration until token expiry
func (t *OSSToken) TimeToExpiry() time.Duration {
	if t == nil {
		return 0
	}
	exp := time.Time(t.Expiration)
	if exp.IsZero() {
		// Should not happen with OpenAPI tokens, but handle defensively
		return 3e9 * time.Second // ~95 years
	}
	// Use a safety margin (e.g., 5 minutes)
	return time.Until(exp) - 5*time.Minute
}

// ------------------------------------------------------------
// Sharing related structs (Assume Traditional API for now)
// ------------------------------------------------------------

// NewURL represents the response for adding offline tasks (Traditional)
type NewURL struct {
	State    bool   `json:"state,omitempty"`
	ErrorMsg string `json:"error_msg,omitempty"`
	Errno    int    `json:"errno,omitempty"`
	Result   []struct {
		State    bool   `json:"state,omitempty"`
		ErrorMsg string `json:"error_msg,omitempty"`
		Errno    int    `json:"errno,omitempty"`
		Errtype  string `json:"errtype,omitempty"`
		Errcode  int    `json:"errcode,omitempty"`
		InfoHash string `json:"info_hash,omitempty"`
		URL      string `json:"url,omitempty"`
		Files    []struct {
			ID   string `json:"id,omitempty"`
			Name string `json:"name,omitempty"`
			Size int64  `json:"size,omitempty"`
		} `json:"files,omitempty"`
	} `json:"result,omitempty"`
	Errcode int `json:"errcode,omitempty"`
}

// ShareSnap represents the response for listing shared files (Traditional)
type ShareSnap struct {
	TraditionalBase
	Data *ShareSnapData `json:"data,omitempty"`
}

type ShareSnapData struct {
	Userinfo struct {
		UserID   string `json:"user_id,omitempty"`
		UserName string `json:"user_name,omitempty"`
		Face     string `json:"face,omitempty"`
	} `json:"userinfo,omitempty"`
	Shareinfo struct {
		SnapID           string      `json:"snap_id,omitempty"`
		FileSize         string      `json:"file_size,omitempty"`
		ShareTitle       string      `json:"share_title,omitempty"`
		ShareState       json.Number `json:"share_state,omitempty"`
		ForbidReason     string      `json:"forbid_reason,omitempty"`
		CreateTime       string      `json:"create_time,omitempty"`
		ReceiveCode      string      `json:"receive_code,omitempty"`
		ReceiveCount     string      `json:"receive_count,omitempty"`
		ExpireTime       int         `json:"expire_time,omitempty"`
		FileCategory     int         `json:"file_category,omitempty"`
		AutoRenewal      string      `json:"auto_renewal,omitempty"`
		AutoFillRecvcode string      `json:"auto_fill_recvcode,omitempty"`
		CanReport        int         `json:"can_report,omitempty"`
		CanNotice        int         `json:"can_notice,omitempty"`
		HaveVioFile      int         `json:"have_vio_file,omitempty"`
	} `json:"shareinfo,omitempty"`
	Count      int         `json:"count,omitempty"`
	List       []*File     `json:"list,omitempty"` // Uses the common File struct
	ShareState json.Number `json:"share_state,omitempty"`
	UserAppeal struct {
		CanAppeal       int `json:"can_appeal,omitempty"`
		CanShareAppeal  int `json:"can_share_appeal,omitempty"`
		PopupAppealPage int `json:"popup_appeal_page,omitempty"`
		CanGlobalAppeal int `json:"can_global_appeal,omitempty"`
	} `json:"user_appeal,omitempty"`
}

// ShareDownloadInfo represents the response for getting download URL from share (Traditional)
type ShareDownloadInfo struct {
	FileID   string      `json:"fid"`
	FileName string      `json:"fn"`
	FileSize Int64       `json:"fs"`
	URL      DownloadURL `json:"url"`
}

// SampleInitResp represents the response from sampleinitupload.php (Traditional)
type SampleInitResp struct {
	Object    string `json:"object"`
	AccessID  string `json:"accessid"`
	Host      string `json:"host"`
	Policy    string `json:"policy"`
	Signature string `json:"signature"`
	Expire    int64  `json:"expire"`
	Callback  string `json:"callback"`
	ErrorCode int    `json:"errno,omitempty"`
	Error     string `json:"error,omitempty"`
}
