package _115

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rclone/rclone/backend/115/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/lib/rest"
)

// listAll retrieves directory listings, using OpenAPI if possible.
// User function fn should return true to stop processing.
type listAllFn func(*api.File) bool

func (f *Fs) listAll(ctx context.Context, dirID string, limit int, filesOnly, dirsOnly bool, fn listAllFn) (found bool, err error) {
	if f.isShare {
		// Use traditional share listing API
		return f.listShare(ctx, dirID, limit, fn)
	}

	// Use OpenAPI listing
	params := url.Values{}
	params.Set("cid", dirID)
	params.Set("limit", strconv.Itoa(limit))
	params.Set("offset", "0")
	params.Set("show_dir", "1") // Include directories in the listing

	// Sorting (OpenAPI uses query params)
	params.Set("o", "user_utime") // Default sort: update time
	params.Set("asc", "0")        // Default sort: descending

	offset := 0
	for {
		params.Set("offset", strconv.Itoa(offset))
		opts := rest.Opts{
			Method:     "GET",
			Path:       "/open/ufile/files",
			Parameters: params,
		}

		var info api.FileList
		err = f.CallOpenAPI(ctx, &opts, nil, &info, false) // Use OpenAPI call
		if err != nil {
			return found, fmt.Errorf("OpenAPI list failed for dir %s: %w", dirID, err)
		}

		if len(info.Files) == 0 {
			break // No more items
		}

		for _, item := range info.Files {
			isDir := item.IsDir()
			// Apply client-side filtering if needed
			if filesOnly && isDir {
				continue
			}
			if dirsOnly && !isDir {
				continue
			}
			// Censored check only applicable if using traditional API fallback
			// if f.opt.CensoredOnly && item.Censored == 0 { continue }

			// Decode name
			item.FileName = f.opt.Enc.ToStandardName(item.FileNameBest()) // Use best name getter

			if fn(item) {
				found = true
				return found, nil // Early exit
			}
		}

		// Check if we have fetched all items based on total count from response
		currentOffset, _ := strconv.Atoi(params.Get("offset"))
		offset = currentOffset + len(info.Files)

		// Stop listing when we've reached the total count
		if info.Count > 0 && offset >= info.Count {
			break // We've reached or exceeded the total count
		}
	}
	return found, nil
}

// getDirPath returns the absolute path for a directory ID using OpenAPI.
func (f *Fs) getDirPath(ctx context.Context, dirID string) (dirPath string, err error) {
	if dirID == "0" {
		return "", nil
	}
	if f.isShare {
		// Path calculation for shares might need traditional API or different logic
		return "", errors.New("getDirPath not supported for shared filesystem")
	}

	// Use OpenAPI folder details endpoint
	params := url.Values{}
	params.Set("file_id", dirID)
	opts := rest.Opts{
		Method:     "GET",
		Path:       "/open/folder/get_info",
		Parameters: params,
	}

	var info api.FileStats // Reusing FileStats struct, mapping fields from FolderInfoData
	err = f.CallOpenAPI(ctx, &opts, nil, &info, false)
	if err != nil {
		// Check if it's a "not found" error
		if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "不存在") { // Heuristic check
			return "", fs.ErrorDirNotFound
		}
		return "", fmt.Errorf("OpenAPI get_info failed for ID %s: %w", dirID, err)
	}

	if info.Data == nil || len(info.Data.Paths) == 0 {
		// If path is empty but call succeeded, it might be the root or an issue
		if dirID == f.rootFolderID { // Check if it's the configured root
			return "", nil // Path is empty for the root itself
		}
		return "", fmt.Errorf("OpenAPI get_info for ID %s returned no path data", dirID)
	}

	// Construct path from response
	var pathParts []string
	for _, p := range info.Data.Paths {
		// Skip the root "0" if present in the path
		if p.FileID == "0" {
			continue
		}
		pathParts = append(pathParts, f.opt.Enc.ToStandardName(p.FileName))
	}
	dirPath = path.Join(pathParts...)

	return dirPath, nil
}

// makeDir creates a directory using OpenAPI.
func (f *Fs) makeDir(ctx context.Context, pid, name string) (info *api.NewDir, err error) {
	if f.isShare {
		return nil, errors.New("makeDir unsupported for shared filesystem")
	}
	form := url.Values{}
	form.Set("pid", pid)
	form.Set("file_name", f.opt.Enc.FromStandardName(name))

	opts := rest.Opts{
		Method: "POST",
		Path:   "/open/folder/add",
		Body:   strings.NewReader(form.Encode()), // Send as form data in body
		ExtraHeaders: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}

	info = new(api.NewDir)
	err = f.CallOpenAPI(ctx, &opts, nil, info, false)
	if err != nil {
		// Check for specific "already exists" error code from OpenAPI
		// Assuming code 20004 or similar based on traditional API
		if info.ErrCode() == 20004 || strings.Contains(info.ErrMsg(), "exists") || strings.Contains(info.ErrMsg(), "已存在") {
			// Try to find the existing directory's ID
			existingID, found, findErr := f.FindLeaf(ctx, pid, f.opt.Enc.FromStandardName(name))
			if findErr == nil && found {
				// Return info for the existing directory
				return &api.NewDir{
					OpenAPIBase: api.OpenAPIBase{State: true}, // Mark as success
					Data: &api.NewDirData{
						FileID:   existingID,
						FileName: name,
					},
				}, fs.ErrorDirExists // Return specific error
			}
			// If finding fails, return the original Mkdir error
			return nil, fmt.Errorf("makeDir failed and could not find existing dir: %w", err)
		}
		return nil, fmt.Errorf("OpenAPI makeDir failed: %w", err)
	}
	// Ensure FileID is populated
	if info.Data == nil || info.Data.FileID == "" {
		return nil, errors.New("OpenAPI makeDir response missing file_id")
	}
	return info, nil
}

// renameFile renames a file or folder using OpenAPI.
func (f *Fs) renameFile(ctx context.Context, fid, newName string) (err error) {
	if f.isShare {
		return errors.New("renameFile unsupported for shared filesystem")
	}
	form := url.Values{}
	form.Set("file_id", fid)
	form.Set("file_name", f.opt.Enc.FromStandardName(newName))

	opts := rest.Opts{
		Method: "POST",
		Path:   "/open/ufile/update", // Endpoint for renaming/starring
		Body:   strings.NewReader(form.Encode()),
		ExtraHeaders: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}

	var baseResp api.OpenAPIBase
	err = f.CallOpenAPI(ctx, &opts, nil, &baseResp, false)
	if err != nil {
		return fmt.Errorf("OpenAPI rename failed for ID %s: %w", fid, err)
	}
	return nil
}

// deleteFiles deletes files or folders by ID using OpenAPI.
func (f *Fs) deleteFiles(ctx context.Context, fids []string) (err error) {
	if f.isShare {
		return errors.New("deleteFiles unsupported for shared filesystem")
	}
	if len(fids) == 0 {
		return nil
	}
	form := url.Values{}
	form.Set("file_ids", strings.Join(fids, ","))
	// parent_id is optional according to docs

	opts := rest.Opts{
		Method: "POST",
		Path:   "/open/ufile/delete",
		Body:   strings.NewReader(form.Encode()),
		ExtraHeaders: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}

	var baseResp api.OpenAPIBase
	err = f.CallOpenAPI(ctx, &opts, nil, &baseResp, false)
	if err != nil {
		// Check for "not found" errors if possible, otherwise return generic error
		return fmt.Errorf("OpenAPI delete failed for IDs %v: %w", fids, err)
	}
	return nil
}

// moveFiles moves files or folders by ID using OpenAPI.
func (f *Fs) moveFiles(ctx context.Context, fids []string, pid string) (err error) {
	if f.isShare {
		return errors.New("moveFiles unsupported for shared filesystem")
	}
	if len(fids) == 0 {
		return nil
	}
	form := url.Values{}
	form.Set("file_ids", strings.Join(fids, ","))
	form.Set("to_cid", pid) // Target directory ID

	opts := rest.Opts{
		Method: "POST",
		Path:   "/open/ufile/move",
		Body:   strings.NewReader(form.Encode()),
		ExtraHeaders: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}

	var baseResp api.OpenAPIBase
	err = f.CallOpenAPI(ctx, &opts, nil, &baseResp, false)
	if err != nil {
		return fmt.Errorf("OpenAPI move failed for IDs %v to %s: %w", fids, pid, err)
	}
	return nil
}

// copyFiles copies files or folders by ID using OpenAPI.
func (f *Fs) copyFiles(ctx context.Context, fids []string, pid string) (err error) {
	if f.isShare {
		return errors.New("copyFiles unsupported for shared filesystem")
	}
	if len(fids) == 0 {
		return nil
	}
	form := url.Values{}
	form.Set("file_id", strings.Join(fids, ",")) // Note: param name is file_id (singular)
	form.Set("pid", pid)                         // Target directory ID
	form.Set("nodupli", "0")                     // Allow duplicates by default

	opts := rest.Opts{
		Method: "POST",
		Path:   "/open/ufile/copy",
		Body:   strings.NewReader(form.Encode()),
		ExtraHeaders: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}

	var baseResp api.OpenAPIBase
	err = f.CallOpenAPI(ctx, &opts, nil, &baseResp, false)
	if err != nil {
		return fmt.Errorf("OpenAPI copy failed for IDs %v to %s: %w", fids, pid, err)
	}
	return nil
}

// indexInfo gets user quota info (Traditional API).
func (f *Fs) indexInfo(ctx context.Context) (data *api.IndexData, err error) {
	if f.isShare {
		return nil, errors.New("indexInfo unsupported for shared filesystem")
	}
	opts := rest.Opts{
		Method: "GET",
		Path:   "/files/index_info", // Traditional endpoint
	}

	var info *api.IndexInfo
	// Use traditional API call
	err = f.CallTraditionalAPI(ctx, &opts, nil, &info, false) // Not skipping encryption
	if err != nil {
		return nil, fmt.Errorf("traditional indexInfo failed: %w", err)
	}
	if info.Data == nil {
		return nil, errors.New("traditional indexInfo returned no data")
	}
	return info.Data, nil
}

// Some downurl responses return an empty array instead of an object, which breaks JSON unmarshalling.
// Treat that as a transient server glitch and retry once.
func isDownurlDataArrayError(err error) bool {
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		if typeErr.Struct == "OpenAPIDownloadResp" && strings.EqualFold(typeErr.Field, "data") && typeErr.Value == "array" {
			return true
		}
	}
	// Fallback string check in case the error shape changes.
	return strings.Contains(err.Error(), "OpenAPIDownloadResp.data") && strings.Contains(err.Error(), "cannot unmarshal array")
}

func (f *Fs) getOpenAPIDownloadResp(ctx context.Context, pickCode string) (*api.OpenAPIDownloadResp, error) {
	form := url.Values{"pick_code": {pickCode}}
	const maxAttempts = 5
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		opts := rest.Opts{
			Method: "POST",
			Path:   "/open/ufile/downurl",
			Body:   strings.NewReader(form.Encode()),
			ExtraHeaders: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
		}

		var respData api.OpenAPIDownloadResp
		err := f.CallOpenAPI(ctx, &opts, nil, &respData, false)
		if err == nil {
			return &respData, nil
		}

		if attempt < maxAttempts && isDownurlDataArrayError(err) {
			fs.Debugf(f, "downurl returned array data for pickcode %s, retrying attempt %d/%d", pickCode, attempt+1, maxAttempts)
			continue
		}

		return nil, fmt.Errorf("OpenAPI downurl failed for pickcode %s: %w", pickCode, err)
	}
	return nil, fmt.Errorf("OpenAPI downurl retries exhausted for pickcode %s", pickCode)
}

// getDownloadURL gets a download URL using OpenAPI.
func (f *Fs) getDownloadURL(ctx context.Context, pickCode string) (durl *api.DownloadURL, err error) {
	if f.isShare {
		// Should call getDownloadURLFromShare for shared links
		return nil, errors.New("use getDownloadURLFromShare for shared filesystems")
	}
	respData, err := f.getOpenAPIDownloadResp(ctx, pickCode)
	if err != nil {
		return nil, err
	}

	// The response data is a map where the key is the file ID.
	// We need to extract the URL from the first (and likely only) entry.
	for _, downInfo := range respData.Data {
		if downInfo != nil {
			// Manually add cookies from the response if needed (though OpenAPI shouldn't need them)
			// downInfo.URL.Cookies = resp.Cookies() // 'resp' is not available here
			return &downInfo.URL, nil
		}
	}

	return nil, fs.ErrorObjectNotFound // Or appropriate error if map is empty
}

// getFile gets information about a file or directory using OpenAPI list endpoint.
// Note: OpenAPI doesn't have a direct get_info equivalent that works for both files and folders by ID easily.
// We list the parent and find the item.
func (f *Fs) getFile(ctx context.Context, fid, pc string) (file *api.File, err error) {
	if fid == "0" {
		// Return a synthetic root directory object
		return &api.File{
			CID:      "0",
			FileName: "", // Root has no name relative to itself
			IsFolder: 0,  // Mark as folder
		}, nil
	}
	if f.isShare {
		// Share info needs traditional API or specific share logic
		return nil, errors.New("getFile not supported for shared filesystem, use listShare")
	}

	// Strategy:
	// 1. If pickCode is provided, try getting download URL first, as it returns file info.
	// 2. If only fid is provided, or step 1 fails, list the parent to find the item.

	if pc != "" {
		// Try getting info via downurl endpoint
		respData, apiErr := f.getOpenAPIDownloadResp(ctx, pc)
		if apiErr == nil {
			for itemFid, downInfo := range respData.Data {
				if downInfo != nil {
					// Construct an api.File from the download info
					return &api.File{
						FID:      itemFid, // Key is the file ID
						FileName: downInfo.FileName,
						FileSize: downInfo.FileSize,
						PickCode: downInfo.PickCode,
						Sha1:     downInfo.Sha1,
						IsFolder: 1, // Assume file if downurl works
						// Timestamps are missing here
					}, nil
				}
			}
		}
		// If downurl failed or returned empty, fall through to listing parent
		fs.Debugf(f, "downurl failed for pickcode %s, falling back to listing parent: %v", pc, apiErr)
	}

	if fid == "" {
		return nil, errors.New("getFile requires either fid or pickCode")
	}

	// Need parent ID to list. How to get parent ID from child ID efficiently?
	// OpenAPI doesn't seem to offer this directly.
	// Fallback: Use traditional /files/get_info which might still work? Risky.
	// Alternative: Assume the caller knows the parent or accept inefficiency.
	// Let's try the traditional endpoint as a last resort, requires cookie.
	fs.Debugf(f, "Attempting traditional get_info for fid %s as OpenAPI lacks direct equivalent", fid)
	params := url.Values{}
	params.Set("file_id", fid)
	opts := rest.Opts{
		Method:     "GET",
		Path:       "/files/get_info", // Traditional endpoint
		Parameters: params,
	}
	var info api.FileInfo
	err = f.CallTraditionalAPI(ctx, &opts, nil, &info, false) // Needs encryption
	if err != nil {
		return nil, fmt.Errorf("traditional get_info failed for ID %s: %w", fid, err)
	}
	if len(info.Data) > 0 {
		file = info.Data[0]
		// Decode name from traditional response
		file.Name = f.opt.Enc.ToStandardName(file.Name)
		// Map traditional fields to common fields if needed
		file.FileName = file.Name
		file.FileSize = file.Size
		file.Sha1 = file.Sha
		// IsDir check needs traditional logic here
		if file.FID == "" && file.CID != "" { // Traditional folder check
			file.IsFolder = 0
		} else {
			file.IsFolder = 1
		}
		return file, nil
	}

	return nil, fs.ErrorObjectNotFound // Not found via traditional API either
}

// getStats gets folder statistics using OpenAPI.
func (f *Fs) getStats(ctx context.Context, cid string) (info *api.FileStats, err error) {
	if cid == "0" {
		// Maybe return default stats for root? Or error?
		return nil, errors.New("getting stats for root directory '0' is not directly supported")
	}
	if f.isShare {
		return nil, errors.New("getStats unsupported for shared filesystem")
	}

	params := url.Values{}
	params.Set("file_id", cid)
	opts := rest.Opts{
		Method:     "GET",
		Path:       "/open/folder/get_info",
		Parameters: params,
	}

	info = new(api.FileStats) // Initialize the struct
	err = f.CallOpenAPI(ctx, &opts, nil, info, false)
	if err != nil {
		return nil, fmt.Errorf("OpenAPI get_info (for stats) failed for ID %s: %w", cid, err)
	}
	if info.Data != nil {
		// Decode names in path
		info.Data.FileName = f.opt.Enc.ToStandardName(info.Data.FileName)
		for i := range info.Data.Paths {
			info.Data.Paths[i].FileName = f.opt.Enc.ToStandardName(info.Data.Paths[i].FileName)
		}
	} else {
		return nil, errors.New("OpenAPI get_info (for stats) returned no data")
	}
	return info, nil
}

// ------------------------------------------------------------
// Traditional API Helpers (Sharing, Offline Download)
// ------------------------------------------------------------

// addURLs adds offline download tasks (Traditional API).
func (f *Fs) addURLs(ctx context.Context, dir string, urls []string) (info *api.NewURL, err error) {
	if f.userID == "" {
		return nil, errors.New("cannot add URLs without userID (login required)")
	}
	parentID := "0" // Default parent
	if dir != "" {
		foundID, findErr := f.dirCache.FindDir(ctx, dir, false) // Find target dir ID
		if findErr != nil {
			fs.Logf(f, "Target directory %q not found for addURLs, using default: %v", dir, findErr)
		} else {
			parentID = foundID
		}
	}

	payload := map[string]string{
		"ac":         "add_task_urls",
		"app_ver":    f.appVer, // Use parsed app version
		"uid":        f.userID,
		"wp_path_id": parentID,
	}
	for ind, url := range urls {
		payload[fmt.Sprintf("url[%d]", ind)] = url
	}

	opts := rest.Opts{
		Method:     "POST",
		RootURL:    "https://lixian.115.com/lixianssp/", // Traditional endpoint
		Parameters: url.Values{"ac": {"add_task_urls"}}, // Query param seems redundant but keep for safety
	}

	info = new(api.NewURL)
	// Use traditional API call with encryption
	err = f.CallTraditionalAPI(ctx, &opts, payload, info, false) // Pass payload for encryption
	// Don't return error from CallTraditionalAPI directly, check info struct
	if err != nil {
		fs.Errorf(f, "addURLs API call failed: %v", err)
		// Return the info struct anyway, as it might contain partial results/errors
	}
	return info, nil // Command expects nil error, user checks output
}

// listShare lists shared files (Traditional API).
func (f *Fs) listShare(ctx context.Context, dirID string, limit int, fn listAllFn) (found bool, err error) {
	params := url.Values{}
	params.Set("share_code", f.opt.ShareCode)
	params.Set("receive_code", f.opt.ReceiveCode)
	params.Set("cid", dirID) // Use cid for directory within share
	params.Set("limit", strconv.Itoa(limit))
	params.Set("offset", "0")

	opts := rest.Opts{
		Method:     "GET",
		Path:       "/share/snap", // Traditional endpoint
		Parameters: params,
	}

	offset := 0
OUTER:
	for {
		params.Set("offset", strconv.Itoa(offset))
		opts.Parameters = params // Update offset in opts

		var info *api.ShareSnap
		// Use traditional API call (requires cookie, no encryption for GET?) - Assume no encryption for GET
		err = f.CallTraditionalAPI(ctx, &opts, nil, &info, true) // Skip encryption for GET
		if err != nil {
			return found, fmt.Errorf("traditional listShare failed: %w", err)
		}
		if info.Data == nil || len(info.Data.List) == 0 {
			break // No more items or error in response
		}

		for _, item := range info.Data.List {
			// Decode name
			item.Name = f.opt.Enc.ToStandardName(item.Name)
			// Map traditional fields to common fields if needed
			item.FileName = item.Name
			item.FileSize = item.Size
			item.Sha1 = item.Sha
			if item.FID == "" && item.CID != "" {
				item.IsFolder = 0
			} else {
				item.IsFolder = 1
			}

			if fn(item) {
				found = true
				break OUTER
			}
		}
		offset += len(info.Data.List) // Use actual count returned
		if offset >= info.Data.Count {
			break // Reached total count
		}
	}
	return found, nil
}

// copyFromShare copies from a share link (Traditional API).
func (f *Fs) copyFromShare(ctx context.Context, shareCode, receiveCode, fid, cid string) (err error) {
	if f.userID == "" {
		return errors.New("cannot copy from share without userID (login required)")
	}
	form := url.Values{}
	form.Set("share_code", shareCode)
	form.Set("receive_code", receiveCode)
	form.Set("file_id", fid)      // Source file/folder ID within share ("0" for all)
	form.Set("cid", cid)          // Destination folder ID in user's drive
	form.Set("user_id", f.userID) // User ID of the destination owner

	opts := rest.Opts{
		Method:          "POST",
		Path:            "/share/receive", // Traditional endpoint
		MultipartParams: form,
	}

	var baseResp api.TraditionalBase
	// Use traditional API call (requires cookie, assume encryption needed for POST)
	err = f.CallTraditionalAPI(ctx, &opts, nil, &baseResp, false) // No skipEncrypt
	if err != nil {
		return fmt.Errorf("traditional copyFromShare failed: %w", err)
	}
	return nil
}

// getDownloadURLFromShare gets download URL from share (Traditional API).
func (f *Fs) getDownloadURLFromShare(ctx context.Context, fid string) (durl *api.DownloadURL, err error) {
	req := map[string]string{
		"share_code":   f.opt.ShareCode,
		"receive_code": f.opt.ReceiveCode,
		"file_id":      fid,
	}
	t := strconv.FormatInt(time.Now().Unix(), 10)
	opts := rest.Opts{
		Method:     "POST",
		RootURL:    "https://proapi.115.com/app/share/downurl", // Traditional endpoint
		Parameters: url.Values{"t": {t}},                       // Timestamp param
	}

	downInfo := api.ShareDownloadInfo{}
	// Use traditional API call with encryption
	resp, err := f.CallTraditionalAPIWithResp(ctx, &opts, req, &downInfo, false) // Get response for cookies
	if err != nil {
		return nil, fmt.Errorf("traditional getDownloadURLFromShare failed: %w", err)
	}
	if downInfo.URL.URL == "" {
		return nil, errors.New("traditional getDownloadURLFromShare returned empty URL")
	}

	durl = &downInfo.URL
	if resp != nil {
		durl.Cookies = resp.Cookies() // Attach cookies from response
	}
	return durl, nil
}

// CallTraditionalAPIWithResp is a variant that returns the http.Response for cookie access.
func (f *Fs) CallTraditionalAPIWithResp(ctx context.Context, opts *rest.Opts, request any, response any, skipEncrypt bool) (*http.Response, error) {
	// Ensure root URL is set if not provided in opts
	if opts.RootURL == "" {
		opts.RootURL = traditionalRootURL
	}

	var httpResp *http.Response
	err := f.globalPacer.Call(func() (shouldRetryGlobal bool, errGlobal error) {
		// Wait for traditional pacer
		if err := f.enforceTraditionalPacerDelay(); err != nil {
			return false, backoff.Permanent(err)
		}

		// Make the API call (with or without encryption)
		var apiErr error
		httpResp, apiErr = f.executeTraditionalAPICall(ctx, opts, request, response, skipEncrypt)

		// Check for retryable errors
		retryNeeded, retryErr := shouldRetry(ctx, httpResp, apiErr)
		if retryNeeded {
			fs.Debugf(f, "pacer: low level retry required for traditional call with response (error: %v)", retryErr)
			return true, retryErr // Signal globalPacer to retry
		}

		// Handle non-retryable errors
		if apiErr != nil {
			fs.Debugf(f, "pacer: permanent error encountered in traditional call with response: %v", apiErr)
			// Ensure the error is marked as permanent
			var permanentErr *backoff.PermanentError
			if !errors.As(apiErr, &permanentErr) {
				return false, backoff.Permanent(apiErr)
			}
			return false, apiErr // Already permanent
		}

		// Check API-level errors in response struct
		if errResp := f.checkResponseForAPIErrors(response, false, nil); errResp != nil {
			fs.Debugf(f, "pacer: permanent API error encountered in traditional call with response: %v", errResp)
			return false, backoff.Permanent(errResp)
		}

		fs.Debugf(f, "pacer: traditional call with response successful")
		return false, nil // Success, don't retry
	})

	return httpResp, err
}
