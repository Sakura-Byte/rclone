package _115

import (
	"bytes"
	"context" // Keep for traditional token generation
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	"github.com/cenkalti/backoff/v4"

	// "github.com/pierrec/lz4/v4" // Keep commented out unless lz4 errors reappear
	"github.com/rclone/rclone/backend/115/api" // Keep for traditional initUpload
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/accounting"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/rest"
)

// Globals
const (
	cachePrefix  = "rclone-115-sha1sum-"
	md5Salt      = "Qclm8MGWUv59TnrR0XPg"     // Salt for traditional token generation
	OSSRegion    = "cn-shenzhen"              // Default OSS region
	OSSUserAgent = "aliyun-sdk-android/2.9.1" // Keep or update as needed
)

// RereadableObject represents a source that can be re-opened for multiple reads
type RereadableObject struct {
	src        fs.ObjectInfo
	ctx        context.Context
	currReader io.Reader
	options    []fs.OpenOption
	size       int64                // Track the source size for accounting
	acc        *accounting.Account  // Store the accounting object
	fsInfo     fs.Info              // Source filesystem info
	transfer   *accounting.Transfer // Keep track of the transfer object
}

// NewRereadableObject creates a wrapper that supports re-opening the source
func NewRereadableObject(ctx context.Context, src fs.ObjectInfo, options ...fs.OpenOption) (*RereadableObject, error) {
	// Try to extract the filesystem info from the source
	var fsInfo fs.Info

	// Try different ways of getting the filesystem info
	if o, ok := src.(fs.Object); ok {
		// If it's a direct Object
		fsInfo = o.Fs()
	} else if o, ok := fs.UnWrapObjectInfo(src).(fs.Object); ok {
		// Try to unwrap it first
		fsInfo = o.Fs()
	} else if i, ok := src.(interface{ Fs() fs.Info }); ok {
		// If it has an Fs() method that returns fs.Info
		fsInfo = i.Fs()
	}

	r := &RereadableObject{
		src:     src,
		ctx:     ctx,
		options: options,
		size:    src.Size(), // Remember the size for accounting
		fsInfo:  fsInfo,     // Store the filesystem info
	}

	// Open it once to make sure it works and assign to currReader
	reader, err := r.Open()
	if err != nil {
		return nil, err
	}
	r.currReader = reader
	return r, nil
}

// retryWithExponentialBackoff provides a standard implementation of sophisticated retry logic
// with exponential backoff for handling rate limiting issues.
func retryWithExponentialBackoff(
	ctx context.Context,
	description string, // Description of the operation being retried (for logging)
	loggingObj interface{}, // Object to log against
	operation func() error, // Operation to execute and retry
	maxRetries int, // Maximum number of retries
	initialDelay time.Duration, // Initial delay between retries
	maxDelay time.Duration, // Maximum delay between retries
	maxElapsedTime time.Duration, // Maximum total retry time
) error {
	// Set up exponential backoff
	var retryCount int
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = initialDelay
	expBackoff.MaxInterval = maxDelay
	expBackoff.MaxElapsedTime = maxElapsedTime
	expBackoff.Multiplier = 2.5          // More aggressive multiplier
	expBackoff.RandomizationFactor = 0.5 // Add jitter to prevent thundering herd

	// Create retry context with timeout based on maxElapsedTime
	// Give some buffer beyond MaxElapsedTime for the final attempt + operation time
	retryCtx, cancelRetry := context.WithTimeout(ctx, maxElapsedTime+maxDelay+10*time.Second)
	defer cancelRetry()

	// Define the retry wrapper
	retryOperation := func() error {
		// Check context cancellation before proceeding
		if err := retryCtx.Err(); err != nil {
			fs.Debugf(loggingObj, "Retry context cancelled for '%s': %v", description, err)
			return backoff.Permanent(fmt.Errorf("retry cancelled for '%s': %w", description, err))
		}

		if retryCount > 0 {
			// Check context cancellation again before sleeping
			if err := retryCtx.Err(); err != nil {
				fs.Debugf(loggingObj, "Retry context cancelled before delay for '%s': %v", description, err)
				return backoff.Permanent(fmt.Errorf("retry cancelled before delay for '%s': %w", description, err))
			}

			nextDelay := expBackoff.NextBackOff()
			if nextDelay == backoff.Stop {
				// This condition might be reached if MaxElapsedTime is exceeded by the time calculation
				// or if the backoff itself decides to stop for other reasons.
				fs.Logf(loggingObj, "Exceeded max retry duration or backoff stopped for '%s'", description)
				return backoff.Permanent(fmt.Errorf("exceeded maximum retry duration or backoff stopped for '%s'", description))
			}

			// Use more visible logging for retries
			fs.Logf(loggingObj, "Retrying '%s': Waiting %v before retry %d/%d",
				description, nextDelay, retryCount+1, maxRetries)

			// Wait for the delay, but honor context cancellation
			select {
			case <-time.After(nextDelay):
				// Continue after delay
			case <-retryCtx.Done():
				fs.Logf(loggingObj, "Retry context cancelled while waiting for delay in '%s': %v", description, retryCtx.Err())
				return backoff.Permanent(fmt.Errorf("retry cancelled while waiting for delay in '%s': %w", description, retryCtx.Err()))
			}
		}
		retryCount++ // Increment retry count *after* the first attempt (retryCount=0)

		// Execute the actual operation
		err := operation()

		// On success, return nil to break the retry loop
		if err == nil {
			return nil
		}

		// Check if we've hit max retries (retryCount is now 1 for the first attempt, so compare with >= maxRetries)
		if retryCount >= maxRetries {
			fs.Logf(loggingObj, "Giving up '%s' after %d attempts: %v",
				description, retryCount, err)
			return backoff.Permanent(fmt.Errorf("giving up '%s' after %d attempts: %w", description, retryCount, err))
		}

		// Check if this is a rate limit error or other error that we should retry
		shouldRetryErr, classification := shouldRetry(retryCtx, nil, err) // Pass retryCtx
		if !shouldRetryErr {
			// Non-retryable error
			fs.Debugf(loggingObj, "Non-retryable error (%s) when '%s': %v", classification, description, err)
			return backoff.Permanent(err) // Wrap in Permanent to stop retries
		}

		// Log retryable errors
		fs.Debugf(loggingObj, "Retryable error (%s) on attempt %d for '%s', will retry: %v", classification, retryCount, description, err)

		return err // Return the retryable error to trigger the next retry
	}

	// Define notify function for logging retry attempts (optional, handled within retryOperation now)
	// notify := func(err error, delay time.Duration) {
	// 	if err != nil {
	// 		fs.Debugf(loggingObj, "Error during '%s': %v. Retrying in %v...", description, err, delay)
	// 	}
	// }

	// Execute the retry logic using the context-aware wrapper
	// No explicit notify needed if logging is done within retryOperation
	return backoff.Retry(retryOperation, backoff.WithContext(expBackoff, retryCtx))
}

// Open (re)opens the source file
func (r *RereadableObject) Open() (io.Reader, error) {
	// Close existing reader if it's a ReadCloser
	if r.currReader != nil {
		if rc, ok := r.currReader.(io.ReadCloser); ok {
			_ = rc.Close() // Ignore errors on close
		}
	}

	// Try to get the original fs.Object if it's an fs.Object
	// This is for supporting direct methods like RangeSeek later
	obj := unWrapObjectInfo(r.src)
	if obj != nil {
		var rc io.ReadCloser
		var err error

		// First try to get the pacer from the Fs
		var pacer *fs.Pacer
		if fsObj, ok := obj.Fs().(*Fs); ok {
			pacer = fsObj.globalPacer
		}

		// Set retry parameters
		maxRetries := 15
		initialDelay := 1 * time.Second
		maxDelay := 300 * time.Second
		maxElapsedTime := 30 * time.Minute

		// Define the operation to retry
		openOperation := func() error {
			var openErr error
			if pacer != nil {
				// Apply pacer to handle rate limiting (429 errors)
				err = pacer.Call(func() (bool, error) {
					rc, openErr = obj.Open(r.ctx, r.options...)
					if openErr != nil {
						// Check for 429 rate limit error
						retry, _ := shouldRetry(r.ctx, nil, openErr)
						if retry {
							fs.Debugf(obj, "Pacer: Retrying Open after rate limit error: %v", openErr)
							return true, openErr // Let pacer handle retry timing
						}
					}
					return false, openErr
				})
			} else {
				// Fall back to direct open if we can't use pacer
				rc, err = obj.Open(r.ctx, r.options...)
			}
			return err
		}

		// Retry with exponential backoff
		err = retryWithExponentialBackoff(
			r.ctx,
			"reopening object",
			obj,
			openOperation,
			maxRetries,
			initialDelay,
			maxDelay,
			maxElapsedTime,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to reopen source object after retries: %w", err)
		}

		// Check if we already have an accounting wrapper
		// If this is a fresh Open, extract the existing accounting if any
		if r.acc == nil {
			// Get the underlying accounting.Account if there is one
			// The accounting system might wrap our reader with its own accounting
			// We need to preserve this for speed tracking to work
			_, acc := accounting.UnWrapAccounting(rc)
			if acc != nil {
				r.acc = acc
				fs.Debugf(nil, "Preserved existing accounting wrapper for RereadableObject")
			}
		}

		// Always wrap with accounting, even if we found an existing one
		// The accounting system will handle this properly
		stats := accounting.Stats(r.ctx)
		if stats == nil {
			fs.Debugf(nil, "No Stats found - accounting may not work correctly")
			r.currReader = rc
			return rc, nil
		}

		name := ""
		if obj != nil {
			name = obj.Remote()
		} else if r.src != nil {
			name = r.src.String()
		}

		// Try to get real Fs objects if available by downcasting fs.Info to fs.Fs
		var srcFs, dstFs fs.Fs
		if r.fsInfo != nil {
			if f, ok := r.fsInfo.(fs.Fs); ok {
				srcFs = f
			}
		}

		// Create a new transfer or reuse existing one
		if r.transfer == nil {
			// Create an accounting transfer with the best filesystem info we have
			r.transfer = stats.NewTransferRemoteSize(name, r.size, srcFs, dstFs)
		}

		// Create a new accounting wrapper using the transfer
		accReader := r.transfer.Account(r.ctx, rc).WithBuffer()
		r.currReader = accReader

		// Extract the accounting object for later use
		_, r.acc = accounting.UnWrapAccounting(accReader)

		return r.currReader, nil
	}

	return nil, errors.New("source doesn't support reopening")
}

// Read reads from the current reader
func (r *RereadableObject) Read(p []byte) (n int, err error) {
	if r.currReader == nil {
		return 0, errors.New("no current reader available")
	}
	return r.currReader.Read(p)
}

// MarkComplete marks the transfer as complete with success
func (r *RereadableObject) MarkComplete(ctx context.Context) {
	if r.transfer != nil {
		// Mark the transfer as successful and done
		r.transfer.Done(ctx, nil)
		r.transfer = nil // Clear to avoid double completion
	}
}

// Close closes the current reader if it's a ReadCloser
func (r *RereadableObject) Close() error {
	var err error

	// Close the current reader
	if r.currReader != nil {
		if rc, ok := r.currReader.(io.ReadCloser); ok {
			err = rc.Close()
		}
		r.currReader = nil
	}

	// Don't finalize the transfer here - this is just closing a read
	// The transfer should be finalized by the caller when the operation is complete
	// via MarkComplete() or by creating a new transfer

	return err
}

// getUploadBasicInfo retrieves userkey using the traditional API (needed for traditional initUpload signature).
func (f *Fs) getUploadBasicInfo(ctx context.Context) error {
	if f.userkey != "" {
		return nil // Already have it
	}
	opts := rest.Opts{
		Method:  "GET",
		RootURL: "https://proapi.115.com/app/uploadinfo", // Traditional endpoint
	}
	var info *api.UploadBasicInfo

	// Use traditional API call (requires cookie)
	// Assume no encryption needed for this GET request? Let's try skipping.
	err := f.CallTraditionalAPI(ctx, &opts, nil, &info, true) // skipEncrypt = true
	if err != nil {
		return fmt.Errorf("traditional uploadinfo call failed: %w", err)
	}
	if err = info.Err(); err != nil {
		return fmt.Errorf("traditional uploadinfo API error: %s (%d)", info.Error, info.Errno)
	}
	userID := info.UserID.String()
	// Verify userID matches the one from login if possible
	if f.userID != "" && userID != f.userID {
		fs.Logf(f, "Warning: UserID from uploadinfo (%s) differs from login UserID (%s)", userID, f.userID)
		// Don't fail, but log discrepancy. Use the login UserID.
	} else if f.userID == "" {
		f.userID = userID // Set userID if not already set
	}

	if info.Userkey == "" {
		return errors.New("traditional uploadinfo returned empty userkey")
	}
	f.userkey = info.Userkey
	return nil
}

// bufferIO handles buffering of input streams based on size thresholds.
// Returns the potentially buffered reader and a cleanup function.
func bufferIO(f *Fs, in io.Reader, size, threshold int64) (out io.Reader, cleanup func(), err error) {
	cleanup = func() {} // Default no-op cleanup

	// If NoBuffer option is enabled, don't buffer to disk or memory
	if f.opt.NoBuffer {
		// Just return the original reader
		fs.Debugf(f, "Skipping buffering due to no_buffer option")
		return in, cleanup, nil
	}

	// If size is unknown or below threshold, read into memory
	if size < 0 || size <= threshold {
		inData, err := io.ReadAll(in)
		if err != nil {
			return nil, cleanup, fmt.Errorf("failed to read input to memory buffer: %w", err)
		}
		return bytes.NewReader(inData), cleanup, nil
	}

	// Size is known and above threshold, buffer to disk
	tempDir := os.TempDir()
	tempFile, err := os.CreateTemp("", cachePrefix)
	if err != nil {
		// Get some basic info about the temp directory
		var dirInfo string
		if stat, statErr := os.Stat(tempDir); statErr == nil {
			dirInfo = fmt.Sprintf(" (temp dir: %s, mode: %s)", tempDir, stat.Mode())
		} else {
			dirInfo = fmt.Sprintf(" (temp dir: %s, stat error: %v)", tempDir, statErr)
		}

		return nil, cleanup, fmt.Errorf("failed to create temp file for buffering%s: %w",
			dirInfo, err)
	}
	fs.Debugf(nil, "Buffering upload to temp file: %s", tempFile.Name())

	// Define cleanup function to close and remove the temp file
	cleanup = func() {
		closeErr := tempFile.Close()
		removeErr := os.Remove(tempFile.Name())
		if closeErr != nil {
			fs.Errorf(nil, "Failed to close temp file %s: %v", tempFile.Name(), closeErr)
		}
		if removeErr != nil {
			fs.Errorf(nil, "Failed to remove temp file %s: %v", tempFile.Name(), removeErr)
		} else {
			fs.Debugf(nil, "Cleaned up temp file: %s", tempFile.Name())
		}
	}

	// Copy data to temp file
	_, err = io.Copy(tempFile, in)
	if err != nil {
		cleanup() // Clean up immediately on error
		return nil, func() {}, fmt.Errorf("failed to copy to temp file: %w", err)
	}

	// Seek back to the beginning of the temp file
	_, err = tempFile.Seek(0, io.SeekStart)
	if err != nil {
		cleanup() // Clean up immediately on error
		return nil, func() {}, fmt.Errorf("failed to seek temp file: %w", err)
	}

	return tempFile, cleanup, nil
}

// bufferIOwithSHA1 buffers the input and calculates its SHA-1 hash.
// Returns the SHA-1 hash, the potentially buffered reader, and a cleanup function.
func bufferIOwithSHA1(f *Fs, in io.Reader, src fs.ObjectInfo, size, threshold int64, ctx context.Context, options ...fs.OpenOption) (sha1sum string, out io.Reader, cleanup func(), err error) {
	cleanup = func() {} // Default no-op cleanup

	// First check if the source object already has the SHA1 hash
	if srcObj, ok := src.(fs.Object); ok {
		hashVal, hashErr := srcObj.Hash(ctx, hash.SHA1)
		if hashErr == nil && hashVal != "" {
			fs.Debugf(srcObj, "Using precalculated SHA1: %s", hashVal)
			return hashVal, in, cleanup, nil
		}
	}

	// If NoBuffer option is enabled, calculate the SHA1 using a non-buffering approach
	if f.opt.NoBuffer {
		fs.Debugf(f, "Computing SHA1 without buffering due to no_buffer option")

		// Create a rereadable source if it's not already one
		var rereadable *RereadableObject
		if ro, ok := in.(*RereadableObject); ok {
			rereadable = ro
		} else {
			// Try to create a new rereadable source
			ro, roErr := NewRereadableObject(ctx, src, options...)
			if roErr != nil {
				return "", in, cleanup, fmt.Errorf("failed to create rereadable object: %w", roErr)
			}
			rereadable = ro
			cleanup = func() { _ = rereadable.Close() }
		}

		// Calculate hash using the rereadable source
		hashVal := sha1.New()
		_, hashErr := io.Copy(hashVal, rereadable)
		if hashErr != nil {
			return "", in, cleanup, fmt.Errorf("failed to calculate SHA1 without buffering: %w", hashErr)
		}

		// Reopen the source for the actual upload
		var newReader io.Reader
		var reopenErr error

		// Set retry parameters for reopening
		maxRetries := 12
		initialDelay := 1 * time.Second
		maxDelay := 180 * time.Second
		maxElapsedTime := 20 * time.Minute

		// Define the reopening operation
		reopenOperation := func() error {
			var openErr error
			newReader, openErr = rereadable.Open()
			return openErr
		}

		// Retry with exponential backoff
		reopenErr = retryWithExponentialBackoff(
			ctx,
			"reopening after SHA1",
			f,
			reopenOperation,
			maxRetries,
			initialDelay,
			maxDelay,
			maxElapsedTime,
		)

		if reopenErr != nil {
			return "", in, cleanup, fmt.Errorf("failed to reopen source after SHA1 calculation: %w", reopenErr)
		}

		sha1sum = hex.EncodeToString(hashVal.Sum(nil))
		fs.Debugf(f, "Calculated SHA1 without buffering: %s", sha1sum)
		return sha1sum, newReader, cleanup, nil
	}

	// Standard buffering approach
	hashVal := sha1.New()
	tee := io.TeeReader(in, hashVal)

	// Buffer the input using the tee reader
	out, cleanup, err = bufferIO(f, tee, size, threshold)
	if err != nil {
		// Cleanup is handled by bufferIO on error
		return "", nil, cleanup, fmt.Errorf("failed to buffer input for SHA1 calculation: %w", err)
	}

	// Calculate the final hash
	sha1sum = hex.EncodeToString(hashVal.Sum(nil))
	return sha1sum, out, cleanup, nil
}

// initUploadOpenAPI calls the OpenAPI /open/upload/init endpoint.
func (f *Fs) initUploadOpenAPI(ctx context.Context, size int64, name, dirID, sha1sum, preSha1, pickCode, signKey, signVal string) (*api.UploadInitInfo, error) {
	form := url.Values{}
	form.Set("file_name", f.opt.Enc.FromStandardName(name))
	form.Set("file_size", strconv.FormatInt(size, 10))
	form.Set("target", "U_1_"+dirID)
	if sha1sum != "" {
		form.Set("fileid", strings.ToUpper(sha1sum)) // fileid is the full SHA1
	}
	if preSha1 != "" {
		form.Set("preid", preSha1) // preid is the 128k SHA1
	}
	if pickCode != "" {
		form.Set("pick_code", pickCode) // For resuming? Docs are unclear if init uses this. Resume endpoint definitely does.
	}
	if signKey != "" && signVal != "" {
		form.Set("sign_key", signKey)
		form.Set("sign_val", signVal) // Value should be uppercase SHA1 of range
	}
	// topupload parameter seems related to folder uploads, skip for single files

	// Log parameters for debugging, but mask sensitive values
	fs.Debugf(f, "Initializing upload for file_name=%q, size=%d, target=U_1_%s, has_fileid=%v, has_preid=%v, has_pickcode=%v, has_sign=%v",
		name, size, dirID, sha1sum != "", preSha1 != "", pickCode != "", signKey != "")

	// Create request options
	opts := rest.Opts{
		Method: "POST",
		Path:   "/open/upload/init",
		Body:   strings.NewReader(form.Encode()),
		ExtraHeaders: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
		},
	}

	var info api.UploadInitInfo // Response structure includes nested Data for OpenAPI
	err := f.CallOpenAPI(ctx, &opts, nil, &info, false)
	if err != nil {
		// If it's a parameter error (code 1001), provide more context
		if strings.Contains(err.Error(), "参数错误") || strings.Contains(err.Error(), "1001") {
			return nil, fmt.Errorf("OpenAPI initUpload failed with parameter error: %w (file_name=%q, size=%d, dirID=%s)",
				err, name, size, dirID)
		}

		// If it's a rate limit error, provide advice
		if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "Too Many Requests") {
			return nil, fmt.Errorf("OpenAPI initUpload failed due to rate limiting: %w. Consider using --low-level-retries flag to increase retries",
				err)
		}

		// General error handling
		return nil, fmt.Errorf("OpenAPI initUpload failed: %w", err)
	}

	// Error checking is handled by CallOpenAPI using info.Err()
	if info.Data == nil {
		// If Data is nil but call succeeded, maybe it's a 秒传 response where fields are top-level?
		if info.State {
			if info.GetFileID() != "" && info.GetPickCode() != "" {
				// This is likely a successful 秒传 response with top-level fields
				fs.Debugf(f, "Detected direct 秒传 success response with top-level fields")
				return &info, nil
			}
			return nil, fmt.Errorf("OpenAPI initUpload returned success state but no data and insufficient top-level fields (file_id=%q, pick_code=%q)",
				info.GetFileID(), info.GetPickCode())
		}

		// If state is false, CallOpenAPI should have returned an error, but let's add an extra check
		errMsg := info.ErrMsg()
		if info.ErrCode() != 0 || errMsg != "" {
			return nil, fmt.Errorf("OpenAPI initUpload failed with error code %d: %s",
				info.ErrCode(), errMsg)
		}

		return nil, errors.New("internal error: OpenAPI initUpload failed but CallOpenAPI returned no error")
	}

	// Log successful initialization
	statusMsg := "normal upload"
	if info.GetStatus() == 2 {
		statusMsg = "秒传 success"
	}
	fs.Debugf(f, "Upload initialized: status=%d (%s), bucket=%q, object=%q",
		info.GetStatus(), statusMsg, info.GetBucket(), info.GetObject())

	return &info, nil
}

// postUpload processes the JSON callback after an upload to OSS.
// The callback result from OSS SDK v2 is already a map[string]any.
func (f *Fs) postUpload(callbackResult map[string]any) (*api.CallbackData, error) {
	if callbackResult == nil {
		return nil, errors.New("received nil callback result from OSS")
	}

	// Check for standard OSS callback status if present
	if statusVal, ok := callbackResult["Status"]; ok {
		if statusStr, ok := statusVal.(string); ok && !strings.HasPrefix(statusStr, "OK") {
			// Try to get more info from the map
			errMsg := fmt.Sprintf("OSS callback failed with Status: %s", statusStr)
			if bodyVal, ok := callbackResult["body"]; ok {
				if bodyStr, ok := bodyVal.(string); ok {
					errMsg += fmt.Sprintf(", Body: %s", bodyStr)
				}
			}
			return nil, errors.New(errMsg)
		}
	}

	// Check for OpenAPI format (with state/code/message/data structure)
	var cbData *api.CallbackData

	// First, check if this is an OpenAPI format response
	if _, ok := callbackResult["state"]; ok {
		// This could be an OpenAPI format response
		if dataVal, ok := callbackResult["data"]; ok {
			if dataMap, ok := dataVal.(map[string]any); ok {
				// Try to extract file_id and pick_code from the data field
				fileID, fileIDExists := dataMap["file_id"].(string)
				pickCode, pickCodeExists := dataMap["pick_code"].(string)

				if fileIDExists && pickCodeExists {
					// Create a CallbackData from the nested data map
					cbData = &api.CallbackData{
						FileID:   fileID,
						PickCode: pickCode,
					}

					// Copy other fields if they exist
					if fileName, ok := dataMap["file_name"].(string); ok {
						cbData.FileName = fileName
					}
					if fileSize, ok := dataMap["file_size"].(string); ok {
						if size, err := strconv.ParseInt(fileSize, 10, 64); err == nil {
							cbData.FileSize = api.Int64(size)
						}
					}
					if sha1, ok := dataMap["sha1"].(string); ok {
						cbData.Sha = sha1
					}

					// Log the values for debugging
					fs.Debugf(f, "OpenAPI callback data parsed: file_id=%q, pick_code=%q", cbData.FileID, cbData.PickCode)

					// Early return if we successfully extracted data
					if cbData.FileID != "" && cbData.PickCode != "" {
						return cbData, nil
					}
				}
			}
		}
	}

	// If we couldn't extract from OpenAPI format, try traditional format
	// Need to marshal it back to JSON and then unmarshal to CallbackData for validation/typing
	callbackJSON, err := json.Marshal(callbackResult)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OSS callback result: %w", err)
	}

	cbData = &api.CallbackData{}
	if err := json.Unmarshal(callbackJSON, cbData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OSS callback result into CallbackData: %w. JSON: %s", err, string(callbackJSON))
	}

	// Basic validation
	if cbData.FileID == "" || cbData.PickCode == "" {
		// Debugging information
		fs.Debugf(f, "Callback data missing required fields: file_id=%q, pick_code=%q, raw JSON: %s",
			cbData.FileID, cbData.PickCode, string(callbackJSON))
		return nil, fmt.Errorf("OSS callback data missing required fields (file_id or pick_code). JSON: %s", string(callbackJSON))
	}

	fs.Debugf(f, "Traditional callback data parsed: file_id=%q, pick_code=%q", cbData.FileID, cbData.PickCode)
	return cbData, nil
}

// getOSSToken fetches OSS credentials using the OpenAPI.
func (f *Fs) getOSSToken(ctx context.Context) (*api.OSSToken, error) {
	opts := rest.Opts{
		Method: "GET",
		Path:   "/open/upload/get_token",
	}
	var info api.OSSTokenResp
	err := f.CallOpenAPI(ctx, &opts, nil, &info, false)
	if err != nil {
		return nil, fmt.Errorf("OpenAPI get_token failed: %w", err)
	}
	if info.Data == nil {
		return nil, errors.New("OpenAPI get_token returned no data")
	}

	if info.Data.AccessKeyID == "" || info.Data.AccessKeySecret == "" || info.Data.SecurityToken == "" {
		return nil, errors.New("OpenAPI get_token response missing essential credential fields")
	}
	return info.Data, nil
}

// newOSSClient builds an OSS client with dynamic credentials from OpenAPI.
func (f *Fs) newOSSClient() (*oss.Client, error) {
	// Use CredentialsFetcherProvider from SDK v2
	provider := credentials.NewCredentialsFetcherProvider(
		credentials.CredentialsFetcherFunc(func(ctx context.Context) (credentials.Credentials, error) {
			fs.Debugf(f, "Fetching new OSS credentials via OpenAPI...")
			t, err := f.getOSSToken(ctx)
			if err != nil {
				fs.Errorf(f, "Failed to fetch OSS token: %v", err)
				return credentials.Credentials{}, fmt.Errorf("failed to fetch OSS token: %w", err)
			}
			fs.Debugf(f, "Successfully fetched OSS credentials, expires at %v", time.Time(t.Expiration))
			return credentials.Credentials{
				AccessKeyID:     t.AccessKeyID,
				AccessKeySecret: t.AccessKeySecret,
				SecurityToken:   t.SecurityToken,
				Expires:         (*time.Time)(&t.Expiration), // Convert api.Time to *time.Time
			}, nil
		}),
	)

	// Load default config and override necessary parts
	cfg := oss.LoadDefaultConfig().
		WithCredentialsProvider(provider).
		WithRegion(OSSRegion). // Use constant region
		WithUserAgent(OSSUserAgent).
		WithUseDualStackEndpoint(f.opt.DualStack).
		WithUseInternalEndpoint(f.opt.Internal).
		WithConnectTimeout(time.Duration(f.opt.ConTimeout)). // Set timeouts
		WithReadWriteTimeout(time.Duration(f.opt.Timeout))

	// Create the client
	client := oss.NewClient(cfg)
	if client == nil {
		return nil, errors.New("failed to create OSS client")
	}
	return client, nil
}

// unWrapObjectInfo attempts to unwrap the underlying fs.Object from fs.ObjectInfo.
func unWrapObjectInfo(oi fs.ObjectInfo) fs.Object {
	if o, ok := oi.(fs.Object); ok {
		return fs.UnWrapObject(o) // Use standard unwrapper
	}
	// Handle specific wrappers like OverrideRemote if necessary
	// if do, ok := oi.(*fs.OverrideRemote); ok {
	// 	return do.UnWrap()
	// }
	return nil
}

// calcBlockSHA1 calculates SHA-1 for a specified byte range from a source reader.
// The reader `in` should ideally be seekable (e.g., buffered file).
func calcBlockSHA1(ctx context.Context, in io.Reader, src fs.ObjectInfo, rangeSpec string) (string, error) {
	var start, end int64
	// OpenAPI range is "start-end" (inclusive)
	if n, err := fmt.Sscanf(rangeSpec, "%d-%d", &start, &end); err != nil || n != 2 {
		return "", fmt.Errorf("invalid range spec format %q: %w", rangeSpec, err)
	}
	if start < 0 || end < start {
		return "", fmt.Errorf("invalid range spec values %q", rangeSpec)
	}
	length := end - start + 1

	var sectionReader io.Reader

	// Check if input is a RereadableObject first
	if ro, ok := in.(*RereadableObject); ok {
		// Try to open a new reader with robust retries for rate limiting
		var reader io.Reader // Holds the successfully opened reader
		var err error

		// Set retry parameters for reopening within calcBlockSHA1
		maxRetries := 10                       // Max retries for opening range
		initialDelay := 500 * time.Millisecond // Start with 500ms
		maxDelay := 60 * time.Second           // Max delay 1 minute
		maxElapsedTime := 5 * time.Minute      // Max total time

		// Define the reopening operation
		reopenOperation := func() error {
			var openErr error
			reader, openErr = ro.Open() // Attempt to open
			if openErr != nil {
				fs.Debugf(src, "Open attempt failed in calcBlockSHA1: %v", openErr)
			}
			return openErr // Return error for retry logic
		}

		// Retry with exponential backoff
		err = retryWithExponentialBackoff(
			ctx,
			"opening object for range SHA1",
			src, // Log against the source object info
			reopenOperation,
			maxRetries,
			initialDelay,
			maxDelay,
			maxElapsedTime,
		)

		if err != nil {
			return "", fmt.Errorf("failed to open RereadableObject reader for range SHA1 after retries: %w", err)
		}

		// If the obtained reader is an io.ReadCloser, ensure it's closed when calcBlockSHA1 finishes.
		// This does NOT close the parent RereadableObject 'ro'.
		closeReader := func() {} // No-op default
		if rc, ok := reader.(io.ReadCloser); ok {
			closeReader = func() { _ = rc.Close() }
		}
		defer closeReader() // Close the specific reader obtained for this SHA1 calc

		// Skip to the start position using the successfully opened 'reader'
		if seeker, ok := reader.(io.Seeker); ok {
			if _, err := seeker.Seek(start, io.SeekStart); err != nil {
				// Attempt to close the reader before returning error
				closeReader()
				return "", fmt.Errorf("failed to seek RereadableObject reader to %d: %w", start, err)
			}
			sectionReader = io.LimitReader(reader, length)
		} else {
			// If not seekable, try skipping bytes
			if start > 0 {
				// Use io.CopyN for skipping
				skipped, err := io.CopyN(io.Discard, reader, start)
				if err != nil {
					// Attempt to close the reader before returning error
					closeReader()
					return "", fmt.Errorf("failed to skip %d bytes in RereadableObject reader (skipped %d): %w", start, skipped, err)
				}
				if skipped != start {
					// Attempt to close the reader before returning error
					closeReader()
					return "", fmt.Errorf("failed to skip requested %d bytes in RereadableObject reader, only skipped %d", start, skipped)
				}
			}
			sectionReader = io.LimitReader(reader, length)
		}
	} else if seeker, ok := in.(io.Seeker); ok {
		// Try to create a SectionReader if the input is seekable
		// IMPORTANT: Seek back to start after reading the section
		currentOffset, seekErr := seeker.Seek(0, io.SeekCurrent)
		if seekErr != nil {
			return "", fmt.Errorf("failed to get current offset for SHA1 range: %w", seekErr)
		}
		defer func() {
			_, _ = seeker.Seek(currentOffset, io.SeekStart) // Restore original position
		}()

		// Seek to the start of the required section
		_, seekErr = seeker.Seek(start, io.SeekStart)
		if seekErr != nil {
			// Maybe the buffer doesn't contain the required range?
			return "", fmt.Errorf("failed to seek to start %d for SHA1 range: %w", start, seekErr)
		}
		sectionReader = io.LimitReader(in, length)
	} else {
		// If not seekable, we cannot reliably calculate the hash for an arbitrary range.
		// This might happen if the input is a direct network stream and hasn't been buffered.
		// Try opening the source object directly if possible.
		srcObj := unWrapObjectInfo(src)
		if srcObj != nil {
			fs.Debugf(src, "Input reader not seekable for SHA1 range, opening source object directly.")

			// Try to open with retries for rate limiting
			var rc io.ReadCloser
			var err error

			// Define maximum retries and use exponential backoff
			maxRetries := 10                       // Max retries
			initialDelay := 500 * time.Millisecond // Start delay
			maxDelay := 60 * time.Second           // Max delay
			maxElapsedTime := 5 * time.Minute      // Max total time

			// Define the operation
			openRangeOperation := func() error {
				var openErr error
				// Use RangeOption for efficiency if supported
				rc, openErr = srcObj.Open(ctx, &fs.RangeOption{Start: start, End: end})
				if openErr != nil {
					fs.Debugf(srcObj, "Open range attempt failed: %v", openErr)
				}
				return openErr
			}

			// Retry with exponential backoff
			err = retryWithExponentialBackoff(
				ctx,
				"opening source object range directly",
				srcObj,
				openRangeOperation,
				maxRetries,
				initialDelay,
				maxDelay,
				maxElapsedTime,
			)

			if err != nil {
				return "", fmt.Errorf("failed to open source object for SHA1 range %q after retries: %w", rangeSpec, err)
			}
			// Defer closing the reader obtained specifically for this operation
			defer fs.CheckClose(rc, &err)
			sectionReader = rc
		} else {
			return "", fmt.Errorf("cannot calculate SHA1 for range %q: input reader not seekable and source object unavailable", rangeSpec)
		}
	}

	// Calculate hash of the section
	hashVal := sha1.New()
	_, err := io.Copy(hashVal, sectionReader)
	if err != nil {
		return "", fmt.Errorf("failed to read data for SHA1 range %q: %w", rangeSpec, err)
	}
	return strings.ToUpper(hex.EncodeToString(hashVal.Sum(nil))), nil
}

// sampleInitUpload prepares a traditional "simple form" upload (for smaller files).
func (f *Fs) sampleInitUpload(ctx context.Context, size int64, name, dirID string) (*api.SampleInitResp, error) {
	// Try to get userID if not already set (e.g., during initial login)
	if f.userID == "" {
		// Get userID from uploadinfo API
		if err := f.getUploadBasicInfo(ctx); err != nil {
			return nil, fmt.Errorf("failed to get userID: %w", err)
		}
	}

	form := url.Values{}
	form.Set("userid", f.userID)
	form.Set("filename", f.opt.Enc.FromStandardName(name))
	form.Set("filesize", strconv.FormatInt(size, 10))
	form.Set("target", "U_1_"+dirID)

	opts := rest.Opts{
		Method:      "POST",
		RootURL:     "https://uplb.115.com/3.0/sampleinitupload.php", // Traditional endpoint
		ContentType: "application/x-www-form-urlencoded",
		Body:        strings.NewReader(form.Encode()),
	}
	var info *api.SampleInitResp
	// Use traditional API call (requires cookie, assume no encryption needed for this endpoint?)
	err := f.CallTraditionalAPI(ctx, &opts, nil, &info, true) // skipEncrypt = true
	if err != nil {
		return nil, fmt.Errorf("traditional sampleInitUpload call failed: %w", err)
	}
	if info.ErrorCode != 0 {
		return nil, fmt.Errorf("traditional sampleInitUpload API error: %s (%d)", info.Error, info.ErrorCode)
	}
	if info.Host == "" || info.Object == "" {
		return nil, errors.New("traditional sampleInitUpload response missing required fields (host or object)")
	}
	return info, nil
}

// sampleUploadForm uses multipart form to upload smaller files via traditional sample upload flow.
func (f *Fs) sampleUploadForm(ctx context.Context, in io.Reader, initResp *api.SampleInitResp, name string, size int64, options ...fs.OpenOption) (*api.CallbackData, error) {
	// Safety check for nil input
	if in == nil {
		return nil, errors.New("nil input reader provided to sampleUploadForm")
	}
	if initResp == nil {
		return nil, errors.New("nil initResp provided to sampleUploadForm")
	}

	pipeReader, pipeWriter := io.Pipe()
	multipartWriter := multipart.NewWriter(pipeWriter)
	errChan := make(chan error, 1)

	// Start goroutine to write multipart data to the pipe
	go func() {
		var err error
		defer func() {
			closeErr := multipartWriter.Close()
			if err == nil {
				err = closeErr // Assign close error if no previous error
			}
			writeCloseErr := pipeWriter.CloseWithError(err) // Close pipe with error status
			if err == nil {
				err = writeCloseErr
			}
			errChan <- err // Send final status
		}()

		// Write standard fields
		fields := map[string]string{
			"name":                  name, // Use original name for form field?
			"key":                   initResp.Object,
			"policy":                initResp.Policy,
			"OSSAccessKeyId":        initResp.AccessID,
			"success_action_status": "200", // OSS expects 200 for success
			"callback":              initResp.Callback,
			"signature":             initResp.Signature,
		}
		for k, v := range fields {
			if v == "" {
				fs.Debugf(f, "Warning: empty value for form field %q", k)
				// Continue anyway, some fields might be optional
			}
			if err = multipartWriter.WriteField(k, v); err != nil {
				err = fmt.Errorf("failed to write field %s: %w", k, err)
				return
			}
		}

		// Add optional headers from fs.OpenOption
		for _, opt := range options {
			k, v := opt.Header()
			lowerK := strings.ToLower(k)
			// Include headers supported by OSS PostObject policy/form
			if lowerK == "cache-control" || lowerK == "content-disposition" || lowerK == "content-encoding" || lowerK == "content-type" || strings.HasPrefix(lowerK, "x-oss-meta-") {
				if err = multipartWriter.WriteField(k, v); err != nil {
					err = fmt.Errorf("failed to write optional field %s: %w", k, err)
					return
				}
			}
		}

		// Write file data
		filePart, err := multipartWriter.CreateFormFile("file", f.opt.Enc.FromStandardName(name)) // Use encoded name for file part?
		if err != nil {
			err = fmt.Errorf("failed to create form file: %w", err)
			return
		}

		// Double-check in is not nil again (just being extra careful)
		if in == nil {
			err = errors.New("input reader became nil before copy in sampleUploadForm")
			return
		}

		// Copy file data
		if _, err = io.Copy(filePart, in); err != nil {
			err = fmt.Errorf("failed to copy file data to form: %w", err)
			return
		}
	}()

	// Create and send the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", initResp.Host, pipeReader)
	if err != nil {
		_ = pipeWriter.CloseWithError(err) // Ensure goroutine exits
		return nil, fmt.Errorf("failed to create sample upload request: %w", err)
	}
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	// Set Content-Length? OSS might require it for POST uploads.
	// However, with pipeReader, length is unknown beforehand. Let http client handle chunked encoding.
	// req.ContentLength = -1 // Indicate unknown length

	// Use a standard HTTP client, paced by global pacer
	var resp *http.Response
	err = f.globalPacer.Call(func() (bool, error) {
		httpClient := fshttp.NewClient(ctx)
		resp, err = httpClient.Do(req)
		if err != nil {
			retry, retryErr := shouldRetry(ctx, resp, err)
			if retry {
				return true, retryErr
			}
			return false, backoff.Permanent(fmt.Errorf("sample upload POST failed: %w", err))
		}
		return false, nil // Success
	})

	// Wait for the goroutine writing to the pipe to finish
	writeErr := <-errChan
	if err == nil { // If HTTP call succeeded, check for writer error
		err = writeErr
	}
	if err != nil {
		// If there was an error during HTTP or writing, close response body if non-nil
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, fmt.Errorf("sample upload failed: %w", err)
	}

	// Process the response
	defer fs.CheckClose(resp.Body, &err)
	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, fmt.Errorf("failed to read sample upload response body: %w", readErr)
	}

	// OSS POST upload returns 200 on success with callback body, or other status on error
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("sample upload failed: status %s, body: %s", resp.Status, string(respBody))
	}

	// Response body contains the result from the 115 callback URL
	var respMap map[string]any
	if err := json.Unmarshal(respBody, &respMap); err != nil {
		// Sometimes the body might not be JSON if callback failed internally on 115 side
		fs.Logf(f, "Failed to unmarshal sample upload callback response as JSON: %v. Body: %s", err, string(respBody))
		// Try to find essential info heuristically? Risky. Return error.
		return nil, fmt.Errorf("failed to parse sample upload callback response: %w", err)
	}

	// Process the callback map using the existing postUpload function
	return f.postUpload(respMap)
}

// ------------------------------------------------------------
// Main Upload Logic
// ------------------------------------------------------------

// tryHashUpload attempts 秒传 using OpenAPI.
// Returns (found bool, uploadInitInfo *api.UploadInitInfo, potentiallyBufferedInput io.Reader, cleanup func(), err error)
func (f *Fs) tryHashUpload(
	ctx context.Context,
	in io.Reader,
	src fs.ObjectInfo,
	o *Object,
	leaf, dirID string,
	size int64,
	options ...fs.OpenOption,
) (found bool, ui *api.UploadInitInfo, newIn io.Reader, cleanup func(), err error) {
	cleanup = func() {} // Default no-op cleanup
	newIn = in          // Assume input reader doesn't change unless buffered

	defer func() {
		if err != nil && cleanup != nil {
			cleanup() // Ensure cleanup happens on error exit
		}
	}()

	fs.Debugf(o, "Attempting hash upload (秒传) via OpenAPI...")

	// 1. Get SHA1 hash
	hashStr, err := src.Hash(ctx, hash.SHA1)
	if err != nil || hashStr == "" {
		fs.Debugf(o, "Source SHA1 not available, calculating locally...")
		var localCleanup func()
		// Buffer the input while calculating hash
		hashStr, newIn, localCleanup, err = bufferIOwithSHA1(f, in, src, size, int64(f.opt.HashMemoryThreshold), ctx, options...)
		cleanup = localCleanup // Assign the cleanup function from bufferIO
		if err != nil {
			return false, nil, newIn, cleanup, fmt.Errorf("failed to calculate SHA1: %w", err)
		}
		fs.Debugf(o, "Calculated SHA1: %s", hashStr)
	} else {
		fs.Debugf(o, "Using provided SHA1: %s", hashStr)

		// If NoBuffer is enabled, wrap the input in a RereadableObject
		if f.opt.NoBuffer {
			// Create a rereadable source
			ro, roErr := NewRereadableObject(ctx, src, options...)
			if roErr != nil {
				// Continue with original reader if failed
				fs.Debugf(o, "Failed to create rereadable object: %v", roErr)
			} else {
				newIn = ro
				cleanup = func() { _ = ro.Close() }
			}
		}
	}
	o.sha1sum = strings.ToLower(hashStr) // Store hash in object

	// 2. Call OpenAPI initUpload with SHA1
	// We don't have preid (128k SHA1) easily available here, skip it for now.
	ui, err = f.initUploadOpenAPI(ctx, size, leaf, dirID, hashStr, "", "", "", "")
	if err != nil {
		return false, nil, newIn, cleanup, fmt.Errorf("OpenAPI initUpload for hash check failed: %w", err)
	}

	// 3. Handle response status
	signKey, signVal := "", ""
	for {
		status := ui.GetStatus()
		switch status {
		case 2: // 秒传 success!
			fs.Debugf(o, "Hash upload (秒传) successful.")
			// Mark accounting as server-side copy
			reader, _ := accounting.UnWrap(newIn)
			if acc, ok := reader.(*accounting.Account); ok && acc != nil {
				acc.ServerSideTransferStart() // Mark start
				acc.ServerSideCopyEnd(size)   // Mark end immediately
			}
			// Update object metadata from response (FileID is important)
			o.id = ui.GetFileID()
			o.pickCode = ui.GetPickCode() // Get pick code too
			o.hasMetaData = true          // Mark as having basic metadata

			// Mark complete on RereadableObject if applicable
			if ro, ok := newIn.(*RereadableObject); ok {
				ro.MarkComplete(ctx)
				fs.Debugf(o, "Marked RereadableObject transfer as complete after hash upload")
			}

			// Optionally, call getFile to get full metadata, but might be slow/costly
			// info, getErr := f.getFile(ctx, o.id, "")
			// if getErr == nil { o.setMetaData(info) }
			return true, ui, newIn, cleanup, nil // Found = true

		case 1: // Non-秒传, need actual upload
			fs.Debugf(o, "Hash upload (秒传) not available (status 1). Proceeding with normal upload.")
			return false, ui, newIn, cleanup, nil // Found = false

		case 7: // Need secondary auth (sign_check)
			fs.Debugf(o, "Hash upload requires secondary auth (status 7). Calculating range SHA1...")
			signKey = ui.GetSignKey()
			signCheckRange := ui.GetSignCheck()
			if signKey == "" || signCheckRange == "" {
				return false, nil, newIn, cleanup, errors.New("hash upload status 7 but sign_key or sign_check missing")
			}
			// Calculate SHA1 for the specified range
			signVal, err = calcBlockSHA1(ctx, newIn, src, signCheckRange)
			if err != nil {
				return false, nil, newIn, cleanup, fmt.Errorf("failed to calculate SHA1 for range %q: %w", signCheckRange, err)
			}
			fs.Debugf(o, "Calculated range SHA1: %s for range %s", signVal, signCheckRange)

			// Retry initUpload with sign_key and sign_val with exponential backoff for network errors
			var retryErr error
			// Define retry parameters
			maxRetries := 12
			initialDelay := 1 * time.Second
			maxDelay := 60 * time.Second
			maxElapsedTime := 10 * time.Minute

			// Define the operation to be retried
			initUploadOperation := func() error {
				var initErr error
				ui, initErr = f.initUploadOpenAPI(ctx, size, leaf, dirID, hashStr, "", "", signKey, signVal)
				return initErr
			}

			// Execute with exponential backoff
			retryErr = retryWithExponentialBackoff(
				ctx,
				"OpenAPI initUpload with signature",
				o,
				initUploadOperation,
				maxRetries,
				initialDelay,
				maxDelay,
				maxElapsedTime,
			)

			if retryErr != nil {
				return false, nil, newIn, cleanup, fmt.Errorf("OpenAPI initUpload retry with signature failed after multiple attempts: %w", retryErr)
			}
			continue // Re-evaluate the new status

		case 6, 8: // Other auth-related statuses? Treat as failure for now.
			fs.Errorf(o, "Hash upload failed with unexpected auth status %d. Message: %s", status, ui.ErrMsg())
			return false, nil, newIn, cleanup, fmt.Errorf("hash upload failed with status %d: %s", status, ui.ErrMsg())

		default: // Unexpected status
			fs.Errorf(o, "Hash upload failed with unexpected status %d. Message: %s", status, ui.ErrMsg())
			return false, nil, newIn, cleanup, fmt.Errorf("unexpected hash upload status %d: %s", status, ui.ErrMsg())
		}
	}
}

// uploadToOSS performs the actual upload to OSS using multipart via OpenAPI info.
func (f *Fs) uploadToOSS(
	ctx context.Context,
	in io.Reader,
	src fs.ObjectInfo,
	o *Object,
	leaf, dirID string,
	size int64,
	ui *api.UploadInitInfo, // Pre-fetched info (e.g., from failed hash upload)
	options ...fs.OpenOption,
) (fs.Object, error) {
	fs.Debugf(o, "Starting OSS multipart upload...")

	// Initialize upload and get upload info if not provided
	uploadInfo, err := f.getUploadInfo(ctx, ui, leaf, dirID, size, o)
	if err != nil {
		return nil, err
	}
	// Handle case where initUpload resulted in instant upload
	if ui.GetStatus() == 2 {
		return o, nil
	}

	// Create OSS client
	ossClient, err := f.newOSSClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create OSS client: %w", err)
	}

	// Configure and perform the upload
	callbackData, err := f.performOSSUpload(ctx, ossClient, in, src, o, size, uploadInfo, options...)
	if err != nil {
		return nil, err
	}

	// Update object metadata
	if err = o.setMetaDataFromCallBack(callbackData); err != nil {
		return nil, fmt.Errorf("failed to set metadata from callback: %w", err)
	}

	// 7. Mark complete on RereadableObject if applicable
	if ro, ok := in.(*RereadableObject); ok {
		ro.MarkComplete(ctx)
		fs.Debugf(o, "Marked RereadableObject transfer as complete")
	}

	fs.Debugf(o, "OSS multipart upload successful.")
	return o, nil
}

// getUploadInfo gets or validates upload information
func (f *Fs) getUploadInfo(
	ctx context.Context,
	ui *api.UploadInitInfo,
	leaf, dirID string,
	size int64,
	o *Object,
) (*api.UploadInitInfo, error) {
	// If upload info is already provided, use it
	if ui != nil {
		return ui, nil
	}

	// Initialize upload without SHA1
	ui, err := f.initUploadOpenAPI(ctx, size, leaf, dirID, "", "", "", "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize multipart upload: %w", err)
	}

	// Handle unexpected status
	if ui.GetStatus() != 1 {
		if ui.GetStatus() == 2 { // Instant upload success (秒传)
			fs.Logf(o, "Warning: initUpload without hash resulted in 秒传 (status 2), handling...")
			o.id = ui.GetFileID()
			o.pickCode = ui.GetPickCode()
			o.hasMetaData = true
		} else {
			return nil, fmt.Errorf("expected status 1 from initUpload for multipart, got %d: %s", ui.GetStatus(), ui.ErrMsg())
		}
	}

	return ui, nil
}

// performOSSUpload handles the actual upload process
func (f *Fs) performOSSUpload(
	ctx context.Context,
	client *oss.Client,
	in io.Reader,
	src fs.ObjectInfo,
	o *Object,
	size int64,
	ui *api.UploadInitInfo,
	options ...fs.OpenOption,
) (*api.CallbackData, error) {
	// Create the chunk writer
	chunkWriter, err := f.newChunkWriter(ctx, src, ui, in, o, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create chunk writer: %w", err)
	}

	// Perform the upload
	if err := chunkWriter.Upload(ctx); err != nil {
		return nil, fmt.Errorf("OSS multipart upload failed: %w", err)
	}

	// Process upload callback
	callbackData, err := f.postUpload(chunkWriter.callbackRes)
	if err != nil {
		return nil, fmt.Errorf("failed to process OSS upload callback: %w", err)
	}

	// Mark complete on RereadableObject if applicable
	if ro, ok := in.(*RereadableObject); ok {
		ro.MarkComplete(ctx)
		fs.Debugf(o, "Marked RereadableObject transfer as complete")
	}

	return callbackData, nil
}

// doSampleUpload performs the traditional streamed upload.
func (f *Fs) doSampleUpload(
	ctx context.Context,
	in io.Reader,
	o *Object,
	leaf, dirID string,
	size int64,
	options ...fs.OpenOption,
) (fs.Object, error) {
	fs.Debugf(o, "Starting traditional sample upload for size=%d", size)
	// 1. Initialize sample upload (traditional API)
	initResp, err := f.sampleInitUpload(ctx, size, leaf, dirID)
	if err != nil {
		return nil, fmt.Errorf("traditional sampleInitUpload failed: %w", err)
	}

	// 2. Perform the form upload
	callbackData, err := f.sampleUploadForm(ctx, in, initResp, leaf, size, options...)
	if err != nil {
		return nil, fmt.Errorf("traditional sampleUploadForm failed: %w", err)
	}

	// 3. Update object metadata from callback
	err = o.setMetaDataFromCallBack(callbackData)
	if err != nil {
		return nil, fmt.Errorf("failed to set metadata from sample upload callback: %w", err)
	}

	// 4. Mark complete on RereadableObject if applicable
	if ro, ok := in.(*RereadableObject); ok {
		ro.MarkComplete(ctx)
		fs.Debugf(o, "Marked RereadableObject transfer as complete after sample upload")
	}

	fs.Debugf(o, "Traditional sample upload successful.")
	return o, nil
}

// upload is the main entry point that decides which upload strategy to use.
func (f *Fs) upload(ctx context.Context, in io.Reader, src fs.ObjectInfo, remote string, options ...fs.OpenOption) (fs.Object, error) {
	if f.isShare {
		return nil, errors.New("upload unsupported for shared filesystem")
	}

	// Start the token renewer if we have a valid one
	if f.tokenRenewer != nil {
		f.tokenRenewer.Start()
		defer f.tokenRenewer.Stop()
	}

	size := src.Size()

	// If NoBuffer option is enabled, try to wrap the input in a RereadableObject early
	if f.opt.NoBuffer && size >= 0 {
		fs.Debugf(src, "Using no_buffer option: file will be read multiple times instead of buffered to disk")
		if _, ok := in.(*RereadableObject); !ok {
			// Create a rereadable wrapper if not already wrapped
			ro, roErr := NewRereadableObject(ctx, src, options...)
			if roErr != nil {
				// Log but continue with original reader
				fs.Logf(src, "Warning: Failed to create rereadable source: %v - will attempt to continue with original reader", roErr)
			} else {
				in = ro
			}
		}
	}

	// Check size limits
	if size > int64(maxUploadSize) {
		return nil, fmt.Errorf("file size %v exceeds upload limit %v", fs.SizeSuffix(size), fs.SizeSuffix(maxUploadSize))
	}
	if size < 0 {
		// Streaming upload with unknown size - check if allowed
		if f.opt.OnlyStream {
			fs.Logf(src, "Streaming upload with unknown size using traditional sample upload (limit %v)", fs.SizeSuffix(StreamUploadLimit))
			// Proceed with sample upload, it might fail if size > limit
		} else if f.opt.FastUpload {
			fs.Logf(src, "Streaming upload with unknown size using traditional sample upload (limit %v) due to fast_upload", fs.SizeSuffix(StreamUploadLimit))
			// Proceed with sample upload
		} else {
			// Default behavior: Use OSS multipart for unknown size
			fs.Logf(src, "Streaming upload with unknown size using OSS multipart upload")
			// Proceed with OSS multipart
		}
		// Note: Hash upload is not possible for unknown size.
	}

	// Create placeholder object and ensure parent directory exists
	o, leaf, dirID, err := f.createObject(ctx, remote, src.ModTime(ctx), size)
	if err != nil {
		return nil, fmt.Errorf("failed to create object placeholder: %w", err)
	}

	// Defer cleanup for any temporary buffers created
	var cleanup func()
	defer func() {
		if cleanup != nil {
			cleanup()
		}
	}()

	// --- Upload Strategy Logic ---

	// 1. OnlyStream flag
	if f.opt.OnlyStream {
		if size < 0 || size <= int64(StreamUploadLimit) {
			return f.doSampleUpload(ctx, in, o, leaf, dirID, size, options...)
		}
		return nil, fserrors.NoRetryError(fmt.Errorf("only_stream is enabled but file size %v exceeds stream upload limit %v", fs.SizeSuffix(size), fs.SizeSuffix(StreamUploadLimit)))
	}

	// 2. FastUpload flag
	if f.opt.FastUpload {
		noHashSize := int64(f.opt.NohashSize)
		streamLimit := int64(StreamUploadLimit)

		if size >= 0 && size <= noHashSize {
			// Small file: Use sample upload directly
			return f.doSampleUpload(ctx, in, o, leaf, dirID, size, options...)
		}

		// Larger file or unknown size: Try hash upload first
		var gotIt bool
		var ui *api.UploadInitInfo
		var newIn io.Reader = in // Assume input doesn't change initially

		if size >= 0 { // Hash upload only possible for known size
			var localCleanup func()
			gotIt, ui, newIn, localCleanup, err = f.tryHashUpload(ctx, in, src, o, leaf, dirID, size, options...)
			cleanup = localCleanup // Assign cleanup function
			if err != nil {
				// Log hash upload error but fallback based on size
				fs.Logf(o, "FastUpload: Hash upload failed, falling back: %v", err)
				// Reset gotIt, ui, and newIn to ensure fallback happens correctly
				// with the original reader since bufferIO may have failed
				gotIt = false
				ui = nil

				// If no_buffer is not enabled, revert to original input
				if !f.opt.NoBuffer {
					newIn = in // Important: revert to original input if hash calculation failed
					if cleanup != nil {
						cleanup()     // Clean up any partial buffers
						cleanup = nil // Mark as cleaned up
					}
				} else {
					// With no_buffer, we need to explicitly reopen the RereadableObject
					// to ensure we're at the beginning of the stream for the next upload attempt
					if ro, ok := newIn.(*RereadableObject); ok {
						fs.Debugf(o, "Reopening RereadableObject after failed hash calculation")
						reopenedReader, reopenErr := ro.Open()
						if reopenErr != nil {
							return nil, fmt.Errorf("failed to reopen source after hash upload failure: %w", reopenErr)
						}
						// IMPORTANT: Actually use the returned reader instead of assuming internal state is reset
						newIn = reopenedReader
						fs.Debugf(o, "Successfully reopened RereadableObject for upload attempt")
					} else {
						// If not a RereadableObject, fall back to original input as a last resort
						fs.Logf(o, "Warning: Expected RereadableObject in no_buffer mode but got %T, reverting to original input", newIn)
						newIn = in
					}
				}
			}
			if gotIt {
				return o, nil // Hash upload successful
			}
		} else {
			fs.Debugf(o, "FastUpload: Skipping hash upload for unknown size.")
		}

		// Hash upload failed or skipped: Fallback based on size
		if size < 0 || size <= streamLimit {
			// Use sample upload if within limit or size unknown
			return f.doSampleUpload(ctx, newIn, o, leaf, dirID, size, options...)
		}
		// Size > streamLimit: Use OSS multipart
		return f.uploadToOSS(ctx, newIn, src, o, leaf, dirID, size, ui, options...) // Pass ui in case init was already done
	}

	// 3. UploadHashOnly flag
	if f.opt.UploadHashOnly {
		if size < 0 {
			return nil, fserrors.NoRetryError(errors.New("upload_hash_only requires known file size"))
		}
		gotIt, _, _, localCleanup, err := f.tryHashUpload(ctx, in, src, o, leaf, dirID, size, options...)
		// Handle cleanup of any temporary resources
		if localCleanup != nil {
			defer localCleanup()
		}
		if err != nil {
			return nil, fmt.Errorf("upload_hash_only: hash upload attempt failed: %w", err)
		}
		if gotIt {
			return o, nil // Success
		}
		// Hash upload didn't find the file on server
		return nil, fserrors.NoRetryError(errors.New("upload_hash_only: file not found on server via hash check, skipping upload"))
	}

	// 4. Default (Normal) Logic
	noHashSize := int64(f.opt.NohashSize)
	uploadCutoff := int64(f.opt.UploadCutoff)

	if size >= 0 && size < noHashSize {
		// Small known size: Use sample upload
		return f.doSampleUpload(ctx, in, o, leaf, dirID, size, options...)
	}

	// Known size >= noHashSize OR unknown size: Try hash upload first (if size known)
	var gotIt bool
	var ui *api.UploadInitInfo
	var newIn io.Reader = in

	if size >= 0 {
		var localCleanup func()
		gotIt, ui, newIn, localCleanup, err = f.tryHashUpload(ctx, in, src, o, leaf, dirID, size, options...)
		cleanup = localCleanup
		if err != nil {
			fs.Logf(o, "Normal Upload: Hash upload failed, falling back to OSS/Sample: %v", err)
			// Reset gotIt, ui, and newIn for fallback
			gotIt = false
			ui = nil

			// If no_buffer is not enabled, revert to original input
			if !f.opt.NoBuffer {
				newIn = in // Important: revert to original input if hash calculation failed
				if cleanup != nil {
					cleanup()     // Clean up any partial buffers
					cleanup = nil // Mark as cleaned up
				}
			} else {
				// With no_buffer, we need to explicitly reopen the RereadableObject
				// to ensure we're at the beginning of the stream for the next upload attempt
				if ro, ok := newIn.(*RereadableObject); ok {
					fs.Debugf(o, "Reopening RereadableObject after failed hash calculation")
					reopenedReader, reopenErr := ro.Open()
					if reopenErr != nil {
						return nil, fmt.Errorf("failed to reopen source after hash upload failure: %w", reopenErr)
					}
					// IMPORTANT: Actually use the returned reader instead of assuming internal state is reset
					newIn = reopenedReader
					fs.Debugf(o, "Successfully reopened RereadableObject for upload attempt")
				} else {
					// If not a RereadableObject, fall back to original input as a last resort
					fs.Logf(o, "Warning: Expected RereadableObject in no_buffer mode but got %T, reverting to original input", newIn)
					newIn = in
				}
			}
		}
		if gotIt {
			return o, nil // Hash upload successful
		}
	} else {
		fs.Debugf(o, "Normal Upload: Skipping hash upload for unknown size.")
	}

	// Hash upload failed or skipped: Decide between Sample and OSS Multipart
	// Note: OpenAPI doesn't support traditional sample upload.
	// If hash upload failed, we *must* use OSS multipart upload via OpenAPI.
	// The only time sample upload is used now is with OnlyStream or FastUpload flags for small files.
	// Therefore, the default path always leads to OSS multipart here.

	// Check against UploadCutoff to decide multipart (though logic above mostly covers this)
	if size < 0 || size >= uploadCutoff {
		// Use OSS multipart
		return f.uploadToOSS(ctx, newIn, src, o, leaf, dirID, size, ui, options...) // Pass ui if available
	}

	// Size is known, >= noHashSize, and < uploadCutoff
	// This case implies hash upload failed, and we should use OSS multipart (PutObject)
	// because sample upload is traditional only.
	fs.Debugf(o, "Normal Upload: Using OSS PutObject (single part) for size %v", fs.SizeSuffix(size))
	// Need a function similar to uploadToOSS but using PutObject instead of multipart.
	// Let's adapt uploadToOSS slightly or create a helper.
	// For simplicity, let uploadToOSS handle the PutObject case internally based on size < cutoff.
	// We need to modify uploadToOSS or multipart.go to handle this.
	// Let's assume uploadToOSS handles it for now. Revisit if multipart.go doesn't.
	// *** Correction: The current multipart.go doesn't handle single PutObject. ***
	// We need to implement the PutObject path here.

	// --- OSS PutObject Implementation ---
	fs.Debugf(o, "Executing OSS PutObject...")
	// 1. Get UploadInitInfo if not already available (from failed hash check)
	if ui == nil {
		var initErr error
		ui, initErr = f.initUploadOpenAPI(ctx, size, leaf, dirID, o.sha1sum, "", "", "", "") // Provide hash if known
		if initErr != nil {
			return nil, fmt.Errorf("failed to initialize PutObject upload: %w", initErr)
		}
		if ui.GetStatus() != 1 { // Should be 1 if hash upload failed/skipped
			if ui.GetStatus() == 2 { // Unexpected 秒传
				fs.Logf(o, "Warning: initUpload for PutObject resulted in 秒传 (status 2), handling...")
				o.id = ui.GetFileID()
				o.pickCode = ui.GetPickCode()
				o.hasMetaData = true
				return o, nil
			}
			return nil, fmt.Errorf("expected status 1 from initUpload for PutObject, got %d: %s", ui.GetStatus(), ui.ErrMsg())
		}
	}

	// 2. Create OSS client
	ossClient, err := f.newOSSClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create OSS client for PutObject: %w", err)
	}

	// 3. Prepare PutObject request
	req := &oss.PutObjectRequest{
		Bucket:      oss.Ptr(ui.GetBucket()),
		Key:         oss.Ptr(ui.GetObject()),
		Body:        newIn, // Use potentially buffered reader
		Callback:    oss.Ptr(ui.GetCallback()),
		CallbackVar: oss.Ptr(ui.GetCallbackVar()),
	}
	// Apply headers from options
	for _, option := range options {
		key, value := option.Header()
		lowerKey := strings.ToLower(key)
		switch lowerKey {
		case "cache-control":
			req.CacheControl = oss.Ptr(value)
		case "content-disposition":
			req.ContentDisposition = oss.Ptr(value)
		case "content-encoding":
			req.ContentEncoding = oss.Ptr(value)
		case "content-type":
			req.ContentType = oss.Ptr(value)
		}
	}

	// 4. Execute PutObject with retry via pacer
	var putRes *oss.PutObjectResult
	err = f.globalPacer.Call(func() (bool, error) {
		var putErr error
		putRes, putErr = ossClient.PutObject(ctx, req)
		retry, retryErr := shouldRetry(ctx, nil, putErr)
		if retry {
			// Rewind body if possible before retry
			if seeker, ok := newIn.(io.Seeker); ok {
				_, _ = seeker.Seek(0, io.SeekStart)
			} else {
				// Cannot retry non-seekable stream after partial read
				return false, backoff.Permanent(fmt.Errorf("cannot retry PutObject with non-seekable stream: %w", putErr))
			}
			return true, retryErr
		}
		if putErr != nil {
			return false, backoff.Permanent(putErr)
		}
		return false, nil // Success
	})
	if err != nil {
		return nil, fmt.Errorf("OSS PutObject failed: %w", err)
	}

	// 5. Process callback
	callbackData, err := f.postUpload(putRes.CallbackResult)
	if err != nil {
		return nil, fmt.Errorf("failed to process PutObject callback: %w", err)
	}

	// 6. Update metadata
	err = o.setMetaDataFromCallBack(callbackData)
	if err != nil {
		return nil, fmt.Errorf("failed to set metadata from PutObject callback: %w", err)
	}

	// 7. Mark complete on RereadableObject if applicable
	if ro, ok := newIn.(*RereadableObject); ok {
		ro.MarkComplete(ctx)
		fs.Debugf(o, "Marked RereadableObject transfer as complete after PutObject upload")
	}

	fs.Debugf(o, "OSS PutObject successful.")
	return o, nil
}
