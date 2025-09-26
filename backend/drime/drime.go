// Package drime provides an interface to the Drime cloud storage system.
package drime

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rclone/rclone/backend/drime/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/rest"
)

const (
	minSleep       = 10 * time.Millisecond
	maxSleep       = 2 * time.Second
	decayConstant  = 2 // bigger for slower decay, exponential
	defaultAPIPath = "/api/v1"
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "drime",
		Description: "Drime cloud storage",
		NewFs:       NewFs,
		Config: func(ctx context.Context, name string, m configmap.Mapper, config fs.ConfigIn) (*fs.ConfigOut, error) {
			return nil, nil
		},
		Options: []fs.Option{{
			Name:     "username",
			Help:     "Username for Drime account",
			Required: true,
		}, {
			Name:       "password",
			Help:       "Password for Drime account",
			IsPassword: true,
			Required:   true,
		}, {
			Name:     "token",
			Help:     "Access token for Drime API",
			Required: true,
		}, {
			Name:    "base_url",
			Help:    "Base URL for Drime API",
			Default: "https://app.drime.cloud",
		}},
	})
}

// Options defines the configuration for this backend
type Options struct {
	Username string `config:"username"`
	Password string `config:"password"`
	Token    string `config:"token"`
	BaseURL  string `config:"base_url"`
}

// Fs represents a remote drime
type Fs struct {
	name     string       // name of this remote
	root     string       // the path we are working on
	opt      *Options     // parsed options
	features *fs.Features // optional features
	srv      *rest.Client // the connection to the server
	pacer    *fs.Pacer    // pacer for API calls
}

// Object describes a drime object
type Object struct {
	fs          *Fs       // what this object is part of
	remote      string    // The remote path
	hasMetaData bool      // whether info below has been set
	size        int64     // size of the object
	modTime     time.Time // modification time of the object
	id          int       // ID of the object
	hash        string    // hash of the object
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return fmt.Sprintf("drime root '%s'", f.root)
}

// Precision return the precision of this Fs
func (f *Fs) Precision() time.Duration {
	return time.Second
}

// Hashes returns the supported hash sets.
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.MD5)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// retryErrorCodes is a slice of error codes that we will retry
var retryErrorCodes = []int{
	429, // Too Many Requests
	500, // Internal Server Error
	502, // Bad Gateway
	503, // Service Unavailable
	504, // Gateway Timeout
	509, // Bandwidth Limit Exceeded
}

// shouldRetry returns a boolean as to whether this resp and err
// deserve to be retried.  It returns the err as a convenience
func shouldRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}
	return fserrors.ShouldRetry(err) || fserrors.ShouldRetryHTTP(resp, retryErrorCodes), err
}



// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	root = strings.Trim(root, "/")

	// Create a new pacer
	pcer := fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant)))

	// Create the REST client with redirect support
	httpClient := fshttp.NewClient(ctx)
	httpClient = rest.ClientWithAuthRedirects(httpClient)
	client := rest.NewClient(httpClient).SetRoot(opt.BaseURL + defaultAPIPath)

	// Set browser-like headers to bypass Cloudflare bot detection
	client.SetHeader("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	client.SetHeader("Accept", "application/json, text/plain, */*")
	client.SetHeader("Accept-Language", "en-US,en;q=0.9")
	client.SetHeader("DNT", "1")
	client.SetHeader("Connection", "keep-alive")
	client.SetHeader("Sec-Fetch-Dest", "empty")
	client.SetHeader("Sec-Fetch-Mode", "cors")
	client.SetHeader("Sec-Fetch-Site", "same-origin")

	// Set authorization header
	client.SetHeader("Authorization", "Bearer "+opt.Token)

	f := &Fs{
		name:  name,
		root:  root,
		opt:   opt,
		srv:   client,
		pacer: pcer,
	}
	f.features = (&fs.Features{
		CaseInsensitive:         false,
		DuplicateFiles:          false,
		ReadMimeType:            true,
		WriteMimeType:           true,
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f)

	// Test the connection by making a simple API call
	_, err = f.testConnection(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Drime API: %w", err)
	}

	// Check if root points to a file
	if root != "" {
		// Try to find the file by checking if the root path is a file
		_, err := f.NewObject(ctx, "")
		if err == nil {
			// Root points to a file, adjust the root to parent directory
			newRoot := ""
			if idx := strings.LastIndex(root, "/"); idx >= 0 {
				newRoot = root[:idx]
			}
			f.root = newRoot
			return f, fs.ErrorIsFile
		}
		// If error is not "object not found", it might be a directory or other issue
		// Continue with normal directory handling
	}

	return f, nil
}

// testConnection tests the connection to the API
func (f *Fs) testConnection(ctx context.Context) (bool, error) {
	// Use HEAD request to uploads endpoint since we know it works
	opts := rest.Opts{
		Method: "HEAD",
		Path:   "/uploads",
	}

	err := f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.Call(ctx, &opts)
		// Accept 200, 405 (Method Not Allowed), or other non-auth errors as success
		if resp != nil && (resp.StatusCode == 200 || resp.StatusCode == 405 || resp.StatusCode == 404) {
			return false, nil // Success - don't retry
		}
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return false, fmt.Errorf("connection test failed: %w", err)
	}

	return true, nil
}

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	// For root directory, only show items with ParentID == nil
	// For subdirectories, we need to find the parent ID first
	var targetParentID *int
	var targetFolderName string

	if dir == "" && f.root == "" {
		// True root directory - show items with no parent
		targetParentID = nil
	} else if dir == "" && f.root != "" {
		// Check if f.root is a file instead of a folder
		// Try to find it as a file first
		obj, err := f.NewObject(ctx, "")
		if err == nil {
			// It's a file, not a folder - create a new object with the correct remote path
			fileObj := &Object{
				fs:          f,
				remote:      f.root,
				hasMetaData: obj.(*Object).hasMetaData,
				size:        obj.(*Object).size,
				modTime:     obj.(*Object).modTime,
				id:          obj.(*Object).id,
				hash:        obj.(*Object).hash,
			}
			return []fs.DirEntry{fileObj}, nil
		}

		// It's not a file, so treat it as a folder
		targetFolderName = f.root
	} else {
		// Listing a subdirectory within the filesystem root
		targetFolderName = dir
	}

	// If we need to find a folder by name, do the lookup
	if targetFolderName != "" {
		folderID, err := f.findFolderByName(ctx, targetFolderName)
		if err != nil {
			return nil, fmt.Errorf("directory %q not found: %w", targetFolderName, err)
		}
		targetParentID = folderID
	}

	err = f.listAll(ctx, dir, targetParentID, func(item *api.FileEntry) bool {
		// Validate item
		if item.Name == "" {
			return true
		}

		// For root directory listing (when targetParentID is nil), filter out items that have a parent
		// This is needed because the API without parentIds parameter returns all items
		if targetParentID == nil && item.ParentID != nil {
			return true
		}

		// Construct the remote path
		remote := item.Name

		if item.Type == "folder" {
			var modTime time.Time
			if item.UpdatedAt != "" {
				if t, err := time.Parse(time.RFC3339, item.UpdatedAt); err == nil {
					modTime = t
				}
			}
			d := fs.NewDir(remote, modTime)
			entries = append(entries, d)
		} else {
			o, err := f.newObjectWithInfo(ctx, remote, item)
			if err != nil {
				return true
			}
			entries = append(entries, o)
		}
		return true
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list directory %q: %w", dir, err)
	}

	return entries, nil
}

// listAll lists the objects into the function supplied
func (f *Fs) listAll(ctx context.Context, dirPath string, parentID *int, fn func(*api.FileEntry) bool) error {
	// Use the correct API endpoint with parentIds parameter
	opts := rest.Opts{
		Method: "GET",
		Path:   "/drive/file-entries",
		Parameters: url.Values{
			"perPage": {"1000"},
		},
	}

	// Add parentIds parameter if we have a specific parent ID
	if parentID != nil {
		opts.Parameters.Set("parentIds", fmt.Sprintf("%d", *parentID))
	}

	var result api.ListResponse
	err := f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.CallJSON(ctx, &opts, nil, &result)
		return shouldRetry(ctx, resp, err)
	})

	// If we get a permission error, try with workspaceId=0
	if err != nil && strings.Contains(err.Error(), "403") {
		opts.Parameters.Set("workspaceId", "0")

		err = f.pacer.Call(func() (bool, error) {
			resp, err := f.srv.CallJSON(ctx, &opts, nil, &result)
			return shouldRetry(ctx, resp, err)
		})
	}

	if err != nil {
		return fmt.Errorf("couldn't list files: %w", err)
	}

	// Handle pagination if there are more results
	for _, item := range result.Data {
		if item == nil {
			continue
		}

		if !fn(item) {
			break
		}
	}

	// Handle pagination if there are more pages
	currentPage := result.CurrentPage
	lastPage := result.LastPage

	if currentPage < lastPage {
		for page := currentPage + 1; page <= lastPage; page++ {
			opts.Parameters.Set("page", strconv.Itoa(page))

			var pageResult api.ListResponse
			err := f.pacer.Call(func() (bool, error) {
				resp, err := f.srv.CallJSON(ctx, &opts, nil, &pageResult)
				return shouldRetry(ctx, resp, err)
			})
			if err != nil {
				return fmt.Errorf("couldn't list files on page %d: %w", page, err)
			}

			for _, item := range pageResult.Data {
				if item == nil {
					continue
				}

				if !fn(item) {
					goto done
				}
			}
		}
	}

done:
	return nil
}

// NewObject finds the Object at remote.  If it can't be found
// it returns the error fs.ErrorObjectNotFound.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	return f.newObjectWithInfo(ctx, remote, nil)
}

// newObjectWithInfo creates a new Object with the given remote and info
func (f *Fs) newObjectWithInfo(ctx context.Context, remote string, info *api.FileEntry) (fs.Object, error) {
	// Allow empty remote when the filesystem root is set (e.g., drime:/file.txt)
	if remote == "" && f.root == "" {
		return nil, fmt.Errorf("remote path cannot be empty")
	}

	o := &Object{
		fs:     f,
		remote: remote,
	}

	var err error
	if info != nil {
		err = o.setMetaData(info)
		if err != nil {
			return nil, fmt.Errorf("failed to set metadata for %q: %w", remote, err)
		}
	} else {
		err = o.readMetaData(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read metadata for %q: %w", remote, err)
		}
	}

	return o, nil
}

// setMetaData sets the metadata from info
func (o *Object) setMetaData(info *api.FileEntry) error {
	o.hasMetaData = true
	o.size = info.FileSize
	o.id = info.ID
	o.hash = info.FileHash
	if info.UpdatedAt != "" {
		modTime, err := time.Parse(time.RFC3339, info.UpdatedAt)
		if err == nil {
			o.modTime = modTime
		}
	}
	return nil
}

// readMetaData gets the metadata if it hasn't already been fetched
func (o *Object) readMetaData(ctx context.Context) error {
	if o.hasMetaData {
		return nil
	}

	// Search for the file by listing all files and finding the one with matching name
	// We need to determine the parent directory and file name
	var parentID *int
	var fileName string

	// Determine the actual file name and parent directory
	if o.fs.root != "" && o.remote == "" {
		// This happens when the filesystem root is the file itself (e.g., drime:/xx.jpg)
		// In this case, we're looking for a file named o.fs.root in the true root directory
		fileName = o.fs.root
		parentID = nil // Search in true root directory
	} else if o.fs.root != "" {
		// The filesystem has a root directory set, and we have a relative path
		folderID, err := o.fs.findFolderByName(ctx, o.fs.root)
		if err != nil {
			return fs.ErrorObjectNotFound
		}
		parentID = folderID
		fileName = o.remote
	} else {
		// No filesystem root set, parse the remote path
		fileName = o.remote
		// Check if the remote contains a path separator
		if strings.Contains(o.remote, "/") {
			parts := strings.Split(o.remote, "/")
			if len(parts) >= 2 {
				folderName := parts[0]
				fileName = parts[len(parts)-1]

				folderID, err := o.fs.findFolderByName(ctx, folderName)
				if err != nil {
					return fs.ErrorObjectNotFound
				}
				parentID = folderID
			}
		}
		// If no path separator, search in root (parentID remains nil)
	}

	// Search for the file using the listAll function
	var found bool
	err := o.fs.listAll(ctx, "", parentID, func(item *api.FileEntry) bool {
		if item.Name == fileName && item.Type != "folder" {
			err := o.setMetaData(item)
			if err != nil {
				return false
			}
			found = true
			return false // Stop searching
		}
		return true // Continue searching
	})

	if err != nil {
		return fmt.Errorf("failed to search for file %q: %w", fileName, err)
	}

	if !found {
		return fs.ErrorObjectNotFound
	}

	return nil
}

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Return a string version
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

// Hash returns the MD5 of an object returning a lowercase hex string
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	if t != hash.MD5 {
		return "", hash.ErrUnsupported
	}
	return o.hash, nil
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	err := o.readMetaData(context.TODO())
	if err != nil {
		fs.Logf(o, "Failed to read metadata: %v", err)
		return 0
	}
	return o.size
}

// ModTime returns the modification time of the object
func (o *Object) ModTime(ctx context.Context) time.Time {
	err := o.readMetaData(ctx)
	if err != nil {
		fs.Logf(o, "Failed to read metadata: %v", err)
		return time.Now()
	}
	return o.modTime
}

// SetModTime sets the modification time of the local fs object
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return fs.ErrorCantSetModTime
}

// Storable returns whether this object is storable
func (o *Object) Storable() bool {
	return true
}

// Open an object for read
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	// Create base64 encoded ID with pipe character for download URL
	idWithPipe := strconv.Itoa(o.id) + "|"
	encodedID := base64.StdEncoding.EncodeToString([]byte(idWithPipe))
	// Remove base64 padding to match expected format
	encodedID = strings.TrimRight(encodedID, "=")

	// Use the encoded file ID in the download URL
	downloadPath := fmt.Sprintf("/file-entries/download/%s", encodedID)

	// Make a direct HTTP request to get the redirect URL without following it
	downloadURL := o.fs.opt.BaseURL + defaultAPIPath + downloadPath + "?workspaceId=0"

	// Create HTTP client that doesn't follow redirects
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication headers
	if o.fs.opt.Token != "" {
		req.Header.Set("Authorization", "Bearer "+o.fs.opt.Token)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download file %q: %w", o.remote, err)
	}

	var redirectURL string

	// Handle HTTP redirects (302, 301)
	if resp.StatusCode == 302 || resp.StatusCode == 301 {
		location := resp.Header.Get("Location")
		resp.Body.Close()

		if location == "" {
			return nil, fmt.Errorf("redirect response missing Location header")
		}

		redirectURL = location
	} else if resp.StatusCode == 200 {
		// Check if this is an HTML response with a redirect (common with some APIs)
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "text/html") {
			// Handle HTML redirect - read the body to extract the redirect URL
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to read HTML redirect response: %w", err)
			}

			bodyStr := string(body)

			// Look for the redirect URL in the HTML
			// Pattern: href="https://drimestorage...
			start := strings.Index(bodyStr, `href="https://drimestorage.`)
			if start == -1 {
				return nil, fmt.Errorf("could not find redirect URL in HTML response")
			}
			start += 6 // Skip 'href="'

			end := strings.Index(bodyStr[start:], `"`)
			if end == -1 {
				return nil, fmt.Errorf("could not find end of redirect URL in HTML response")
			}

			redirectURL = bodyStr[start : start+end]
			// Decode HTML entities
			redirectURL = strings.ReplaceAll(redirectURL, "&amp;", "&")
		}
	}

	// If we have a redirect URL, follow it
	if redirectURL != "" {
		// Make a direct HTTP request to the redirect URL
		httpClient := fshttp.NewClient(ctx)
		req, err := http.NewRequestWithContext(ctx, "GET", redirectURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create redirect request: %w", err)
		}

		resp, err = httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to follow redirect: %w", err)
		}
	}

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("download failed for file %q: HTTP %d", o.remote, resp.StatusCode)
	}

	return resp.Body, nil
}

// findFolderByName finds a folder by name and returns its ID
func (f *Fs) findFolderByName(ctx context.Context, folderName string) (*int, error) {
	opts := rest.Opts{
		Method: "GET",
		Path:   "/drive/file-entries",
		Parameters: url.Values{
			"perPage": {"1000"},
		},
	}

	var result api.ListResponse
	err := f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.CallJSON(ctx, &opts, nil, &result)
		return shouldRetry(ctx, resp, err)
	})

	if err != nil {
		return nil, fmt.Errorf("couldn't list files: %w", err)
	}

	// Look for the folder in the results
	for _, item := range result.Data {
		if item != nil && item.Type == "folder" && item.Name == folderName {
			return &item.ID, nil
		}
	}

	return nil, fmt.Errorf("folder %q not found", folderName)
}

// Update the object with the contents of the io.Reader, modTime and size
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	// Parse the remote path to extract directory and filename
	var parentID string = "null" // default to root
	var fileName string = o.remote
	var targetFolder string = ""

	// Check if the filesystem root is a folder (when using drime:"folder name/")
	if o.fs.root != "" {
		targetFolder = o.fs.root
		fileName = o.remote // In this case, remote is just the filename
	} else if strings.Contains(o.remote, "/") {
		// Check if the remote path contains a directory (when using drime:folder/file.ext)
		parts := strings.Split(o.remote, "/")
		if len(parts) >= 2 {
			targetFolder = parts[0]
			fileName = parts[len(parts)-1] // Get the last part as filename
		}
	}

	// If we have a target folder, find its ID
	if targetFolder != "" {
		folderID, err := o.fs.findFolderByName(ctx, targetFolder)
		if err != nil {
			return fmt.Errorf("failed to find folder %q: %w", targetFolder, err)
		}
		parentID = fmt.Sprintf("%d", *folderID)
	}

	// Prepare multipart upload using rest.MultipartUpload
	parameters := url.Values{
		"parentId":     {parentID},
		"relativePath": {fileName}, // Use just the filename, not the full path
	}

	formReader, contentType, overhead, err := rest.MultipartUpload(ctx, in, parameters, "file", o.remote)
	if err != nil {
		return fmt.Errorf("failed to make multipart upload: %w", err)
	}

	totalContentLength := overhead + src.Size()
	opts := rest.Opts{
		Method:        "POST",
		Path:          "/uploads",
		Body:          formReader,
		ContentType:   contentType,
		ContentLength: &totalContentLength,
		Options:       options,
	}

	var resp *http.Response
	err = o.fs.pacer.Call(func() (bool, error) {
		resp, err = o.fs.srv.Call(ctx, &opts)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return fmt.Errorf("upload failed for file %q: %w", o.remote, err)
	}

	// Check if upload was successful
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Try to parse JSON response if available
		var result api.UploadResponse
		if resp.Header.Get("Content-Type") == "application/json" {
			err = rest.DecodeJSON(resp, &result)
			if err == nil && result.FileEntry != nil {
				o.id = result.FileEntry.ID
				o.size = result.FileEntry.FileSize
				o.hasMetaData = true

				// Parse modTime from response if available
				if result.FileEntry.UpdatedAt != "" {
					if t, err := time.Parse(time.RFC3339, result.FileEntry.UpdatedAt); err == nil {
						o.modTime = t
					}
				}
			}
		} else {
			// If no JSON response, set basic metadata
			o.size = src.Size()
			o.hasMetaData = true
		}
	} else {
		return fmt.Errorf("upload failed with status %d", resp.StatusCode)
	}

	return nil
}

// Remove an object
func (o *Object) Remove(ctx context.Context) error {
	// Prepare the deletion request body
	deleteRequest := map[string]interface{}{
		"entryIds":      []int{o.id},
		"deleteForever": false, // Move to trash instead of permanent deletion
	}

	opts := rest.Opts{
		Method: "POST",
		Path:   "/file-entries/delete",
	}

	var result interface{} // The API response structure is not specified
	err := o.fs.pacer.Call(func() (bool, error) {
		resp, err := o.fs.srv.CallJSON(ctx, &opts, &deleteRequest, &result)
		return shouldRetry(ctx, resp, err)
	})

	if err != nil {
		return fmt.Errorf("failed to delete file %q: %w", o.remote, err)
	}

	return nil
}

// Mkdir creates the container if it doesn't exist
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	return fs.ErrorNotImplemented
}

// Rmdir deletes the root folder
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	// Handle the case where dir is empty and f.root is the directory to delete
	targetDir := dir
	if dir == "" && f.root != "" {
		targetDir = f.root
	}

	// Find the directory by name to get its ID
	folderID, err := f.findFolderByName(ctx, targetDir)
	if err != nil {
		return fmt.Errorf("directory %q not found: %w", targetDir, err)
	}

	// Prepare the deletion request body
	deleteRequest := map[string]interface{}{
		"entryIds":      []int{*folderID},
		"deleteForever": false, // Move to trash instead of permanent deletion
	}

	opts := rest.Opts{
		Method: "POST",
		Path:   "/file-entries/delete",
	}

	var result interface{} // The API response structure is not specified
	err = f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.CallJSON(ctx, &opts, &deleteRequest, &result)
		return shouldRetry(ctx, resp, err)
	})

	if err != nil {
		return fmt.Errorf("failed to delete directory %q: %w", targetDir, err)
	}

	return nil
}

// Purge deletes all the files and the container
func (f *Fs) Purge(ctx context.Context, dir string) error {
	return fs.ErrorNotImplemented
}

// Copy src to this remote using server-side copy operations.
func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	return nil, fs.ErrorNotImplemented
}

// Move src to this remote using server-side move operations.
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		return nil, fs.ErrorCantMove
	}

	// Extract the new filename from the remote path
	newName := remote
	if strings.Contains(remote, "/") {
		parts := strings.Split(remote, "/")
		newName = parts[len(parts)-1]
	}

	// Prepare the rename request body
	renameRequest := map[string]interface{}{
		"name":        newName,
		"initialName": srcObj.remote,
	}

	opts := rest.Opts{
		Method: "POST", // Using POST with _method=PUT as shown in curl example
		Path:   fmt.Sprintf("/file-entries/%d", srcObj.id),
		Parameters: url.Values{
			"_method": {"PUT"},
		},
	}

	var result interface{} // The API response structure is not specified
	err := f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.CallJSON(ctx, &opts, &renameRequest, &result)
		return shouldRetry(ctx, resp, err)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to rename file %q: %w", srcObj.remote, err)
	}

	// Create a new object with the updated name
	newObj := &Object{
		fs:          f,
		remote:      remote,
		hasMetaData: srcObj.hasMetaData,
		size:        srcObj.size,
		modTime:     srcObj.modTime,
		id:          srcObj.id,
		hash:        srcObj.hash,
	}

	return newObj, nil
}

// DirMove moves src, srcRemote to this remote at dstRemote
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	srcFs, ok := src.(*Fs)
	if !ok {
		return fs.ErrorCantDirMove
	}

	// Extract the new directory name from the destination path
	// If dstRemote is empty, use the root path
	newName := dstRemote
	if newName == "" {
		newName = f.root
	}
	if strings.Contains(newName, "/") {
		parts := strings.Split(newName, "/")
		newName = parts[len(parts)-1]
	}

	// Get the source directory name
	// If srcRemote is empty, use the source filesystem's root path
	srcName := srcRemote
	if srcName == "" {
		srcName = srcFs.root
	}
	if strings.Contains(srcName, "/") {
		parts := strings.Split(srcName, "/")
		srcName = parts[len(parts)-1]
	}

	// Find the source directory by name to get its ID
	folderID, err := srcFs.findFolderByName(ctx, srcName)
	if err != nil {
		return fmt.Errorf("source directory %q not found: %w", srcName, err)
	}

	// Prepare the rename request body
	renameRequest := map[string]interface{}{
		"name":        newName,
		"initialName": srcName,
	}

	opts := rest.Opts{
		Method: "POST", // Using POST with _method=PUT as shown in curl example
		Path:   fmt.Sprintf("/file-entries/%d", *folderID),
		Parameters: url.Values{
			"_method": {"PUT"},
		},
	}

	var result interface{} // The API response structure is not specified
	err = f.pacer.Call(func() (bool, error) {
		resp, err := f.srv.CallJSON(ctx, &opts, &renameRequest, &result)
		return shouldRetry(ctx, resp, err)
	})

	if err != nil {
		return fmt.Errorf("failed to rename directory %q: %w", srcName, err)
	}

	return nil
}

// Put the object into the container
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	if src.Size() == 0 {
		return nil, fs.ErrorCantUploadEmptyFiles
	}

	// Create a new object to upload
	o := &Object{
		fs:      f,
		remote:  src.Remote(),
		size:    src.Size(),
		modTime: src.ModTime(ctx),
	}

	// Use the Update method to perform the actual upload
	err := o.Update(ctx, in, src, options...)
	if err != nil {
		return nil, err
	}

	return o, nil
}

// Check the interfaces are satisfied
var (
	_ fs.Fs     = (*Fs)(nil)
	_ fs.Object = (*Object)(nil)
)