// Package clouddrive implements the CloudDrive2 gRPC backend.
package clouddrive

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/rclone/rclone/backend/clouddrive/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultChunkSize = 4 * 1024 * 1024
	defaultTimeout   = 30 * time.Second
)

// Options defines the configuration for this backend
type Options struct {
	Server       string      `config:"server"`
	Token        string      `config:"token"`
	Username     string      `config:"user"`
	Password     string      `config:"pass"`
	TOTP         string      `config:"totp"`
	Insecure     bool        `config:"insecure"`
	DownloadHost string      `config:"download_host"`
	Timeout      fs.Duration `config:"timeout"`
}

// Fs represents a remote clouddrive
type Fs struct {
	name       string
	root       string
	opt        Options
	features   *fs.Features
	client     api.CloudDriveFileSrvClient
	conn       *grpc.ClientConn
	httpClient *http.Client
	token      string
	baseScheme string
	baseHost   string
}

// Object describes a clouddrive object
type Object struct {
	fs      *Fs
	remote  string
	size    int64
	modTime time.Time
	hashes  map[hash.Type]string
	id      string
	known   bool
}

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "clouddrive",
		Description: "CloudDrive2 gRPC API",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:     "server",
			Help:     "CloudDrive2 gRPC server address (host:port).",
			Required: true,
		}, {
			Name:       "token",
			Help:       "API token or JWT. Leave blank to fetch using user/pass.",
			Sensitive:  true,
			IsPassword: true,
		}, {
			Name:      "user",
			Help:      "Username used to request token when token is empty.",
			Sensitive: true,
			NoPrefix:  true,
		}, {
			Name:       "pass",
			Help:       "Password used to request token when token is empty.",
			Sensitive:  true,
			IsPassword: true,
			NoPrefix:   true,
		}, {
			Name:      "totp",
			Help:      "Optional TOTP/recovery code when account has 2FA enabled.",
			Sensitive: true,
			Advanced:  true,
			NoPrefix:  true,
		}, {
			Name:     "insecure",
			Help:     "Allow plaintext gRPC connection (no TLS).",
			Default:  false,
			Advanced: true,
		}, {
			Name:     "download_host",
			Help:     "Override host:port used to build download URLs. Defaults to the gRPC server host:port.",
			Advanced: true,
		}, {
			Name:     "timeout",
			Default:  fs.Duration(defaultTimeout),
			Help:     "Dial timeout for gRPC connections.",
			Advanced: true,
		}},
	})
}

// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := Options{}
	if err := configstruct.Set(m, &opt); err != nil {
		return nil, fmt.Errorf("failed to parse options: %w", err)
	}
	if opt.Server == "" {
		return nil, errors.New("server is required")
	}
	if opt.Timeout <= 0 {
		opt.Timeout = fs.Duration(defaultTimeout)
	}

	conn, client, err := dial(ctx, opt)
	if err != nil {
		return nil, err
	}

	token := obscure.MustReveal(opt.Token)
	if token == "" {
		token, err = fetchToken(ctx, client, opt)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("failed to fetch token: %w", err)
		}
		if token != "" {
			m.Set("token", token)
		}
	}

	f := &Fs{
		name:       name,
		root:       cleanRoot(root),
		opt:        opt,
		client:     client,
		conn:       conn,
		token:      token,
		httpClient: fshttp.NewClient(ctx),
	}
	f.baseScheme, f.baseHost = f.detectDownloadEndpoint()

	features := (&fs.Features{
		DuplicateFiles:          false,
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f)
	features.PutStream = f.PutStream
	features.Move = f.Move
	features.DirMove = f.DirMove
	features.Copy = f.Copy
	f.features = features

	// Verify root exists if not empty
	if f.root != "" {
		if _, err := f.statPath(ctx, ""); err != nil && !errors.Is(err, fs.ErrorDirNotFound) {
			fs.Debugf(f, "ignoring root lookup error: %v", err)
		}
	}

	return f, nil
}

// detectDownloadEndpoint determines the scheme/host for download URL placeholder substitution.
func (f *Fs) detectDownloadEndpoint() (scheme, host string) {
	host = f.opt.DownloadHost
	scheme = "https"
	if f.opt.Insecure {
		scheme = "http"
	}

	if host != "" {
		return scheme, host
	}

	server := f.opt.Server
	if strings.HasPrefix(server, "dns:///") {
		server = strings.TrimPrefix(server, "dns:///")
	}
	if strings.Contains(server, "://") {
		if u, err := url.Parse(server); err == nil {
			if u.Scheme != "" {
				scheme = u.Scheme
			}
			if u.Host != "" {
				host = u.Host
			}
		}
	}
	if host == "" {
		host = server
	}
	return scheme, host
}

// dial gRPC server
func dial(ctx context.Context, opt Options) (*grpc.ClientConn, api.CloudDriveFileSrvClient, error) {
	dctx, cancel := context.WithTimeout(ctx, time.Duration(opt.Timeout))
	defer cancel()

	var creds credentials.TransportCredentials
	if opt.Insecure {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewTLS(&tls.Config{})
	}

	conn, err := grpc.DialContext(dctx, opt.Server, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial %q: %w", opt.Server, err)
	}
	client := api.NewCloudDriveFileSrvClient(conn)
	return conn, client, nil
}

// fetchToken exchanges username/password for JWT when token is empty.
func fetchToken(ctx context.Context, client api.CloudDriveFileSrvClient, opt Options) (string, error) {
	if opt.Username == "" || opt.Password == "" {
		return "", errors.New("token not set and missing user/pass")
	}
	req := &api.GetTokenRequest{
		UserName: opt.Username,
		Password: obscure.MustReveal(opt.Password),
	}
	if opt.TOTP != "" {
		req.TotpCode = &opt.TOTP
	}
	resp, err := client.GetToken(ctx, req)
	if err != nil {
		return "", err
	}
	if !resp.GetSuccess() {
		return "", fmt.Errorf("token request failed: %s", resp.GetErrorMessage())
	}
	return resp.GetToken(), nil
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
	if f.root == "" {
		return "CloudDrive2 root"
	}
	return fmt.Sprintf("CloudDrive2 root '%s'", f.root)
}

// Precision return the precision of this Fs
func (f *Fs) Precision() time.Duration {
	return time.Second
}

// Hashes returns the supported hash types of the filesystem
func (f *Fs) Hashes() hash.Set {
	return hash.NewHashSet(hash.MD5, hash.SHA1)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// cleanRoot normalizes the root passed into NewFs.
func cleanRoot(root string) string {
	root = strings.Trim(root, "/")
	return root
}

// fullPath returns the absolute path for a relative path on the remote.
func (f *Fs) fullPath(remote string) string {
	remote = strings.Trim(remote, "/")
	if f.root != "" {
		remote = path.Join(f.root, remote)
	}
	if remote == "" {
		return "/"
	}
	return "/" + remote
}

// timestampToTime safely converts a protobuf timestamp.
func timestampToTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// withAuth injects the bearer token into context metadata.
func (f *Fs) withAuth(ctx context.Context) context.Context {
	if f.token == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+f.token)
}

// List the objects and directories in dir.
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	ctx = f.withAuth(ctx)
	req := &api.ListSubFileRequest{
		Path:         f.fullPath(dir),
		ForceRefresh: false,
	}
	stream, err := f.client.GetSubFiles(ctx, req)
	if err != nil {
		return nil, translateError(err)
	}
	for {
		resp, recErr := stream.Recv()
		if recErr == io.EOF {
			break
		}
		if recErr != nil {
			return nil, translateError(recErr)
		}
		for _, item := range resp.GetSubFiles() {
			remote := path.Join(dir, item.GetName())
			if item.GetIsDirectory() || item.GetFileType() == api.CloudDriveFile_Directory {
				entries = append(entries, fs.NewDir(remote, timestampToTime(item.GetWriteTime())))
			} else {
				entries = append(entries, f.newObjectFromItem(remote, item))
			}
		}
	}
	return entries, nil
}

// Mkdir creates a directory
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	ctx = f.withAuth(ctx)
	p := f.fullPath(dir)
	parent, leaf := path.Split(p)
	if parent == "" {
		parent = "/"
	}
	req := &api.CreateFolderRequest{
		ParentPath: strings.TrimSuffix(parent, "/"),
		FolderName: strings.Trim(leaf, "/"),
	}
	res, err := f.client.CreateFolder(ctx, req)
	if err != nil {
		return translateError(err)
	}
	if res.GetResult() != nil && !res.GetResult().GetSuccess() {
		return errors.New(res.GetResult().GetErrorMessage())
	}
	return nil
}

// Rmdir removes the directory
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	ctx = f.withAuth(ctx)
	p := f.fullPath(dir)
	if p == "/" {
		return errors.New("refusing to delete root")
	}
	req := &api.FileRequest{Path: p}
	res, err := f.client.DeleteFile(ctx, req)
	if err != nil {
		return translateError(err)
	}
	if !res.GetSuccess() {
		return errors.New(res.GetErrorMessage())
	}
	return nil
}

// NewObject finds the Object at remote.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	item, err := f.getFile(ctx, remote)
	if err != nil {
		return nil, err
	}
	if item.GetIsDirectory() || item.GetFileType() == api.CloudDriveFile_Directory {
		return nil, fs.ErrorIsDir
	}
	return f.newObjectFromItem(remote, item), nil
}

// getFile fetches metadata for a remote path.
func (f *Fs) getFile(ctx context.Context, remote string) (*api.CloudDriveFile, error) {
	ctx = f.withAuth(ctx)
	p := f.fullPath(remote)
	parent, name := path.Split(p)
	if parent == "" {
		parent = "/"
	}

	req := &api.FindFileByPathRequest{
		ParentPath: strings.TrimSuffix(parent, "/"),
		Path:       name,
	}
	item, err := f.client.FindFileByPath(ctx, req)
	if err == nil {
		return item, nil
	}
	if status.Code(err) == codes.Unimplemented {
		// fallback to listing parent
		return f.getFileByListing(ctx, remote)
	}
	return nil, translateError(err)
}

// getFileByListing lists the parent and finds the child.
func (f *Fs) getFileByListing(ctx context.Context, remote string) (*api.CloudDriveFile, error) {
	parent, leaf := path.Split(remote)
	entries, err := f.List(ctx, strings.Trim(parent, "/"))
	if err != nil {
		return nil, err
	}
	target := path.Join(strings.Trim(parent, "/"), strings.Trim(leaf, "/"))
	for _, entry := range entries {
		if entry.Remote() == target {
			if obj, ok := entry.(fs.Object); ok {
				if co, ok2 := obj.(*Object); ok2 {
					return co.toItem(), nil
				}
			}
		}
	}
	return nil, fs.ErrorObjectNotFound
}

// Put uploads data to the remote path
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	if err := f.put(ctx, in, src, options...); err != nil {
		return nil, err
	}
	return f.NewObject(ctx, src.Remote())
}

// PutStream implements streaming upload without knowing size.
func (f *Fs) PutStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.Put(ctx, in, src, options...)
}

// put uploads/overwrites a file
func (f *Fs) put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	ctx = f.withAuth(ctx)
	remote := src.Remote()
	p := f.fullPath(remote)
	parentPath, fileName := path.Split(p)
	if parentPath == "" {
		parentPath = "/"
	}

	createReq := &api.CreateFileRequest{
		ParentPath: strings.TrimSuffix(parentPath, "/"),
		FileName:   strings.Trim(fileName, "/"),
	}
	createRes, err := f.client.CreateFile(ctx, createReq)
	if err != nil {
		return translateError(err)
	}
	handle := createRes.GetFileHandle()
	stream, err := f.client.WriteToFileStream(ctx)
	if err != nil {
		return translateError(err)
	}

	buf := make([]byte, defaultChunkSize)
	var offset uint64
	for {
		n, readErr := io.ReadFull(in, buf)
		if readErr == io.ErrUnexpectedEOF || readErr == io.EOF {
			if n > 0 {
				if sendErr := stream.Send(&api.WriteFileRequest{
					FileHandle: handle,
					StartPos:   offset,
					Length:     uint64(n),
					Buffer:     buf[:n],
					CloseFile:  true,
				}); sendErr != nil {
					return translateError(sendErr)
				}
				offset += uint64(n)
			} else {
				// If file is empty, still send a close to commit
				if offset == 0 {
					if sendErr := stream.Send(&api.WriteFileRequest{
						FileHandle: handle,
						StartPos:   0,
						Length:     0,
						CloseFile:  true,
					}); sendErr != nil {
						return translateError(sendErr)
					}
				}
			}
			break
		}
		if readErr != nil {
			return readErr
		}

		if sendErr := stream.Send(&api.WriteFileRequest{
			FileHandle: handle,
			StartPos:   offset,
			Length:     uint64(n),
			Buffer:     buf[:n],
		}); sendErr != nil {
			return translateError(sendErr)
		}
		offset += uint64(n)
	}

	if _, err = stream.CloseAndRecv(); err != nil {
		return translateError(err)
	}

	// Ensure file is closed server-side
	if _, err = f.client.CloseFile(ctx, &api.CloseFileRequest{FileHandle: handle}); err != nil {
		// log but ignore since file might already be closed
		fs.Debugf(remote, "close file warning: %v", err)
	}
	return nil
}

// Move moves a single object
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	dstParent, dstLeaf := path.Split(remote)
	srcParent := path.Dir(src.Remote())

	if srcParent == strings.Trim(dstParent, "/") {
		// rename in place
		if err := f.rename(ctx, src.Remote(), dstLeaf); err == nil {
			return f.NewObject(ctx, remote)
		}
	}

	if err := f.moveFile(ctx, []string{src.Remote()}, dstParent); err != nil {
		return nil, err
	}
	if dstLeaf != path.Base(src.Remote()) {
		if err := f.rename(ctx, path.Join(dstParent, path.Base(src.Remote())), dstLeaf); err != nil {
			return nil, err
		}
	}
	return f.NewObject(ctx, remote)
}

// DirMove moves a directory tree
func (f *Fs) DirMove(ctx context.Context, src fs.Fs, srcRemote, dstRemote string) error {
	if f != src {
		return fs.ErrorCantDirMove
	}
	return f.moveFile(ctx, []string{srcRemote}, dstRemote)
}

// Copy copies a single object
func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	ctx = f.withAuth(ctx)
	destDir, _ := path.Split(remote)
	req := &api.CopyFileRequest{
		TheFilePaths:   []string{f.fullPath(src.Remote())},
		DestPath:       f.fullPath(strings.TrimSuffix(destDir, "/")),
		ConflictPolicy: api.CopyFileRequest_Rename.Enum(),
	}
	res, err := f.client.CopyFile(ctx, req)
	if err != nil {
		return nil, translateError(err)
	}
	if !res.GetSuccess() {
		return nil, errors.New(res.GetErrorMessage())
	}
	return f.NewObject(ctx, remote)
}

// moveFile moves files or folders to destination directory.
func (f *Fs) moveFile(ctx context.Context, remotes []string, dstDir string) error {
	ctx = f.withAuth(ctx)
	paths := make([]string, 0, len(remotes))
	for _, r := range remotes {
		paths = append(paths, f.fullPath(r))
	}
	req := &api.MoveFileRequest{
		TheFilePaths:   paths,
		DestPath:       f.fullPath(strings.Trim(dstDir, "/")),
		ConflictPolicy: api.MoveFileRequest_Rename.Enum(),
	}
	res, err := f.client.MoveFile(ctx, req)
	if err != nil {
		return translateError(err)
	}
	if !res.GetSuccess() {
		return errors.New(res.GetErrorMessage())
	}
	return nil
}

// rename changes the base name of a path within its parent.
func (f *Fs) rename(ctx context.Context, remote, newName string) error {
	ctx = f.withAuth(ctx)
	req := &api.RenameFileRequest{
		TheFilePath: f.fullPath(remote),
		NewName:     newName,
	}
	res, err := f.client.RenameFile(ctx, req)
	if err != nil {
		return translateError(err)
	}
	if !res.GetSuccess() {
		return errors.New(res.GetErrorMessage())
	}
	return nil
}

// Hash of the object
func (o *Object) Hash(ctx context.Context, hashType hash.Type) (string, error) {
	if err := o.ensureMeta(ctx); err != nil {
		return "", err
	}
	if o.hashes == nil {
		return "", nil
	}
	sum, ok := o.hashes[hashType]
	if !ok {
		return "", nil
	}
	return sum, nil
}

// Storable returns whether the object is storable
func (o *Object) Storable() bool {
	return true
}

// Fs returns read only access to the Fs that this object is part of
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// String returns a description
func (o *Object) String() string {
	if o.id != "" {
		return o.id
	}
	return o.remote
}

// Size returns the size of the object
func (o *Object) Size() int64 {
	return o.size
}

// ModTime returns modification time
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

// SetModTime sets the modification time of the object
func (o *Object) SetModTime(ctx context.Context, t time.Time) error {
	return fs.ErrorCantSetModTime
}

// Open opens the object for reading
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	if err := o.ensureMeta(ctx); err != nil {
		return nil, err
	}

	urlInfo, err := o.fs.getDownloadInfo(ctx, o.remote)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", urlInfo.url, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range urlInfo.headers {
		req.Header.Set(k, v)
	}
	fs.OpenOptionAddHTTPHeaders(req.Header, options)

	resp, err := o.fs.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("download failed: %s", resp.Status)
	}
	return resp.Body, nil
}

// Update the object with contents of io.Reader
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	return o.fs.put(ctx, in, src, options...)
}

// Remove deletes the object
func (o *Object) Remove(ctx context.Context) error {
	ctx = o.fs.withAuth(ctx)
	req := &api.FileRequest{Path: o.fs.fullPath(o.remote)}
	res, err := o.fs.client.DeleteFile(ctx, req)
	if err != nil {
		return translateError(err)
	}
	if !res.GetSuccess() {
		return errors.New(res.GetErrorMessage())
	}
	return nil
}

// ensureMeta fetches metadata if missing
func (o *Object) ensureMeta(ctx context.Context) error {
	if o.known {
		return nil
	}
	item, err := o.fs.getFile(ctx, o.remote)
	if err != nil {
		return err
	}
	o.populateFromItem(item)
	o.known = true
	return nil
}

// populateFromItem sets object fields from CloudDriveFile
func (o *Object) populateFromItem(item *api.CloudDriveFile) {
	o.id = item.GetId()
	o.size = item.GetSize()
	o.modTime = timestampToTime(item.GetWriteTime())
	o.hashes = extractHashes(item)
}

// toItem converts the Object back into CloudDriveFile metadata.
func (o *Object) toItem() *api.CloudDriveFile {
	hashes := map[uint32]string{}
	for k, v := range o.hashes {
		switch k {
		case hash.MD5:
			hashes[uint32(api.CloudDriveFile_Md5)] = v
		case hash.SHA1:
			hashes[uint32(api.CloudDriveFile_Sha1)] = v
		}
	}
	item := &api.CloudDriveFile{
		Id:           o.id,
		Name:         path.Base(o.remote),
		FullPathName: o.fs.fullPath(o.remote),
		Size:         o.size,
		IsDirectory:  false,
		FileType:     api.CloudDriveFile_File,
		FileHashes:   hashes,
	}
	if !o.modTime.IsZero() {
		item.WriteTime = timestamppb.New(o.modTime)
	}
	return item
}

// newObjectFromItem creates object from metadata
func (f *Fs) newObjectFromItem(remote string, item *api.CloudDriveFile) *Object {
	o := &Object{
		fs:     f,
		remote: remote,
		known:  true,
	}
	o.populateFromItem(item)
	return o
}

// statPath validates a directory exists; if remote empty uses root
func (f *Fs) statPath(ctx context.Context, remote string) (*api.CloudDriveFile, error) {
	p := strings.Trim(remote, "/")
	if p == "" && f.root == "" {
		return nil, nil
	}
	return f.getFile(ctx, p)
}

type downloadInfo struct {
	url     string
	headers map[string]string
}

// getDownloadInfo resolves a download URL for a path.
func (f *Fs) getDownloadInfo(ctx context.Context, remote string) (*downloadInfo, error) {
	ctx = f.withAuth(ctx)
	req := &api.GetDownloadUrlPathRequest{
		Path:         f.fullPath(remote),
		Preview:      false,
		LazyRead:     false,
		GetDirectUrl: true,
	}
	res, err := f.client.GetDownloadUrlPath(ctx, req)
	if err != nil {
		return nil, translateError(err)
	}
	u := res.GetDirectUrl()
	if u == "" {
		u = res.GetDownloadUrlPath()
		u = strings.ReplaceAll(u, "{SCHEME}", f.baseScheme)
		u = strings.ReplaceAll(u, "{HOST}", f.baseHost)
		u = strings.ReplaceAll(u, "{PREVIEW}", "false")

		// --- 添加修复代码开始 ---
		// 如果返回的是相对路径，需要拼接完整的 URL
		if strings.HasPrefix(u, "/") {
			u = fmt.Sprintf("%s://%s%s", f.baseScheme, f.baseHost, u)
		}
		// --- 添加修复代码结束 ---
	}
	headers := map[string]string{}
	for k, v := range res.GetAdditionalHeaders() {
		headers[k] = v
	}
	if ua := res.GetUserAgent(); ua != "" {
		headers["User-Agent"] = ua
	}
	return &downloadInfo{url: u, headers: headers}, nil
}

// extractHashes converts fileHashes map to hash.Type keyed map.
func extractHashes(item *api.CloudDriveFile) map[hash.Type]string {
	if len(item.GetFileHashes()) == 0 {
		return nil
	}
	h := make(map[hash.Type]string)
	for k, v := range item.GetFileHashes() {
		switch api.CloudDriveFile_HashType(k) {
		case api.CloudDriveFile_Md5:
			h[hash.MD5] = strings.ToLower(v)
		case api.CloudDriveFile_Sha1:
			h[hash.SHA1] = strings.ToLower(v)
		}
	}
	return h
}

// translateError maps gRPC errors to fs errors.
func translateError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return err
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound:
			return fs.ErrorObjectNotFound
		case codes.PermissionDenied:
			return fs.ErrorPermissionDenied
		case codes.Unimplemented:
			return fs.ErrorNotImplemented
		}
	}
	return err
}
