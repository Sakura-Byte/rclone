package clouddrive

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/rclone/rclone/backend/clouddrive/api"
	"github.com/rclone/rclone/backend/local"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/operations"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type encodingClient struct {
	api.CloudDriveFileSrvClient
	list     func(*api.ListSubFileRequest) []*api.CloudDriveFile
	download func(*api.GetDownloadUrlPathRequest) *api.DownloadUrlPathInfo
	rename   func(*api.RenameFileRequest)
}

func (c *encodingClient) GetDownloadUrlPath(_ context.Context, req *api.GetDownloadUrlPathRequest, _ ...grpc.CallOption) (*api.DownloadUrlPathInfo, error) {
	return c.download(req), nil
}

func (c *encodingClient) RenameFile(_ context.Context, req *api.RenameFileRequest, _ ...grpc.CallOption) (*api.FileOperationResult, error) {
	c.rename(req)
	return &api.FileOperationResult{Success: true}, nil
}

func (c *encodingClient) GetSubFiles(_ context.Context, req *api.ListSubFileRequest, _ ...grpc.CallOption) (api.CloudDriveFileSrv_GetSubFilesClient, error) {
	return &encodingStream{items: c.list(req)}, nil
}

type encodingStream struct {
	grpc.ClientStream
	items []*api.CloudDriveFile
}

func (s *encodingStream) Recv() (*api.SubFilesReply, error) {
	if s.items == nil {
		return nil, io.EOF
	}
	items := s.items
	s.items = nil
	return &api.SubFilesReply{SubFiles: items}, nil
}

func newEncodingTestFs(t *testing.T) *Fs {
	t.Helper()
	ri, err := fs.Find("clouddrive")
	require.NoError(t, err)
	var opt Options
	require.NoError(t, configstruct.Set(fs.ConfigMap(ri.Prefix, ri.Options, "", nil), &opt))
	return &Fs{opt: opt, features: &fs.Features{}, pacer: fs.NewPacer(context.Background(), pacer.NewDefault())}
}

func TestListPreservesLiteralNames(t *testing.T) {
	for _, name := range []string{
		"[2026-06-03][ASMR／ear cleaning].mp4",
		"record‛／part.mp4",
		"record␀part.mp4",
		"record␁part.mp4",
		"３．２．１.mp4",
	} {
		for _, isDir := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/file", true: "/directory"}[isDir], func(t *testing.T) {
				f := newEncodingTestFs(t)
				f.client = &encodingClient{list: func(req *api.ListSubFileRequest) []*api.CloudDriveFile {
					assert.Equal(t, "/recordings", req.Path)
					return []*api.CloudDriveFile{{Name: name, IsDirectory: isDir, FileType: api.CloudDriveFile_File}}
				}}
				entries, err := f.List(context.Background(), "recordings")
				require.NoError(t, err)
				require.Len(t, entries, 1)
				// A Raw destination must receive the original name without new path separators.
				assert.Equal(t, path.Join("recordings", name), encoder.EncodeRaw.FromStandardPath(entries[0].Remote()))
			})
		}
	}
}

func TestFullPathPreservesLiteralNames(t *testing.T) {
	f := newEncodingTestFs(t)
	f.root = encoder.EncodeRaw.ToStandardPath("recordings／archive")
	remote := encoder.EncodeRaw.ToStandardPath("artist／name/recording／title.mp4")
	assert.Equal(t, "/recordings／archive/artist／name/recording／title.mp4", f.fullPath(remote))
}

func TestRenamePreservesLiteralNames(t *testing.T) {
	f := newEncodingTestFs(t)
	f.root = "recordings"
	f.client = &encodingClient{rename: func(req *api.RenameFileRequest) {
		assert.Equal(t, "/recordings/old／name.mp4", req.TheFilePath)
		assert.Equal(t, "new／name.mp4", req.NewName)
	}}
	err := f.rename(context.Background(), encoder.EncodeRaw.ToStandardPath("old／name.mp4"), encoder.EncodeRaw.ToStandardName("new／name.mp4"))
	require.NoError(t, err)
}

func TestObjectMetadataPreservesLiteralNames(t *testing.T) {
	f := newEncodingTestFs(t)
	f.root = "recordings"
	o := &Object{fs: f, remote: encoder.EncodeRaw.ToStandardName("recording／title.mp4")}
	item := o.toItem()
	assert.Equal(t, "recording／title.mp4", item.Name)
	assert.Equal(t, "/recordings/recording／title.mp4", item.FullPathName)
}

func TestObjectString(t *testing.T) {
	o := &Object{remote: "recordings/file.mp4", id: "123456"}
	assert.Equal(t, o.Remote(), o.String())
}

func TestCopyPreservesLiteralSlash(t *testing.T) {
	ctx := context.Background()
	const name = "[ASMR／ear cleaning].mp4"
	const contents = "recording"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, contents)
	}))
	t.Cleanup(server.Close)
	f := newEncodingTestFs(t)
	f.root = "recordings"
	f.httpClient = server.Client()
	f.client = &encodingClient{
		list: func(req *api.ListSubFileRequest) []*api.CloudDriveFile {
			return []*api.CloudDriveFile{{Id: "123456", Name: name, Size: int64(len(contents)), FileType: api.CloudDriveFile_File}}
		},
		download: func(req *api.GetDownloadUrlPathRequest) *api.DownloadUrlPathInfo {
			assert.Equal(t, "/recordings/"+name, req.Path)
			return &api.DownloadUrlPathInfo{DownloadUrlPath: server.URL}
		},
	}
	entries, err := f.List(ctx, "")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	src := entries[0].(fs.Object)
	dstDir := t.TempDir()
	dst, err := local.NewFs(ctx, "local", filepath.ToSlash(dstDir), configmap.Simple{"encoding": "Raw"})
	require.NoError(t, err)
	_, err = operations.Copy(ctx, dst, nil, src.Remote(), src)
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(dstDir, name))
	require.NoError(t, err)
	assert.Equal(t, contents, string(data))
	files, err := os.ReadDir(dstDir)
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.False(t, files[0].IsDir())
}

// opClient records the CloudDrive operations a backend call makes.
type opClient struct {
	api.CloudDriveFileSrvClient
	calls     []string
	existing  map[string]bool
	renameErr string
}

func (c *opClient) RenameFile(_ context.Context, req *api.RenameFileRequest, _ ...grpc.CallOption) (*api.FileOperationResult, error) {
	c.calls = append(c.calls, "rename "+req.TheFilePath+" -> "+req.NewName)
	if c.renameErr != "" {
		return &api.FileOperationResult{Success: false, ErrorMessage: c.renameErr}, nil
	}
	parent, _ := splitFull(req.TheFilePath)
	delete(c.existing, req.TheFilePath)
	c.existing[joinFull(parent, req.NewName)] = true
	return &api.FileOperationResult{Success: true}, nil
}

func (c *opClient) MoveFile(_ context.Context, req *api.MoveFileRequest, _ ...grpc.CallOption) (*api.FileOperationResult, error) {
	c.calls = append(c.calls, "move "+req.TheFilePaths[0]+" -> "+req.DestPath+" "+req.GetConflictPolicy().String())
	for _, p := range req.TheFilePaths {
		_, leaf := splitFull(p)
		delete(c.existing, p)
		c.existing[joinFull(req.DestPath, leaf)] = true
	}
	return &api.FileOperationResult{Success: true}, nil
}

func (c *opClient) CopyFile(_ context.Context, req *api.CopyFileRequest, _ ...grpc.CallOption) (*api.FileOperationResult, error) {
	c.calls = append(c.calls, "copy "+req.TheFilePaths[0]+" -> "+req.DestPath+" "+req.GetConflictPolicy().String())
	_, leaf := splitFull(req.TheFilePaths[0])
	c.existing[joinFull(req.DestPath, leaf)] = true
	return &api.FileOperationResult{Success: true}, nil
}

func (c *opClient) DeleteFile(_ context.Context, req *api.FileRequest, _ ...grpc.CallOption) (*api.FileOperationResult, error) {
	c.calls = append(c.calls, "delete "+req.Path)
	delete(c.existing, req.Path)
	return &api.FileOperationResult{Success: true}, nil
}

func (c *opClient) FindFileByPath(_ context.Context, req *api.FindFileByPathRequest, _ ...grpc.CallOption) (*api.CloudDriveFile, error) {
	p := joinFull(req.ParentPath, req.Path)
	if !c.existing[p] {
		return nil, status.Error(codes.NotFound, "not found")
	}
	return &api.CloudDriveFile{Name: req.Path, FullPathName: p, FileType: api.CloudDriveFile_File}, nil
}

func newOpTestFs(t *testing.T, existing ...string) (*Fs, *opClient) {
	f := newEncodingTestFs(t)
	f.root = "rec"
	c := &opClient{existing: map[string]bool{}}
	for _, p := range existing {
		c.existing[p] = true
	}
	f.client = c
	return f, c
}

func TestMoveSameDirFailedRenameDoesNotMove(t *testing.T) {
	f, c := newOpTestFs(t, "/rec/a/old.m4a")
	c.renameErr = "boom"
	src := &Object{fs: f, remote: "a/old.m4a"}
	_, err := f.Move(context.Background(), src, "a/new.m4a")
	require.Error(t, err)
	// Falling back to MoveFile into the same directory makes CloudDrive
	// rename the file to "old(1).m4a".
	assert.Equal(t, []string{"rename /rec/a/old.m4a -> new.m4a"}, c.calls)
}

func TestMoveSameDirLiteralFullwidthSlash(t *testing.T) {
	f, c := newOpTestFs(t, "/rec/a/x／old.m4a")
	src := &Object{fs: f, remote: encoder.EncodeRaw.ToStandardPath("a/x／old.m4a")}
	_, err := f.Move(context.Background(), src, encoder.EncodeRaw.ToStandardPath("a/x／new.m4a"))
	require.NoError(t, err)
	assert.Equal(t, []string{"rename /rec/a/x／old.m4a -> x／new.m4a"}, c.calls)
}

func TestMoveRejectsRealSlash(t *testing.T) {
	f, c := newOpTestFs(t, "/rec/a/x／old.m4a")
	src := &Object{fs: f, remote: encoder.EncodeRaw.ToStandardPath("a/x／old.m4a")}
	// An unquoted "／" in an rclone name stands for "/", which CloudDrive
	// would turn into a directory level.
	_, err := f.Move(context.Background(), src, "a/x／new.m4a")
	require.Error(t, err)
	assert.Empty(t, c.calls)
}

func TestMoveAcrossDirsRenamesFirst(t *testing.T) {
	// "b/old.m4a" is an unrelated file: the old code moved with the Rename
	// policy (creating "old(1).m4a") and then renamed this one.
	f, c := newOpTestFs(t, "/rec/a/old.m4a", "/rec/b/old.m4a")
	src := &Object{fs: f, remote: "a/old.m4a"}
	_, err := f.Move(context.Background(), src, "b/new.m4a")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"rename /rec/a/old.m4a -> new.m4a",
		"move /rec/a/new.m4a -> /rec/b Overwrite",
	}, c.calls)
	assert.True(t, c.existing["/rec/b/old.m4a"])
	assert.True(t, c.existing["/rec/b/new.m4a"])
}

func TestMoveUsesSourceFsRoot(t *testing.T) {
	f, c := newOpTestFs(t, "/other/x.m4a")
	srcFs := *f
	srcFs.root = "other"
	src := &Object{fs: &srcFs, remote: "x.m4a"}
	_, err := f.Move(context.Background(), src, "x.m4a")
	require.NoError(t, err)
	assert.Equal(t, []string{"move /other/x.m4a -> /rec Overwrite"}, c.calls)
}

func TestDirMoveRenamesInPlace(t *testing.T) {
	f, c := newOpTestFs(t, "/rec/a/old")
	require.NoError(t, f.DirMove(context.Background(), f, "a/old", "a/new"))
	assert.Equal(t, []string{"rename /rec/a/old -> new"}, c.calls)
}

func TestDirMoveAcrossDirs(t *testing.T) {
	f, c := newOpTestFs(t, "/rec/a/old", "/rec/b")
	require.NoError(t, f.DirMove(context.Background(), f, "a/old", "b/new"))
	assert.Equal(t, []string{
		"rename /rec/a/old -> new",
		"move /rec/a/new -> /rec/b Skip",
	}, c.calls)
}

func TestDirMoveExisting(t *testing.T) {
	f, c := newOpTestFs(t, "/rec/a/old", "/rec/a/new")
	assert.ErrorIs(t, f.DirMove(context.Background(), f, "a/old", "a/new"), fs.ErrorDirExists)
	assert.Empty(t, c.calls)
}

func TestCopyNewLeaf(t *testing.T) {
	f, c := newOpTestFs(t, "/rec/a/old.m4a", "/rec/b/new.m4a")
	src := &Object{fs: f, remote: "a/old.m4a"}
	_, err := f.Copy(context.Background(), src, "b/new.m4a")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"copy /rec/a/old.m4a -> /rec/b Skip",
		"delete /rec/b/new.m4a",
		"rename /rec/b/old.m4a -> new.m4a",
	}, c.calls)
}

func TestCopyNewLeafClash(t *testing.T) {
	f, c := newOpTestFs(t, "/rec/a/old.m4a", "/rec/b/old.m4a")
	src := &Object{fs: f, remote: "a/old.m4a"}
	_, err := f.Copy(context.Background(), src, "b/new.m4a")
	assert.ErrorIs(t, err, fs.ErrorCantCopy)
	assert.Empty(t, c.calls)
}
