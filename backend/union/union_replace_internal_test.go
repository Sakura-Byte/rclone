package union

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/rclone/rclone/backend/local"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/operations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListResult(t *testing.T) {
	boom := errors.New("boom")
	assert.NoError(t, listResult(Errors{nil, nil}))
	assert.NoError(t, listResult(Errors{nil, fs.ErrorDirNotFound}))
	assert.ErrorIs(t, listResult(Errors{fs.ErrorDirNotFound, fs.ErrorDirNotFound}), fs.ErrorDirNotFound)
	// One upstream failing while another lists fine must not look like
	// "these files are absent".
	assert.ErrorIs(t, listResult(Errors{nil, boom}), boom)
	assert.ErrorIs(t, listResult(Errors{fs.ErrorDirNotFound, boom}), boom)
}

// Replacing a file that lives on a no-create upstream must update it in
// place, not create a second copy on the create upstream.
func TestReplaceOnNoCreateUpstream(t *testing.T) {
	ctx := context.Background()
	full, spare, srcDir := t.TempDir(), t.TempDir(), t.TempDir()
	old := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)
	require.NoError(t, os.WriteFile(filepath.Join(full, "a.m4a"), []byte("same size"), 0o644))
	require.NoError(t, os.Chtimes(filepath.Join(full, "a.m4a"), old, old))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "a.m4a"), []byte("SAME SIZE"), 0o644))

	u, err := NewFs(ctx, "u", "", configmap.Simple{
		"upstreams":     full + ":nc " + spare,
		"create_policy": "ff",
		"action_policy": "epall",
		"search_policy": "ff",
		"cache_time":    "120",
	})
	require.NoError(t, err)
	assert.False(t, u.Features().PartialUploads)
	src, err := fs.NewFs(ctx, srcDir)
	require.NoError(t, err)

	require.NoError(t, operations.CopyFile(ctx, u, src, "a.m4a", "a.m4a"))

	got, err := os.ReadFile(filepath.Join(full, "a.m4a"))
	require.NoError(t, err)
	assert.Equal(t, "SAME SIZE", string(got))
	_, err = os.Stat(filepath.Join(spare, "a.m4a"))
	assert.True(t, os.IsNotExist(err), "second copy created on the create upstream")
}
