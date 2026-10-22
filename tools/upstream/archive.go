package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

// UpstreamTree holds the regular files of one upstream commit, keyed by slash-separated path.
// Contents are the raw upstream bytes: the module path is not rewritten.
type UpstreamTree struct {
	SHA   string
	Files map[string][]byte
}

var (
	errArchiveMissing   = errors.New("upstream archive is not cached and offline mode is set")
	errArchiveCommit    = errors.New("upstream archive does not match the requested commit")
	errArchiveEmpty     = errors.New("upstream archive contains no files")
	errArchiveTooLarge  = errors.New("upstream archive entry exceeds the size limit")
	errGitObjectMissing = errors.New("commit object is not present in the local git repository")
	archiveCacheSuffix  = ".tar.gz"
)

// ReadUpstreamArchive parses a gzip tar stream and verifies its root directory names wantSHA.
// GitHub codeload and `git archive --prefix=gvisor-<sha>/` both produce this layout.
func ReadUpstreamArchive(r io.Reader, wantSHA string) (*UpstreamTree, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	tree := &UpstreamTree{SHA: wantSHA, Files: make(map[string][]byte)}
	tr := tar.NewReader(gz)
	rootChecked := false
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.Join(fmt.Errorf("read tar header: %w", err), gz.Close())
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		root, _, _ := strings.Cut(filepath.ToSlash(hdr.Name), "/")
		if !rootChecked {
			if root != wantSHA && !strings.HasSuffix(root, "-"+wantSHA) {
				return nil, errors.Join(fmt.Errorf("%w: root %q, want suffix %s", errArchiveCommit, root, wantSHA), gz.Close())
			}
			rootChecked = true
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		rel, err := stripArchiveRootPrefix(hdr.Name)
		if err != nil {
			return nil, errors.Join(err, gz.Close())
		}
		if rel == "" {
			continue
		}
		if hdr.Size < 0 || hdr.Size > maxExtractedFileSize {
			return nil, errors.Join(fmt.Errorf("%w: %s is %d bytes", errArchiveTooLarge, rel, hdr.Size), gz.Close())
		}
		data, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return nil, errors.Join(fmt.Errorf("read archive entry %s: %w", rel, err), gz.Close())
		}
		tree.Files[rel] = data
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("close gzip stream: %w", err)
	}
	if len(tree.Files) == 0 {
		return nil, errArchiveEmpty
	}
	return tree, nil
}

// ArchiveSource locates the upstream archive for one commit.
//
// Load tries, in order: ArchivePath, the cache file, a `git archive` of the local
// repository, and finally a download. Offline mode skips the download and fails clearly.
type ArchiveSource struct {
	// ArchivePath is an explicit tar.gz file. It overrides the cache.
	ArchivePath string
	// CacheDir stores <sha>.tar.gz files. Empty selects the per-user cache directory.
	CacheDir string
	// GitDir is a local repository that may hold the commit. Empty disables the git source.
	GitDir string
	// Offline forbids network access.
	Offline bool
	// BaseURL is the codeload base URL. Empty selects DefaultCodeloadBaseURL.
	BaseURL    string
	HTTPClient *http.Client
}

// DefaultArchiveCacheDir returns the per-user directory that caches upstream archives.
func DefaultArchiveCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache directory: %w", err)
	}
	return filepath.Join(base, "gvx", "upstream"), nil
}

// CachePath returns the cache file path for sha.
func (s ArchiveSource) CachePath(sha string) (string, error) {
	dir := s.CacheDir
	if dir == "" {
		var err error
		if dir, err = DefaultArchiveCacheDir(); err != nil {
			return "", err
		}
	}
	return filepath.Join(dir, sha+archiveCacheSuffix), nil
}

// Load returns the upstream tree for sha.
func (s ArchiveSource) Load(ctx context.Context, sha string) (*UpstreamTree, error) {
	sha, err := ValidateCommitSHA(sha)
	if err != nil {
		return nil, err
	}
	if s.ArchivePath != "" {
		return readArchiveFile(s.ArchivePath, sha)
	}
	cachePath, err := s.CachePath(sha)
	if err != nil {
		return nil, err
	}
	tree, err := readArchiveFile(cachePath, sha)
	if err == nil {
		return tree, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if s.GitDir != "" {
		if gitErr := writeGitArchive(ctx, s.GitDir, sha, cachePath); gitErr == nil {
			return readArchiveFile(cachePath, sha)
		} else if !errors.Is(gitErr, errGitObjectMissing) {
			return nil, gitErr
		}
	}
	if s.Offline {
		return nil, fmt.Errorf("%w: %s (cache file %s; run once without -offline to download it)", errArchiveMissing, sha, cachePath)
	}
	if err := s.download(ctx, sha, cachePath); err != nil {
		return nil, err
	}
	return readArchiveFile(cachePath, sha)
}

func readArchiveFile(p, sha string) (_ *UpstreamTree, err error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("open upstream archive: %w", err)
	}
	defer func() {
		err = errors.Join(err, f.Close())
	}()
	tree, err := ReadUpstreamArchive(f, sha)
	if err != nil {
		return nil, fmt.Errorf("read upstream archive %s: %w", p, err)
	}
	return tree, nil
}

func (s ArchiveSource) download(ctx context.Context, sha, cachePath string) (err error) {
	base := s.BaseURL
	if base == "" {
		base = DefaultCodeloadBaseURL
	}
	client := s.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	url := strings.TrimRight(base, "/") + "/" + sha
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer func() {
		err = errors.Join(err, resp.Body.Close())
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %d from %s", errHTTPStatus, resp.StatusCode, url)
	}
	return writeCacheFile(cachePath, resp.Body)
}

// writeCacheFile stores r at cachePath through a temporary file so readers never see a partial archive.
func writeCacheFile(cachePath string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(cachePath), ".download-*")
	if err != nil {
		return fmt.Errorf("create temporary cache file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, r); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", tmpName, err), tmp.Close(), os.Remove(tmpName))
	}
	if err := tmp.Close(); err != nil {
		return errors.Join(fmt.Errorf("close %s: %w", tmpName, err), os.Remove(tmpName))
	}
	if err := os.Rename(tmpName, cachePath); err != nil {
		return errors.Join(fmt.Errorf("rename %s to %s: %w", tmpName, cachePath, err), os.Remove(tmpName))
	}
	return nil
}

// writeGitArchive writes `git archive` output of sha to cachePath.
// It returns errGitObjectMissing when the repository lacks the commit.
func writeGitArchive(ctx context.Context, gitDir, sha, cachePath string) error {
	if err := exec.CommandContext(ctx, "git", "-C", gitDir, "cat-file", "-e", sha+"^{commit}").Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("%w: %s", errGitObjectMissing, sha)
		}
		return fmt.Errorf("run git cat-file: %w", err)
	}
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "git", "-C", gitDir, "archive", "--format=tar.gz", "--prefix=gvisor-"+sha+"/", sha)
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git archive %s: %w: %s", sha, err, strings.TrimSpace(stderr.String()))
	}
	return writeCacheFile(cachePath, &out)
}

// UpstreamGoFiles lists the Go and assembly paths in tree that the mask does not exclude.
func (t *UpstreamTree) UpstreamGoFiles(mask *FileMask) (included []string, excluded int) {
	for rel := range t.Files {
		if !isGoSource(rel) {
			continue
		}
		if mask != nil && mask.Decide(rel) == MaskExclude {
			excluded++
			continue
		}
		included = append(included, rel)
	}
	return included, excluded
}

// pristine returns the upstream bytes of rel with the module path rewritten to the gvx module.
func (t *UpstreamTree) pristine(rel string) ([]byte, bool) {
	raw, ok := t.Files[rel]
	if !ok {
		return nil, false
	}
	if path.Ext(rel) == ".go" || path.Ext(rel) == ".s" {
		return rewriteModulePath(raw), true
	}
	return raw, true
}
