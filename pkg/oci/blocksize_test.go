// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oci

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/erofs"
)

var allBlockSizes = []int{4096, 16384, 65536}

// compileTarWithBlockSize compiles raw with an explicit block size. It skips
// the test when pkg/erofs refuses images of that size in the current build,
// which happens when the size is not a multiple of the sentry page size.
func compileTarWithBlockSize(t *testing.T, raw []byte, bs int) (string, CompileStats) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "layer.erofs")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stats, err := CompileTarToEROFSWithOptions(bytes.NewReader(raw), f, CompileOptions{BlockSize: bs})
	if err != nil {
		t.Fatalf("CompileTarToEROFSWithOptions(block size %d): %v", bs, err)
	}
	probe, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	img, err := erofs.OpenImage(probe)
	if err != nil {
		_ = probe.Close()
		if strings.Contains(err.Error(), "unsupported block size") {
			t.Skipf("pkg/erofs refuses block size %d in this build: %v", bs, err)
		}
		t.Fatalf("erofs.OpenImage: %v", err)
	}
	img.Close()
	return p, stats
}

func TestCompileRoundTripsForEveryBlockSize(t *testing.T) {
	for _, bs := range allBlockSizes {
		t.Run(fmt.Sprint(bs), func(t *testing.T) {
			longTarget := strings.Repeat("t", 3000)
			bigFile := patternBytes(5*bs+123, 41)
			sparse := make([]byte, 40*bs+17)
			copy(sparse[3*bs:], patternBytes(100, 42))
			copy(sparse[len(sparse)-9:], "the-end!!")
			wholeHole := make([]byte, 40*bs)

			entries := []tarEntry{
				dirEntry("etc/"), dirEntry("dev/"), dirEntry("opq/"),
				fileEntry("etc/empty", ""), fileEntry("etc/one", "x"),
				fileEntry("etc/exact", string(patternBytes(bs, 43))),
				fileEntry("etc/plus1", string(patternBytes(bs+1, 44))),
				fileEntry("etc/minus1", string(patternBytes(bs-1, 45))),
				fileEntry("etc/big", string(bigFile)),
				fileEntry("etc/sparse", string(sparse)),
				fileEntry("etc/whole-hole", string(wholeHole)),
				symlinkEntry("etc/short", "one"), symlinkEntry("etc/long", longTarget),
				symlinkEntry("etc/max", strings.Repeat("m", 4095)),
				linkEntry("etc/hard", "etc/one"),
				deviceEntry("dev/null", tar.TypeChar, 1, 3), deviceEntry("dev/loop0", tar.TypeBlock, 7, 0),
				{hdr: tar.Header{Name: "dev/fifo", Typeflag: tar.TypeFifo, Mode: 0o600, ModTime: epoch}},
				{hdr: tar.Header{Name: "etc/ping", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1, ModTime: epoch,
					PAXRecords: map[string]string{
						"SCHILY.xattr.security.capability": "\x01\x00\x00\x02",
						"SCHILY.xattr.user.big":            strings.Repeat("v", 3000),
					}}, data: []byte("p")},
				fileEntry("opq/.wh..wh..opq", ""), fileEntry("opq/kept", "k"), fileEntry("etc/.wh.gone", ""),
			}
			// A directory that spans several blocks and one that fits inline.
			for i := range bs / 10 {
				entries = append(entries, fileEntry(fmt.Sprintf("etc/many/f-%06d", i), "v"))
			}
			for i := range 3 {
				entries = append(entries, fileEntry(fmt.Sprintf("etc/few/f%d", i), "v"))
			}

			p, stats := compileTarWithBlockSize(t, buildTar(t, entries...), bs)
			if stats.BlockSize != bs {
				t.Errorf("stats.BlockSize = %d, want %d", stats.BlockSize, bs)
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if got := int(raw[EROFSSuperBlockOffset+12]); got != bits.TrailingZeros(uint(bs)) {
				t.Errorf("superblock block size bits = %d, want %d", got, bits.TrailingZeros(uint(bs)))
			}
			if len(raw)%bs != 0 || int64(len(raw)) != stats.TotalBytes || uint32(len(raw)/bs) != stats.TotalBlocks {
				t.Errorf("image has %d bytes, stats %+v", len(raw), stats)
			}

			tree := readImage(t, p)
			for name, want := range map[string][]byte{
				"/etc/empty": nil, "/etc/one": []byte("x"), "/etc/hard": []byte("x"),
				"/etc/exact": patternBytes(bs, 43), "/etc/plus1": patternBytes(bs+1, 44), "/etc/minus1": patternBytes(bs-1, 45),
				"/etc/big": bigFile, "/etc/sparse": sparse, "/etc/whole-hole": wholeHole,
			} {
				n := tree[name]
				if n == nil || !bytes.Equal(n.content, want) {
					t.Errorf("%s: content differs (present %v)", name, n != nil)
				}
			}
			if tree["/etc/one"].nid != tree["/etc/hard"].nid || tree["/etc/one"].nlink != 2 {
				t.Error("hardlink is not one inode with nlink 2")
			}
			if tree["/etc/short"].target != "one" || tree["/etc/long"].target != longTarget || len(tree["/etc/max"].target) != 4095 {
				t.Error("symlink targets differ")
			}
			if n := tree["/dev/null"]; n.mode != linux.S_IFCHR|0o600 || n.major != 1 || n.minor != 3 {
				t.Errorf("char device = %+v", n)
			}
			if n := tree["/dev/loop0"]; n.mode != linux.S_IFBLK|0o600 || n.major != 7 || n.minor != 0 {
				t.Errorf("block device = %+v", n)
			}
			if n := tree["/etc/ping"]; n.xattrs["security.capability"] != "\x01\x00\x00\x02" || n.xattrs["user.big"] != strings.Repeat("v", 3000) {
				t.Errorf("xattrs differ: %d entries", len(n.xattrs))
			}
			if n := tree["/opq"]; n.xattrs[OpaqueXattrName] != "y" || tree["/opq/kept"] == nil {
				t.Errorf("opaque dir = %+v", n)
			}
			if n := tree["/etc/gone"]; n == nil || n.mode != linux.S_IFCHR || n.major != 0 || n.minor != 0 {
				t.Errorf("whiteout = %+v", n)
			}
			many := tree["/etc/many"]
			if len(many.children) != bs/10 || many.size <= uint64(bs) {
				t.Errorf("multi-block directory has %d children and size %d", len(many.children), many.size)
			}
			if len(tree["/etc/few"].children) != 3 {
				t.Errorf("small directory has %d children", len(tree["/etc/few"].children))
			}
			for _, name := range []string{"/etc/sparse", "/etc/whole-hole"} {
				if got := dataLayoutOf(t, p, name); got != erofs.InodeDataLayoutChunkBased {
					t.Errorf("%s data layout = %d, want chunk based", name, got)
				}
			}
			for name, n := range tree {
				if n.mode&linux.S_IFMT == linux.S_IFREG {
					if got := dataLayoutOf(t, p, name); got == erofs.InodeDataLayoutFlatInline {
						t.Errorf("regular file %s is tail-packed, which the sentry cannot map", name)
					}
				}
			}
		})
	}
}

func dataLayoutOf(t *testing.T, imagePath, name string) uint16 {
	t.Helper()
	f, err := os.Open(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	img, err := erofs.OpenImage(f)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	ino, err := img.Inode(img.RootNid())
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range strings.Split(strings.Trim(name, "/"), "/") {
		nid, err := ino.Lookup(part)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		if ino, err = img.Inode(nid); err != nil {
			t.Fatal(err)
		}
	}
	return ino.DataLayout()
}

func TestCompileRejectsInvalidBlockSizes(t *testing.T) {
	raw := buildTar(t, fileEntry("f", "x"))
	for _, bs := range []int{-4096, 1, 512, 2048, 4097, 5000, 8191, 131072, 1 << 20} {
		if _, err := CompileTarToEROFSWithOptions(bytes.NewReader(raw), newMemImage(), CompileOptions{BlockSize: bs}); err == nil {
			t.Errorf("block size %d was accepted", bs)
		}
		if _, err := NewLayerCacheWithOptions(t.TempDir(), CacheOptions{BlockSize: bs}); err == nil {
			t.Errorf("cache block size %d was accepted", bs)
		}
	}
	stats, err := CompileTarToEROFSWithOptions(bytes.NewReader(raw), newMemImage(), CompileOptions{})
	if err != nil || stats.BlockSize != DefaultBlockSize {
		t.Errorf("zero block size: stats %+v, err %v", stats, err)
	}
	for _, bs := range allBlockSizes {
		if !ValidBlockSize(bs) {
			t.Errorf("ValidBlockSize(%d) = false", bs)
		}
	}
	if c, err := NewLayerCache(t.TempDir()); err != nil || c.BlockSize() != DefaultBlockSize {
		t.Errorf("NewLayerCache block size = %v, %v", c, err)
	}
}

func TestLayerCachesWithOtherBlockSizesNeverShareFiles(t *testing.T) {
	dir := t.TempDir()
	raw := buildTar(t, dirEntry("d/"), fileEntry("d/f", strings.Repeat("x", 9000)))
	blob := gzipBytes(t, raw)
	digest := sha256Digest(blob)
	hexStr := strings.TrimPrefix(digest, "sha256:")

	caches := make(map[int]*LayerCache)
	paths := make(map[int]string)
	for _, bs := range []int{4096, 16384} {
		c, err := NewLayerCacheWithOptions(dir, CacheOptions{BlockSize: bs})
		if err != nil {
			t.Fatal(err)
		}
		caches[bs] = c
		if want := fmt.Sprintf("%s.gvx-erofs-v3-b%d.erofs", hexStr, bs); filepath.Base(mustLayerPath(t, c, digest)) != want {
			t.Errorf("layer file name = %q, want %q", filepath.Base(mustLayerPath(t, c, digest)), want)
		}
	}

	// Compile with the 16 KiB cache only. The 4 KiB cache must not see it.
	p16, stats, err := caches[16384].CompileAndStore(digest, bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	paths[16384] = p16
	if stats.BlockSize != 16384 || stats.TotalBytes%16384 != 0 {
		t.Errorf("stats = %+v", stats)
	}
	if _, ok := caches[4096].HasLayer(digest); ok {
		t.Error("the 4 KiB cache served a 16 KiB layer")
	}
	if _, err := caches[4096].OpenLayerHandles([]string{digest}); err == nil {
		t.Error("the 4 KiB cache opened a 16 KiB layer")
	}

	// Compiling in the 4 KiB cache leaves the 16 KiB files untouched.
	before, err := os.ReadFile(p16)
	if err != nil {
		t.Fatal(err)
	}
	p4, stats4, err := caches[4096].CompileAndStore(digest, bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if p4 == p16 || stats4.BlockSize != 4096 {
		t.Errorf("4 KiB layer path %q, stats %+v", p4, stats4)
	}
	after, err := os.ReadFile(p16)
	if err != nil || !bytes.Equal(before, after) {
		t.Errorf("the 16 KiB layer changed (err %v)", err)
	}
	fresh, _ := NewLayerCacheWithOptions(dir, CacheOptions{BlockSize: 16384})
	if _, ok := fresh.HasLayer(digest); !ok {
		t.Error("the 16 KiB layer is no longer valid")
	}

	// A record written for one block size is rejected by the other format.
	record, err := os.ReadFile(caches[16384].sumPath(hexStr))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := caches[4096].parseSumRecord(record); err == nil {
		t.Error("a 4 KiB cache accepted a 16 KiB integrity record")
	}
}

func mustLayerPath(t *testing.T, c *LayerCache, digest string) string {
	t.Helper()
	p, err := c.LayerPath(digest)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestImageAndTagRecordsAreKeyedByBlockSize(t *testing.T) {
	reg := newFakeRegistry(t)
	img := twoLayerImage(t, "amd64", "A=1")
	reg.tag("v1", reg.addImage(img))
	dir := t.TempDir()
	base, repo := pullArgs(reg)

	small, err := NewLayerCacheWithOptions(dir, CacheOptions{BlockSize: 4096})
	if err != nil {
		t.Fatal(err)
	}
	got := mustPull(t, reg, small, "v1", "amd64")
	if got.LayerPaths[0] != filepath.Join(dir, got.LayerDigests[0]+".gvx-erofs-v3-b4096.erofs") {
		t.Errorf("layer path = %q", got.LayerPaths[0])
	}

	// A cache of another block size over the same directory has no image
	// and no tag, and a pull compiles its own layers.
	large, err := NewLayerCacheWithOptions(dir, CacheOptions{BlockSize: 16384})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := large.LoadCachedImage(base, repo, "v1", "amd64"); !errors.Is(err, ErrNotCached) {
		t.Errorf("16 KiB cache LoadCachedImage: err = %v, want ErrNotCached", err)
	}
	if _, err := large.LoadCachedImage(base, repo, img.digest(), "amd64"); !errors.Is(err, ErrNotCached) {
		t.Errorf("16 KiB cache LoadCachedImage by digest: err = %v, want ErrNotCached", err)
	}
	pulled := mustPull(t, reg, large, "v1", "amd64")
	for _, p := range pulled.LayerPaths {
		if !strings.HasSuffix(p, ".gvx-erofs-v3-b16384.erofs") {
			t.Errorf("layer path %q is not in the 16 KiB format", p)
		}
	}
	if pulled.LayerDigests[0] != got.LayerDigests[0] {
		t.Errorf("layer digests differ between block sizes")
	}
	// Both caches now serve their own files offline.
	reg.srv.Close()
	for _, bs := range []int{4096, 16384} {
		c, _ := NewLayerCacheWithOptions(dir, CacheOptions{BlockSize: bs})
		loaded, err := c.LoadCachedImage(base, repo, "v1", "amd64")
		if err != nil {
			t.Fatalf("block size %d: %v", bs, err)
		}
		if want := fmt.Sprintf(".gvx-erofs-v3-b%d.erofs", bs); !strings.HasSuffix(loaded.LayerPaths[1], want) {
			t.Errorf("block size %d: layer path %q", bs, loaded.LayerPaths[1])
		}
		loaded.Close()
	}

	// An image record whose format differs from the cache's is not trusted.
	recPath := large.imageRecordPath(base, repo, img.digest(), "amd64")
	raw, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), `"format":"gvx-erofs-v3-b16384"`, `"format":"gvx-erofs-v3-b4096"`, 1)
	if edited == string(raw) {
		t.Fatalf("record %s does not name its format", raw)
	}
	if err := os.WriteFile(recPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := large.LoadCachedImage(base, repo, "v1", "amd64"); !errors.Is(err, ErrNotCached) {
		t.Errorf("record with a foreign format: err = %v, want ErrNotCached", err)
	}

	if _, err := small.ImportCachedImage(large, base, repo, "v1", "amd64"); err == nil {
		t.Error("ImportCachedImage accepted a source cache with another block size")
	}
}
