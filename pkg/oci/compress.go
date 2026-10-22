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
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// compression identifies the encoding of a layer or archive stream.
type compression int

const (
	compressionNone compression = iota
	compressionGzip
	compressionZstd
	compressionXZ
	compressionBzip2
)

// magicPeekLen is the number of leading bytes that detectCompression needs.
const magicPeekLen = 10

var (
	gzipMagic     = []byte{0x1f, 0x8b}
	zstdMagic     = []byte{0x28, 0xb5, 0x2f, 0xfd}
	xzMagic       = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}
	bzip2Magic    = []byte{'B', 'Z', 'h'}
	bzip2BlockTag = []byte{0x31, 0x41, 0x59, 0x26, 0x53, 0x59}
)

// detectCompression classifies a stream by its leading bytes. A zstd stream
// can begin with a skippable frame, whose magic is 0x184D2A5? in little endian.
func detectCompression(head []byte) compression {
	switch {
	case bytes.HasPrefix(head, gzipMagic):
		return compressionGzip
	case bytes.HasPrefix(head, zstdMagic):
		return compressionZstd
	case len(head) >= 4 && head[0]&0xf0 == 0x50 && head[1] == 0x2a && head[2] == 0x4d && head[3] == 0x18:
		return compressionZstd
	case bytes.HasPrefix(head, xzMagic):
		return compressionXZ
	case len(head) >= 4+len(bzip2BlockTag) && bytes.HasPrefix(head, bzip2Magic) &&
		head[3] >= '1' && head[3] <= '9' && bytes.Equal(head[4:4+len(bzip2BlockTag)], bzip2BlockTag):
		return compressionBzip2
	default:
		return compressionNone
	}
}

// openDecompressed returns a reader of the uncompressed bytes of r. The caller
// must close it. Closing releases the decoder but never closes r.
func openDecompressed(r io.Reader, lim Limits) (io.ReadCloser, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	head, err := br.Peek(magicPeekLen)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("oci: read stream header: %w", err)
	}
	switch detectCompression(head) {
	case compressionGzip:
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("oci: open gzip stream: %w", err)
		}
		return gz, nil
	case compressionZstd:
		// One decoder goroutine-free stream, and a window cap that bounds the
		// decoder memory regardless of what the frame header claims.
		dec, err := zstd.NewReader(br,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxWindow(lim.MaxZstdWindowBytes),
			zstd.WithDecoderMaxMemory(lim.MaxZstdWindowBytes),
		)
		if err != nil {
			return nil, fmt.Errorf("oci: open zstd stream: %w", err)
		}
		return dec.IOReadCloser(), nil
	case compressionXZ:
		return nil, errors.New("oci: xz-compressed layers are not supported")
	case compressionBzip2:
		return nil, errors.New("oci: bzip2-compressed layers are not supported")
	default:
		return io.NopCloser(br), nil
	}
}
