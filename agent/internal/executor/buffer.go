package executor

import (
	"fmt"
	"sync"

	"github.com/revmcp/revmcp/proto"
)

const minBufferBytes = 256

// HeadTailBuffer is a concurrency-safe bounded io.Writer that retains the beginning
// (25%) and most recent end (75%) of an output stream without unbounded memory growth.
type HeadTailBuffer struct {
	mu      sync.Mutex
	headCap int
	tailCap int

	head     []byte
	tail     []byte
	tailPos  int
	tailFull bool
	dropped  int64
}

// NewHeadTailBuffer creates a bounded buffer clamped to [256, proto.HardMaxOutputBytes].
func NewHeadTailBuffer(maxBytes int) *HeadTailBuffer {
	if maxBytes <= 0 {
		maxBytes = proto.DefaultMaxOutputBytes
	}
	if maxBytes < minBufferBytes {
		maxBytes = minBufferBytes
	}
	if maxBytes > proto.HardMaxOutputBytes {
		maxBytes = proto.HardMaxOutputBytes
	}

	headCap := maxBytes / 4
	tailCap := maxBytes - headCap
	return &HeadTailBuffer{
		headCap: headCap,
		tailCap: tailCap,
		head:    make([]byte, 0, headCap),
		tail:    make([]byte, tailCap),
	}
}

// Write appends p into the head/tail buffers while discarding excess middle bytes.
func (b *HeadTailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	n := len(p)
	if len(b.head) < b.headCap {
		rem := b.headCap - len(b.head)
		if len(p) <= rem {
			b.head = append(b.head, p...)
			return n, nil
		}
		b.head = append(b.head, p[:rem]...)
		p = p[rem:]
	}

	// Remaining bytes go into the circular tail buffer.
	if b.tailCap == 0 {
		b.dropped += int64(len(p))
		return n, nil
	}

	if len(p) >= b.tailCap {
		// Entire tail buffer will be overwritten; count previously stored tail bytes + skipped prefix.
		if b.tailFull {
			b.dropped += int64(b.tailCap)
		} else {
			b.dropped += int64(b.tailPos)
		}
		b.dropped += int64(len(p) - b.tailCap)
		copy(b.tail, p[len(p)-b.tailCap:])
		b.tailPos = 0
		b.tailFull = true
		return n, nil
	}

	for _, ch := range p {
		if b.tailFull {
			b.dropped++
		}
		b.tail[b.tailPos] = ch
		b.tailPos++
		if b.tailPos == b.tailCap {
			b.tailPos = 0
			b.tailFull = true
		}
	}

	return n, nil
}

// Truncated reports whether any bytes were dropped from the middle of the stream.
func (b *HeadTailBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped > 0
}

// Dropped returns the number of dropped middle bytes.
func (b *HeadTailBuffer) Dropped() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

// String renders the captured head, optional truncation marker, and tail bytes.
func (b *HeadTailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	var tailBytes []byte
	if b.tailFull {
		tailBytes = make([]byte, b.tailCap)
		first := copy(tailBytes, b.tail[b.tailPos:])
		copy(tailBytes[first:], b.tail[:b.tailPos])
	} else {
		tailBytes = b.tail[:b.tailPos]
	}

	if b.dropped == 0 {
		out := make([]byte, 0, len(b.head)+len(tailBytes))
		out = append(out, b.head...)
		out = append(out, tailBytes...)
		return string(out)
	}

	marker := fmt.Sprintf("\n... [truncated %d bytes, use grep_file or read_file with offset] ...\n", b.dropped)
	out := make([]byte, 0, len(b.head)+len(marker)+len(tailBytes))
	out = append(out, b.head...)
	out = append(out, marker...)
	out = append(out, tailBytes...)
	return string(out)
}
