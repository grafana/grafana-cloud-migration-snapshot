package ioext

import (
	"errors"
	"io"
)

var ErrMaxNumberOfBytesRead = errors.New("the configured maximum number of bytes has been read from the underlying io.Reader")

// Limits the number of bytes that can be read from a `io.Reader`.
type WithSizeLimitReader struct {
	r            io.Reader
	numBytesRead int
	maxNumBytes  int
}

// Pass 0 as argument for `maxNumBytes` to disable the limit.
func NewWithSizeLimitReader(r io.Reader, maxNumBytes int) *WithSizeLimitReader {
	return &WithSizeLimitReader{r: r, maxNumBytes: maxNumBytes}
}

func (limiter *WithSizeLimitReader) Read(p []byte) (n int, err error) {
	n, err = limiter.r.Read(p)
	limiter.numBytesRead += n

	if limiter.maxNumBytes != 0 && limiter.numBytesRead > limiter.maxNumBytes {
		return n, ErrMaxNumberOfBytesRead
	}
	return n, err
}
