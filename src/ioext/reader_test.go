package ioext

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestWithSizeLimitReader(t *testing.T) {
	t.Parallel()

	t.Run("property", func(t *testing.T) {
		t.Parallel()

		rapid.Check(t, func(t *rapid.T) {
			input := string(rapid.SliceOfN(rapid.Byte(), 0, 128).Draw(t, "input"))
			maxNumBytes := rapid.IntRange(0, 128).Draw(t, "maxNumBytes")

			reader := strings.NewReader(input)
			limiter := NewWithSizeLimitReader(reader, maxNumBytes)

			_, err := io.ReadAll(limiter)

			if maxNumBytes != 0 && len(input) > maxNumBytes {
				require.ErrorIs(t, err, ErrMaxNumberOfBytesRead)
			} else {
				require.NoError(t, err)
			}
		})
	})

	t.Run("returns err when max number of bytes is exceeded", func(t *testing.T) {
		t.Parallel()

		reader := strings.NewReader("aaa")
		limiter := NewWithSizeLimitReader(reader, 2)
		_, err := io.ReadAll(limiter)
		require.ErrorIs(t, err, ErrMaxNumberOfBytesRead)
	})

	t.Run("doesn't return error when max number of bytes is not exceeded", func(t *testing.T) {
		t.Parallel()

		reader := strings.NewReader("aaa")
		limiter := NewWithSizeLimitReader(reader, 3)
		_, err := io.ReadAll(limiter)
		require.NoError(t, err)
	})
}
