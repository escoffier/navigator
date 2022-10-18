package fs

import (
	"hash/crc32"
	"io"
	"os"
)

const (
	hashByteRange int64 = 1024
)

func FileHashCrc32(path string, size int64) uint32 {
	var crc uint32

	if f, err := os.Open(path); err == nil {
		defer func() {
			_ = f.Close()
		}()
		buf := make([]byte, hashByteRange)

		// explore leading section
		if n, err := f.Read(buf); err == nil {
			crc = crc32.ChecksumIEEE(buf[:n])
		}
		if size > hashByteRange {
			// explore ending section
			f.Seek(-hashByteRange, io.SeekEnd)
			if n, err := f.Read(buf); err == nil {
				crc += crc32.ChecksumIEEE(buf[:n])

			}
		}

		crc += uint32(size)
	}
	return crc
}

func IsExec(mode os.FileMode) bool {
	return mode&0111 != 0
}

func CleanCreateDir(path string) error {
	err := os.RemoveAll(path)
	if err != nil {
		return err
	}
	return os.MkdirAll(path, os.ModePerm)
}
