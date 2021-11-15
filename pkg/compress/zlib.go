package compress

import (
	"bytes"
	"compress/zlib"
	"io"
)

func ZlipCompress(src []byte) ([]byte, error) {
	var in bytes.Buffer

	w := zlib.NewWriter(&in)

	_, err := w.Write(src)
	if err != nil {
		return nil, err
	}

	_ = w.Close()

	return in.Bytes(), nil
}

func ZlipDecompress(src []byte) ([]byte, error) {
	b := bytes.NewReader(src)
	var out bytes.Buffer

	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}

	defer func() { _ = r.Close() }()

	_, err = io.Copy(&out, r)
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
