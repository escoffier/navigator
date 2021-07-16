package cryption

import (
	"bytes"
	"crypto/md5"
	binary "encoding/binary"
	"errors"
)

type DataHeader struct {
	_     	   [2]byte
	Offset     uint16
	MD5Checksum [16]byte
}

func (dh *DataHeader) dump(data []byte) ([]byte, error) {
	dh.Offset = dataHeaderSize
	buf := new(bytes.Buffer)
	dh.MD5Checksum = md5.Sum(data)
	err := binary.Write(buf, binary.LittleEndian, dh)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func readDataBlock(blockData []byte) (DataHeader,[]byte, error) {
	header := DataHeader{}
	err := binary.Read(bytes.NewBuffer(blockData[:dataHeaderSize]), binary.LittleEndian, &header)
	if err != nil {
		return DataHeader{}, nil, err
	}
	if int(header.Offset) > len(blockData) {
		return DataHeader{}, nil, errors.New("offset error")
	}
	retBytes := blockData[header.Offset:]
	if header.MD5Checksum != md5.Sum(retBytes) {
		return DataHeader{}, nil, errors.New("md5 error")
	}
	return header, retBytes, nil
}