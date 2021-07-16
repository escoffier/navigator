package cryption

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"math/rand"
	"time"
)

type FileHeader struct {
	_           [1]byte
	MagicNum	[6]byte
	Offset 		uint16
	BlockSize	uint8
	BlockNum    uint32
	MD5Offset 	uint8
	Version   	[2]uint16
	Action    	uint8 //update: reload, gen diff etc.
	MD5      	[16]byte
}

func (fh *FileHeader) Init(md5sum []byte) {
	var magicNum [6]byte
	for k, v := range []byte("tensor"){
		magicNum[k] = byte(v)
	}
	fh.MagicNum = magicNum
	fh.Offset = fileHeaderSize
	fh.BlockSize = dataHeaderSize + dataBlockSize
	rand.Seed(time.Now().UnixNano())
	fh.MD5Offset = uint8(rand.Uint32() % md5.Size)
	i := uint8(0)
	for ; i < md5.Size; i++ {
		fh.MD5[i] = md5sum[(i + fh.MD5Offset) % md5.Size]
	}
}

func readHeader(fData []byte) (FileHeader, error) {

	//dataBytes := make([]byte, unsafe.Sizeof(FileHeader{}))
	data := FileHeader{}
	//n, err := fp.Read(dataBytes)
	//if err != nil {
	//	return FileHeader{}, err
	//}
	//dataBytes = dataBytes[:n]

	err := binary.Read(bytes.NewBuffer(fData), binary.LittleEndian, &data)
	if err != nil {
		return data, err
	}
	return data, nil
}