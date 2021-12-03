package offline

// func writeOutputFile(fp *os.File, header *cryption.FileHeader, data []byte) error {
//
//	buf := new(bytes.Buffer)
//	err := binary.Write(buf, binary.LittleEndian, header)
//	if err != nil {
//		return err
//	}
//	_, err = fp.Write(buf.Bytes())
//	if err != nil {
//		return err
//	}
//	_, err = fp.Write(data)
//	if err != nil {
//		return err
//	}
//	err = fp.Sync()
//	if err != nil {
//		return err
//	}
//	return nil
// }
