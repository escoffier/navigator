package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"
)

const (
	CTA_IP_V4_SRC = 1
	CTA_IP_V4_DST = 2
	CTA_IP_V6_SRC = 3
	CTA_IP_V6_DST = 4
)

const (
	CTA_PROTO_NUM           = 1
	CTA_PROTO_SRC_PORT      = 2
	CTA_PROTO_DST_PORT      = 3
	CTA_PROTOINFO_TCP       = 1
	CTA_PROTOINFO_TCP_STATE = 1
)

const (
	SizeofNfgenmsg      = 4
	SizeofNfattr        = 4
	SizeofNfConntrack   = 376
	SizeofNfctTupleHead = 52
)

var L4ProtoMap = map[uint8]string{
	6:  "tcp",
	17: "udp",
}

const (
	// backward compatibility with golang 1.6 which does not have io.SeekCurrent
	seekCurrent = 1
)

const (
	CTA_COUNTERS_PACKETS = 1
	CTA_COUNTERS_BYTES   = 2
)

const (
	CTA_TIMESTAMP_START = 1
	CTA_TIMESTAMP_STOP  = 2
)

const (
	NLA_F_NESTED        uint16 = (1 << 15) // #define NLA_F_NESTED (1 << 15)
	NLA_F_NET_BYTEORDER uint16 = (1 << 14) // #define NLA_F_NESTED (1 << 14)
	NLA_TYPE_MASK              = ^(NLA_F_NESTED | NLA_F_NET_BYTEORDER)
	NLA_ALIGNTO         uint16 = 4 // #define NLA_ALIGNTO 4
)

const (
	CTA_TUPLE_ORIG     = 1
	CTA_TUPLE_REPLY    = 2
	CTA_STATUS         = 3
	CTA_PROTOINFO      = 4
	CTA_TIMEOUT        = 7
	CTA_MARK           = 8
	CTA_COUNTERS_ORIG  = 9
	CTA_COUNTERS_REPLY = 10
	CTA_USE            = 11
	CTA_ID             = 12
	CTA_TIMESTAMP      = 20
)

const (
	CTA_TUPLE_IP    = 1
	CTA_TUPLE_PROTO = 2
)

type ipTuple struct {
	Bytes    uint64
	DstIP    net.IP
	DstPort  uint16
	Packets  uint64
	Protocol uint8
	SrcIP    net.IP
	SrcPort  uint16
}

type ConntrackFlow struct {
	FamilyType uint8
	TcpState   uint8
	Forward    ipTuple
	Reverse    ipTuple
	Mark       uint32
	TimeStart  uint64
	TimeStop   uint64
	TimeOut    uint32
}

var nativeEndian binary.ByteOrder

// NativeEndian gets native endianness for the system
func NativeEndian() binary.ByteOrder {
	if nativeEndian == nil {
		var x uint32 = 0x01020304
		if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
			nativeEndian = binary.BigEndian
		} else {
			nativeEndian = binary.LittleEndian
		}
	}
	return nativeEndian
}

func (s *ConntrackFlow) String() string {
	// conntrack cmd output:
	// udp      17 src=127.0.0.1 dst=127.0.0.1 sport=4001 dport=1234 packets=5 bytes=532 [UNREPLIED] src=127.0.0.1 dst=127.0.0.1 sport=1234 dport=4001 packets=10 bytes=1078 mark=0
	//             start=2019-07-26 01:26:21.557800506 +0000 UTC stop=1970-01-01 00:00:00 +0000 UTC timeout=30(sec)
	start := time.Unix(0, int64(s.TimeStart))
	stop := time.Unix(0, int64(s.TimeStop))
	timeout := int32(s.TimeOut)
	return fmt.Sprintf("%s\t%d src=%s dst=%s sport=%d dport=%d packets=%d bytes=%d\tsrc=%s dst=%s sport=%d dport=%d packets=%d bytes=%d mark=0x%x start=%v stop=%v timeout=%d(sec)",
		L4ProtoMap[s.Forward.Protocol], s.Forward.Protocol,
		s.Forward.SrcIP.String(), s.Forward.DstIP.String(), s.Forward.SrcPort, s.Forward.DstPort, s.Forward.Packets, s.Forward.Bytes,
		s.Reverse.SrcIP.String(), s.Reverse.DstIP.String(), s.Reverse.SrcPort, s.Reverse.DstPort, s.Reverse.Packets, s.Reverse.Bytes,
		s.Mark, start, stop, timeout)
}

// This method parse the ip tuple structure
// The message structure is the following:
// <len, [CTA_IP_V4_SRC|CTA_IP_V6_SRC], 16 bytes for the IP>
// <len, [CTA_IP_V4_DST|CTA_IP_V6_DST], 16 bytes for the IP>
// <len, NLA_F_NESTED|CTA_TUPLE_PROTO, 1 byte for the protocol, 3 bytes of padding>
// <len, CTA_PROTO_SRC_PORT, 2 bytes for the source port, 2 bytes of padding>
// <len, CTA_PROTO_DST_PORT, 2 bytes for the source port, 2 bytes of padding>
func parseIpTuple(reader *bytes.Reader, tpl *ipTuple) uint8 {
	for i := 0; i < 2; i++ {
		_, t, _, v := parseNfAttrTLV(reader)
		switch t {
		case CTA_IP_V4_SRC, CTA_IP_V6_SRC:
			tpl.SrcIP = v
		case CTA_IP_V4_DST, CTA_IP_V6_DST:
			tpl.DstIP = v
		}
	}
	// Get total length of nested protocol-specific info.
	_, _, protoInfoTotalLen := parseNfAttrTL(reader)
	_, t, l, v := parseNfAttrTLV(reader)
	// Track the number of bytes read.
	protoInfoBytesRead := uint16(SizeofNfattr) + l
	if t == CTA_PROTO_NUM {
		tpl.Protocol = uint8(v[0])
	}
	// We only parse TCP & UDP headers. Skip the others.
	if tpl.Protocol != IPPROTO_TCP && tpl.Protocol != IPPROTO_UDP {
		// skip the rest
		bytesRemaining := protoInfoTotalLen - protoInfoBytesRead
		_, _ = reader.Seek(int64(bytesRemaining), seekCurrent)
		return tpl.Protocol
	}
	// Skip 3 bytes of padding
	_, _ = reader.Seek(3, seekCurrent)
	protoInfoBytesRead += 3
	for i := 0; i < 2; i++ {
		_, t, _ := parseNfAttrTL(reader)
		protoInfoBytesRead += uint16(SizeofNfattr)
		switch t {
		case CTA_PROTO_SRC_PORT:
			parseBERaw16(reader, &tpl.SrcPort)
			protoInfoBytesRead += 2
		case CTA_PROTO_DST_PORT:
			parseBERaw16(reader, &tpl.DstPort)
			protoInfoBytesRead += 2
		}
		// Skip 2 bytes of padding
		_, _ = reader.Seek(2, seekCurrent)
		protoInfoBytesRead += 2
	}
	// Skip any remaining/unknown parts of the message
	bytesRemaining := protoInfoTotalLen - protoInfoBytesRead
	_, _ = reader.Seek(int64(bytesRemaining), seekCurrent)
	return tpl.Protocol
}

func parseNfAttrTLV(r *bytes.Reader) (isNested bool, attrType, len uint16, value []byte) {
	isNested, attrType, len = parseNfAttrTL(r)

	value = make([]byte, len)
	_ = binary.Read(r, binary.BigEndian, &value)
	return isNested, attrType, len, value
}

func parseNfAttrTL(r *bytes.Reader) (isNested bool, attrType, len uint16) {
	_ = binary.Read(r, NativeEndian(), &len)
	len -= SizeofNfattr

	_ = binary.Read(r, NativeEndian(), &attrType)
	isNested = (attrType & NLA_F_NESTED) == NLA_F_NESTED
	attrType = attrType & (NLA_F_NESTED - 1)
	return isNested, attrType, len
}

func skipNfAttrValue(r *bytes.Reader, len uint16) {
	len = (len + NLA_ALIGNTO - 1) & ^(NLA_ALIGNTO - 1)
	_, _ = r.Seek(int64(len), seekCurrent)
}

func parseBERaw16(r *bytes.Reader, v *uint16) {
	_ = binary.Read(r, binary.BigEndian, v)
}

func parseBERaw32(r *bytes.Reader, v *uint32) {
	_ = binary.Read(r, binary.BigEndian, v)
}

func parseBERaw64(r *bytes.Reader, v *uint64) {
	_ = binary.Read(r, binary.BigEndian, v)
}

func parseByteAndPacketCounters(r *bytes.Reader) (bytes, packets uint64) {
	for i := 0; i < 2; i++ {
		switch _, t, _ := parseNfAttrTL(r); t {
		case CTA_COUNTERS_BYTES:
			parseBERaw64(r, &bytes)
		case CTA_COUNTERS_PACKETS:
			parseBERaw64(r, &packets)
		default:
			return
		}
	}
	return
}

// when the flow is alive, only the timestamp_start is returned in structure
func parseTimeStamp(r *bytes.Reader, readSize uint16) (tstart, tstop uint64) {
	var numTimeStamps int
	oneItem := SizeofNfattr + 8 // 4 bytes attr header + 8 bytes timestamp
	if readSize == uint16(oneItem) {
		numTimeStamps = 1
	} else if readSize == 2*uint16(oneItem) {
		numTimeStamps = 2
	} else {
		return
	}

	for i := 0; i < numTimeStamps; i++ {
		switch _, t, _ := parseNfAttrTL(r); t {
		case CTA_TIMESTAMP_START:
			parseBERaw64(r, &tstart)
		case CTA_TIMESTAMP_STOP:
			parseBERaw64(r, &tstop)
		default:
			return
		}
	}
	return

}

func parseTimeOut(r *bytes.Reader) (ttimeout uint32) {
	parseBERaw32(r, &ttimeout)
	return
}

func parseConnectionMark(r *bytes.Reader) (mark uint32) {
	parseBERaw32(r, &mark)
	return
}

func parseProtoInfoTcpState(r *bytes.Reader, length uint16) (uint8, uint16) {
	//fmt.Printf("proto info length : %v.\n", length)
	var nlaLen, nlaType, offset uint16
	//get nla len
	_ = binary.Read(r, NativeEndian(), &nlaLen)
	//get nla type
	_ = binary.Read(r, NativeEndian(), &nlaType)
	//offset
	offset = SizeofNfattr
	//get type
	if nlaType&NLA_TYPE_MASK != CTA_PROTOINFO_TCP {
		return 0, offset
	}

	//get nla len
	_ = binary.Read(r, NativeEndian(), &nlaLen)
	//get nla type
	_ = binary.Read(r, NativeEndian(), &nlaType)
	//offset
	offset += SizeofNfattr
	//get type
	if nlaType&NLA_TYPE_MASK != CTA_PROTOINFO_TCP_STATE {
		return 0, offset
	}
	//tcp state
	var tcpState uint8
	//get tcp state
	_ = binary.Read(r, NativeEndian(), &tcpState)
	//offset
	offset += 1

	return tcpState, offset
}

func ParseRawData(data []byte) *ConntrackFlow {
	s := &ConntrackFlow{}
	// First there is the Nfgenmsg header
	// consume only the family field
	reader := bytes.NewReader(data)
	_ = binary.Read(reader, NativeEndian(), &s.FamilyType)

	// skip rest of the Netfilter header
	_, _ = reader.Seek(3, seekCurrent)
	// The message structure is the following:
	// <len, NLA_F_NESTED|CTA_TUPLE_ORIG> 4 bytes
	// <len, NLA_F_NESTED|CTA_TUPLE_IP> 4 bytes
	// flow information of the forward flow
	// <len, NLA_F_NESTED|CTA_TUPLE_REPLY> 4 bytes
	// <len, NLA_F_NESTED|CTA_TUPLE_IP> 4 bytes
	// flow information of the reverse flow
	for reader.Len() > 0 {
		if nested, t, l := parseNfAttrTL(reader); nested {
			switch t {
			case CTA_TUPLE_ORIG:
				if nested, t, _ = parseNfAttrTL(reader); nested && t == CTA_TUPLE_IP {
					parseIpTuple(reader, &s.Forward)
				}
			case CTA_TUPLE_REPLY:
				if nested, t, l = parseNfAttrTL(reader); nested && t == CTA_TUPLE_IP {
					parseIpTuple(reader, &s.Reverse)
				} else {
					// Header not recognized skip it
					skipNfAttrValue(reader, l)
				}
			case CTA_COUNTERS_ORIG:
				s.Forward.Bytes, s.Forward.Packets = parseByteAndPacketCounters(reader)
			case CTA_COUNTERS_REPLY:
				s.Reverse.Bytes, s.Reverse.Packets = parseByteAndPacketCounters(reader)
			case CTA_TIMESTAMP:
				s.TimeStart, s.TimeStop = parseTimeStamp(reader, l)
			case CTA_PROTOINFO:
				var offset uint16
				s.TcpState, offset = parseProtoInfoTcpState(reader, l)
				skipNfAttrValue(reader, offset)
			default:
				skipNfAttrValue(reader, l)
			}
		} else {
			switch t {
			case CTA_MARK:
				s.Mark = parseConnectionMark(reader)
			case CTA_TIMEOUT:
				s.TimeOut = parseTimeOut(reader)
			case CTA_STATUS, CTA_USE, CTA_ID:
				skipNfAttrValue(reader, l)
			default:
				skipNfAttrValue(reader, l)
			}
		}
	}

	return s
}
