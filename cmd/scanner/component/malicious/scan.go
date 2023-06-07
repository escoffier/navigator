package malicious

import (
	"fmt"
	"unsafe"
)

// if you use none-system dir for libxxx.so, you need use follow command to compile
// for eg:
// "export LD_LIBRARY_PATH=/root/go/src/github.com/wadeling/scanner-clamav/component/lib/:$LD_LIBRARY_PATH"
// #cgo CFLAGS: -I./lib
// #cgo LDFLAGS:-L${SRCDIR}/lib -Wl,-rpath,$SRCDIR/lib -lclamav

/*
#cgo LDFLAGS:-L/usr/lib/x86_64-linux-gnu -lclamav
#include "clamav.h"
#include <stdlib.h>
*/
import "C"

const (
	DbDefaultOpt = C.CL_DB_STDOPT
)

type Engine C.struct_cl_engine

type ClamavScanner struct {
	engine *Engine
}

func ClErrString(err C.cl_error_t) string {
	return C.GoString(C.cl_strerror(C.int(err)))
}

func InitClamav() error {
	err := C.cl_init(C.uint(C.CL_INIT_DEFAULT))
	if err != C.CL_SUCCESS {
		return fmt.Errorf("init err.%v", ClErrString(err))
	}
	return nil
}

func NewClamavScanner() *ClamavScanner {
	return &ClamavScanner{}
}

func (cs *ClamavScanner) InitClEngine() error {
	eng := (*Engine)(C.cl_engine_new())
	//if (*C.struct_cl_engine)(eng) == C.NULL {
	if eng == nil {
		return fmt.Errorf("new cl engine failed")
	}
	cs.engine = eng
	return nil
}

func (cs *ClamavScanner) CloseClEngine() error {
	err := C.cl_engine_free((*C.struct_cl_engine)(cs.engine))
	if err != C.CL_SUCCESS {
		return fmt.Errorf("close engine err.%v", ClErrString(err))
	}
	return nil
}

func (cs *ClamavScanner) Load(path string, dbopts uint) (uint, error) {
	var signo uint
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	err := C.cl_load(cpath, (*C.struct_cl_engine)(cs.engine), (*C.uint)(unsafe.Pointer(&signo)), C.uint(dbopts))
	if err != C.CL_SUCCESS {
		return 0, fmt.Errorf("load db err: %v", ClErrString(err))
	}
	return signo, nil
}

// Compile called after load database
func (cs *ClamavScanner) Compile() error {
	err := C.cl_engine_compile((*C.struct_cl_engine)(cs.engine))
	if err != C.CL_SUCCESS {
		return fmt.Errorf("compile err:%v", ClErrString(err))
	}
	return nil
}

func (cs *ClamavScanner) ScanFile(path string) (string, uint, error) {
	var name *C.char
	var scanned C.ulong
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	var opts C.struct_cl_scan_options
	var defaultParseOpt uint32 = 0
	defaultParseOpt = ^defaultParseOpt

	opts.general = SCAN_GENERAL_ALLMATCHES
	opts.parse = (C.uint32_t)(defaultParseOpt)
	opts.heuristic = 0
	opts.mail = 0
	opts.dev = 0
	err := C.cl_scanfile(cpath, &name, &scanned, (*C.struct_cl_engine)(cs.engine), (*C.struct_cl_scan_options)(unsafe.Pointer(&opts)))
	if err == C.CL_CLEAN {
		return "", 0, nil
	}
	if err == C.CL_VIRUS {
		return C.GoString(name), uint(scanned), nil
	}

	return "", 0, fmt.Errorf(ClErrString(err))
}
