package clamavengin

import (
	"fmt"
	"os"
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

type ClamavEngin struct {
	engine *Engine
}

func clErr(err C.cl_error_t) string {
	return C.GoString(C.cl_strerror(C.int(err)))
}

func GetClamavEngin() (*ClamavEngin, error) {

	eng := (*Engine)(C.cl_engine_new())
	if eng == nil {
		return nil, fmt.Errorf("new clamav engine failed")
	}
	return &ClamavEngin{engine: eng}, nil
}

func (cs *ClamavEngin) CloseClEngine() error {
	err := C.cl_engine_free((*C.struct_cl_engine)(cs.engine))
	if err != C.CL_SUCCESS {
		return fmt.Errorf("close engine err.%v", clErr(err))
	}
	return nil
}

func (cs *ClamavEngin) ReloadDB(path string) error {
	_, err2 := os.Stat(path)
	if err2 != nil {
		return err2
	}

	var signo uint
	fp := C.CString(path)
	defer C.free(unsafe.Pointer(fp))
	err := C.cl_load(fp, (*C.struct_cl_engine)(cs.engine), (*C.uint)(unsafe.Pointer(&signo)), C.uint(DbDefaultOpt))
	if err != C.CL_SUCCESS {
		return fmt.Errorf("load db err: %v", clErr(err))
	}
	err = C.cl_engine_compile((*C.struct_cl_engine)(cs.engine))
	if err != C.CL_SUCCESS {
		return fmt.Errorf("compile err:%v", clErr(err))
	}
	return nil
}

func (cs *ClamavEngin) ScanFile(path string) (string, error) {
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
		return "", nil
	}
	if err == C.CL_VIRUS {
		return C.GoString(name), nil
	}

	return "", fmt.Errorf(clErr(err))
}
