package prepare

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/atomic"
)

type Semaphore struct {
	MG    sync.Locker
	Max   int64
	value *atomic.Int64
}

func NewSemaphore(initialValue int64) *Semaphore {
	s := &Semaphore{
		MG:    &sync.Mutex{},
		value: atomic.NewInt64(0),
		Max:   initialValue,
	}
	return s
}

func (s *Semaphore) Acquire() {
	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()
	for {
		s.MG.Lock()
		if s.value.Load() < s.Max {
			s.value.Add(1)
			s.MG.Unlock()
			return
		}
		s.MG.Unlock()
		<-ticker.C
	}
}

func (s *Semaphore) Release() {
	s.MG.Lock()
	defer s.MG.Unlock()
	s.value.Dec()
}

var webshellMap = map[string]bool{
	".php":      true,
	".php5":     true,
	".php4":     true,
	".asp":      true,
	".aspx":     true,
	".asmx":     true,
	".ashx":     true,
	".jsp":      true,
	".jspa":     true,
	".jspx":     true,
	".jspf":     true,
	".cer":      true,
	".htaccess": true,
}

// 判断webshell文件后缀是否是给定的后缀
func FilterWebshell(fi os.FileInfo) bool {
	ext := filepath.Ext(fi.Name())
	return webshellMap[ext]
}

// 判断webshell文件后缀是否是给定的后缀
func FilterMalware(fi os.FileInfo) bool {
	/*
		这几个目录加白
		/proc: 包含系统进程信息。
		/sys: 包含与内核和硬件相关的信息。
		/dev: 包含设备文件。
		/run: 包含运行时信息。
		/var/log: 包含系统和应用程序日志
	*/
	dn := fi.Name()
	if !strings.HasPrefix(dn, "/") {
		dn = "/" + dn
	}

	if strings.HasPrefix(dn, "/proc") || strings.HasPrefix(dn, "/sys") ||
		strings.HasPrefix(dn, "/dev") || strings.HasPrefix(dn, "/var/log") {
		return false
	}

	return true
}
