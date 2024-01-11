package metrics

import (
	"bufio"
	"fmt"
	v1 "github.com/containerd/cgroups/v3/cgroup1/stats"
	"github.com/pkg/errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	ErrInvalidPid               = errors.New("cgroups: pid must be greater than 0")
	ErrMountPointNotExist       = errors.New("cgroups: cgroup mountpoint does not exist")
	ErrInvalidFormat            = errors.New("cgroups: parsing file with invalid format failed")
	ErrFreezerNotSupported      = errors.New("cgroups: freezer cgroup not supported on this system")
	ErrMemoryNotSupported       = errors.New("cgroups: memory cgroup not supported on this system")
	ErrCgroupDeleted            = errors.New("cgroups: cgroup deleted")
	ErrNoCgroupMountDestination = errors.New("cgroups: cannot find cgroup mount destination")
)

// Name is a typed name for a cgroup subsystem
type Name string

const (
	Devices   Name = "devices"
	Hugetlb   Name = "hugetlb"
	Freezer   Name = "freezer"
	Pids      Name = "pids"
	NetCLS    Name = "net_cls"
	NetPrio   Name = "net_prio"
	PerfEvent Name = "perf_event"
	Cpuset    Name = "cpuset"
	Cpu       Name = "cpu"
	Cpuacct   Name = "cpuacct"
	Memory    Name = "memory"
	Blkio     Name = "blkio"
	Rdma      Name = "rdma"
)

type blkioController struct {
	root     string
	procRoot string
}

// NewBlkio returns a Blkio controller given the root folder of cgroups.
// It may optionally accept other configuration options, such as ProcRoot(path)
func NewBlkio(root, procRoot string) *blkioController {
	ctrl := &blkioController{
		root:     root,
		procRoot: procRoot,
	}
	return ctrl
}

type blkioStatSettings struct {
	name  string
	entry *[]*v1.BlkIOEntry
}

// v1MountPoint returns the mount point where the cgroup
// mountpoints are mounted in a single hiearchy
func V1MountPoint() (string, error) {
	f, err := os.Open("/host/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var (
			text      = scanner.Text()
			fields    = strings.Split(text, " ")
			numFields = len(fields)
		)
		if numFields < 10 {
			return "", fmt.Errorf("mountinfo: bad entry %q", text)
		}
		if fields[numFields-3] == "cgroup" {
			return filepath.Dir(fields[4]), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", ErrMountPointNotExist
}

func (b *blkioController) Stat(path string) (*v1.BlkIOStat, error) {
	//stats.Blkio = &v1.BlkIOStat{}
	blkioStat := &v1.BlkIOStat{}

	var settings []blkioStatSettings

	// Try to read CFQ stats available on all CFQ enabled kernels first
	if _, err := os.Lstat(filepath.Join(b.Path(path), "blkio.io_serviced_recursive")); err == nil {
		settings = []blkioStatSettings{
			{
				name:  "sectors_recursive",
				entry: &blkioStat.SectorsRecursive,
			},
			{
				name:  "io_service_bytes_recursive",
				entry: &blkioStat.IoServiceBytesRecursive,
			},
			{
				name:  "io_serviced_recursive",
				entry: &blkioStat.IoServicedRecursive,
			},
			{
				name:  "io_queued_recursive",
				entry: &blkioStat.IoQueuedRecursive,
			},
			{
				name:  "io_service_time_recursive",
				entry: &blkioStat.IoServiceTimeRecursive,
			},
			{
				name:  "io_wait_time_recursive",
				entry: &blkioStat.IoWaitTimeRecursive,
			},
			{
				name:  "io_merged_recursive",
				entry: &blkioStat.IoMergedRecursive,
			},
			{
				name:  "time_recursive",
				entry: &blkioStat.IoTimeRecursive,
			},
		}
	}

	f, err := os.Open(filepath.Join(b.procRoot, "partitions"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	devices, err := getDevices(f)
	if err != nil {
		return nil, err
	}

	var size int
	for _, t := range settings {
		if err := b.readEntry(devices, path, t.name, t.entry); err != nil {
			return nil, err
		}
		size += len(*t.entry)
	}
	if size > 0 {
		return nil, nil
	}

	// Even the kernel is compiled with the CFQ scheduler, the cgroup may not use
	// block devices with the CFQ scheduler. If so, we should fallback to throttle.* files.
	settings = []blkioStatSettings{
		{
			name:  "throttle.io_serviced",
			entry: &blkioStat.IoServicedRecursive,
		},
		{
			name:  "throttle.io_service_bytes",
			entry: &blkioStat.IoServiceBytesRecursive,
		},
	}
	for _, t := range settings {
		if err := b.readEntry(devices, path, t.name, t.entry); err != nil {
			return nil, err
		}
	}
	return blkioStat, nil
}

func (b *blkioController) readEntry(devices map[deviceKey]string, path, name string, entry *[]*v1.BlkIOEntry) error {
	f, err := os.Open(filepath.Join(b.Path(path), "blkio."+name))
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// format: dev type amount
		fields := strings.FieldsFunc(sc.Text(), splitBlkIOStatLine)
		if len(fields) < 3 {
			if len(fields) == 2 && fields[0] == "Total" {
				// skip total line
				continue
			} else {
				return fmt.Errorf("invalid line found while parsing %s: %s", path, sc.Text())
			}
		}
		major, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return err
		}
		minor, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return err
		}
		op := ""
		valueField := 2
		if len(fields) == 4 {
			op = fields[2]
			valueField = 3
		}
		v, err := strconv.ParseUint(fields[valueField], 10, 64)
		if err != nil {
			return err
		}
		*entry = append(*entry, &v1.BlkIOEntry{
			Device: devices[deviceKey{major, minor}],
			Major:  major,
			Minor:  minor,
			Op:     op,
			Value:  v,
		})
	}
	return sc.Err()
}

func splitBlkIOStatLine(r rune) bool {
	return r == ' ' || r == ':'
}

type deviceKey struct {
	major, minor uint64
}

// getDevices makes a best effort attempt to read all the devices into a map
// keyed by major and minor number. Since devices may be mapped multiple times,
// we err on taking the first occurrence.
func getDevices(r io.Reader) (map[deviceKey]string, error) {

	var (
		s       = bufio.NewScanner(r)
		devices = make(map[deviceKey]string)
	)
	for i := 0; s.Scan(); i++ {
		if i < 2 {
			continue
		}
		fields := strings.Fields(s.Text())
		major, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, err
		}
		minor, err := strconv.Atoi(fields[1])
		if err != nil {
			return nil, err
		}
		key := deviceKey{
			major: uint64(major),
			minor: uint64(minor),
		}
		if _, ok := devices[key]; ok {
			continue
		}
		devices[key] = filepath.Join("/dev", fields[3])
	}
	return devices, s.Err()
}

func (b *blkioController) Path(path string) string {
	return filepath.Join(b.root, path)
}
