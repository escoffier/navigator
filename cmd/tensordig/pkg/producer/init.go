package producer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	bpf "github.com/iovisor/gobpf/bcc"
	log "github.com/sirupsen/logrus"
)

type Producer interface {
	// Init Producer
	Init(*bpf.Module)
	// Start Producer
	// Start()
	// Stop Producer
	// Stop()
	// Used by scheduler/consumer to consume data
	// GetDataChan() <-chan constant.Data
	// GetName()
	GetName() *string
}

type ProducerT int

const (
	Syscall ProducerT = iota
	Net
)

var EventInfoFields = map[string]bool{
	"pid": true, "tid": true, "gid": true,
	"uid": true, "euid": true, "egid": true,
	"procName": true, "ptid": true, "pgid": true,
	"nsid": true, "netns": true, "ptgid": true,
}

var fdVariation = map[string]int{
	"fd":     3,
	"in_fd":  3,
	"out_fd": 4,
	"oldfd":  3,
	"newfd":  4,
	"dfd":    3,
	"ufd":    3,
}

var fdCreator = map[string]bool{
	"open": true, "socket": true, "openat": true,
	"access": true, "memfd_create": true,
}

var fdUsedAndCreate = map[string]bool{
	"dup": true,
}

var fdCloser = map[string]bool{
	"close": true,
}

var cacheFork = map[string]bool{
	"fork": true, "vfork": true,
	"clone": true,
}

var pipes = map[string]bool{
	"pipe": true, "pipe2": true,
}

var enterHooks = map[string]bool{
	"close": true,
}

type ProducerInfoT struct {
	ProducerType    ProducerT
	ProducerName    string
	ProducerFilters []FilterT
	FilterLogic     string
}

type FieldOperationT int

const (
	Unknown FieldOperationT = iota
	FEqualTo
	FNotEqualTo
	FLessThan
	FGreaterThan
	FEqualLessThan
	FEqualGreaterThan
	FStartsWith
	FNotStartsWith
	FEndsWith
	FNotEndsWith
	FInArray            // x==A || x==B
	FNotInArray         // x!=A && x!=B
	FStartsWithArray    // x==A || x==B
	FNotStartsWithArray // x!=A && x!=B
	FEndsWithArray      // x==A || x==B
	FNotEndsWithArray   // x!=A && x!=B
	FLogicAndIs         // x & B == C
	FLogicAndIsNot      // x & B == C
	FLogicOrIs          // x | B == C
	FLogicOrIsNot       // x | B == C
	FLogicXorIs         // x ^ B == C
	FLogicXorIsNot      // x ^ B == C
)

var FieldOperationTName = []string{
	"equalTo",
	"notEqualTo",
	"lessThan",
	"greaterThan",
	"equalLessThan",
	"equalGreaterThan",
	"startsWith",
	"notStartsWith",
	"endsWith",
	"notEndsWith",
	"inArray",
	"notInArray",
	"startsWithArray",
	"notStartsWithArray",
	"endsWithArray",
	"notEndsWithArray",
	"logicAndIs",
	"logicAndIsNot",
	"logicOrIs",
	"logicOrIsNot",
	"logicXorIs",
	"logicXorIsNot",
}

var FIntOperation = map[FieldOperationT]string{
	FEqualTo:          "==",
	FNotEqualTo:       "!=",
	FLessThan:         "<",
	FGreaterThan:      ">",
	FEqualLessThan:    "<=",
	FEqualGreaterThan: ">=",
	FInArray:          "==",
	FNotInArray:       "!=",
}
var FIntLogicOperation = map[FieldOperationT]string{
	FLogicAndIs:    "andIs",
	FLogicAndIsNot: "andIsNot",
	FLogicOrIs:     "orIs",
	FLogicOrIsNot:  "orIsNot",
	FLogicXorIs:    "xorIs",
	FLogicXorIsNot: "xorIsNot",
}
var FStrOperation = map[FieldOperationT]string{
	FEqualTo:            "strEqualTo",
	FInArray:            "strEqualTo",
	FNotEqualTo:         "strNotEqualTo",
	FNotInArray:         "strNotEqualTo",
	FStartsWith:         "strStartsWith",
	FStartsWithArray:    "strStartsWith",
	FNotStartsWith:      "!strStartsWith",
	FNotStartsWithArray: "!strStartsWith",
	FEndsWith:           "strEndsWith",
	FEndsWithArray:      "strEndsWith",
	FNotEndsWith:        "!strEndsWith",
	FNotEndsWithArray:   "!strEndsWith",
}
var FArrayLogic = map[FieldOperationT]string{
	FInArray:            "||",
	FStartsWithArray:    "||",
	FEndsWithArray:      "||",
	FNotInArray:         "&&",
	FNotStartsWithArray: "&&",
	FNotEndsWithArray:   "&&",
}

var FPtrOperation = map[FieldOperationT]string{}

type FilterT struct {
	Id        string          `json:"id"`
	Field     string          `json:"field"`
	Operation FieldOperationT `json:"operation"`
	ValueStr  []string        `json:"value_str"`
}

// The filter must be checked correctly. Unless we will fatal the program
func CheckFilters(Filters []FilterT, fieldsMap map[string]string, probeName string) {
	idMap := make(map[string]struct{})
	idReg := regexp.MustCompile(`^\w+$`)
	for _, filter := range Filters {
		if filter.Id != "" {
			if !idReg.MatchString(filter.Id) {
				log.Error("Only [0-9A-Za-z_] can be used in filter ID")
				log.Fatalf("Filter ID [%s] illegal (in probeName %s)", filter.Id, strings.ToUpper(probeName))
			}
			if strings.HasPrefix(filter.Id, "_") {
				log.Error("Filter ID shouldn't start with `_`")
				log.Fatalf("Filter ID [%s] illegal (in probeName %s)", filter.Id, strings.ToUpper(probeName))
			}
			if _, ok := idMap[filter.Id]; ok {
				log.Fatalf("Filter ID [%s] duplicated set in probeName %s", filter.Id, strings.ToUpper(probeName))
			}
			idMap[filter.Id] = struct{}{}
		}
		if fieldType, ok := fieldsMap[filter.Field]; ok || EventInfoFields[filter.Field] {
			if fieldType == "string" || filter.Field == "procName" {
				fieldType = "string"
				if _, ok := FStrOperation[filter.Operation]; !ok {
					log.Fatalf("%s is [%s] type, cannot do %s operation", filter.Field, fieldType, FieldOperationTName[filter.Operation])
				}
				continue
			}
			if fieldType == "pointer" {
				fieldType = "pointer"
				if _, ok := FPtrOperation[filter.Operation]; !ok {
					log.Fatalf("%s is [%s] type, cannot do %s operation", filter.Field, fieldType, FieldOperationTName[filter.Operation])
				}
				continue
			}

			// include integer type and pid && nsid
			_, isIntNormalOperation := FIntOperation[filter.Operation]
			_, isIntLogicOperation := FIntLogicOperation[filter.Operation]
			if !isIntNormalOperation && !isIntLogicOperation {
				fieldType = "integer"
				log.Fatalf("%s is [%s] type, cannot do %s operation", filter.Field, fieldType, FieldOperationTName[filter.Operation])
			}
			for _, v := range filter.ValueStr {
				if _, ok := strconv.Atoi(v); ok != nil {
					log.Fatalf("%s is [%s] type,  cannot compare with %s", filter.Field, fieldType, filter.ValueStr)
				}
			}
			continue
		} else {
			log.Fatalf("Cannot find [%s] field in probe %s", filter.Field, strings.ToUpper(probeName))
		}
	}
}

// A complex generator (OvO)
func FilterGenerator(filters []FilterT, fieldsMap map[string]string, logic string, probeName string) string {

	// no common filter
	if len(filters) == 0 {
		return "flag = 1;"
	}

	// filterMap is filter in syscall_enter
	filterMap := make(map[string]string, len(filters))

	// each filter string
	var filterStr strings.Builder

	for _, filter := range filters {
		filterStr.Reset()
		fieldType, _ := fieldsMap[filter.Field]

		_, isLogicOperation := FIntLogicOperation[filter.Operation]
		_, isArrayOperation := FArrayLogic[filter.Operation]
		isNormalOperation := !isLogicOperation && !isArrayOperation

		if isLogicOperation && len(filter.ValueStr) != 2 {
			log.Fatalf("Operation [%s] of [%s] need 2 parameters, but found %d parameters", FieldOperationTName[filter.Operation], filter.Field, len(filter.ValueStr))
		}

		if isNormalOperation && len(filter.ValueStr) > 1 {
			log.Fatalf("Operation [%s] of [%s] need a single parameter, but found an array with %d values", FieldOperationTName[filter.Operation], filter.Field, len(filter.ValueStr))
		}

		// no need for checking type, all check has done in `CheckFilters` function
		if fieldType == "string" || filter.Field == "procName" {
			filterStr.WriteString("(")
			for _, v := range filter.ValueStr[:len(filter.ValueStr)-1] {
				if filter.Field == "procName" {
					filterStr.WriteString(fmt.Sprintf("%s(\"%s\", d.event_info.procname)%s",
						FStrOperation[filter.Operation],
						v, FArrayLogic[filter.Operation]))

				} else {
					filterStr.WriteString(fmt.Sprintf("%s(\"%s\", d.%s)%s",
						FStrOperation[filter.Operation],
						v, filter.Field, FArrayLogic[filter.Operation]))
				}
			}
			if filter.Field == "procName" {
				filterStr.WriteString(fmt.Sprintf("%s(\"%s\", d.event_info.procname))",
					FStrOperation[filter.Operation],
					filter.ValueStr[len(filter.ValueStr)-1]))
			} else {
				filterStr.WriteString(fmt.Sprintf("%s(\"%s\", d.%s))",
					FStrOperation[filter.Operation],
					filter.ValueStr[len(filter.ValueStr)-1], filter.Field))
			}

			if filter.Id != "" {
				filterMap[filter.Id] = filterStr.String()
			}
			continue
		}
		if fieldType == "pointer" {
			continue
		}

		// include integer type and Xid

		if cOperation, ok := FIntLogicOperation[filter.Operation]; ok {
			// Logic operation
			if EventInfoFields[filter.Field] {
				filterStr.WriteString(fmt.Sprintf("(%s(d.event_info.%s,%s,%s))",
					cOperation, filter.Field, filter.ValueStr[0], filter.ValueStr[1]))
			} else {
				filterStr.WriteString(fmt.Sprintf("(%s(d.%s,%s,%s))",
					cOperation, filter.Field, filter.ValueStr[0], filter.ValueStr[1]))
			}
		} else {
			// Other operations (include normal-operation and array-operation)
			filterStr.WriteString("(")
			for _, v := range filter.ValueStr[:len(filter.ValueStr)-1] {
				if EventInfoFields[filter.Field] {
					filterStr.WriteString(fmt.Sprintf("(d.event_info.%s %s %s)%s",
						filter.Field, FIntOperation[filter.Operation], v, FArrayLogic[filter.Operation]))
				} else {
					filterStr.WriteString(fmt.Sprintf("(d.%s %s %s)%s",
						filter.Field, FIntOperation[filter.Operation], v, FArrayLogic[filter.Operation]))
				}
			}
			if EventInfoFields[filter.Field] {
				filterStr.WriteString(fmt.Sprintf("(d.event_info.%s %s %s))",
					filter.Field, FIntOperation[filter.Operation], filter.ValueStr[len(filter.ValueStr)-1]))
			} else {
				filterStr.WriteString(fmt.Sprintf("(d.%s %s %s))",
					filter.Field, FIntOperation[filter.Operation], filter.ValueStr[len(filter.ValueStr)-1]))
			}
		}
		if filter.Id != "" {
			filterMap[filter.Id] = filterStr.String()
		}
	}

	var filterResult string

	// only one filter
	if len(filters) == 1 {
		filterResult = fmt.Sprintf("if (%s) flag = 1;", filterStr.String()) // filterStr is the only and last one
		return filterResult
	}

	// prepare for filling filterMap into logic express
	var filterResultBuilder strings.Builder
	nonWordReg := regexp.MustCompile(` [^0-9A-Za-z_\(\)\&\|]`)
	logic = nonWordReg.ReplaceAllString(logic, "")
	wordReg := regexp.MustCompile(`^\w+`)
	anyWordReg := regexp.MustCompile(`\w+`)
	opReg := regexp.MustCompile(`^\W+`)
	filterCountOfLogic := len(anyWordReg.FindAllString(logic, -1))
	if filterCountOfLogic == 0 {
		log.Fatalf("[%s] You set more than one filters, but didn't specify any logic express.", strings.ToUpper(probeName))
	}
	if len(filterMap) != len(filters) {
		log.Warnf("[%s] You set %d filters, but only %d filters has the ID.", strings.ToUpper(probeName), len(filters), len(filterMap))
	}
	if filterCountOfLogic < len(filterMap) {
		log.Warnf("[%s] You set %d filters with ID, but only %d ID found in logic express.", strings.ToUpper(probeName), len(filterMap), filterCountOfLogic)
	}

	// scan logic express for filling
	for logic != "" {
		var subStr string
		subStr = opReg.FindString(logic)
		if subStr != "" {
			filterResultBuilder.WriteString(subStr)
			logic = opReg.ReplaceAllString(logic, "")
		}
		subStr = wordReg.FindString(logic)
		if subStr != "" {
			if _, ok := filterMap[subStr]; ok {
				filterResultBuilder.WriteString(filterMap[subStr])
				logic = wordReg.ReplaceAllString(logic, "")
			} else {
				log.Fatalf("Cannot found filter ID=%s", subStr)
			}
		}
	}

	// generate common filter express
	filterResult = fmt.Sprintf("if (%s) flag = 1;", filterResultBuilder.String())
	return filterResult
}

func AssignGenerator(fieldsMap map[string]string, syscall *string) (string, string) {
	var assign strings.Builder
	var fdAssign strings.Builder
	if fieldsMap == nil {
		return "", ""
	}
	// Start from 3
	hit := 0
	var propagate bool
	var propagateName string
	var sourceName string
	var sfCode string
	fdCode := ""
	for fieldName, fieldType := range fieldsMap {
		if fieldType == "string" {
			if strings.HasPrefix(fieldName, "argv") {
				continue
			} else {
				assign.WriteString(
					fmt.Sprintf("bpf_probe_read(&d.%s, sizeof(d.%s), (void *)ctx->%s);\n",
						fieldName, fieldName, fieldName))
			}
		} else if !("readfd" == fieldName || "writefd" == fieldName) { // pipe support
			assign.WriteString(fmt.Sprintf("d.%s=ctx->%s;\n", fieldName, fieldName))
		}
		position := fdVariation[fieldName]
		if position > 0 {
			if hit >= 3 {
				log.Errorf("System cals with more than 2 fds is not supported currently")
				continue
			}
			// 不要试图改下面这坨屎，我也知道idx = idx & 7很蠢
			if !fdCreator[*syscall] {
				switch *syscall {
				case "read":
					sfCode = fmt.Sprintf(`
						struct fdArray fdarr = {
							.fds = {0,0,0,0,0,0,0,0},
							.read_count = {0,0,0,0,0,0,0,0},
							.write_count = {0,0,0,0,0,0,0,0},
						};
						if (d.fd < 256) {
							fdarr.fds[0] = 7;
						}
						sf_multi_lookup_or_try_init(d.fd, &d.event_info.pid, &fdarr);

						struct fdArray* fds = sf_multi_lookup(d.%s, &d.event_info.pid);
						if (fds != 0){
							int idx = d.%s %% 256 / 32;
							int offset = d.%s %% 32;
							if (idx < 8){
								idx = idx & 7;
								if (fds->fds[idx] & (0x00000001 << offset)) {
									if (!(fds->read_count[idx] & (0x00000001 << offset))) {
										sffd = true;
										fds->read_count[idx] = fds->read_count[idx] | (0x00000001 << offset);
									}
								}
							}
						} 
					`, fieldName, fieldName, fieldName)
				case "write":
					sfCode = fmt.Sprintf(`
						
						struct fdArray fdarr = {
							.fds = {0,0,0,0,0,0,0,0},
							.read_count = {0,0,0,0,0,0,0,0},
							.write_count = {0,0,0,0,0,0,0,0},
						};
						if (d.fd < 256) {
							fdarr.fds[0] = 7;
						}
						sf_multi_lookup_or_try_init(d.fd, &d.event_info.pid, &fdarr);
\
						struct fdArray* fds = sf_multi_lookup(d.%s, &d.event_info.pid);
						if (fds != 0){
							int idx = d.%s %% 256 / 32;
							int offset = d.%s %% 32;
							if (idx < 8){
								idx = idx & 7;
								if (fds->fds[idx] & (0x00000001 << offset)) {
									if (!(fds->write_count[idx] & (0x01 << offset))) {
										sffd = true;
										fds->write_count[idx] = fds->write_count[idx] | (0x00000001 << offset);
									}
								}
							}
						}
					`, fieldName, fieldName, fieldName)
				case "close":
					sfCode = ``
				default:
					sfCode = fmt.Sprintf(`
						struct fdArray fdarr = {
							.fds = {0,0,0,0,0,0,0,0},
							.read_count = {0,0,0,0,0,0,0,0},
							.write_count = {0,0,0,0,0,0,0,0},
						};
						if (d.fd < 256) {
							fdarr.fds[0] = 7;
						}
						sf_multi_lookup_or_try_init(d.fd, &d.event_info.pid, &fdarr);

						struct fdArray* fds = sf_multi_lookup(d.%s, &d.event_info.pid);
						if (fds != 0){
							int idx = d.%s %% 256 / 32;
							int offset = d.%s %% 32;
							if (idx < 8){
								idx = idx & 7;
								if (fds->fds[idx] & (0x01 << offset)) {
									sffd = true;
								}
							}
						}
					`, fieldName, fieldName, fieldName)
				}
				hit++
			}
			if 4 == position {
				propagate = true
				propagateName = fieldName
			} else {
				// position == 3
				sourceName = fieldName
				if !("close" == *syscall) {
					fdCode = fmt.Sprintf(`
						if (d.%s >= 0){
							%s
							%s
						}`, fieldName, sfCode, fdAssignCodeGen(fmt.Sprintf("d.%s", fieldName), position))
				}
			}
		}
	}
	if propagate {
		propagateCode := fmt.Sprintf(`
			if (fd_exist & (1<<(d.%s/256))){
				struct fdArray* fds = sf_multi_lookup(d.%s, &d.event_info.pid);
				if (fds != 0) {
					int idx = d.%s %% 256 / 32;
					int offset = d.%s %% 32;
					if (idx < 8){
						idx = idx & 7;
						if (fds->fds[idx] & (0x00000001 << offset)) {
							sffd = true;
							idx = d.%s %% 256 / 32;
							offset = d.%s %% 32;
							if (idx <8 && idx >=0){
								idx = idx & 7;
								fds->fds[idx] = fds->fds[idx] | (0x01 << offset);
							}
						}
					}
				}
			}
		`, sourceName, sourceName, sourceName, sourceName, propagateName, propagateName)
		// Write 3
		fdCode = fmt.Sprintf(`
			if (d.%s >= 0){
				%s
				%s
			}
		`, sourceName, propagateCode, fdAssignCodeGen(fmt.Sprintf("d.%s", sourceName), 3))
		fdAssign.WriteString(fdCode)
		// Write 4
		fdCode = fmt.Sprintf(`
			if (d.%s >=0){
				%s
			}`, propagateName, fdAssignCodeGen(fmt.Sprintf("d.%s", propagateName), 4))
		fdAssign.WriteString(fdCode)
	} else {
		fdAssign.WriteString(fdCode)
	}

	if *syscall == "execve" {
		assign.WriteString(fmt.Sprintf(
			`
				argv = NULL;
				bpf_probe_read(&argv, sizeof(argv), (void *)&ctx->argv[1]);
				if (argv){
					bpf_probe_read(d.argv1, sizeof(d.argv1), argv);
				}else{
					goto out;
				}
				argv = NULL;
				bpf_probe_read(&argv, sizeof(argv), (void *)&ctx->argv[2]);
				if (argv){
					bpf_probe_read(d.argv2, sizeof(d.argv2), argv);
				}else{goto out;}
				argv = NULL;
				bpf_probe_read(&argv, sizeof(argv), (void *)&ctx->argv[3]);
				if (argv){
					bpf_probe_read(d.argv3, sizeof(d.argv3), argv);
				}else{goto out;}
			`))
	}
	if hit == 0 {
		fdAssign.WriteString("sffd=true;")
	}

	return assign.String(), fdAssign.String()
}

func handleEnterHook(syscall string) string {
	if syscall == "close" {
		return fmt.Sprintf(`
		struct file **fs = ts->files->fdt->fd;
		if (fs == 0){
			return 0;
		}
		struct file *f;
		umode_t m;
		dev_t dev;
		u32 sport;
		u32 dport;
		%s
		`, fdAssignCodeGen("d.fd", 3))

	}
	if syscall == "write" {
		return fmt.Sprintf(`
        struct task_struct* t;
        struct files_struct* f;
        struct fdtable* fdt;
        struct file** fdd;
        struct file* file;
        struct path path;
        struct dentry* dentry;
        struct qstr pathname;
        char filename[64];

        t = (struct task_struct*)bpf_get_current_task();
        f = t->files;

        bpf_probe_read(&fdt, sizeof(fdt), (void*)&f->fdt);
        int ret = bpf_probe_read(&fdd, sizeof(fdd), (void*)&fdt->fd);
        if (ret) {
            bpf_trace_printk("bpf_probe_read failed: %d\\n", ret);
            return 0;
        }
        bpf_probe_read(&file, sizeof(file), (void*)&fdd[d.fd]);
        bpf_probe_read(&path, sizeof(path), (const void*)&file->f_path);

        dentry = path.dentry;
        bpf_probe_read(&pathname, sizeof(pathname), (const void*)&dentry->d_name);
        bpf_probe_read_str((void*)d.buf, sizeof(d.buf), (const void*)pathname.name);
        `)
	}
	if syscall == "openat" {
		return fmt.Sprintf(`
        const char *pathname;
        u32 map_id;
        int res;
//         res = bpf_probe_read(&pathname, sizeof(pathname), &d.filename);
//
//         map_id = 0;
//         notify_t* n = tmp_storage_map.lookup(&map_id);
//         if (!n) return 0;

//         bpf_probe_read_str(&n->data[0], PATH_MAX, &pathname);
//         res = bpf_probe_read_str(&map_value, sizeof(map_value), &pathname);
//         if (res > 0) {
//             map_value[(res - 1) & (PATH_MAX - 1)] = 0;
//         }
//         bpf_probe_read_str(&d.filename, sizeof(d.filename), &n->data[0]);
        `)
	}
	return ""

}
