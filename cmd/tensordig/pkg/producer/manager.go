package producer

import (
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/constant"
	"gitlab.com/piccolo_su/vegeta/cmd/tensordig/pkg/utils"
	"gitlab.com/piccolo_su/vegeta/pkg/logging"

	bpf "gitlab.com/tensorsecurity-rd/gobpf/bcc"
)

type Manager struct {
	Module           *bpf.Module
	PerfMap          *bpf.PerfMap
	Table            *bpf.Table
	byteChan         chan []byte
	lostChan         chan uint64
	DataChan         chan constant.Data
	StopChan         chan struct{}
	QuitChan         chan struct{}
	SyscallProducers []*SyscallProducer
	NetProducers     []*SocketProducer
	NsMap            *utils.NsMap
	ExitP            *ExitProducer
}

var bufferRemain = 0

//DataChanBufferSize 32
const DataChanBufferSize = 10000

type SortBuffer []*constant.TotalData

func (sb SortBuffer) Len() int           { return len(sb) }
func (sb SortBuffer) Less(i, j int) bool { return sb[i].EventInfo.Ts > sb[j].EventInfo.Ts }
func (sb SortBuffer) Swap(i, j int)      { sb[i], sb[j] = sb[j], sb[i] }

func NewManager(syscallPIFS, netPIFS []ProducerInfoT) *Manager {
	if len(syscallPIFS) == 0 && len(netPIFS) == 0 {
		log.Fatal("New manager failed. You have to specify at least one producer.")
	}
	var syscallProducers []*SyscallProducer
	var netProducers []*SocketProducer

	if len(syscallPIFS) > 0 {
		syscallProducers = make([]*SyscallProducer, len(syscallPIFS))
		for idx, pif := range syscallPIFS {
			log.Infof("[%s] init", strings.ToUpper(pif.ProducerName))
			syscallProducers[idx] = NewSyscallProducer(&pif)
		}
	}

	if len(netPIFS) > 0 {
		netProducers = make([]*SocketProducer, 1)
		netProducers[0] = NewSocketProducer(netPIFS)
	}

	//nsMap := utils.NewNsMap()

	return &Manager{
		Module:           nil,
		PerfMap:          nil,
		Table:            nil,
		DataChan:         make(chan constant.Data, DataChanBufferSize),
		byteChan:         nil,
		QuitChan:         make(chan struct{}),
		StopChan:         make(chan struct{}),
		SyscallProducers: syscallProducers,
		NetProducers:     netProducers,
		//NsMap:            nsMap,
		ExitP: NewExitProducer(),
	}
}

func handleFdRelated(syscall *string) (fdUpdate string) {
	// 不要试图改下面这坨屎，使用了两三重trick来欺骗verifier.除非你对verifier特别熟悉，知道为什么这样能欺骗
	if fdCloser[*syscall] {
		fdUpdate = `
				if (d.event_info.ret == 0){
					if (fd_exist & (1<<(d.fd/256))){
						struct fdArray* fds = sf_multi_lookup(d.fd, &d.event_info.pid);
						if (fds != 0) {
							int idx = d.fd % 256 / 32;
							int offset = d.fd % 32;
							if (idx < 8){
								idx = idx & 7;
								if (fds->fds[idx] & (0x00000001 << offset)) {
									fds->fds[idx] = fds->fds[idx] & (~(0x00000001 << offset));
									fds->read_count[idx] = fds->read_count[idx] & (~(0x00000001 << offset));
									fds->write_count[idx] = fds->write_count[idx] & (~(0x00000001 << offset));
									sffd = true;
								}
							}
						}
					} else if(0 == d.fd || 1 == d.fd || 2 == d.fd) {
						// close init fd. Bytedig is started before any service.
						sffd = true;
					}
				}
			`
	} else if fdCreator[*syscall] {
		fdUpdate = fmt.Sprintf(`
			if (d.event_info.ret >= 0){
				%s

				struct fdArray fdarr = {
					.fds = {0,0,0,0,0,0,0,0},
					.read_count = {0,0,0,0,0,0,0,0},
					.write_count = {0,0,0,0,0,0,0,0},
				};
				if (d.event_info.ret < 256) {
					fdarr.fds[0] = 7;
				}
				sf_multi_lookup_or_try_init(d.event_info.ret, &d.event_info.pid, &fdarr);

				struct fdArray* fds = sf_multi_lookup(d.event_info.ret, &d.event_info.pid);
				if (fds != 0){
					int idx = d.event_info.ret %% 256 / 32;
					int offset = d.event_info.ret %% 32;
					if (idx < 8) {
						idx = idx & 7;
						fds->fds[idx] = fds->fds[idx] | (0x01 << offset);
					}
				}
			}`, fdAssignCodeGen("d.event_info.ret", 3))
	} else if cacheFork[*syscall] {
		// Bug here. If clone() creates tid, it will return tid rather than pid.
		// For threads, it share the fd cache. So, wee need need to do CLONE_FILES cehck
		// for clone syscall. Currently, I do clone check in the yaml file.
		fdUpdate = `
				if (d.event_info.ret > 0){
					if (fd_exist){ // Any partition
						// fork cache here.
						struct fdArray fdarr = {};
						int part;
						struct fdArray* fds;

						part = 0;
						fds = sf_multi_lookup(part*256, &d.event_info.pid);
						if (fds != 0) {
							for (int i=0; i<8; i++){
								fdarr.fds[i] = fds->fds[i];
								// fdarr.read_count[i] = fds->read_count[i];
								// fdarr.write_count[i] = fds->write_count[i];
							}
							sf_multi_update(part*256, &d.event_info.ret, &fdarr);
						}

						part = 1;
						fds = sf_multi_lookup(part*256, &d.event_info.pid);
						if (fds != 0) {
							for (int i=0; i<8; i++){
								fdarr.fds[i] = fds->fds[i];
								// fdarr.read_count[i] = fds->read_count[i];
								// fdarr.write_count[i] = fds->write_count[i];
							}
							sf_multi_update(part*256, &d.event_info.ret, &fdarr);
						}

						part = 2;
						fds = sf_multi_lookup(part*256, &d.event_info.pid);
						if (fds != 0) {
							for (int i=0; i<8; i++){
								fdarr.fds[i] = fds->fds[i];
								// fdarr.read_count[i] = fds->read_count[i];
								// fdarr.write_count[i] = fds->write_count[i];
							}
							sf_multi_update(part*256, &d.event_info.ret, &fdarr);
						}

						part = 3;
						fds = sf_multi_lookup(part*256, &d.event_info.pid);
						if (fds != 0) {
							for (int i=0; i<8; i++){
								fdarr.fds[i] = fds->fds[i];
								// fdarr.read_count[i] = fds->read_count[i];
								// fdarr.write_count[i] = fds->write_count[i];
							}
							sf_multi_update(part*256, &d.event_info.ret, &fdarr);
						}

						part = 4;
						fds = sf_multi_lookup(part*256, &d.event_info.pid);
						if (fds != 0) {
							for (int i=0; i<8; i++){
								fdarr.fds[i] = fds->fds[i];
								// fdarr.read_count[i] = fds->read_count[i];
								// fdarr.write_count[i] = fds->write_count[i];
							}
							sf_multi_update(part*256, &d.event_info.ret, &fdarr);
						}

						part = 5;
						fds = sf_multi_lookup(part*256, &d.event_info.pid);
						if (fds != 0) {
							for (int i=0; i<8; i++){
								fdarr.fds[i] = fds->fds[i];
								// fdarr.read_count[i] = fds->read_count[i];
								// fdarr.write_count[i] = fds->write_count[i];
							}
							sf_multi_update(part*256, &d.event_info.ret, &fdarr);
						}

						part = 6;
						fds = sf_multi_lookup(part*256, &d.event_info.pid);
						if (fds != 0) {
							for (int i=0; i<8; i++){
								fdarr.fds[i] = fds->fds[i];
								// fdarr.read_count[i] = fds->read_count[i];
								// fdarr.write_count[i] = fds->write_count[i];
							}
							sf_multi_update(part*256, &d.event_info.ret, &fdarr);
						}

						part = 7;
						fds = sf_multi_lookup(part*256, &d.event_info.pid);
						if (fds != 0) {
							for (int i=0; i<8; i++){
								fdarr.fds[i] = fds->fds[i];
								// fdarr.read_count[i] = fds->read_count[i];
								// fdarr.write_count[i] = fds->write_count[i];
							}
							sf_multi_update(part*256, &d.event_info.ret, &fdarr);
						}

					}else{
						// Pid reused. Clear the cache. Exit has already clear it.
						// sf_multi_delete(&d.event_info.ret);
						sffd=false;
					}
				}
			`
	} else if fdUsedAndCreate[*syscall] {
		fdUpdate = fmt.Sprintf(`
			if (d.event_info.ret >= 0){
				%s

				struct fdArray fdarr = {
					.fds = {0,0,0,0,0,0,0,0},
					.read_count = {0,0,0,0,0,0,0,0},
					.write_count = {0,0,0,0,0,0,0,0},
				};
				if (d.event_info.ret < 256) {
					fdarr.fds[0] = 7;
				}
				sf_multi_lookup_or_try_init(d.event_info.ret, &d.event_info.pid, &fdarr);

				struct fdArray* fds = sf_multi_lookup(d.event_info.ret, &d.event_info.pid);
				if (sffd) {
					if (fds != 0) {
						int idx = d.event_info.ret %% 256 / 32;
						int offset = d.event_info.ret %% 32;
						if (idx < 8) {
							idx = idx & 7;
							fds->fds[idx] = fds->fds[idx] | (0x01 << offset);
						}
					}
				}
			}`, fdAssignCodeGen("d.event_info.ret", 4))
	} else if pipes[*syscall] {
		fdUpdate = `
			if (d.event_info.ret == 0){
				int data;
				if (d.fildes != 0){
					bpf_probe_read(&d.readfd, sizeof(data), (void *)d.fildes);
					bpf_probe_read(&d.writefd, sizeof(data), (void *)((int *)d.fildes + 1));

					struct fdArray fdarr = {
						.fds = {0,0,0,0,0,0,0,0},
						.read_count = {0,0,0,0,0,0,0,0},
						.write_count = {0,0,0,0,0,0,0,0},
					};
					if (d.readfd < 256) {
						fdarr.fds[0] = 7;
					}
					sf_multi_lookup_or_try_init(d.readfd, &d.event_info.pid, &fdarr);
					if (d.writefd < 256) {
						fdarr.fds[0] = 7;
					} else {
						fdarr.fds[0] = 0;
					}
					sf_multi_lookup_or_try_init(d.writefd, &d.event_info.pid, &fdarr);

					if (sffd) {
						struct fdArray* fds;
						fds = sf_multi_lookup(d.readfd, &d.event_info.pid);
						if (fds != 0) {
							int idx = d.readfd % 256 / 32;
							int offset = d.readfd % 32;
							if (idx < 8) {
								idx = idx & 7;
								fds->fds[idx] = fds->fds[idx] | (0x01 << offset);
							}
						}
						fds = sf_multi_lookup(d.writefd, &d.event_info.pid);
						if (fds != 0) {
							int idx = d.writefd % 256 / 32;
							int offset = d.writefd % 32;
							if (idx < 8) {
								idx = idx & 7;
								fds->fds[idx] = fds->fds[idx] | (0x01 << offset);
							}
						}
					}

					d.event_info.is_sock[3] = 2;
					d.event_info.is_sock[4] = 2;
					f = *(fs + d.readfd);
					d.event_info.inodes[3] = f->f_inode->i_ino;
					f = *(fs + d.writefd);
					d.event_info.inodes[4] = f->f_inode->i_ino;
				}
			}
		`
	} else {
		fdUpdate = `
			sffd = true;
		`
	}
	return
}

func (m *Manager) progGenerator() string {
	var prog strings.Builder
	// Generate syscall producer code
	prog.WriteString(syscallBasicProg)

	for _, p := range m.SyscallProducers {
		s := p.Syscall
		perfData := s + "_data"
		perfArgs := "struct pt_regs* curr_ctx"
		if len(constant.SyscallIoArgsMap[s]) > 0 {
			perfArgs += ", " + constant.SyscallIoArgsMap[s]
		}
		cArgs := constant.SyscallIoStructMap[perfArgs]
		cData := constant.SyscallIoStructMap[perfData]
		fieldsMap := p.getFieldsAbbr()
		assignCode, fdCode := AssignGenerator(fieldsMap, &p.Syscall)
		CheckFilters(p.Filters, fieldsMap, p.Syscall)
		// 		myPid := os.Getpid()
		//         filterCode := fmt.Sprintf(" if (((d.event_info.pid != %d))) flag = 1;", myPid)
		filterCode := FilterGenerator(p.Filters, fieldsMap, p.FilterLogic, p.Syscall)
		inputFdCode := fdAssignCodeGen("0", 0)
		outputFdCode := fdAssignCodeGen("1", 1)
		errorFdCode := fdAssignCodeGen("2", 2)
		fdUpdate := handleFdRelated(&s)
		enterHook := handleEnterHook(p.Syscall)
		progTmp := fmt.Sprintf(syscallTemplate,
			cData, cArgs, s, perfData, s,
			perfArgs, s, perfData, assignCode, enterHook, s,
			s, perfData, s, perfData, filterCode, inputFdCode,
			outputFdCode, errorFdCode, fdCode, fdUpdate, s)
		prog.WriteString(progTmp)
	}
	prog.WriteString("\n")
	// log.Fatal(prog.String()) // Debug bpf-c code

	// Generate socket producer code
	prog.WriteString(netBasicProg)
	for _, p := range m.NetProducers {
		for i, probeName := range p.ProbeNames {
			filedsMap := p.getFieldsAbbr()
			CheckFilters(p.Filters[i], filedsMap, probeName)
			filterCode := FilterGenerator(p.Filters[i], filedsMap, p.FilterLogics[i], probeName)
			if strings.HasPrefix(probeName, "inet") {
				retCode := fmt.Sprintf(socketReturn, probeName, probeName, filterCode)
				if "inet_accept" == probeName {
					prog.WriteString(fmt.Sprintf(inetAccept, probeName))
				} else {
					prog.WriteString(fmt.Sprintf(socketTemplate, probeName))
				}
				prog.WriteString(retCode)
			} else {
				retCode := fmt.Sprintf(sockReturnTeamplate, probeName, probeName, filterCode)
				prog.WriteString(fmt.Sprintf(sockTemplate, probeName))
				prog.WriteString(retCode)
			}
		}
	}
	// Exit Code
	// prog.WriteString(exitCode)
	return prog.String()
}

func (m *Manager) Init() {
	var err error
	prog := m.progGenerator()
	m.Module = bpf.NewModule(prog, []string{})
	// Init syscall
	if len(m.SyscallProducers) > 0 {
		for _, p := range m.SyscallProducers {
			p.Init(m.Module)
		}
	}

	// init exit
	// m.ExitP.Init(m.Module)

	// init Net
	if len(m.NetProducers) > 0 {
		for _, p := range m.NetProducers {
			p.Init(m.Module)
			log.Infof("%s init", *p.GetName())
		}
	}

	m.Table = bpf.NewTable(m.Module.TableId("events_output"), m.Module)
	// create channel to receive from the bpf perf
	m.byteChan = make(chan []byte)
	// Create perMap from table and channel
	m.PerfMap, err = bpf.InitPerfMap(m.Table, m.byteChan, nil)
	if err != nil {
		log.Fatalf("Counld not get  perMap of events_output. Error: %s\n", err)
	}

}

func (m *Manager) Start() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
			}
		}()

		var wg sync.WaitGroup
		wg.Add(1)
		if len(m.SyscallProducers) > 0 {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
					}
				}()

				for byteData := range m.byteChan {
					d, err := m.Deserialize(byteData)
					if err != nil {
						log.Fatalf("Deserialize failed. Impossible.")
					}
					if d != nil {
						m.process(d)
					}
				}
				wg.Done()
			}()
			m.PerfMap.Start()
			<-m.StopChan
			m.PerfMap.Stop()
			close(m.byteChan)
			wg.Wait()
			m.QuitChan <- struct{}{}
		}

		if len(m.NetProducers) > 0 {
			for _, p := range m.NetProducers {
				go p.Start()
				log.Infof("%s started", *p.GetName())
			}
		}
	}()

}

func (m *Manager) StartChronologicalPoll() {
	if len(m.SyscallProducers) > 0 {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
				}
			}()
			m.ChronologicalPoll()
		}()
	}
}

func (m *Manager) PollOnce(buffer SortBuffer) SortBuffer {
	var wg sync.WaitGroup
	var stopChan = make(chan struct{})
	wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.GetLogger().Error().Msgf("Panic : %v. stack: %s", r, debug.Stack())
			}
		}()

		for {
			select {
			case <-stopChan:
				log.Info("Requst to stop polling")
				wg.Done()
				return
			case byteData := <-m.byteChan:
				d, err := m.Deserialize(byteData)
				if err != nil {
					log.Fatalf("Deserialize failed. Impossible.")
				}
				buffer = append(buffer, d)
				wg.Done()
				return
			}
		}
	}()
	// 	m.PerfMap.CustomPoll(1000, stopChan)
	wg.Wait()
	return buffer
}

func (m *Manager) ChronologicalPoll() {
	log.Info("ChronologicalPoll started")
	buffer := make(SortBuffer, 0, 1000)
	m.PerfMap.Start()
	for {
		buffer = m.PollOnce(buffer)
		sort.Sort(buffer)
		for i := len(buffer) - 1; i >= bufferRemain; i-- {
			d := buffer[i]
			m.process(d)
			buffer = buffer[:i]
		}
		select {
		case <-m.StopChan:
			log.Error("Cat Manager stop signal.")
			m.PerfMap.Stop()
			m.QuitChan <- struct{}{}
			return
		default:
		}
	}
}

func (m *Manager) Stop() {
	log.Info("Stop Manager.")
	if len(m.SyscallProducers) > 0 {
		m.StopChan <- struct{}{}
		<-m.QuitChan
		close(m.DataChan)
	}

	// if len(m.NetProducers) > 0 {
	// 	for _, p := range m.NetProducers {
	// 		p.Stop()
	// 	}
	// }
	m.Module.Close()
	log.Error("Manager stoped.")
}

func (m *Manager) process(data *constant.TotalData) {
	if (cap(m.DataChan) - len(m.DataChan)) > 0 {
		m.DataChan <- data
	} else {
		<-m.DataChan
		m.DataChan <- data // drop the oldest element
		log.Error("Scheduler or consumer is too slow. Lost data!")
	}

}
