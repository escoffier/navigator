package constant

type Data interface{}

type EventInfoT struct {
	EventName [16]byte  `json:"event_name"`
	Ts        uint64    `json:"ts"`
	Pid       uint32    `json:"pid"`
	Tid       uint32    `json:"tid"`
	Gid       uint32    `json:"gid"`
	Uid       uint32    `json:"uid"`
	Euid      uint32    `json:"euid"`
	Egid      uint32    `json:"egid"`
	Major     uint32    `json:"major"`
	Minor     uint32    `json:"minor"`
	Nsid      uint32    `json:"nsid"`
	FileType  [5]uint32 `json:"file_type"` // 1 represent socket, 2 represent pipe
	Sports    [5]uint32 `json:"sports"`
	Dports    [5]uint32 `json:"dports"`
	Saddrs    [5]uint32 `json:"saddrs"`
	Daddrs    [5]uint32 `json:"daddrs"`
	Inodes    [5]uint64 `json:"inodes"`
	Ptid      uint32    `json:"parent_tid"`
	Ptgid     uint32    `json:"parent_pid"`
	ProcName  [16]byte  `json:"proc_name"`
	Netns     uint32    `json:"netns"`
	Protos    [5]uint32 `json:"Protos"`
	Ret       int64     `json:"Ret"`
}

type TimeData struct {
	EventInfo EventInfoT
	Tloc      uint64
}

type MigratePagesData struct {
	EventInfo EventInfoT
	Pid       uint64
	Maxnode   uint64
	OldNodes  uint64
	NewNodes  uint64
}

type LsetxattrData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
	Name      [64]byte
	Value     uint64
	Size      uint64
	Flags     uint64
}

type ClockGetresData struct {
	EventInfo  EventInfoT
	WhichClock uint64
	Tp         uint64
}

type SetTidAddressData struct {
	EventInfo EventInfoT
	Tidptr    uint64
}

type Pipe2Data struct {
	EventInfo EventInfoT
	Fildes    uint64
	Flags     uint64
	ReadFd    uint64
	WriteFd   uint64
}

type SethostnameData struct {
	EventInfo EventInfoT
	Name      [64]byte
	Len       uint64
}

type Dup3Data struct {
	EventInfo EventInfoT
	Oldfd     uint64
	Newfd     uint64
	Flags     uint64
}

type UmaskData struct {
	EventInfo EventInfoT
	Mask      uint64
}

type ExitGroupData struct {
	EventInfo EventInfoT
	ErrorCode uint64
}

type SetRobustListData struct {
	EventInfo EventInfoT
	Head      uint64
	Len       uint64
}

type IoplData struct {
	EventInfo EventInfoT
	Level     uint64
}

type LgetxattrData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
	Name      [64]byte
	Value     uint64
	Size      uint64
}

type KillData struct {
	EventInfo EventInfoT
	Pid       uint64
	Sig       uint64
}

type Pread64Data struct {
	EventInfo EventInfoT
	Fd        uint64
	Buf       [64]byte
	Count     uint64
	Pos       uint64
}

type NewfstatatData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Filename  [64]byte
	Statbuf   uint64
	Flag      uint64
}

type NewlstatData struct {
	EventInfo EventInfoT
	Filename  [64]byte
	Statbuf   uint64
}

type WriteData struct {
	EventInfo EventInfoT
	Fd        uint64
	Buf       [64]byte
	Count     uint64
}

type SetregidData struct {
	EventInfo EventInfoT
	Rgid      uint64
	Egid      uint64
}

type UstatData struct {
	EventInfo EventInfoT
	Dev       uint64
	Ubuf      uint64
}

type PauseData struct {
	EventInfo EventInfoT
}

type GetrlimitData struct {
	EventInfo EventInfoT
	Resource  uint64
	Rlim      uint64
}

type TkillData struct {
	EventInfo EventInfoT
	Pid       uint64
	Sig       uint64
}

type Dup2Data struct {
	EventInfo EventInfoT
	Oldfd     uint64
	Newfd     uint64
}

type ClockAdjtimeData struct {
	EventInfo  EventInfoT
	WhichClock uint64
	Utx        uint64
}

type RtSigqueueinfoData struct {
	EventInfo EventInfoT
	Pid       uint64
	Sig       uint64
	Uinfo     uint64
}

type UtimeData struct {
	EventInfo EventInfoT
	Filename  [64]byte
	Times     uint64
}

type SetxattrData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
	Name      [64]byte
	Value     uint64
	Size      uint64
	Flags     uint64
}

type MembarrierData struct {
	EventInfo EventInfoT
	Cmd       uint64
	Flags     uint64
}

type GetegidData struct {
	EventInfo EventInfoT
}

type MlockData struct {
	EventInfo EventInfoT
	Start     uint64
	Len       uint64
}

type TeeData struct {
	EventInfo EventInfoT
	Fdin      uint64
	Fdout     uint64
	Len       uint64
	Flags     uint64
}

type SetpgidData struct {
	EventInfo EventInfoT
	Pid       uint64
	Pgid      uint64
}

type UtimesData struct {
	EventInfo EventInfoT
	Filename  [64]byte
	Utimes    uint64
}

type LremovexattrData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
	Name      [64]byte
}

type LinkData struct {
	EventInfo EventInfoT
	Oldname   [64]byte
	Newname   [64]byte
}

type ReadvData struct {
	EventInfo EventInfoT
	Fd        uint64
	Vec       uint64
	Vlen      uint64
}

type FutexData struct {
	EventInfo EventInfoT
	Uaddr     uint64
	Op        uint64
	Val       uint64
	Utime     uint64
	Uaddr2    uint64
	Val3      uint64
}

type GetxattrData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
	Name      [64]byte
	Value     uint64
	Size      uint64
}

type SchedGetPriorityMaxData struct {
	EventInfo EventInfoT
	Policy    uint64
}

type Preadv2Data struct {
	EventInfo EventInfoT
	Fd        uint64
	Vec       uint64
	Vlen      uint64
	PosL      uint64
	PosH      uint64
	Flags     uint64
}

type ReadlinkatData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Pathname  [64]byte
	Buf       [64]byte
	Bufsiz    uint64
}

type PrctlData struct {
	EventInfo EventInfoT
	Option    uint64
	Arg2      uint64
	Arg3      uint64
	Arg4      uint64
	Arg5      uint64
}

type RenameatData struct {
	EventInfo EventInfoT
	Olddfd    uint64
	Oldname   [64]byte
	Newdfd    uint64
	Newname   [64]byte
}

type Renameat2Data struct {
	EventInfo EventInfoT
	Olddfd    uint64
	Oldname   [64]byte
	Newdfd    uint64
	Newname   [64]byte
	Flags     uint64
}

type SendmmsgData struct {
	EventInfo EventInfoT
	Fd        uint64
	Mmsg      uint64
	Vlen      uint64
	Flags     uint64
}

type ModifyLdtData struct {
	EventInfo EventInfoT
	Func      uint64
	Ptr       uint64
	Bytecount uint64
}

type CloseData struct {
	EventInfo EventInfoT
	Fd        uint64
}

type IoprioGetData struct {
	EventInfo EventInfoT
	Which     uint64
	Who       uint64
}

type SetreuidData struct {
	EventInfo EventInfoT
	Ruid      uint64
	Euid      uint64
}

type Sendfile64Data struct {
	EventInfo EventInfoT
	OutFd     uint64
	InFd      uint64
	Offset    uint64
	Count     uint64
}

type StatfsData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
	Buf       uint64
}

type GetpriorityData struct {
	EventInfo EventInfoT
	Which     uint64
	Who       uint64
}

type TruncateData struct {
	EventInfo EventInfoT
	Path      [64]byte
	Length    uint64
}

type GetcpuData struct {
	EventInfo EventInfoT
	Cpup      uint64
	Nodep     uint64
	Unused    uint64
}

type ShmatData struct {
	EventInfo EventInfoT
	Shmid     uint64
	Shmaddr   [64]byte
	Shmflg    uint64
}

type SwaponData struct {
	EventInfo   EventInfoT
	Specialfile [64]byte
	SwapFlags   uint64
}

type WaitidData struct {
	EventInfo EventInfoT
	Which     uint64
	Upid      uint64
	Infop     uint64
	Options   uint64
	Ru        uint64
}

type SyncFileRangeData struct {
	EventInfo EventInfoT
	Fd        uint64
	Offset    uint64
	Nbytes    uint64
	Flags     uint64
}

type SchedRrGetIntervalData struct {
	EventInfo EventInfoT
	Pid       uint64
	Interval  uint64
}

type SchedGetschedulerData struct {
	EventInfo EventInfoT
	Pid       uint64
}

type SignalfdData struct {
	EventInfo EventInfoT
	Ufd       uint64
	UserMask  uint64
	Sizemask  uint64
}

type Accept4Data struct {
	EventInfo     EventInfoT
	Fd            uint64
	UpeerSockaddr uint64
	UpeerAddrlen  uint64
	Flags         uint64
}

type IoDestroyData struct {
	EventInfo EventInfoT
	Ctx       uint64
}

type ShutdownData struct {
	EventInfo EventInfoT
	Fd        uint64
	How       uint64
}

type ExecveatData struct {
	EventInfo EventInfoT
	Fd        uint64
	Filename  [64]byte
	Argv1     [16]byte
	Argv2     [16]byte
	Argv3     [16]byte
	Envp      uint64
	Flags     uint64
}

type ReadaheadData struct {
	EventInfo EventInfoT
	Fd        uint64
	Offset    uint64
	Count     uint64
}

type MsgrcvData struct {
	EventInfo EventInfoT
	Msqid     uint64
	Msgp      uint64
	Msgsz     uint64
	Msgtyp    uint64
	Msgflg    uint64
}

type RemovexattrData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
	Name      [64]byte
}

type ShmctlData struct {
	EventInfo EventInfoT
	Shmid     uint64
	Cmd       uint64
	Buf       uint64
}

type SendmsgData struct {
	EventInfo EventInfoT
	Fd        uint64
	Msg       uint64
	Flags     uint64
}

type SetrlimitData struct {
	EventInfo EventInfoT
	Resource  uint64
	Rlim      uint64
}

type MunmapData struct {
	EventInfo EventInfoT
	Addr      uint64
	Len       uint64
}

type ExitData struct {
	EventInfo EventInfoT
	ErrorCode uint64
}

type IoGeteventsData struct {
	EventInfo EventInfoT
	CtxId     uint64
	MinNr     uint64
	Nr        uint64
	Events    uint64
	Timeout   uint64
}

type SymlinkData struct {
	EventInfo EventInfoT
	Oldname   [64]byte
	Newname   [64]byte
}

type RtSigpendingData struct {
	EventInfo  EventInfoT
	Uset       uint64
	Sigsetsize uint64
}

type FanotifyInitData struct {
	EventInfo   EventInfoT
	Flags       uint64
	EventFFlags uint64
}

type GeteuidData struct {
	EventInfo EventInfoT
}

type GetpeernameData struct {
	EventInfo    EventInfoT
	Fd           uint64
	Usockaddr    uint64
	UsockaddrLen uint64
}

type FsetxattrData struct {
	EventInfo EventInfoT
	Fd        uint64
	Name      [64]byte
	Value     uint64
	Size      uint64
	Flags     uint64
}

type AcctData struct {
	EventInfo EventInfoT
	Name      [64]byte
}

type TimesData struct {
	EventInfo EventInfoT
	Tbuf      uint64
}

type MsggetData struct {
	EventInfo EventInfoT
	Key       uint64
	Msgflg    uint64
}

type InotifyAddWatchData struct {
	EventInfo EventInfoT
	Fd        uint64
	Pathname  [64]byte
	Mask      uint64
}

type TimerfdGettimeData struct {
	EventInfo EventInfoT
	Ufd       uint64
	Otmr      uint64
}

type RtTgsigqueueinfoData struct {
	EventInfo EventInfoT
	Tgid      uint64
	Pid       uint64
	Sig       uint64
	Uinfo     uint64
}

type TimerDeleteData struct {
	EventInfo EventInfoT
	TimerId   uint64
}

type PkeyAllocData struct {
	EventInfo EventInfoT
	Flags     uint64
	InitVal   uint64
}

type SetfsgidData struct {
	EventInfo EventInfoT
	Gid       uint64
}

type TgkillData struct {
	EventInfo EventInfoT
	Tgid      uint64
	Pid       uint64
	Sig       uint64
}

type SetgidData struct {
	EventInfo EventInfoT
	Gid       uint64
}

type AdjtimexData struct {
	EventInfo EventInfoT
	TxcP      uint64
}

type BdFlush struct {
	EventInfo EventInfoT
	Func      uint64
	Data      uint64
}

type FgetxattrData struct {
	EventInfo EventInfoT
	Fd        uint64
	Name      [64]byte
	Value     uint64
	Size      uint64
}

type PkeyMprotectData struct {
	EventInfo EventInfoT
	Start     uint64
	Len       uint64
	Prot      uint64
	Pkey      uint64
}

type SchedSetschedulerData struct {
	EventInfo EventInfoT
	Pid       uint64
	Policy    uint64
	Param     uint64
}

type MqNotifyData struct {
	EventInfo     EventInfoT
	Mqdes         uint64
	UNotification uint64
}

type EpollPwaitData struct {
	EventInfo  EventInfoT
	Epfd       uint64
	Events     uint64
	Maxevents  uint64
	Timeout    uint64
	Sigmask    uint64
	Sigsetsize uint64
}

type SyncfsData struct {
	EventInfo EventInfoT
	Fd        uint64
}

type GetrandomData struct {
	EventInfo EventInfoT
	Buf       [64]byte
	Count     uint64
	Flags     uint64
}

type CreatData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
	Mode      uint64
}

type PpollData struct {
	EventInfo  EventInfoT
	Ufds       uint64
	Nfds       uint64
	Tsp        uint64
	Sigmask    uint64
	Sigsetsize uint64
}

type SyncData struct {
	EventInfo EventInfoT
}

type FutimesatData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Filename  [64]byte
	Utimes    uint64
}

type GetuidData struct {
	EventInfo EventInfoT
}

type KexecLoadData struct {
	EventInfo  EventInfoT
	Entry      uint64
	NrSegments uint64
	Segments   uint64
	Flags      uint64
}

type FanotifyMarkData struct {
	EventInfo  EventInfoT
	FanotifyFd uint64
	Flags      uint64
	Mask       uint64
	Dfd        uint64
	Pathname   [64]byte
}

type ChrootData struct {
	EventInfo EventInfoT
	Filename  [64]byte
}

type SelectData struct {
	EventInfo EventInfoT
	N         uint64
	Inp       uint64
	Outp      uint64
	Exp       uint64
	Tvp       uint64
}

type GetrusageData struct {
	EventInfo EventInfoT
	Who       uint64
	Ru        uint64
}

type PwritevData struct {
	EventInfo EventInfoT
	Fd        uint64
	Vec       uint64
	Vlen      uint64
	PosL      uint64
	PosH      uint64
}

type GetsockoptData struct {
	EventInfo EventInfoT
	Fd        uint64
	Level     uint64
	Optname   uint64
	Optval    [64]byte
	Optlen    uint64
}

type RenameData struct {
	EventInfo EventInfoT
	Oldname   [64]byte
	Newname   [64]byte
}

type FstatfsData struct {
	EventInfo EventInfoT
	Fd        uint64
	Buf       uint64
}

type SysfsData struct {
	EventInfo EventInfoT
	Option    uint64
	Arg1      uint64
	Arg2      uint64
}

type MincoreData struct {
	EventInfo EventInfoT
	Start     uint64
	Len       uint64
	Vec       uint64
}

type CopyFileRangeData struct {
	EventInfo EventInfoT
	FdIn      uint64
	OffIn     uint64
	FdOut     uint64
	OffOut    uint64
	Len       uint64
	Flags     uint64
}

type SpliceData struct {
	EventInfo EventInfoT
	FdIn      uint64
	OffIn     uint64
	FdOut     uint64
	OffOut    uint64
	Len       uint64
	Flags     uint64
}

type NewstatData struct {
	EventInfo EventInfoT
	Filename  [64]byte
	Statbuf   uint64
}

type ProcessVmWritevData struct {
	EventInfo EventInfoT
	Pid       uint64
	Lvec      uint64
	Liovcnt   uint64
	Rvec      uint64
	Riovcnt   uint64
	Flags     uint64
}

type TimerGettimeData struct {
	EventInfo EventInfoT
	TimerId   uint64
	Setting   uint64
}

type PivotRootData struct {
	EventInfo EventInfoT
	NewRoot   [64]byte
	PutOld    [64]byte
}

type NameToHandleAtData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Name      [64]byte
	Handle    uint64
	MntId     uint64
	Flag      uint64
}

type BindData struct {
	EventInfo EventInfoT
	Fd        uint64
	Umyaddr   uint64
	Addrlen   uint64
}

type ReadlinkData struct {
	EventInfo EventInfoT
	Path      [64]byte
	Buf       [64]byte
	Bufsiz    uint64
}

type GetppidData struct {
	EventInfo EventInfoT
}

type SetuidData struct {
	EventInfo EventInfoT
	Uid       uint64
}

type MremapData struct {
	EventInfo EventInfoT
	Addr      uint64
	OldLen    uint64
	NewLen    uint64
	Flags     uint64
	NewAddr   uint64
}

type KeyctlData struct {
	EventInfo EventInfoT
	Option    uint64
	Arg2      uint64
	Arg3      uint64
	Arg4      uint64
	Arg5      uint64
}

type Pselect6Data struct {
	EventInfo EventInfoT
	N         uint64
	Inp       uint64
	Outp      uint64
	Exp       uint64
	Tsp       uint64
	Sig       uint64
}

type DeleteModuleData struct {
	EventInfo EventInfoT
	NameUser  [64]byte
	Flags     uint64
}

type UtimensatData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Filename  [64]byte
	Utimes    uint64
	Flags     uint64
}

type GetMempolicyData struct {
	EventInfo EventInfoT
	Policy    uint64
	Nmask     uint64
	Maxnode   uint64
	Addr      uint64
	Flags     uint64
}

type DupData struct {
	EventInfo EventInfoT
	Fildes    uint64
}

type EventfdData struct {
	EventInfo EventInfoT
	Count     uint64
}

type RecvfromData struct {
	EventInfo EventInfoT
	Fd        uint64
	Ubuf      uint64
	Size      uint64
	Flags     uint64
	Addr      uint64
	AddrLen   uint64
}

type StatxData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Filename  [64]byte
	Flags     uint64
	Mask      uint64
	Buffer    uint64
}

type RtSigactionData struct {
	EventInfo  EventInfoT
	Sig        uint64
	Act        uint64
	Oact       uint64
	Sigsetsize uint64
}

type MunlockallData struct {
	EventInfo EventInfoT
}

type GetdentsData struct {
	EventInfo EventInfoT
	Fd        uint64
	Dirent    uint64
	Count     uint64
}

type EpollCreate1Data struct {
	EventInfo EventInfoT
	Flags     uint64
}

type Wait4Data struct {
	EventInfo EventInfoT
	Upid      uint64
	StatAddr  uint64
	Options   uint64
	Ru        uint64
}

type SchedYieldData struct {
	EventInfo EventInfoT
}

type MlockallData struct {
	EventInfo EventInfoT
	Flags     uint64
}

type SchedGetattrData struct {
	EventInfo EventInfoT
	Pid       uint64
	Uattr     uint64
	Size      uint64
	Flags     uint64
}

type SetpriorityData struct {
	EventInfo EventInfoT
	Which     uint64
	Who       uint64
	Niceval   uint64
}

type SocketData struct {
	EventInfo EventInfoT
	Family    uint64
	Type      uint64
	Protocol  uint64
}

type SemtimedopData struct {
	EventInfo EventInfoT
	Semid     uint64
	Tsops     uint64
	Nsops     uint64
	Timeout   uint64
}

type SetfsuidData struct {
	EventInfo EventInfoT
	Uid       uint64
}

type EpollCreateData struct {
	EventInfo EventInfoT
	Size      uint64
}

type SemopData struct {
	EventInfo EventInfoT
	Semid     uint64
	Tsops     uint64
	Nsops     uint64
}

type OpenData struct {
	EventInfo EventInfoT
	Filename  [64]byte
	Flags     uint64
	Mode      uint64
}

type OpenatData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Filename  [64]byte
	Flags     uint64
	Mode      uint64
}

type FremovexattrData struct {
	EventInfo EventInfoT
	Fd        uint64
	Name      [64]byte
}

type FaccessatData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Filename  [64]byte
	Mode      uint64
}

type FtruncateData struct {
	EventInfo EventInfoT
	Fd        uint64
	Length    uint64
}

type SchedGetPriorityMinData struct {
	EventInfo EventInfoT
	Policy    uint64
}

type MovePagesData struct {
	EventInfo EventInfoT
	Pid       uint64
	NrPages   uint64
	Pages     uint64
	Nodes     uint64
	Status    uint64
	Flags     uint64
}

type LseekData struct {
	EventInfo EventInfoT
	Fd        uint64
	Offset    uint64
	Whence    uint64
}

type PollData struct {
	EventInfo    EventInfoT
	Ufds         uint64
	Nfds         uint64
	TimeoutMsecs uint64
}

type FdatasyncData struct {
	EventInfo EventInfoT
	Fd        uint64
}

type FsyncData struct {
	EventInfo EventInfoT
	Fd        uint64
}

type SetsockoptData struct {
	EventInfo EventInfoT
	Fd        uint64
	Level     uint64
	Optname   uint64
	Optval    [64]byte
	Optlen    uint64
}

type TimerGetoverrunData struct {
	EventInfo EventInfoT
	TimerId   uint64
}

type GetgidData struct {
	EventInfo EventInfoT
}

type CapsetData struct {
	EventInfo EventInfoT
	Header    uint64
	Data      uint64
}

type SemgetData struct {
	EventInfo EventInfoT
	Key       uint64
	Nsems     uint64
	Semflg    uint64
}

type Prlimit64Data struct {
	EventInfo EventInfoT
	Pid       uint64
	Resource  uint64
	NewRlim   uint64
	OldRlim   uint64
}

type MqUnlinkData struct {
	EventInfo EventInfoT
	UName     [64]byte
}

type ClockSettimeData struct {
	EventInfo  EventInfoT
	WhichClock uint64
	Tp         uint64
}

type RtSigtimedwaitData struct {
	EventInfo  EventInfoT
	Uthese     uint64
	Uinfo      uint64
	Uts        uint64
	Sigsetsize uint64
}

type SigaltstackData struct {
	EventInfo EventInfoT
	Uss       uint64
	Uoss      uint64
}

type ShmgetData struct {
	EventInfo EventInfoT
	Key       uint64
	Size      uint64
	Shmflg    uint64
}

type WritevData struct {
	EventInfo EventInfoT
	Fd        uint64
	Vec       uint64
	Vlen      uint64
}

type MprotectData struct {
	EventInfo EventInfoT
	Start     uint64
	Len       uint64
	Prot      uint64
}

type SetitimerData struct {
	EventInfo EventInfoT
	Which     uint64
	Value     uint64
	Ovalue    uint64
}

type RemapFilePagesData struct {
	EventInfo EventInfoT
	Start     uint64
	Size      uint64
	Prot      uint64
	Pgoff     uint64
	Flags     uint64
}

type GetresgidData struct {
	EventInfo EventInfoT
	Rgidp     uint64
	Egidp     uint64
	Sgidp     uint64
}

type SeccompData struct {
	EventInfo EventInfoT
	Op        uint64
	Flags     uint64
	Uargs     [64]byte
}

type GettimeofdayData struct {
	EventInfo EventInfoT
	Tv        uint64
	Tz        uint64
}

type GetsocknameData struct {
	EventInfo    EventInfoT
	Fd           uint64
	Usockaddr    uint64
	UsockaddrLen uint64
}

type SymlinkatData struct {
	EventInfo EventInfoT
	Oldname   [64]byte
	Newdfd    uint64
	Newname   [64]byte
}

type GetpidData struct {
	EventInfo EventInfoT
}

type VforkData struct {
	EventInfo EventInfoT
}

type ForkData struct {
	EventInfo EventInfoT
}

type GetpgrpData struct {
	EventInfo EventInfoT
}

type TimerCreateData struct {
	EventInfo      EventInfoT
	WhichClock     uint64
	TimerEventSpec uint64
	CreatedTimerId uint64
}

type ListxattrData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
	List      [64]byte
	Size      uint64
}

type KexecFileLoadData struct {
	EventInfo  EventInfoT
	KernelFd   uint64
	InitrdFd   uint64
	CmdlineLen uint64
	CmdlinePtr [64]byte
	Flags      uint64
}

type MsgsndData struct {
	EventInfo EventInfoT
	Msqid     uint64
	Msgp      uint64
	Msgsz     uint64
	Msgflg    uint64
}

type UnlinkatData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Pathname  [64]byte
	Flag      uint64
	Fd        uint64
}

type GettidData struct {
	EventInfo EventInfoT
}

type ExecveData struct {
	EventInfo EventInfoT
	Filename  [64]byte
	Argv1     [16]byte
	Argv2     [16]byte
	Argv3     [16]byte
	Envp      uint64
}

type CloneData struct {
	EventInfo    EventInfoT
	CloneFlags   uint64
	Newsp        uint64
	ParentTidptr uint64
	ChildTidptr  uint64
	Tls          uint64
}

type RseqData struct {
	EventInfo EventInfoT
	Rseq      uint64
	RseqLen   uint64
	Flags     uint64
	Sig       uint64
}

type RtSigreturnData struct {
	EventInfo EventInfoT
}

type FinitModuleData struct {
	EventInfo EventInfoT
	Fd        uint64
	Uargs     [64]byte
	Flags     uint64
}

type PkeyFreeData struct {
	EventInfo EventInfoT
	Pkey      uint64
}

type BrkData struct {
	EventInfo EventInfoT
	Brk       uint64
}

type SetresuidData struct {
	EventInfo EventInfoT
	Ruid      uint64
	Euid      uint64
	Suid      uint64
}

type RtSigsuspendData struct {
	EventInfo  EventInfoT
	Unewset    uint64
	Sigsetsize uint64
}

type LchownData struct {
	EventInfo EventInfoT
	Filename  [64]byte
	User      uint64
	Group     uint64
}

type FallocateData struct {
	EventInfo EventInfoT
	Fd        uint64
	Mode      uint64
	Offset    uint64
	Len       uint64
}

type IoprioSetData struct {
	EventInfo EventInfoT
	Which     uint64
	Who       uint64
	Ioprio    uint64
}

type MknodatData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Filename  [64]byte
	Mode      uint64
	Dev       uint64
}

type PipeData struct {
	EventInfo EventInfoT
	Fildes    uint64
	ReadFd    uint64
	WriteFd   uint64
}

type RebootData struct {
	EventInfo EventInfoT
	Magic1    uint64
	Magic2    uint64
	Cmd       uint64
	Arg       uint64
}

type Eventfd2Data struct {
	EventInfo EventInfoT
	Count     uint64
	Flags     uint64
}

type UnlinkData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
}

type RecvmmsgData struct {
	EventInfo EventInfoT
	Fd        uint64
	Mmsg      uint64
	Vlen      uint64
	Flags     uint64
	Timeout   uint64
}

type MsyncData struct {
	EventInfo EventInfoT
	Start     uint64
	Len       uint64
	Flags     uint64
}

type AccessData struct {
	EventInfo EventInfoT
	Filename  [64]byte
	Mode      uint64
}

type Signalfd4Data struct {
	EventInfo EventInfoT
	Ufd       uint64
	UserMask  uint64
	Sizemask  uint64
	Flags     uint64
}

type MbindData struct {
	EventInfo EventInfoT
	Start     uint64
	Len       uint64
	Mode      uint64
	Nmask     uint64
	Maxnode   uint64
	Flags     uint64
}

type MknodData struct {
	EventInfo EventInfoT
	Filename  [64]byte
	Mode      uint64
	Dev       uint64
}

type MunlockData struct {
	EventInfo EventInfoT
	Start     uint64
	Len       uint64
}

type GetpgidData struct {
	EventInfo EventInfoT
	Pid       uint64
}

type GetresuidData struct {
	EventInfo EventInfoT
	Ruidp     uint64
	Euidp     uint64
	Suidp     uint64
}

type FchownatData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Filename  [64]byte
	User      uint64
	Group     uint64
	Flag      uint64
}

type PerfEventOpenData struct {
	EventInfo EventInfoT
	AttrUptr  uint64
	Pid       uint64
	Cpu       uint64
	GroupFd   uint64
	Flags     uint64
}

type NewunameData struct {
	EventInfo EventInfoT
	Name      uint64
}

type TimerfdCreateData struct {
	EventInfo EventInfoT
	Clockid   uint64
	Flags     uint64
}

type ShmdtData struct {
	EventInfo EventInfoT
	Shmaddr   [64]byte
}

type RmdirData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
}

type OpenByHandleAtData struct {
	EventInfo  EventInfoT
	Mountdirfd uint64
	Handle     uint64
	Flags      uint64
}

type SocketpairData struct {
	EventInfo EventInfoT
	Family    uint64
	Type      uint64
	Protocol  uint64
	Usockvec  uint64
}

type SetresgidData struct {
	EventInfo EventInfoT
	Rgid      uint64
	Egid      uint64
	Sgid      uint64
}

type GetitimerData struct {
	EventInfo EventInfoT
	Which     uint64
	Value     uint64
}

type MqGetsetattrData struct {
	EventInfo EventInfoT
	Mqdes     uint64
	UMqstat   uint64
	UOmqstat  uint64
}

type ChdirData struct {
	EventInfo EventInfoT
	Filename  [64]byte
}

type FchdirData struct {
	EventInfo EventInfoT
	Fd        uint64
}

type MmapData struct {
	EventInfo EventInfoT
	Addr      uint64
	Len       uint64
	Prot      uint64
	Flags     uint64
	Fd        uint64
	Off       uint64
}

type LookupDcookieData struct {
	EventInfo EventInfoT
	Cookie64  uint64
	Buf       [64]byte
	Len       uint64
}

type SyslogData struct {
	EventInfo EventInfoT
	Type      uint64
	Buf       [64]byte
	Len       uint64
}

type AcceptData struct {
	EventInfo     EventInfoT
	Fd            uint64
	UpeerSockaddr uint64
	UpeerAddrlen  uint64
}

type SetMempolicyData struct {
	EventInfo EventInfoT
	Mode      uint64
	Nmask     uint64
	Maxnode   uint64
}

type MkdiratData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Pathname  [64]byte
	Mode      uint64
	Fd        uint64
}

type FchmodatData struct {
	EventInfo EventInfoT
	Dfd       uint64
	Filename  [64]byte
	Mode      uint64
}

type MkdirData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
	Mode      uint64
}

type MountData struct {
	EventInfo EventInfoT
	DevName   [32]byte
	DirName   [32]byte
	Type      [32]byte
	Flags     uint64
	Data      uint64
}

type SchedSetaffinityData struct {
	EventInfo   EventInfoT
	Pid         uint64
	Len         uint64
	UserMaskPtr uint64
}

type MqTimedreceiveData struct {
	EventInfo   EventInfoT
	Mqdes       uint64
	UMsgPtr     [64]byte
	MsgLen      uint64
	UMsgPrio    uint64
	UAbsTimeout uint64
}

type GetsidData struct {
	EventInfo EventInfoT
	Pid       uint64
}

type UnshareData struct {
	EventInfo    EventInfoT
	UnshareFlags uint64
}

type CapgetData struct {
	EventInfo EventInfoT
	Header    uint64
	Dataptr   uint64
}

type LinkatData struct {
	EventInfo EventInfoT
	Olddfd    uint64
	Oldname   [64]byte
	Newdfd    uint64
	Newname   [64]byte
	Flags     uint64
}

type AlarmData struct {
	EventInfo EventInfoT
	Seconds   uint64
}

type IoSetupData struct {
	EventInfo EventInfoT
	NrEvents  uint64
	Ctxp      uint64
}

type MqTimedsendData struct {
	EventInfo   EventInfoT
	Mqdes       uint64
	UMsgPtr     [64]byte
	MsgLen      uint64
	MsgPrio     uint64
	UAbsTimeout uint64
}

type GetcwdData struct {
	EventInfo EventInfoT
	Buf       [64]byte
	Size      uint64
}

type EpollWaitData struct {
	EventInfo EventInfoT
	Epfd      uint64
	Events    uint64
	Maxevents uint64
	Timeout   uint64
}

type IopermData struct {
	EventInfo EventInfoT
	From      uint64
	Num       uint64
	TurnOn    uint64
}

type FlockData struct {
	EventInfo EventInfoT
	Fd        uint64
	Cmd       uint64
}

type EpollCtlData struct {
	EventInfo EventInfoT
	Epfd      uint64
	Op        uint64
	Fd        uint64
	Event     uint64
}

type ClockGettimeData struct {
	EventInfo  EventInfoT
	WhichClock uint64
	Tp         uint64
}

type SemctlData struct {
	EventInfo EventInfoT
	Semid     uint64
	Semnum    uint64
	Cmd       uint64
	Arg       uint64
}

type RtSigprocmaskData struct {
	EventInfo  EventInfoT
	How        uint64
	Nset       uint64
	Oset       uint64
	Sigsetsize uint64
}

type PersonalityData struct {
	EventInfo   EventInfoT
	Personality uint64
}

type LlistxattrData struct {
	EventInfo EventInfoT
	Pathname  [64]byte
	List      [64]byte
	Size      uint64
}

type PtraceData struct {
	EventInfo EventInfoT
	Request   uint64
	Pid       uint64
	Addr      uint64
	Data      uint64
}

type SetdomainnameData struct {
	EventInfo EventInfoT
	Name      [64]byte
	Len       uint64
}

type ProcessVmReadvData struct {
	EventInfo EventInfoT
	Pid       uint64
	Lvec      uint64
	Liovcnt   uint64
	Rvec      uint64
	Riovcnt   uint64
	Flags     uint64
}

type VhangupData struct {
	EventInfo EventInfoT
}

type ArchPrctlData struct {
	EventInfo EventInfoT
	Option    uint64
	Arg2      uint64
}

type RecvmsgData struct {
	EventInfo EventInfoT
	Fd        uint64
	Msg       uint64
	Flags     uint64
}

type NanosleepData struct {
	EventInfo EventInfoT
	Rqtp      uint64
	Rmtp      uint64
}

type FcntlData struct {
	EventInfo EventInfoT
	Fd        uint64
	Cmd       uint64
	Arg       uint64
}

type IoCancelData struct {
	EventInfo EventInfoT
	CtxId     uint64
	Iocb      uint64
	Result    uint64
}

type Getdents64Data struct {
	EventInfo EventInfoT
	Fd        uint64
	Dirent    uint64
	Count     uint64
}

type InotifyRmWatchData struct {
	EventInfo EventInfoT
	Fd        uint64
	Wd        uint64
}

type FlistxattrData struct {
	EventInfo EventInfoT
	Fd        uint64
	List      [64]byte
	Size      uint64
}

type ReadData struct {
	EventInfo EventInfoT
	Fd        uint64
	Buf       [64]byte
	Count     uint64
}

type ClockNanosleepData struct {
	EventInfo  EventInfoT
	WhichClock uint64
	Flags      uint64
	Rqtp       uint64
	Rmtp       uint64
}

type SysctlData struct {
	EventInfo EventInfoT
	Args      uint64
}

type ChownData struct {
	EventInfo EventInfoT
	Filename  [64]byte
	User      uint64
	Group     uint64
}

type SetgroupsData struct {
	EventInfo  EventInfoT
	Gidsetsize uint64
	Grouplist  uint64
}

type NewfstatData struct {
	EventInfo EventInfoT
	Fd        uint64
	Statbuf   uint64
}

type MadviseData struct {
	EventInfo EventInfoT
	Start     uint64
	LenIn     uint64
	Behavior  uint64
}

type FchownData struct {
	EventInfo EventInfoT
	Fd        uint64
	User      uint64
	Group     uint64
}

type InotifyInit1Data struct {
	EventInfo EventInfoT
	Flags     uint64
}

type AddKeyData struct {
	EventInfo   EventInfoT
	Type        [64]byte
	Description [64]byte
	Payload     uint64
	Plen        uint64
	Ringid      uint64
}

type MemfdCreateData struct {
	EventInfo EventInfoT
	Uname     [64]byte
	Flags     uint64
}

type MqOpenData struct {
	EventInfo EventInfoT
	UName     [64]byte
	Oflag     uint64
	Mode      uint64
	UAttr     uint64
}

type InitModuleData struct {
	EventInfo EventInfoT
	Umod      uint64
	Len       uint64
	Uargs     [64]byte
}

type SchedSetattrData struct {
	EventInfo EventInfoT
	Pid       uint64
	Uattr     uint64
	Flags     uint64
}

type RestartSyscallData struct {
	EventInfo EventInfoT
}

type IoctlData struct {
	EventInfo EventInfoT
	Fd        uint64
	Cmd       uint64
	Arg       uint64
}

type RequestKeyData struct {
	EventInfo   EventInfoT
	Type        [64]byte
	Description [64]byte
	CalloutInfo [64]byte
	Destringid  uint64
}

type InotifyInitData struct {
	EventInfo EventInfoT
}

type UmountData struct {
	EventInfo EventInfoT
	Name      [64]byte
	Flags     uint64
}

type PreadvData struct {
	EventInfo EventInfoT
	Fd        uint64
	Vec       uint64
	Vlen      uint64
	PosL      uint64
	PosH      uint64
}

type VmspliceData struct {
	EventInfo EventInfoT
	Fd        uint64
	Uiov      uint64
	NrSegs    uint64
	Flags     uint64
}

type SysinfoData struct {
	EventInfo EventInfoT
	Info      uint64
}

type TimerSettimeData struct {
	EventInfo  EventInfoT
	TimerId    uint64
	Flags      uint64
	NewSetting uint64
	OldSetting uint64
}

type QuotactlData struct {
	EventInfo EventInfoT
	Cmd       uint64
	Special   [64]byte
	Id        uint64
	Addr      uint64
}

type GetgroupsData struct {
	EventInfo  EventInfoT
	Gidsetsize uint64
	Grouplist  uint64
}

type FchmodData struct {
	EventInfo EventInfoT
	Fd        uint64
	Mode      uint64
}

type Fadvise64Data struct {
	EventInfo EventInfoT
	Fd        uint64
	Offset    uint64
	Len       uint64
	Advice    uint64
}

type IoSubmitData struct {
	EventInfo EventInfoT
	CtxId     uint64
	Nr        uint64
	Iocbpp    uint64
}

type ChmodData struct {
	EventInfo EventInfoT
	Filename  [64]byte
	//Fd	uint64
	Mode uint64
}

type Pwrite64Data struct {
	EventInfo EventInfoT
	Fd        uint64
	Buf       [64]byte
	Count     uint64
	Pos       uint64
}

type SettimeofdayData struct {
	EventInfo EventInfoT
	Tv        uint64
	Tz        uint64
}

type SchedGetparamData struct {
	EventInfo EventInfoT
	Pid       uint64
	Param     uint64
}

type SchedGetaffinityData struct {
	EventInfo   EventInfoT
	Pid         uint64
	Len         uint64
	UserMaskPtr uint64
}

type MsgctlData struct {
	EventInfo EventInfoT
	Msqid     uint64
	Cmd       uint64
	Buf       uint64
}

type TimerfdSettimeData struct {
	EventInfo EventInfoT
	Ufd       uint64
	Flags     uint64
	Utmr      uint64
	Otmr      uint64
}

type SetsidData struct {
	EventInfo EventInfoT
}

type ConnectData struct {
	EventInfo EventInfoT
	Fd        uint64
	Uservaddr uint64
	Addrlen   uint64
}

type SendtoData struct {
	EventInfo EventInfoT
	Fd        uint64
	Buff      uint64
	Len       uint64
	Flags     uint64
	Addr      uint64
	AddrLen   uint64
}

type BpfData struct {
	EventInfo EventInfoT
	Cmd       uint64
	Uattr     uint64
	Size      uint64
}

type KcmpData struct {
	EventInfo EventInfoT
	Pid1      uint64
	Pid2      uint64
	Type      uint64
	Idx1      uint64
	Idx2      uint64
}

type Mlock2Data struct {
	EventInfo EventInfoT
	Start     uint64
	Len       uint64
	Flags     uint64
}

type Pwritev2Data struct {
	EventInfo EventInfoT
	Fd        uint64
	Vec       uint64
	Vlen      uint64
	PosL      uint64
	PosH      uint64
	Flags     uint64
}

type SchedSetparamData struct {
	EventInfo EventInfoT
	Pid       uint64
	Param     uint64
}

type SwapoffData struct {
	EventInfo   EventInfoT
	Specialfile [64]byte
}

type UserfaultfdData struct {
	EventInfo EventInfoT
	Flags     uint64
}

type IoPgeteventsData struct {
	EventInfo EventInfoT
	CtxId     uint64
	MinNr     uint64
	Nr        uint64
	Events    uint64
	Timeout   uint64
	Usig      uint64
}

type ListenData struct {
	EventInfo EventInfoT
	Fd        uint64
	Backlog   uint64
}

type GetRobustListData struct {
	EventInfo EventInfoT
	Pid       uint64
	HeadPtr   uint64
	LenPtr    uint64
}

type SetnsData struct {
	EventInfo EventInfoT
	Fd        uint64
	Nstype    uint64
}

type TotalData struct {
	IsSyscall                   bool       `json:"is_syscall"`
	EventInfo                   EventInfoT `json:"event_info"`
	TimeTloc                    uint64     `json:"time__tloc"`
	BdFlushFunc                 uint64     `json:"bdflush__func"`
	BdFlushData                 uint64     `json:"bdflush__data"`
	MigratePagesPid             uint64     `json:"migrate_pages__pid"`
	MigratePagesMaxnode         uint64     `json:"migrate_pages__maxnode"`
	MigratePagesOldNodes        uint64     `json:"migrate_pages__old_nodes"`
	MigratePagesNewNodes        uint64     `json:"migrate_pages__new_nodes"`
	LsetxattrPathname           string     `json:"lsetxattr__pathname"`
	LsetxattrName               string     `json:"lsetxattr__name"`
	LsetxattrValue              uint64     `json:"lsetxattr__value"`
	LsetxattrSize               uint64     `json:"lsetxattr__size"`
	LsetxattrFlags              uint64     `json:"lsetxattr__flags"`
	ClockGetresWhichClock       uint64     `json:"clock_getres__which_clock"`
	ClockGetresTp               uint64     `json:"clock_getres__tp"`
	SetTidAddressTidptr         uint64     `json:"set_tid_address__tidptr"`
	Pipe2Fildes                 uint64     `json:"pipe2__fildes"`
	Pipe2Readfd                 uint64     `json:"pipe2__readfd"`
	Pipe2Writefd                uint64     `json:"pipe2__writefd"`
	Pipe2Flags                  uint64     `json:"pipe2__flags"`
	SethostnameName             string     `json:"sethostname__name"`
	SethostnameLen              uint64     `json:"sethostname__len"`
	Dup3Oldfd                   uint64     `json:"dup3__oldfd"`
	Dup3Newfd                   uint64     `json:"dup3__newfd"`
	Dup3Flags                   uint64     `json:"dup3__flags"`
	UmaskMask                   uint64     `json:"umask__mask"`
	ExitGroupErrorCode          uint64     `json:"exit_group__error_code"`
	SetRobustListHead           uint64     `json:"set_robust_list__head"`
	SetRobustListLen            uint64     `json:"set_robust_list__len"`
	IoplLevel                   uint64     `json:"iopl__level"`
	LgetxattrPathname           string     `json:"lgetxattr__pathname"`
	LgetxattrName               string     `json:"lgetxattr__name"`
	LgetxattrValue              uint64     `json:"lgetxattr__value"`
	LgetxattrSize               uint64     `json:"lgetxattr__size"`
	KillPid                     uint64     `json:"kill__pid"`
	KillSig                     uint64     `json:"kill__sig"`
	Pread64Fd                   uint64     `json:"pread64__fd"`
	Pread64Buf                  string     `json:"pread64__buf"`
	Pread64Count                uint64     `json:"pread64__count"`
	Pread64Pos                  uint64     `json:"pread64__pos"`
	NewfstatatDfd               uint64     `json:"newfstatat__dfd"`
	NewfstatatFilename          string     `json:"newfstatat__filename"`
	NewfstatatStatbuf           uint64     `json:"newfstatat__statbuf"`
	NewfstatatFlag              uint64     `json:"newfstatat__flag"`
	NewlstatFilename            string     `json:"newlstat__filename"`
	NewlstatStatbuf             uint64     `json:"newlstat__statbuf"`
	WriteFd                     uint64     `json:"write__fd"`
	WriteBuf                    string     `json:"write__buf"`
	WriteCount                  uint64     `json:"write__count"`
	SetregidRgid                uint64     `json:"setregid__rgid"`
	SetregidEgid                uint64     `json:"setregid__egid"`
	UstatDev                    uint64     `json:"ustat__dev"`
	UstatUbuf                   uint64     `json:"ustat__ubuf"`
	GetrlimitResource           uint64     `json:"getrlimit__resource"`
	GetrlimitRlim               uint64     `json:"getrlimit__rlim"`
	TkillPid                    uint64     `json:"tkill__pid"`
	TkillSig                    uint64     `json:"tkill__sig"`
	Dup2Oldfd                   uint64     `json:"dup2__oldfd"`
	Dup2Newfd                   uint64     `json:"dup2__newfd"`
	ClockAdjtimeWhichClock      uint64     `json:"clock_adjtime__which_clock"`
	ClockAdjtimeUtx             uint64     `json:"clock_adjtime__utx"`
	RtSigqueueinfoPid           uint64     `json:"rt_sigqueueinfo__pid"`
	RtSigqueueinfoSig           uint64     `json:"rt_sigqueueinfo__sig"`
	RtSigqueueinfoUinfo         uint64     `json:"rt_sigqueueinfo__uinfo"`
	UtimeFilename               string     `json:"utime__filename"`
	UtimeTimes                  uint64     `json:"utime__times"`
	SetxattrPathname            string     `json:"setxattr__pathname"`
	SetxattrName                string     `json:"setxattr__name"`
	SetxattrValue               uint64     `json:"setxattr__value"`
	SetxattrSize                uint64     `json:"setxattr__size"`
	SetxattrFlags               uint64     `json:"setxattr__flags"`
	MembarrierCmd               uint64     `json:"membarrier__cmd"`
	MembarrierFlags             uint64     `json:"membarrier__flags"`
	MlockStart                  uint64     `json:"mlock__start"`
	MlockLen                    uint64     `json:"mlock__len"`
	TeeFdin                     uint64     `json:"tee__fdin"`
	TeeFdout                    uint64     `json:"tee__fdout"`
	TeeLen                      uint64     `json:"tee__len"`
	TeeFlags                    uint64     `json:"tee__flags"`
	SetpgidPid                  uint64     `json:"setpgid__pid"`
	SetpgidPgid                 uint64     `json:"setpgid__pgid"`
	UtimesFilename              string     `json:"utimes__filename"`
	UtimesUtimes                uint64     `json:"utimes__utimes"`
	LremovexattrPathname        string     `json:"lremovexattr__pathname"`
	LremovexattrName            string     `json:"lremovexattr__name"`
	LinkOldname                 string     `json:"link__oldname"`
	LinkNewname                 string     `json:"link__newname"`
	ReadvFd                     uint64     `json:"readv__fd"`
	ReadvVec                    uint64     `json:"readv__vec"`
	ReadvVlen                   uint64     `json:"readv__vlen"`
	FutexUaddr                  uint64     `json:"futex__uaddr"`
	FutexOp                     uint64     `json:"futex__op"`
	FutexVal                    uint64     `json:"futex__val"`
	FutexUtime                  uint64     `json:"futex__utime"`
	FutexUaddr2                 uint64     `json:"futex__uaddr2"`
	FutexVal3                   uint64     `json:"futex__val3"`
	GetxattrPathname            string     `json:"getxattr__pathname"`
	GetxattrName                string     `json:"getxattr__name"`
	GetxattrValue               uint64     `json:"getxattr__value"`
	GetxattrSize                uint64     `json:"getxattr__size"`
	SchedGetPriorityMaxPolicy   uint64     `json:"sched_get_priority_max__policy"`
	Preadv2Fd                   uint64     `json:"preadv2__fd"`
	Preadv2Vec                  uint64     `json:"preadv2__vec"`
	Preadv2Vlen                 uint64     `json:"preadv2__vlen"`
	Preadv2PosL                 uint64     `json:"preadv2__pos_l"`
	Preadv2PosH                 uint64     `json:"preadv2__pos_h"`
	Preadv2Flags                uint64     `json:"preadv2__flags"`
	ReadlinkatDfd               uint64     `json:"readlinkat__dfd"`
	ReadlinkatPathname          string     `json:"readlinkat__pathname"`
	ReadlinkatBuf               string     `json:"readlinkat__buf"`
	ReadlinkatBufsiz            uint64     `json:"readlinkat__bufsiz"`
	PrctlOption                 uint64     `json:"prctl__option"`
	PrctlArg2                   uint64     `json:"prctl__arg2"`
	PrctlArg3                   uint64     `json:"prctl__arg3"`
	PrctlArg4                   uint64     `json:"prctl__arg4"`
	PrctlArg5                   uint64     `json:"prctl__arg5"`
	RenameatOlddfd              uint64     `json:"renameat__olddfd"`
	RenameatOldname             string     `json:"renameat__oldname"`
	RenameatNewdfd              uint64     `json:"renameat__newdfd"`
	RenameatNewname             string     `json:"renameat__newname"`
	Renameat2Olddfd             uint64     `json:"renameat2__olddfd"`
	Renameat2Oldname            string     `json:"renameat2__oldname"`
	Renameat2Newdfd             uint64     `json:"renameat2__newdfd"`
	Renameat2Newname            string     `json:"renameat2__newname"`
	Renameat2Flags              uint64     `json:"renameat2__flags"`
	SendmmsgFd                  uint64     `json:"sendmmsg__fd"`
	SendmmsgMmsg                uint64     `json:"sendmmsg__mmsg"`
	SendmmsgVlen                uint64     `json:"sendmmsg__vlen"`
	SendmmsgFlags               uint64     `json:"sendmmsg__flags"`
	ModifyLdtFunc               uint64     `json:"modify_ldt__func"`
	ModifyLdtPtr                uint64     `json:"modify_ldt__ptr"`
	ModifyLdtBytecount          uint64     `json:"modify_ldt__bytecount"`
	CloseFd                     uint64     `json:"close__fd"`
	IoprioGetWhich              uint64     `json:"ioprio_get__which"`
	IoprioGetWho                uint64     `json:"ioprio_get__who"`
	SetreuidRuid                uint64     `json:"setreuid__ruid"`
	SetreuidEuid                uint64     `json:"setreuid__euid"`
	Sendfile64OutFd             uint64     `json:"sendfile64__out_fd"`
	Sendfile64InFd              uint64     `json:"sendfile64__in_fd"`
	Sendfile64Offset            uint64     `json:"sendfile64__offset"`
	Sendfile64Count             uint64     `json:"sendfile64__count"`
	StatfsPathname              string     `json:"statfs__pathname"`
	StatfsBuf                   uint64     `json:"statfs__buf"`
	GetpriorityWhich            uint64     `json:"getpriority__which"`
	GetpriorityWho              uint64     `json:"getpriority__who"`
	TruncatePath                string     `json:"truncate__path"`
	TruncateLength              uint64     `json:"truncate__length"`
	GetcpuCpup                  uint64     `json:"getcpu__cpup"`
	GetcpuNodep                 uint64     `json:"getcpu__nodep"`
	GetcpuUnused                uint64     `json:"getcpu__unused"`
	ShmatShmid                  uint64     `json:"shmat__shmid"`
	ShmatShmaddr                string     `json:"shmat__shmaddr"`
	ShmatShmflg                 uint64     `json:"shmat__shmflg"`
	SwaponSpecialfile           string     `json:"swapon__specialfile"`
	SwaponSwapFlags             uint64     `json:"swapon__swap_flags"`
	WaitidWhich                 uint64     `json:"waitid__which"`
	WaitidUpid                  uint64     `json:"waitid__upid"`
	WaitidInfop                 uint64     `json:"waitid__infop"`
	WaitidOptions               uint64     `json:"waitid__options"`
	WaitidRu                    uint64     `json:"waitid__ru"`
	SyncFileRangeFd             uint64     `json:"sync_file_range__fd"`
	SyncFileRangeOffset         uint64     `json:"sync_file_range__offset"`
	SyncFileRangeNbytes         uint64     `json:"sync_file_range__nbytes"`
	SyncFileRangeFlags          uint64     `json:"sync_file_range__flags"`
	SchedRrGetIntervalPid       uint64     `json:"sched_rr_get_interval__pid"`
	SchedRrGetIntervalInterval  uint64     `json:"sched_rr_get_interval__interval"`
	SchedGetschedulerPid        uint64     `json:"sched_getscheduler__pid"`
	SignalfdUfd                 uint64     `json:"signalfd__ufd"`
	SignalfdUserMask            uint64     `json:"signalfd__user_mask"`
	SignalfdSizemask            uint64     `json:"signalfd__sizemask"`
	Accept4Fd                   uint64     `json:"accept4__fd"`
	Accept4UpeerSockaddr        uint64     `json:"accept4__upeer_sockaddr"`
	Accept4UpeerAddrlen         uint64     `json:"accept4__upeer_addrlen"`
	Accept4Flags                uint64     `json:"accept4__flags"`
	IoDestroyCtx                uint64     `json:"io_destroy__ctx"`
	ShutdownFd                  uint64     `json:"shutdown__fd"`
	ShutdownHow                 uint64     `json:"shutdown__how"`
	ExecveatFd                  uint64     `json:"execveat__fd"`
	ExecveatFilename            string     `json:"execveat__filename"`
	ExecveatArgv1               string     `json:"execveat__argv1"`
	ExecveatArgv2               string     `json:"execveat__argv2"`
	ExecveatArgv3               string     `json:"execveat__argv3"`
	ExecveatEnvp                uint64     `json:"execveat__envp"`
	ExecveatFlags               uint64     `json:"execveat__flags"`
	ReadaheadFd                 uint64     `json:"readahead__fd"`
	ReadaheadOffset             uint64     `json:"readahead__offset"`
	ReadaheadCount              uint64     `json:"readahead__count"`
	MsgrcvMsqid                 uint64     `json:"msgrcv__msqid"`
	MsgrcvMsgp                  uint64     `json:"msgrcv__msgp"`
	MsgrcvMsgsz                 uint64     `json:"msgrcv__msgsz"`
	MsgrcvMsgtyp                uint64     `json:"msgrcv__msgtyp"`
	MsgrcvMsgflg                uint64     `json:"msgrcv__msgflg"`
	RemovexattrPathname         string     `json:"removexattr__pathname"`
	RemovexattrName             string     `json:"removexattr__name"`
	ShmctlShmid                 uint64     `json:"shmctl__shmid"`
	ShmctlCmd                   uint64     `json:"shmctl__cmd"`
	ShmctlBuf                   uint64     `json:"shmctl__buf"`
	SendmsgFd                   uint64     `json:"sendmsg__fd"`
	SendmsgMsg                  uint64     `json:"sendmsg__msg"`
	SendmsgFlags                uint64     `json:"sendmsg__flags"`
	SetrlimitResource           uint64     `json:"setrlimit__resource"`
	SetrlimitRlim               uint64     `json:"setrlimit__rlim"`
	MunmapAddr                  uint64     `json:"munmap__addr"`
	MunmapLen                   uint64     `json:"munmap__len"`
	ExitErrorCode               uint64     `json:"exit__error_code"`
	IoGeteventsCtxId            uint64     `json:"io_getevents__ctx_id"`
	IoGeteventsMinNr            uint64     `json:"io_getevents__min_nr"`
	IoGeteventsNr               uint64     `json:"io_getevents__nr"`
	IoGeteventsEvents           uint64     `json:"io_getevents__events"`
	IoGeteventsTimeout          uint64     `json:"io_getevents__timeout"`
	SymlinkOldname              string     `json:"symlink__oldname"`
	SymlinkNewname              string     `json:"symlink__newname"`
	RtSigpendingUset            uint64     `json:"rt_sigpending__uset"`
	RtSigpendingSigsetsize      uint64     `json:"rt_sigpending__sigsetsize"`
	FanotifyInitFlags           uint64     `json:"fanotify_init__flags"`
	FanotifyInitEventFFlags     uint64     `json:"fanotify_init__event_f_flags"`
	GetpeernameFd               uint64     `json:"getpeername__fd"`
	GetpeernameUsockaddr        uint64     `json:"getpeername__usockaddr"`
	GetpeernameUsockaddrLen     uint64     `json:"getpeername__usockaddr_len"`
	FsetxattrFd                 uint64     `json:"fsetxattr__fd"`
	FsetxattrName               string     `json:"fsetxattr__name"`
	FsetxattrValue              uint64     `json:"fsetxattr__value"`
	FsetxattrSize               uint64     `json:"fsetxattr__size"`
	FsetxattrFlags              uint64     `json:"fsetxattr__flags"`
	AcctName                    string     `json:"acct__name"`
	TimesTbuf                   uint64     `json:"times__tbuf"`
	MsggetKey                   uint64     `json:"msgget__key"`
	MsggetMsgflg                uint64     `json:"msgget__msgflg"`
	InotifyAddWatchFd           uint64     `json:"inotify_add_watch__fd"`
	InotifyAddWatchPathname     string     `json:"inotify_add_watch__pathname"`
	InotifyAddWatchMask         uint64     `json:"inotify_add_watch__mask"`
	TimerfdGettimeUfd           uint64     `json:"timerfd_gettime__ufd"`
	TimerfdGettimeOtmr          uint64     `json:"timerfd_gettime__otmr"`
	RtTgsigqueueinfoTgid        uint64     `json:"rt_tgsigqueueinfo__tgid"`
	RtTgsigqueueinfoPid         uint64     `json:"rt_tgsigqueueinfo__pid"`
	RtTgsigqueueinfoSig         uint64     `json:"rt_tgsigqueueinfo__sig"`
	RtTgsigqueueinfoUinfo       uint64     `json:"rt_tgsigqueueinfo__uinfo"`
	TimerDeleteTimerId          uint64     `json:"timer_delete__timer_id"`
	PkeyAllocFlags              uint64     `json:"pkey_alloc__flags"`
	PkeyAllocInitVal            uint64     `json:"pkey_alloc__init_val"`
	SetfsgidGid                 uint64     `json:"setfsgid__gid"`
	TgkillTgid                  uint64     `json:"tgkill__tgid"`
	TgkillPid                   uint64     `json:"tgkill__pid"`
	TgkillSig                   uint64     `json:"tgkill__sig"`
	SetgidGid                   uint64     `json:"setgid__gid"`
	AdjtimexTxcP                uint64     `json:"adjtimex__txc_p"`
	FgetxattrFd                 uint64     `json:"fgetxattr__fd"`
	FgetxattrName               string     `json:"fgetxattr__name"`
	FgetxattrValue              uint64     `json:"fgetxattr__value"`
	FgetxattrSize               uint64     `json:"fgetxattr__size"`
	PkeyMprotectStart           uint64     `json:"pkey_mprotect__start"`
	PkeyMprotectLen             uint64     `json:"pkey_mprotect__len"`
	PkeyMprotectProt            uint64     `json:"pkey_mprotect__prot"`
	PkeyMprotectPkey            uint64     `json:"pkey_mprotect__pkey"`
	SchedSetschedulerPid        uint64     `json:"sched_setscheduler__pid"`
	SchedSetschedulerPolicy     uint64     `json:"sched_setscheduler__policy"`
	SchedSetschedulerParam      uint64     `json:"sched_setscheduler__param"`
	MqNotifyMqdes               uint64     `json:"mq_notify__mqdes"`
	MqNotifyUNotification       uint64     `json:"mq_notify__u_notification"`
	EpollPwaitEpfd              uint64     `json:"epoll_pwait__epfd"`
	EpollPwaitEvents            uint64     `json:"epoll_pwait__events"`
	EpollPwaitMaxevents         uint64     `json:"epoll_pwait__maxevents"`
	EpollPwaitTimeout           uint64     `json:"epoll_pwait__timeout"`
	EpollPwaitSigmask           uint64     `json:"epoll_pwait__sigmask"`
	EpollPwaitSigsetsize        uint64     `json:"epoll_pwait__sigsetsize"`
	SyncfsFd                    uint64     `json:"syncfs__fd"`
	GetrandomBuf                string     `json:"getrandom__buf"`
	GetrandomCount              uint64     `json:"getrandom__count"`
	GetrandomFlags              uint64     `json:"getrandom__flags"`
	CreatPathname               string     `json:"creat__pathname"`
	CreatMode                   uint64     `json:"creat__mode"`
	PpollUfds                   uint64     `json:"ppoll__ufds"`
	PpollNfds                   uint64     `json:"ppoll__nfds"`
	PpollTsp                    uint64     `json:"ppoll__tsp"`
	PpollSigmask                uint64     `json:"ppoll__sigmask"`
	PpollSigsetsize             uint64     `json:"ppoll__sigsetsize"`
	FutimesatDfd                uint64     `json:"futimesat__dfd"`
	FutimesatFilename           string     `json:"futimesat__filename"`
	FutimesatUtimes             uint64     `json:"futimesat__utimes"`
	KexecLoadEntry              uint64     `json:"kexec_load__entry"`
	KexecLoadNrSegments         uint64     `json:"kexec_load__nr_segments"`
	KexecLoadSegments           uint64     `json:"kexec_load__segments"`
	KexecLoadFlags              uint64     `json:"kexec_load__flags"`
	FanotifyMarkFanotifyFd      uint64     `json:"fanotify_mark__fanotify_fd"`
	FanotifyMarkFlags           uint64     `json:"fanotify_mark__flags"`
	FanotifyMarkMask            uint64     `json:"fanotify_mark__mask"`
	FanotifyMarkDfd             uint64     `json:"fanotify_mark__dfd"`
	FanotifyMarkPathname        string     `json:"fanotify_mark__pathname"`
	ChrootFilename              string     `json:"chroot__filename"`
	SelectN                     uint64     `json:"select__n"`
	SelectInp                   uint64     `json:"select__inp"`
	SelectOutp                  uint64     `json:"select__outp"`
	SelectExp                   uint64     `json:"select__exp"`
	SelectTvp                   uint64     `json:"select__tvp"`
	GetrusageWho                uint64     `json:"getrusage__who"`
	GetrusageRu                 uint64     `json:"getrusage__ru"`
	PwritevFd                   uint64     `json:"pwritev__fd"`
	PwritevVec                  uint64     `json:"pwritev__vec"`
	PwritevVlen                 uint64     `json:"pwritev__vlen"`
	PwritevPosL                 uint64     `json:"pwritev__pos_l"`
	PwritevPosH                 uint64     `json:"pwritev__pos_h"`
	GetsockoptFd                uint64     `json:"getsockopt__fd"`
	GetsockoptLevel             uint64     `json:"getsockopt__level"`
	GetsockoptOptname           uint64     `json:"getsockopt__optname"`
	GetsockoptOptval            string     `json:"getsockopt__optval"`
	GetsockoptOptlen            uint64     `json:"getsockopt__optlen"`
	RenameOldname               string     `json:"rename__oldname"`
	RenameNewname               string     `json:"rename__newname"`
	FstatfsFd                   uint64     `json:"fstatfs__fd"`
	FstatfsBuf                  uint64     `json:"fstatfs__buf"`
	SysfsOption                 uint64     `json:"sysfs__option"`
	SysfsArg1                   uint64     `json:"sysfs__arg1"`
	SysfsArg2                   uint64     `json:"sysfs__arg2"`
	MincoreStart                uint64     `json:"mincore__start"`
	MincoreLen                  uint64     `json:"mincore__len"`
	MincoreVec                  uint64     `json:"mincore__vec"`
	CopyFileRangeFdIn           uint64     `json:"copy_file_range__fd_in"`
	CopyFileRangeOffIn          uint64     `json:"copy_file_range__off_in"`
	CopyFileRangeFdOut          uint64     `json:"copy_file_range__fd_out"`
	CopyFileRangeOffOut         uint64     `json:"copy_file_range__off_out"`
	CopyFileRangeLen            uint64     `json:"copy_file_range__len"`
	CopyFileRangeFlags          uint64     `json:"copy_file_range__flags"`
	SpliceFdIn                  uint64     `json:"splice__fd_in"`
	SpliceOffIn                 uint64     `json:"splice__off_in"`
	SpliceFdOut                 uint64     `json:"splice__fd_out"`
	SpliceOffOut                uint64     `json:"splice__off_out"`
	SpliceLen                   uint64     `json:"splice__len"`
	SpliceFlags                 uint64     `json:"splice__flags"`
	NewstatFilename             string     `json:"newstat__filename"`
	NewstatStatbuf              uint64     `json:"newstat__statbuf"`
	ProcessVmWritevPid          uint64     `json:"process_vm_writev__pid"`
	ProcessVmWritevLvec         uint64     `json:"process_vm_writev__lvec"`
	ProcessVmWritevLiovcnt      uint64     `json:"process_vm_writev__liovcnt"`
	ProcessVmWritevRvec         uint64     `json:"process_vm_writev__rvec"`
	ProcessVmWritevRiovcnt      uint64     `json:"process_vm_writev__riovcnt"`
	ProcessVmWritevFlags        uint64     `json:"process_vm_writev__flags"`
	TimerGettimeTimerId         uint64     `json:"timer_gettime__timer_id"`
	TimerGettimeSetting         uint64     `json:"timer_gettime__setting"`
	PivotRootNewRoot            string     `json:"pivot_root__new_root"`
	PivotRootPutOld             string     `json:"pivot_root__put_old"`
	NameToHandleAtDfd           uint64     `json:"name_to_handle_at__dfd"`
	NameToHandleAtName          string     `json:"name_to_handle_at__name"`
	NameToHandleAtHandle        uint64     `json:"name_to_handle_at__handle"`
	NameToHandleAtMntId         uint64     `json:"name_to_handle_at__mnt_id"`
	NameToHandleAtFlag          uint64     `json:"name_to_handle_at__flag"`
	BindFd                      uint64     `json:"bind__fd"`
	BindUmyaddr                 uint64     `json:"bind__umyaddr"`
	BindAddrlen                 uint64     `json:"bind__addrlen"`
	ReadlinkPath                string     `json:"readlink__path"`
	ReadlinkBuf                 string     `json:"readlink__buf"`
	ReadlinkBufsiz              uint64     `json:"readlink__bufsiz"`
	SetuidUid                   uint64     `json:"setuid__uid"`
	MremapAddr                  uint64     `json:"mremap__addr"`
	MremapOldLen                uint64     `json:"mremap__old_len"`
	MremapNewLen                uint64     `json:"mremap__new_len"`
	MremapFlags                 uint64     `json:"mremap__flags"`
	MremapNewAddr               uint64     `json:"mremap__new_addr"`
	KeyctlOption                uint64     `json:"keyctl__option"`
	KeyctlArg2                  uint64     `json:"keyctl__arg2"`
	KeyctlArg3                  uint64     `json:"keyctl__arg3"`
	KeyctlArg4                  uint64     `json:"keyctl__arg4"`
	KeyctlArg5                  uint64     `json:"keyctl__arg5"`
	Pselect6N                   uint64     `json:"pselect6__n"`
	Pselect6Inp                 uint64     `json:"pselect6__inp"`
	Pselect6Outp                uint64     `json:"pselect6__outp"`
	Pselect6Exp                 uint64     `json:"pselect6__exp"`
	Pselect6Tsp                 uint64     `json:"pselect6__tsp"`
	Pselect6Sig                 uint64     `json:"pselect6__sig"`
	DeleteModuleNameUser        string     `json:"delete_module__name_user"`
	DeleteModuleFlags           uint64     `json:"delete_module__flags"`
	UtimensatDfd                uint64     `json:"utimensat__dfd"`
	UtimensatFilename           string     `json:"utimensat__filename"`
	UtimensatUtimes             uint64     `json:"utimensat__utimes"`
	UtimensatFlags              uint64     `json:"utimensat__flags"`
	GetMempolicyPolicy          uint64     `json:"get_mempolicy__policy"`
	GetMempolicyNmask           uint64     `json:"get_mempolicy__nmask"`
	GetMempolicyMaxnode         uint64     `json:"get_mempolicy__maxnode"`
	GetMempolicyAddr            uint64     `json:"get_mempolicy__addr"`
	GetMempolicyFlags           uint64     `json:"get_mempolicy__flags"`
	DupFildes                   uint64     `json:"dup__fildes"`
	EventfdCount                uint64     `json:"eventfd__count"`
	RecvfromFd                  uint64     `json:"recvfrom__fd"`
	RecvfromUbuf                uint64     `json:"recvfrom__ubuf"`
	RecvfromSize                uint64     `json:"recvfrom__size"`
	RecvfromFlags               uint64     `json:"recvfrom__flags"`
	RecvfromAddr                uint64     `json:"recvfrom__addr"`
	RecvfromAddrLen             uint64     `json:"recvfrom__addr_len"`
	StatxDfd                    uint64     `json:"statx__dfd"`
	StatxFilename               string     `json:"statx__filename"`
	StatxFlags                  uint64     `json:"statx__flags"`
	StatxMask                   uint64     `json:"statx__mask"`
	StatxBuffer                 uint64     `json:"statx__buffer"`
	RtSigactionSig              uint64     `json:"rt_sigaction__sig"`
	RtSigactionAct              uint64     `json:"rt_sigaction__act"`
	RtSigactionOact             uint64     `json:"rt_sigaction__oact"`
	RtSigactionSigsetsize       uint64     `json:"rt_sigaction__sigsetsize"`
	GetdentsFd                  uint64     `json:"getdents__fd"`
	GetdentsDirent              uint64     `json:"getdents__dirent"`
	GetdentsCount               uint64     `json:"getdents__count"`
	EpollCreate1Flags           uint64     `json:"epoll_create1__flags"`
	Wait4Upid                   uint64     `json:"wait4__upid"`
	Wait4StatAddr               uint64     `json:"wait4__stat_addr"`
	Wait4Options                uint64     `json:"wait4__options"`
	Wait4Ru                     uint64     `json:"wait4__ru"`
	MlockallFlags               uint64     `json:"mlockall__flags"`
	SchedGetattrPid             uint64     `json:"sched_getattr__pid"`
	SchedGetattrUattr           uint64     `json:"sched_getattr__uattr"`
	SchedGetattrSize            uint64     `json:"sched_getattr__size"`
	SchedGetattrFlags           uint64     `json:"sched_getattr__flags"`
	SetpriorityWhich            uint64     `json:"setpriority__which"`
	SetpriorityWho              uint64     `json:"setpriority__who"`
	SetpriorityNiceval          uint64     `json:"setpriority__niceval"`
	SocketFamily                uint64     `json:"socket__family"`
	SocketType                  uint64     `json:"socket__type"`
	SocketProtocol              uint64     `json:"socket__protocol"`
	SemtimedopSemid             uint64     `json:"semtimedop__semid"`
	SemtimedopTsops             uint64     `json:"semtimedop__tsops"`
	SemtimedopNsops             uint64     `json:"semtimedop__nsops"`
	SemtimedopTimeout           uint64     `json:"semtimedop__timeout"`
	SetfsuidUid                 uint64     `json:"setfsuid__uid"`
	EpollCreateSize             uint64     `json:"epoll_create__size"`
	SemopSemid                  uint64     `json:"semop__semid"`
	SemopTsops                  uint64     `json:"semop__tsops"`
	SemopNsops                  uint64     `json:"semop__nsops"`
	OpenFilename                string     `json:"open__filename"`
	OpenFlags                   uint64     `json:"open__flags"`
	OpenMode                    uint64     `json:"open__mode"`
	OpenatDfd                   uint64     `json:"openat__dfd"`
	OpenatFilename              string     `json:"openat__filename"`
	OpenatFlags                 uint64     `json:"openat__flags"`
	OpenatMode                  uint64     `json:"openat__mode"`
	FremovexattrFd              uint64     `json:"fremovexattr__fd"`
	FremovexattrName            string     `json:"fremovexattr__name"`
	FaccessatDfd                uint64     `json:"faccessat__dfd"`
	FaccessatFilename           string     `json:"faccessat__filename"`
	FaccessatMode               uint64     `json:"faccessat__mode"`
	FtruncateFd                 uint64     `json:"ftruncate__fd"`
	FtruncateLength             uint64     `json:"ftruncate__length"`
	SchedGetPriorityMinPolicy   uint64     `json:"sched_get_priority_min__policy"`
	MovePagesPid                uint64     `json:"move_pages__pid"`
	MovePagesNrPages            uint64     `json:"move_pages__nr_pages"`
	MovePagesPages              uint64     `json:"move_pages__pages"`
	MovePagesNodes              uint64     `json:"move_pages__nodes"`
	MovePagesStatus             uint64     `json:"move_pages__status"`
	MovePagesFlags              uint64     `json:"move_pages__flags"`
	LseekFd                     uint64     `json:"lseek__fd"`
	LseekOffset                 uint64     `json:"lseek__offset"`
	LseekWhence                 uint64     `json:"lseek__whence"`
	PollUfds                    uint64     `json:"poll__ufds"`
	PollNfds                    uint64     `json:"poll__nfds"`
	PollTimeoutMsecs            uint64     `json:"poll__timeout_msecs"`
	FdatasyncFd                 uint64     `json:"fdatasync__fd"`
	FsyncFd                     uint64     `json:"fsync__fd"`
	SetsockoptFd                uint64     `json:"setsockopt__fd"`
	SetsockoptLevel             uint64     `json:"setsockopt__level"`
	SetsockoptOptname           uint64     `json:"setsockopt__optname"`
	SetsockoptOptval            string     `json:"setsockopt__optval"`
	SetsockoptOptlen            uint64     `json:"setsockopt__optlen"`
	TimerGetoverrunTimerId      uint64     `json:"timer_getoverrun__timer_id"`
	CapsetHeader                uint64     `json:"capset__header"`
	CapsetData                  uint64     `json:"capset__data"`
	SemgetKey                   uint64     `json:"semget__key"`
	SemgetNsems                 uint64     `json:"semget__nsems"`
	SemgetSemflg                uint64     `json:"semget__semflg"`
	Prlimit64Pid                uint64     `json:"prlimit64__pid"`
	Prlimit64Resource           uint64     `json:"prlimit64__resource"`
	Prlimit64NewRlim            uint64     `json:"prlimit64__new_rlim"`
	Prlimit64OldRlim            uint64     `json:"prlimit64__old_rlim"`
	MqUnlinkUName               string     `json:"mq_unlink__u_name"`
	ClockSettimeWhichClock      uint64     `json:"clock_settime__which_clock"`
	ClockSettimeTp              uint64     `json:"clock_settime__tp"`
	RtSigtimedwaitUthese        uint64     `json:"rt_sigtimedwait__uthese"`
	RtSigtimedwaitUinfo         uint64     `json:"rt_sigtimedwait__uinfo"`
	RtSigtimedwaitUts           uint64     `json:"rt_sigtimedwait__uts"`
	RtSigtimedwaitSigsetsize    uint64     `json:"rt_sigtimedwait__sigsetsize"`
	SigaltstackUss              uint64     `json:"sigaltstack__uss"`
	SigaltstackUoss             uint64     `json:"sigaltstack__uoss"`
	ShmgetKey                   uint64     `json:"shmget__key"`
	ShmgetSize                  uint64     `json:"shmget__size"`
	ShmgetShmflg                uint64     `json:"shmget__shmflg"`
	WritevFd                    uint64     `json:"writev__fd"`
	WritevVec                   uint64     `json:"writev__vec"`
	WritevVlen                  uint64     `json:"writev__vlen"`
	MprotectStart               uint64     `json:"mprotect__start"`
	MprotectLen                 uint64     `json:"mprotect__len"`
	MprotectProt                uint64     `json:"mprotect__prot"`
	SetitimerWhich              uint64     `json:"setitimer__which"`
	SetitimerValue              uint64     `json:"setitimer__value"`
	SetitimerOvalue             uint64     `json:"setitimer__ovalue"`
	RemapFilePagesStart         uint64     `json:"remap_file_pages__start"`
	RemapFilePagesSize          uint64     `json:"remap_file_pages__size"`
	RemapFilePagesProt          uint64     `json:"remap_file_pages__prot"`
	RemapFilePagesPgoff         uint64     `json:"remap_file_pages__pgoff"`
	RemapFilePagesFlags         uint64     `json:"remap_file_pages__flags"`
	GetresgidRgidp              uint64     `json:"getresgid__rgidp"`
	GetresgidEgidp              uint64     `json:"getresgid__egidp"`
	GetresgidSgidp              uint64     `json:"getresgid__sgidp"`
	SeccompOp                   uint64     `json:"seccomp__op"`
	SeccompFlags                uint64     `json:"seccomp__flags"`
	SeccompUargs                string     `json:"seccomp__uargs"`
	GettimeofdayTv              uint64     `json:"gettimeofday__tv"`
	GettimeofdayTz              uint64     `json:"gettimeofday__tz"`
	GetsocknameFd               uint64     `json:"getsockname__fd"`
	GetsocknameUsockaddr        uint64     `json:"getsockname__usockaddr"`
	GetsocknameUsockaddrLen     uint64     `json:"getsockname__usockaddr_len"`
	SymlinkatOldname            string     `json:"symlinkat__oldname"`
	SymlinkatNewdfd             uint64     `json:"symlinkat__newdfd"`
	SymlinkatNewname            string     `json:"symlinkat__newname"`
	TimerCreateWhichClock       uint64     `json:"timer_create__which_clock"`
	TimerCreateTimerEventSpec   uint64     `json:"timer_create__timer_event_spec"`
	TimerCreateCreatedTimerId   uint64     `json:"timer_create__created_timer_id"`
	ListxattrPathname           string     `json:"listxattr__pathname"`
	ListxattrList               string     `json:"listxattr__list"`
	ListxattrSize               uint64     `json:"listxattr__size"`
	KexecFileLoadKernelFd       uint64     `json:"kexec_file_load__kernel_fd"`
	KexecFileLoadInitrdFd       uint64     `json:"kexec_file_load__initrd_fd"`
	KexecFileLoadCmdlineLen     uint64     `json:"kexec_file_load__cmdline_len"`
	KexecFileLoadCmdlinePtr     string     `json:"kexec_file_load__cmdline_ptr"`
	KexecFileLoadFlags          uint64     `json:"kexec_file_load__flags"`
	MsgsndMsqid                 uint64     `json:"msgsnd__msqid"`
	MsgsndMsgp                  uint64     `json:"msgsnd__msgp"`
	MsgsndMsgsz                 uint64     `json:"msgsnd__msgsz"`
	MsgsndMsgflg                uint64     `json:"msgsnd__msgflg"`
	UnlinkatDfd                 uint64     `json:"unlinkat__dfd"`
	UnlinkatPathname            string     `json:"unlinkat__pathname"`
	UnlinkatFlag                uint64     `json:"unlinkat__flag"`
	ExecveFilename              string     `json:"execve__filename"`
	ExecveArgv1                 string     `json:"execve__argv1"`
	ExecveArgv2                 string     `json:"execve__argv2"`
	ExecveArgv3                 string     `json:"execve__argv3"`
	ExecveEnvp                  uint64     `json:"execve__envp"`
	CloneCloneFlags             uint64     `json:"clone__clone_flags"`
	CloneNewsp                  uint64     `json:"clone__newsp"`
	CloneParentTidptr           uint64     `json:"clone__parent_tidptr"`
	CloneChildTidptr            uint64     `json:"clone__child_tidptr"`
	CloneTls                    uint64     `json:"clone__tls"`
	RseqRseq                    uint64     `json:"rseq__rseq"`
	RseqRseqLen                 uint64     `json:"rseq__rseq_len"`
	RseqFlags                   uint64     `json:"rseq__flags"`
	RseqSig                     uint64     `json:"rseq__sig"`
	FinitModuleFd               uint64     `json:"finit_module__fd"`
	FinitModuleUargs            string     `json:"finit_module__uargs"`
	FinitModuleFlags            uint64     `json:"finit_module__flags"`
	PkeyFreePkey                uint64     `json:"pkey_free__pkey"`
	BrkBrk                      uint64     `json:"brk__brk"`
	SetresuidRuid               uint64     `json:"setresuid__ruid"`
	SetresuidEuid               uint64     `json:"setresuid__euid"`
	SetresuidSuid               uint64     `json:"setresuid__suid"`
	RtSigsuspendUnewset         uint64     `json:"rt_sigsuspend__unewset"`
	RtSigsuspendSigsetsize      uint64     `json:"rt_sigsuspend__sigsetsize"`
	LchownFilename              string     `json:"lchown__filename"`
	LchownUser                  uint64     `json:"lchown__user"`
	LchownGroup                 uint64     `json:"lchown__group"`
	FallocateFd                 uint64     `json:"fallocate__fd"`
	FallocateMode               uint64     `json:"fallocate__mode"`
	FallocateOffset             uint64     `json:"fallocate__offset"`
	FallocateLen                uint64     `json:"fallocate__len"`
	IoprioSetWhich              uint64     `json:"ioprio_set__which"`
	IoprioSetWho                uint64     `json:"ioprio_set__who"`
	IoprioSetIoprio             uint64     `json:"ioprio_set__ioprio"`
	MknodatDfd                  uint64     `json:"mknodat__dfd"`
	MknodatFilename             string     `json:"mknodat__filename"`
	MknodatMode                 uint64     `json:"mknodat__mode"`
	MknodatDev                  uint64     `json:"mknodat__dev"`
	PipeFildes                  uint64     `json:"pipe__fildes"`
	PipeReadfd                  uint64     `json:"pipe__readfd"`
	PipeWritefd                 uint64     `json:"pipe__writefd"`
	RebootMagic1                uint64     `json:"reboot__magic1"`
	RebootMagic2                uint64     `json:"reboot__magic2"`
	RebootCmd                   uint64     `json:"reboot__cmd"`
	RebootArg                   uint64     `json:"reboot__arg"`
	Eventfd2Count               uint64     `json:"eventfd2__count"`
	Eventfd2Flags               uint64     `json:"eventfd2__flags"`
	UnlinkPathname              string     `json:"unlink__pathname"`
	RecvmmsgFd                  uint64     `json:"recvmmsg__fd"`
	RecvmmsgMmsg                uint64     `json:"recvmmsg__mmsg"`
	RecvmmsgVlen                uint64     `json:"recvmmsg__vlen"`
	RecvmmsgFlags               uint64     `json:"recvmmsg__flags"`
	RecvmmsgTimeout             uint64     `json:"recvmmsg__timeout"`
	MsyncStart                  uint64     `json:"msync__start"`
	MsyncLen                    uint64     `json:"msync__len"`
	MsyncFlags                  uint64     `json:"msync__flags"`
	AccessFilename              string     `json:"access__filename"`
	AccessMode                  uint64     `json:"access__mode"`
	Signalfd4Ufd                uint64     `json:"signalfd4__ufd"`
	Signalfd4UserMask           uint64     `json:"signalfd4__user_mask"`
	Signalfd4Sizemask           uint64     `json:"signalfd4__sizemask"`
	Signalfd4Flags              uint64     `json:"signalfd4__flags"`
	MbindStart                  uint64     `json:"mbind__start"`
	MbindLen                    uint64     `json:"mbind__len"`
	MbindMode                   uint64     `json:"mbind__mode"`
	MbindNmask                  uint64     `json:"mbind__nmask"`
	MbindMaxnode                uint64     `json:"mbind__maxnode"`
	MbindFlags                  uint64     `json:"mbind__flags"`
	MknodFilename               string     `json:"mknod__filename"`
	MknodMode                   uint64     `json:"mknod__mode"`
	MknodDev                    uint64     `json:"mknod__dev"`
	MunlockStart                uint64     `json:"munlock__start"`
	MunlockLen                  uint64     `json:"munlock__len"`
	GetpgidPid                  uint64     `json:"getpgid__pid"`
	GetresuidRuidp              uint64     `json:"getresuid__ruidp"`
	GetresuidEuidp              uint64     `json:"getresuid__euidp"`
	GetresuidSuidp              uint64     `json:"getresuid__suidp"`
	FchownatDfd                 uint64     `json:"fchownat__dfd"`
	FchownatFilename            string     `json:"fchownat__filename"`
	FchownatUser                uint64     `json:"fchownat__user"`
	FchownatGroup               uint64     `json:"fchownat__group"`
	FchownatFlag                uint64     `json:"fchownat__flag"`
	PerfEventOpenAttrUptr       uint64     `json:"perf_event_open__attr_uptr"`
	PerfEventOpenPid            uint64     `json:"perf_event_open__pid"`
	PerfEventOpenCpu            uint64     `json:"perf_event_open__cpu"`
	PerfEventOpenGroupFd        uint64     `json:"perf_event_open__group_fd"`
	PerfEventOpenFlags          uint64     `json:"perf_event_open__flags"`
	NewunameName                uint64     `json:"newuname__name"`
	TimerfdCreateClockid        uint64     `json:"timerfd_create__clockid"`
	TimerfdCreateFlags          uint64     `json:"timerfd_create__flags"`
	ShmdtShmaddr                string     `json:"shmdt__shmaddr"`
	RmdirPathname               string     `json:"rmdir__pathname"`
	OpenByHandleAtMountdirfd    uint64     `json:"open_by_handle_at__mountdirfd"`
	OpenByHandleAtHandle        uint64     `json:"open_by_handle_at__handle"`
	OpenByHandleAtFlags         uint64     `json:"open_by_handle_at__flags"`
	SocketpairFamily            uint64     `json:"socketpair__family"`
	SocketpairType              uint64     `json:"socketpair__type"`
	SocketpairProtocol          uint64     `json:"socketpair__protocol"`
	SocketpairUsockvec          uint64     `json:"socketpair__usockvec"`
	SetresgidRgid               uint64     `json:"setresgid__rgid"`
	SetresgidEgid               uint64     `json:"setresgid__egid"`
	SetresgidSgid               uint64     `json:"setresgid__sgid"`
	GetitimerWhich              uint64     `json:"getitimer__which"`
	GetitimerValue              uint64     `json:"getitimer__value"`
	MqGetsetattrMqdes           uint64     `json:"mq_getsetattr__mqdes"`
	MqGetsetattrUMqstat         uint64     `json:"mq_getsetattr__u_mqstat"`
	MqGetsetattrUOmqstat        uint64     `json:"mq_getsetattr__u_omqstat"`
	ChdirFilename               string     `json:"chdir__filename"`
	FchdirFd                    uint64     `json:"fchdir__fd"`
	MmapAddr                    uint64     `json:"mmap__addr"`
	MmapLen                     uint64     `json:"mmap__len"`
	MmapProt                    uint64     `json:"mmap__prot"`
	MmapFlags                   uint64     `json:"mmap__flags"`
	MmapFd                      uint64     `json:"mmap__fd"`
	MmapOff                     uint64     `json:"mmap__off"`
	LookupDcookieCookie64       uint64     `json:"lookup_dcookie__cookie64"`
	LookupDcookieBuf            string     `json:"lookup_dcookie__buf"`
	LookupDcookieLen            uint64     `json:"lookup_dcookie__len"`
	SyslogType                  uint64     `json:"syslog__type"`
	SyslogBuf                   string     `json:"syslog__buf"`
	SyslogLen                   uint64     `json:"syslog__len"`
	AcceptFd                    uint64     `json:"accept__fd"`
	AcceptUpeerSockaddr         uint64     `json:"accept__upeer_sockaddr"`
	AcceptUpeerAddrlen          uint64     `json:"accept__upeer_addrlen"`
	SetMempolicyMode            uint64     `json:"set_mempolicy__mode"`
	SetMempolicyNmask           uint64     `json:"set_mempolicy__nmask"`
	SetMempolicyMaxnode         uint64     `json:"set_mempolicy__maxnode"`
	MkdiratDfd                  uint64     `json:"mkdirat__dfd"`
	MkdiratPathname             string     `json:"mkdirat__pathname"`
	MkdiratMode                 uint64     `json:"mkdirat__mode"`
	FchmodatDfd                 uint64     `json:"fchmodat__dfd"`
	FchmodatFilename            string     `json:"fchmodat__filename"`
	FchmodatMode                uint64     `json:"fchmodat__mode"`
	MkdirPathname               string     `json:"mkdir__pathname"`
	MkdirMode                   uint64     `json:"mkdir__mode"`
	MountDevName                string     `json:"mount__dev_name"`
	MountDirName                string     `json:"mount__dir_name"`
	MountType                   string     `json:"mount__type"`
	MountFlags                  uint64     `json:"mount__flags"`
	MountData                   uint64     `json:"mount__data"`
	SchedSetaffinityPid         uint64     `json:"sched_setaffinity__pid"`
	SchedSetaffinityLen         uint64     `json:"sched_setaffinity__len"`
	SchedSetaffinityUserMaskPtr uint64     `json:"sched_setaffinity__user_mask_ptr"`
	MqTimedreceiveMqdes         uint64     `json:"mq_timedreceive__mqdes"`
	MqTimedreceiveUMsgPtr       string     `json:"mq_timedreceive__u_msg_ptr"`
	MqTimedreceiveMsgLen        uint64     `json:"mq_timedreceive__msg_len"`
	MqTimedreceiveUMsgPrio      uint64     `json:"mq_timedreceive__u_msg_prio"`
	MqTimedreceiveUAbsTimeout   uint64     `json:"mq_timedreceive__u_abs_timeout"`
	GetsidPid                   uint64     `json:"getsid__pid"`
	UnshareUnshareFlags         uint64     `json:"unshare__unshare_flags"`
	CapgetHeader                uint64     `json:"capget__header"`
	CapgetDataptr               uint64     `json:"capget__dataptr"`
	LinkatOlddfd                uint64     `json:"linkat__olddfd"`
	LinkatOldname               string     `json:"linkat__oldname"`
	LinkatNewdfd                uint64     `json:"linkat__newdfd"`
	LinkatNewname               string     `json:"linkat__newname"`
	LinkatFlags                 uint64     `json:"linkat__flags"`
	AlarmSeconds                uint64     `json:"alarm__seconds"`
	IoSetupNrEvents             uint64     `json:"io_setup__nr_events"`
	IoSetupCtxp                 uint64     `json:"io_setup__ctxp"`
	MqTimedsendMqdes            uint64     `json:"mq_timedsend__mqdes"`
	MqTimedsendUMsgPtr          string     `json:"mq_timedsend__u_msg_ptr"`
	MqTimedsendMsgLen           uint64     `json:"mq_timedsend__msg_len"`
	MqTimedsendMsgPrio          uint64     `json:"mq_timedsend__msg_prio"`
	MqTimedsendUAbsTimeout      uint64     `json:"mq_timedsend__u_abs_timeout"`
	GetcwdBuf                   string     `json:"getcwd__buf"`
	GetcwdSize                  uint64     `json:"getcwd__size"`
	EpollWaitEpfd               uint64     `json:"epoll_wait__epfd"`
	EpollWaitEvents             uint64     `json:"epoll_wait__events"`
	EpollWaitMaxevents          uint64     `json:"epoll_wait__maxevents"`
	EpollWaitTimeout            uint64     `json:"epoll_wait__timeout"`
	IopermFrom                  uint64     `json:"ioperm__from"`
	IopermNum                   uint64     `json:"ioperm__num"`
	IopermTurnOn                uint64     `json:"ioperm__turn_on"`
	FlockFd                     uint64     `json:"flock__fd"`
	FlockCmd                    uint64     `json:"flock__cmd"`
	EpollCtlEpfd                uint64     `json:"epoll_ctl__epfd"`
	EpollCtlOp                  uint64     `json:"epoll_ctl__op"`
	EpollCtlFd                  uint64     `json:"epoll_ctl__fd"`
	EpollCtlEvent               uint64     `json:"epoll_ctl__event"`
	ClockGettimeWhichClock      uint64     `json:"clock_gettime__which_clock"`
	ClockGettimeTp              uint64     `json:"clock_gettime__tp"`
	SemctlSemid                 uint64     `json:"semctl__semid"`
	SemctlSemnum                uint64     `json:"semctl__semnum"`
	SemctlCmd                   uint64     `json:"semctl__cmd"`
	SemctlArg                   uint64     `json:"semctl__arg"`
	RtSigprocmaskHow            uint64     `json:"rt_sigprocmask__how"`
	RtSigprocmaskNset           uint64     `json:"rt_sigprocmask__nset"`
	RtSigprocmaskOset           uint64     `json:"rt_sigprocmask__oset"`
	RtSigprocmaskSigsetsize     uint64     `json:"rt_sigprocmask__sigsetsize"`
	PersonalityPersonality      uint64     `json:"personality__personality"`
	LlistxattrPathname          string     `json:"llistxattr__pathname"`
	LlistxattrList              string     `json:"llistxattr__list"`
	LlistxattrSize              uint64     `json:"llistxattr__size"`
	PtraceRequest               uint64     `json:"ptrace__request"`
	PtracePid                   uint64     `json:"ptrace__pid"`
	PtraceAddr                  uint64     `json:"ptrace__addr"`
	PtraceData                  uint64     `json:"ptrace__data"`
	SetdomainnameName           string     `json:"setdomainname__name"`
	SetdomainnameLen            uint64     `json:"setdomainname__len"`
	ProcessVmReadvPid           uint64     `json:"process_vm_readv__pid"`
	ProcessVmReadvLvec          uint64     `json:"process_vm_readv__lvec"`
	ProcessVmReadvLiovcnt       uint64     `json:"process_vm_readv__liovcnt"`
	ProcessVmReadvRvec          uint64     `json:"process_vm_readv__rvec"`
	ProcessVmReadvRiovcnt       uint64     `json:"process_vm_readv__riovcnt"`
	ProcessVmReadvFlags         uint64     `json:"process_vm_readv__flags"`
	ArchPrctlOption             uint64     `json:"arch_prctl__option"`
	ArchPrctlArg2               uint64     `json:"arch_prctl__arg2"`
	RecvmsgFd                   uint64     `json:"recvmsg__fd"`
	RecvmsgMsg                  uint64     `json:"recvmsg__msg"`
	RecvmsgFlags                uint64     `json:"recvmsg__flags"`
	NanosleepRqtp               uint64     `json:"nanosleep__rqtp"`
	NanosleepRmtp               uint64     `json:"nanosleep__rmtp"`
	FcntlFd                     uint64     `json:"fcntl__fd"`
	FcntlCmd                    uint64     `json:"fcntl__cmd"`
	FcntlArg                    uint64     `json:"fcntl__arg"`
	IoCancelCtxId               uint64     `json:"io_cancel__ctx_id"`
	IoCancelIocb                uint64     `json:"io_cancel__iocb"`
	IoCancelResult              uint64     `json:"io_cancel__result"`
	Getdents64Fd                uint64     `json:"getdents64__fd"`
	Getdents64Dirent            uint64     `json:"getdents64__dirent"`
	Getdents64Count             uint64     `json:"getdents64__count"`
	InotifyRmWatchFd            uint64     `json:"inotify_rm_watch__fd"`
	InotifyRmWatchWd            uint64     `json:"inotify_rm_watch__wd"`
	FlistxattrFd                uint64     `json:"flistxattr__fd"`
	FlistxattrList              string     `json:"flistxattr__list"`
	FlistxattrSize              uint64     `json:"flistxattr__size"`
	ReadFd                      uint64     `json:"read__fd"`
	ReadBuf                     string     `json:"read__buf"`
	ReadCount                   uint64     `json:"read__count"`
	ClockNanosleepWhichClock    uint64     `json:"clock_nanosleep__which_clock"`
	ClockNanosleepFlags         uint64     `json:"clock_nanosleep__flags"`
	ClockNanosleepRqtp          uint64     `json:"clock_nanosleep__rqtp"`
	ClockNanosleepRmtp          uint64     `json:"clock_nanosleep__rmtp"`
	SysctlArgs                  uint64     `json:"sysctl__args"`
	ChownFilename               string     `json:"chown__filename"`
	ChownUser                   uint64     `json:"chown__user"`
	ChownGroup                  uint64     `json:"chown__group"`
	SetgroupsGidsetsize         uint64     `json:"setgroups__gidsetsize"`
	SetgroupsGrouplist          uint64     `json:"setgroups__grouplist"`
	NewfstatFd                  uint64     `json:"newfstat__fd"`
	NewfstatStatbuf             uint64     `json:"newfstat__statbuf"`
	MadviseStart                uint64     `json:"madvise__start"`
	MadviseLenIn                uint64     `json:"madvise__len_in"`
	MadviseBehavior             uint64     `json:"madvise__behavior"`
	FchownFd                    uint64     `json:"fchown__fd"`
	FchownUser                  uint64     `json:"fchown__user"`
	FchownGroup                 uint64     `json:"fchown__group"`
	InotifyInit1Flags           uint64     `json:"inotify_init1__flags"`
	AddKeyType                  string     `json:"add_key___type"`
	AddKeyDescription           string     `json:"add_key___description"`
	AddKeyPayload               uint64     `json:"add_key___payload"`
	AddKeyPlen                  uint64     `json:"add_key__plen"`
	AddKeyRingid                uint64     `json:"add_key__ringid"`
	MemfdCreateUname            string     `json:"memfd_create__uname"`
	MemfdCreateFlags            uint64     `json:"memfd_create__flags"`
	MqOpenUName                 string     `json:"mq_open__u_name"`
	MqOpenOflag                 uint64     `json:"mq_open__oflag"`
	MqOpenMode                  uint64     `json:"mq_open__mode"`
	MqOpenUAttr                 uint64     `json:"mq_open__u_attr"`
	InitModuleUmod              uint64     `json:"init_module__umod"`
	InitModuleLen               uint64     `json:"init_module__len"`
	InitModuleUargs             string     `json:"init_module__uargs"`
	SchedSetattrPid             uint64     `json:"sched_setattr__pid"`
	SchedSetattrUattr           uint64     `json:"sched_setattr__uattr"`
	SchedSetattrFlags           uint64     `json:"sched_setattr__flags"`
	IoctlFd                     uint64     `json:"ioctl__fd"`
	IoctlCmd                    uint64     `json:"ioctl__cmd"`
	IoctlArg                    uint64     `json:"ioctl__arg"`
	RequestKeyType              string     `json:"request_key___type"`
	RequestKeyDescription       string     `json:"request_key___description"`
	RequestKeyCalloutInfo       string     `json:"request_key___callout_info"`
	RequestKeyDestringid        uint64     `json:"request_key__destringid"`
	UmountName                  string     `json:"umount__name"`
	UmountFlags                 uint64     `json:"umount__flags"`
	PreadvFd                    uint64     `json:"preadv__fd"`
	PreadvVec                   uint64     `json:"preadv__vec"`
	PreadvVlen                  uint64     `json:"preadv__vlen"`
	PreadvPosL                  uint64     `json:"preadv__pos_l"`
	PreadvPosH                  uint64     `json:"preadv__pos_h"`
	VmspliceFd                  uint64     `json:"vmsplice__fd"`
	VmspliceUiov                uint64     `json:"vmsplice__uiov"`
	VmspliceNrSegs              uint64     `json:"vmsplice__nr_segs"`
	VmspliceFlags               uint64     `json:"vmsplice__flags"`
	SysinfoInfo                 uint64     `json:"sysinfo__info"`
	TimerSettimeTimerId         uint64     `json:"timer_settime__timer_id"`
	TimerSettimeFlags           uint64     `json:"timer_settime__flags"`
	TimerSettimeNewSetting      uint64     `json:"timer_settime__new_setting"`
	TimerSettimeOldSetting      uint64     `json:"timer_settime__old_setting"`
	QuotactlCmd                 uint64     `json:"quotactl__cmd"`
	QuotactlSpecial             string     `json:"quotactl__special"`
	QuotactlId                  uint64     `json:"quotactl__id"`
	QuotactlAddr                uint64     `json:"quotactl__addr"`
	GetgroupsGidsetsize         uint64     `json:"getgroups__gidsetsize"`
	GetgroupsGrouplist          uint64     `json:"getgroups__grouplist"`
	FchmodFd                    uint64     `json:"fchmod__fd"`
	FchmodMode                  uint64     `json:"fchmod__mode"`
	Fadvise64Fd                 uint64     `json:"fadvise64__fd"`
	Fadvise64Offset             uint64     `json:"fadvise64__offset"`
	Fadvise64Len                uint64     `json:"fadvise64__len"`
	Fadvise64Advice             uint64     `json:"fadvise64__advice"`
	IoSubmitCtxId               uint64     `json:"io_submit__ctx_id"`
	IoSubmitNr                  uint64     `json:"io_submit__nr"`
	IoSubmitIocbpp              uint64     `json:"io_submit__iocbpp"`
	ChmodFilename               string     `json:"chmod__filename"`
	ChmodMode                   uint64     `json:"chmod__mode"`
	Pwrite64Fd                  uint64     `json:"pwrite64__fd"`
	Pwrite64Buf                 string     `json:"pwrite64__buf"`
	Pwrite64Count               uint64     `json:"pwrite64__count"`
	Pwrite64Pos                 uint64     `json:"pwrite64__pos"`
	SettimeofdayTv              uint64     `json:"settimeofday__tv"`
	SettimeofdayTz              uint64     `json:"settimeofday__tz"`
	SchedGetparamPid            uint64     `json:"sched_getparam__pid"`
	SchedGetparamParam          uint64     `json:"sched_getparam__param"`
	SchedGetaffinityPid         uint64     `json:"sched_getaffinity__pid"`
	SchedGetaffinityLen         uint64     `json:"sched_getaffinity__len"`
	SchedGetaffinityUserMaskPtr uint64     `json:"sched_getaffinity__user_mask_ptr"`
	MsgctlMsqid                 uint64     `json:"msgctl__msqid"`
	MsgctlCmd                   uint64     `json:"msgctl__cmd"`
	MsgctlBuf                   uint64     `json:"msgctl__buf"`
	TimerfdSettimeUfd           uint64     `json:"timerfd_settime__ufd"`
	TimerfdSettimeFlags         uint64     `json:"timerfd_settime__flags"`
	TimerfdSettimeUtmr          uint64     `json:"timerfd_settime__utmr"`
	TimerfdSettimeOtmr          uint64     `json:"timerfd_settime__otmr"`
	ConnectFd                   uint64     `json:"connect__fd"`
	ConnectUservaddr            uint64     `json:"connect__uservaddr"`
	ConnectAddrlen              uint64     `json:"connect__addrlen"`
	SendtoFd                    uint64     `json:"sendto__fd"`
	SendtoBuff                  uint64     `json:"sendto__buff"`
	SendtoLen                   uint64     `json:"sendto__len"`
	SendtoFlags                 uint64     `json:"sendto__flags"`
	SendtoAddr                  uint64     `json:"sendto__addr"`
	SendtoAddrLen               uint64     `json:"sendto__addr_len"`
	BpfCmd                      uint64     `json:"bpf__cmd"`
	BpfUattr                    uint64     `json:"bpf__uattr"`
	BpfSize                     uint64     `json:"bpf__size"`
	KcmpPid1                    uint64     `json:"kcmp__pid1"`
	KcmpPid2                    uint64     `json:"kcmp__pid2"`
	KcmpType                    uint64     `json:"kcmp__type"`
	KcmpIdx1                    uint64     `json:"kcmp__idx1"`
	KcmpIdx2                    uint64     `json:"kcmp__idx2"`
	Mlock2Start                 uint64     `json:"mlock2__start"`
	Mlock2Len                   uint64     `json:"mlock2__len"`
	Mlock2Flags                 uint64     `json:"mlock2__flags"`
	Pwritev2Fd                  uint64     `json:"pwritev2__fd"`
	Pwritev2Vec                 uint64     `json:"pwritev2__vec"`
	Pwritev2Vlen                uint64     `json:"pwritev2__vlen"`
	Pwritev2PosL                uint64     `json:"pwritev2__pos_l"`
	Pwritev2PosH                uint64     `json:"pwritev2__pos_h"`
	Pwritev2Flags               uint64     `json:"pwritev2__flags"`
	SchedSetparamPid            uint64     `json:"sched_setparam__pid"`
	SchedSetparamParam          uint64     `json:"sched_setparam__param"`
	SwapoffSpecialfile          string     `json:"swapoff__specialfile"`
	UserfaultfdFlags            uint64     `json:"userfaultfd__flags"`
	IoPgeteventsCtxId           uint64     `json:"io_pgetevents__ctx_id"`
	IoPgeteventsMinNr           uint64     `json:"io_pgetevents__min_nr"`
	IoPgeteventsNr              uint64     `json:"io_pgetevents__nr"`
	IoPgeteventsEvents          uint64     `json:"io_pgetevents__events"`
	IoPgeteventsTimeout         uint64     `json:"io_pgetevents__timeout"`
	IoPgeteventsUsig            uint64     `json:"io_pgetevents__usig"`
	ListenFd                    uint64     `json:"listen__fd"`
	ListenBacklog               uint64     `json:"listen__backlog"`
	GetRobustListPid            uint64     `json:"get_robust_list__pid"`
	GetRobustListHeadPtr        uint64     `json:"get_robust_list__head_ptr"`
	GetRobustListLenPtr         uint64     `json:"get_robust_list__len_ptr"`
	SetnsFd                     uint64     `json:"setns__fd"`
	SetnsNstype                 uint64     `json:"setns__nstype"`
}
