#pragma once

typedef NTSTATUS(NTAPI *NTCREATESECTION)(
	_Out_    PHANDLE            SectionHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              SectionPageProtection,
	_In_     ULONG              AllocationAttributes,
	_In_opt_ HANDLE             FileHandle
);

typedef NTSTATUS(NTAPI *NTCREATEPROCESSEX)
(
	OUT PHANDLE     ProcessHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes  OPTIONAL,
	IN HANDLE   ParentProcess,
	IN ULONG    Flags,
	IN HANDLE SectionHandle     OPTIONAL,
	IN HANDLE DebugPort     OPTIONAL,
	IN HANDLE ExceptionPort     OPTIONAL,
	IN BOOLEAN  InJob
);

typedef NTSTATUS(NTAPI *NTQUERYINFORMATIONPROCESS)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS  ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

typedef NTSTATUS(NTAPI *NTREADVIRTUALMEMORY)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesRead OPTIONAL
);

typedef NTSTATUS(NTAPI *NTWRITEVIRTUALMEMORY)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL
);

typedef NTSTATUS(WINAPI *NTCREATETHREADEX)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN DWORD StackZeroBits,
	IN DWORD SizeOfStackCommit,
	IN DWORD SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
);

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;

} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG  TimeStamp;
	STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS_DUPLICATE
{
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[0x20];
	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS_DUPLICATE, *PRTL_USER_PROCESS_PARAMETERS_DUPLICATE;

typedef NTSTATUS(NTAPI *RTLCREATEPROCESSPARAMETERSEX)(
	_Out_ PRTL_USER_PROCESS_PARAMETERS_DUPLICATE *pProcessParameters,
	_In_ PUNICODE_STRING ImagePathName,
	_In_opt_ PUNICODE_STRING DllPath,
	_In_opt_ PUNICODE_STRING CurrentDirectory,
	_In_opt_ PUNICODE_STRING CommandLine,
	_In_opt_ PVOID Environment,
	_In_opt_ PUNICODE_STRING WindowTitle,
	_In_opt_ PUNICODE_STRING DesktopInfo,
	_In_opt_ PUNICODE_STRING ShellInfo,
	_In_opt_ PUNICODE_STRING RuntimeData,
	_In_ ULONG Flags
	);

typedef VOID (WINAPI *RTLINITUNICODESTRING)(
	_Inout_  PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR          SourceString
);

typedef NTSTATUS(NTAPI *NTRESUMETHREAD)(
	IN HANDLE               ThreadHandle,
	OUT PULONG              SuspendCount OPTIONAL
);