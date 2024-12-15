#pragma once
#include <Windows.h>

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation, // q: MEMORY_BASIC_INFORMATION
	MemoryWorkingSetInformation, // q: MEMORY_WORKING_SET_INFORMATION
	MemoryMappedFilenameInformation, // q: UNICODE_STRING
	MemoryRegionInformation, // q: MEMORY_REGION_INFORMATION
	MemoryWorkingSetExInformation, // q: MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
	MemorySharedCommitInformation, // q: MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
	MemoryImageInformation, // q: MEMORY_IMAGE_INFORMATION
	MemoryRegionInformationEx, // MEMORY_REGION_INFORMATION
	MemoryPrivilegedBasicInformation, // MEMORY_BASIC_INFORMATION
	MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
	MemoryBasicInformationCapped, // 10
	MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
	MemoryBadInformation, // since WIN11
	MemoryBadInformationAllProcesses, // since 22H1
	MemoryImageExtensionInformation, // MEMORY_IMAGE_EXTENSION_INFORMATION // since 24H2
	MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;


typedef NTSTATUS(WINAPI* pNtReadVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToRead,
	PULONG NumberOfBytesReadOptional
	);

typedef NTSTATUS(WINAPI* pNtWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWrittenOptional
	);

typedef NTSTATUS(WINAPI* pNtQueryVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
	);

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

