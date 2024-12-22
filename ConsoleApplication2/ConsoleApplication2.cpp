#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <chrono>
#include "Header.h"

std::vector<uintptr_t> __forceinline __scan(std::wstring& str, HANDLE hProcess, HMODULE hntdll);
void __forceinline Overwrite(HANDLE hProcess, std::vector<uintptr_t>patternAddresses, HMODULE hntdll, SIZE_T strLength, std::vector<BYTE> buffer);

DWORD __fastcall __gt_PID(const wchar_t* procNameW) {

	DWORD  PID = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 PE;
	PE.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &PE)) {
		do {
			if (!wcscmp(procNameW, PE.szExeFile)) {
				PID = PE.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &PE));
	}

	CloseHandle(hSnapshot);
	return PID;
}

int main() {

	HMODULE hntdll = GetModuleHandleW(L"ntdll.dll");
	if (!hntdll) {
		std::wcerr << L"Failed to get handle to ntdll.dll. Error: " << GetLastError() << std::endl;
		system("pause");
		system("exit");
	}

	std::wstring procNameW = L"";
	std::cout << "Process: ";
	std::getline(std::wcin, procNameW);

	DWORD PID = __gt_PID(procNameW.c_str());

	if (PID == 0) {
		std::wcerr << L"Failed to grab PID for process: '" << procNameW << L"' Error: " << GetLastError() << std::endl;
		system("pause");
		return -1;
	}

	std::wcout << L"PID of '" << procNameW << L"' -> " << PID << std::endl;

	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, PID);
	if (!hProcess) {
		std::wcerr << L"OpenProcess failed. Error: " << GetLastError() << std::endl;
		system("pause");
		return -1;
	}


	std::wstring str;
	std::cout << "String: ";
	std::getline(std::wcin, str);

	SIZE_T strLength = str.size() * sizeof(wchar_t);
	std::vector<BYTE> buffer(strLength, 0x00);


	auto start = std::chrono::high_resolution_clock::now();


	std::vector<uintptr_t> patternAddresses = __scan(str, hProcess, hntdll);
	Overwrite(hProcess, patternAddresses, hntdll, strLength, buffer);

	auto end = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
	std::cout << "Time: " << duration << std::dec << " milliseconds" << std::endl;
	system("pause");

};


std::vector<uintptr_t> __forceinline __scan(std::wstring& str, HANDLE hProcess, HMODULE hntdll) {

	pNtReadVirtualMemory   NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(hntdll, "NtReadVirtualMemory");
	pNtQueryVirtualMemory NtQueryVirtualMemory = (pNtQueryVirtualMemory)GetProcAddress(hntdll, "NtQueryVirtualMemory");

	SYSTEM_INFO s;
	GetSystemInfo(&s);

	uintptr_t Address = (uintptr_t)s.lpMinimumApplicationAddress;
	uintptr_t maxAddress = (uintptr_t)s.lpMaximumApplicationAddress;

	std::vector<uintptr_t> patternAddresses;

	SIZE_T       bytesRead = 0;
	uint64_t heapAllocated = 0;

	std::string str2(str.begin(), str.end());

	std::cout << "How much memory do you want to allocate in the heap to read (MB): ";
	std::cin >> heapAllocated;

	if (heapAllocated >= 1) {
		heapAllocated += 1;
	}

	BYTE* buffer = new BYTE[heapAllocated * 1024000];

	SIZE_T stringSize = str.size() * sizeof(wchar_t);
	SIZE_T stringSize2 = str.size() * sizeof(char);


	while (Address < maxAddress) {
		MEMORY_BASIC_INFORMATION mbi;
		NTSTATUS status = NtQueryVirtualMemory(hProcess, reinterpret_cast<PVOID>(Address), MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);

		if (!NT_SUCCESS(status)) {
			std::cerr << "NtQueryVirtualMemory failed at: " << std::hex << Address << " | NTSTATUS: 0x" << status << std::endl;
			Address += mbi.RegionSize;
		}

		if (mbi.State == 0x00001000 &&
			(mbi.Protect == 0x04 || mbi.Protect == 0x40)) {
				
			Address += mbi.RegionSize;

			if (!VirtualQuery(reinterpret_cast<LPCVOID>(Address), &mbi, sizeof(mbi))) {
				std::cerr << "Failed to query memory at address 0x" << std::hex << Address << std::endl;
				break;
			}

			NTSTATUS readStatus = NtReadVirtualMemory(hProcess, reinterpret_cast<PVOID>(Address), buffer, mbi.RegionSize, (PULONG)&bytesRead);

			if (NT_SUCCESS(readStatus)) {

				for (SIZE_T i = 0; i <= bytesRead - stringSize; ++i) {

					if (memcmp(buffer + i, str.c_str(), stringSize) == 0) {
						uintptr_t matchAddress = Address + i;
						patternAddresses.push_back(matchAddress);
					}

					if (memcmp(buffer + i, str2.c_str(), stringSize2) == 0) {
						uintptr_t matchAddress = Address + i;
						patternAddresses.push_back(matchAddress);

					}
				}
			}
			else {
				if (heapAllocated * 1024000 < mbi.RegionSize) {
					std::cout << "Skipped 0x" << std::hex << Address << " Size: MB " << std::dec << mbi.RegionSize / 1024000 << std::endl; 
				}
				else {
					std::cout << "NtReadVirtualMemory failed at 0x" << std::hex << Address << " | NTSTATUS 0x" << readStatus << std::endl;
				}
			}
		}
		Address += mbi.RegionSize;
	}
	VirtualFree(buffer, 0, MEM_RELEASE);
	return patternAddresses;
};

void __forceinline Overwrite(HANDLE hProcess, std::vector<uintptr_t>patternAddresses, HMODULE hntdll, SIZE_T strLength, std::vector<BYTE> buffer) {

	pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hntdll, "NtWriteVirtualMemory");

	for (const auto& patternAddress : patternAddresses) {
		NTSTATUS writeStatus = NtWriteVirtualMemory(hProcess, reinterpret_cast<PVOID>(patternAddress), buffer.data(), strLength, nullptr);
		std::cout << "[+] Deleted string at address: 0x" << std::hex << patternAddress << std::endl;
	}
}
