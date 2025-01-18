#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <chrono>
#include "Header.h"

std::vector<uintptr_t> __forceinline __scan(std::wstring& str, HANDLE hProcess, HMODULE hntdll);
void __forceinline Overwrite(HANDLE hProcess, std::vector<uintptr_t>patternAddresses, HMODULE hntdll, SIZE_T strLength, std::vector<BYTE> buffer);


int main() {

	HMODULE hntdll = GetModuleHandleW(L"ntdll.dll");
	if (!hntdll) {
		std::wcerr << L"Failed to get handle to ntdll.dll. Error: " << GetLastError() << std::endl;
		system("pause");
		system("exit");
	}
	
	
	DWORD PID;
	std::cout << "PID: ";
	std::cin >> PID;

	HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, PID);
	if (!hProcess) {
		DWORD error = GetLastError();
		if (error == 87) {
			std::cout << "PID you entered doesn't exist :(" << std::endl;
		}
		if (error == 5) {
			std::cout << "Access to that process has been denied, try running as admin." << std::endl;
		}
 		else {
			std::wcerr << L"OpenProcess failed. Error: " << error << std::endl;
		}
		system("pause");
		return -1;
	}


	std::wstring str;
	std::cout << "String: ";
	std::getline(std::wcin, str);

	SIZE_T strLength = str.size() * sizeof(wchar_t);
	std::vector<BYTE> buffer(strLength, 0x00);




	std::vector<uintptr_t> patternAddresses = __scan(str, hProcess, hntdll);
	Overwrite(hProcess, patternAddresses, hntdll, strLength, buffer);

	std::cout << "Finished." << std::endl;
	system("pause");

};


std::vector<uintptr_t> __forceinline __scan(std::wstring& str, HANDLE hProcess, HMODULE hntdll) {

	pNtReadVirtualMemory NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(hntdll, "NtReadVirtualMemory");
	pNtQueryVirtualMemory NtQueryVirtualMemory = (pNtQueryVirtualMemory)GetProcAddress(hntdll, "NtQueryVirtualMemory");

	SYSTEM_INFO s;
	GetSystemInfo(&s);

	uintptr_t Address = (uintptr_t)s.lpMinimumApplicationAddress;
	uintptr_t maxAddress = (uintptr_t)s.lpMaximumApplicationAddress;

	std::vector<uintptr_t> ptrnAddresses;

	SIZE_T bytesRead = 0;

	std::string str2(str.begin(), str.end());

	SIZE_T stringSize = str.size() * sizeof(wchar_t);
	SIZE_T stringSize2 = str.size() * sizeof(char);

	while (Address < maxAddress) {
		MEMORY_BASIC_INFORMATION mbi;
		NTSTATUS status = NtQueryVirtualMemory(hProcess, reinterpret_cast<PVOID>(Address), MemoryBasicInformation, &mbi, sizeof(mbi), nullptr);

		if (!NT_SUCCESS(status)) {
			std::cerr << "NtQueryVirtualMemory failed at: " << std::hex << Address << " | NTSTATUS: 0x" << status << std::endl;
			Address += mbi.RegionSize;
			continue;
		}

		if (mbi.State == MEM_COMMIT &&
			(mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

			std::unique_ptr<BYTE[]> buffer(new BYTE[mbi.RegionSize]);

			NTSTATUS readStatus = NtReadVirtualMemory(hProcess, reinterpret_cast<PVOID>(Address), buffer.get(), mbi.RegionSize, (PULONG)&bytesRead);

			if (NT_SUCCESS(readStatus)) {
				for (SIZE_T i = 0; i <= bytesRead - stringSize; ++i) {
					if (memcmp(buffer.get() + i, str.c_str(), stringSize) == 0) {
						uintptr_t mtchAddress = Address + i;
						ptrnAddresses.push_back(mtchAddress);
					}

					if (memcmp(buffer.get() + i, str2.c_str(), stringSize2) == 0) {
						uintptr_t mtchAddress = Address + i;
						ptrnAddresses.push_back(mtchAddress);
					}
				}
			}
			else {
				std::cout << "NtReadVirtualMemory failed at 0x" << std::hex << Address << " | NTSTATUS 0x" << readStatus << std::endl;
			}
		}
		Address += mbi.RegionSize;
	}
	return ptrnAddresses;
}


void __forceinline Overwrite(HANDLE hProcess, std::vector<uintptr_t>ptrnAddresses, HMODULE hntdll, SIZE_T strLength, std::vector<BYTE> buffer) {

	pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hntdll, "NtWriteVirtualMemory");

	for (const auto& ptrnAddress : ptrnAddresses) {
		NTSTATUS writeStatus = NtWriteVirtualMemory(hProcess, reinterpret_cast<PVOID>(ptrnAddress), buffer.data(), strLength, nullptr);
		std::cout << "[+] Deleted string at address: 0x" << std::hex << ptrnAddress << std::endl;
	}
}
