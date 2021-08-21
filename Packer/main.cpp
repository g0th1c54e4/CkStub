#include <iostream>
#include <Windows.h>
using namespace std;
DWORD GetSectionSize(LPCSTR lpSectionName,PIMAGE_NT_HEADERS pNt);
LPVOID GetSectionDataRVA(LPCSTR lpSectionName, PIMAGE_NT_HEADERS pNt);
DWORD Align(DWORD _SectionAlignment, DWORD Value);
DWORD RVAToFOA(DWORD targetRVA,LPVOID lpBuffer);

int main() {
	CHAR lpFilePath[MAX_PATH] = {0};
	cout << "[*]������Ҫ�ӿǵĳ���·��:";
	cin >> lpFilePath;
	HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return 0;
	}
	DWORD dwFileSize = GetFileSize(hFile, NULL);

	HANDLE hFileStub = CreateFile(TEXT("Stub.dll"), GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFileStub == INVALID_HANDLE_VALUE) {
		return 0;
	}
	DWORD dwStubFileSize = GetFileSize(hFileStub, NULL);
	LPVOID lpStubBuffer = new BYTE[dwStubFileSize];
	DWORD dwNumOfRead = 0;
	if (ReadFile(hFileStub, lpStubBuffer, dwStubFileSize, &dwNumOfRead, NULL) == FALSE) {
		delete[] lpStubBuffer;
		CloseHandle(hFile);
		return 0;
	}
	PIMAGE_DOS_HEADER pDosStub = (PIMAGE_DOS_HEADER)lpStubBuffer;
	PIMAGE_NT_HEADERS pNtStub = (PIMAGE_NT_HEADERS)((DWORD)lpStubBuffer + pDosStub->e_lfanew);

	DWORD NewSectionSize = GetSectionSize(".text", pNtStub);
	LPVOID lpBuffer = new BYTE[dwFileSize + NewSectionSize];
	memset((LPVOID)((DWORD)lpBuffer + dwFileSize), 0, NewSectionSize);
	
	if (ReadFile(hFile, lpBuffer, dwFileSize, &dwNumOfRead, NULL) == FALSE) {
		delete[] lpStubBuffer;
		delete[] lpBuffer;
		CloseHandle(hFile);
		return 0;
	}

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE || pNt->Signature != IMAGE_NT_SIGNATURE) {
		delete[] lpStubBuffer;
		delete[] lpBuffer;
		CloseHandle(hFile);
		return 0;
	}
	if (pNt->OptionalHeader.SizeOfHeaders - (pDos->e_lfanew + sizeof(pNt) + (pNt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER)) < sizeof(IMAGE_SECTION_HEADER) * 2) {
		delete[] lpStubBuffer;
		delete[] lpBuffer;
		CloseHandle(hFile);
		while (1);
	}
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	memset(&pSection[pNt->FileHeader.NumberOfSections + 1], 0, sizeof(IMAGE_SECTION_HEADER));
	PIMAGE_SECTION_HEADER pNewSec = &pSection[pNt->FileHeader.NumberOfSections];
	PIMAGE_SECTION_HEADER pLastSec = &pSection[pNt->FileHeader.NumberOfSections - 1];
	IMAGE_SECTION_HEADER newSec = { 0 };
	CONST BYTE pSecName[8] = ".Ck";

	RtlCopyMemory(&newSec.Name, pSecName, sizeof(pSecName));
	newSec.Characteristics = 0x60000020;
	newSec.VirtualAddress = pLastSec->VirtualAddress + pLastSec->Misc.VirtualSize;
	newSec.Misc.VirtualSize = Align(pNt->OptionalHeader.SectionAlignment, NewSectionSize);
	newSec.PointerToRawData = pLastSec->PointerToRawData + pLastSec->SizeOfRawData;
	newSec.SizeOfRawData = NewSectionSize;

	RtlCopyMemory(pNewSec, &newSec, sizeof(newSec));
	pNt->FileHeader.NumberOfSections++;
	pNt->OptionalHeader.SizeOfImage += NewSectionSize;
	pNt->OptionalHeader.SizeOfHeaders += sizeof(IMAGE_SECTION_HEADER);

	RtlCopyMemory((LPVOID)((DWORD)lpBuffer + dwFileSize), (LPVOID)RVAToFOA((DWORD)GetSectionDataRVA(".text", pNtStub), lpStubBuffer), NewSectionSize);
	pNt->OptionalHeader.AddressOfEntryPoint = newSec.VirtualAddress;//RVAת������

	SetFilePointer(hFile, NULL, NULL, FILE_BEGIN);
	if (WriteFile(hFile, lpBuffer, dwFileSize + NewSectionSize, &dwNumOfRead, NULL) == FALSE) {
		return 0;
	}
	delete[] lpStubBuffer;
	delete[] lpBuffer;
	CloseHandle(hFileStub);
	CloseHandle(hFile);
	return 0;
}

DWORD Align(DWORD _SectionAlignment, DWORD Value) {
	return ((int)(Value / _SectionAlignment) + 1) * _SectionAlignment;
}


DWORD GetSectionSize(LPCSTR lpSectionName, PIMAGE_NT_HEADERS pNt){
	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNt);
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++){
		if (strcmp((LPCSTR)pFirstSection[i].Name, lpSectionName) == 0) {
			return pFirstSection[i].SizeOfRawData;
		}
	}
	return 0;
}

LPVOID GetSectionDataRVA(LPCSTR lpSectionName, PIMAGE_NT_HEADERS pNt) {
	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNt);
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
		if (strcmp((LPCSTR)pFirstSection[i].Name, lpSectionName) == 0) {
			return (LPVOID)pFirstSection[i].VirtualAddress;
		}
	}
	return 0;
}


DWORD RVAToFOA(DWORD targetRVA, LPVOID lpBuffer) {
	
}