#include <Windows.h>
#include "..\Public\Public.h"

#pragma comment(linker, "/merge:.data=.text")
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")
DWORD GetKernelBase();
DWORD GetFuncAddress(LPVOID lpBuffer, LPCSTR lpFunctionName);
BOOL StringCmp(LPCSTR lpStr1, LPCSTR lpStr2);
STUB g_stub = { 0 };


typedef LPVOID(WINAPI* GETPROCADDRESS)(HANDLE, LPCSTR);
typedef HANDLE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef int(WINAPI* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

VOID Start() {
	GETPROCADDRESS GetProcAddress_ = (GETPROCADDRESS)GetFuncAddress((LPVOID)GetKernelBase(), "GetProcAddress");
	LOADLIBRARYA LoadLibraryA_ = (LOADLIBRARYA)GetProcAddress_((HANDLE)GetKernelBase(), "LoadLibraryA");
	MESSAGEBOXA MessageBoxA_ = (MESSAGEBOXA)GetProcAddress_((HANDLE)LoadLibraryA_("user32.dll"), "MessageBoxA");
	MessageBoxA_(NULL, "Hello World", "Shell", MB_OK);
	_asm {
		jmp g_stub.OriginEntryPoint
	}
	return;
}

DWORD GetKernelBase() {
	DWORD dwBase = 0;
	_asm{
		MOV EAX, DWORD PTR FS : [0x30]
		MOV EAX, DWORD PTR DS : [EAX + 0xC]
		MOV ESI, DWORD PTR DS : [EAX + 0x1C]
		LODS DWORD PTR DS : [ESI]
		MOV EBX, DWORD PTR DS : [EAX + 8]
		MOV dwBase, EBX
	}
	return dwBase;
}

DWORD GetFuncAddress(LPVOID lpBuffer, LPCSTR lpFunctionName) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)lpBuffer + pDos->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)lpBuffer + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD dwNum = pExport->NumberOfFunctions;
	PDWORD pdwName = (PDWORD)(pExport->AddressOfNames + (DWORD)lpBuffer);
	PWORD pwOrder = (PWORD)(pExport->AddressOfNameOrdinals + (DWORD)lpBuffer);
	PDWORD pdwFuncAddr = (PDWORD)(pExport->AddressOfFunctions+ (DWORD)lpBuffer);
	for (UINT i = 0; i < dwNum; i++) {
		LPCSTR lpFuncName = (LPCSTR)(pdwName[i] + (DWORD)lpBuffer);
		if (StringCmp(lpFuncName, lpFunctionName)) {
			WORD wOrd = pwOrder[i];
			return (DWORD)lpBuffer + pdwFuncAddr[wOrd];
		}
	}
	return 0;
}


BOOL StringCmp(LPCSTR lpStr1, LPCSTR lpStr2) {
	for (DWORD dwCount = 0; lpStr1[dwCount] != 0 && lpStr2[dwCount] != 0; dwCount++) {
		if (lpStr1[dwCount] != lpStr2[dwCount]) {
			return FALSE;
		}
	}
	return TRUE;
}