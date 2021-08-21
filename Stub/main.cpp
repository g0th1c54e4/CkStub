#include <Windows.h>
#include "..\Public\Public.h"

#pragma comment(linker, "/merge:.data=.text")
#pragma comment(linker, "/merge:.rdata=.text")
#pragma comment(linker, "/section:.text,RWE")
typedef int(WINAPI* MessageBoxA_)(HWND,LPCSTR,LPCSTR,UINT);
VOID Start() {
	MessageBoxA_ messageBoxA = (MessageBoxA_)0x764EED60;
	messageBoxA(NULL, "This is Stub", "Hello", MB_OK);
	__asm {
		jmp label
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		int 3
		label:
	}
	return;
}