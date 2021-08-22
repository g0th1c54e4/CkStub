#ifndef _PUBLIC
#define _PUBLIC

#include <Windows.h>
typedef struct _STUB {
	DWORD OriginEntryPoint;
	BYTE Key;
	DWORD CodeBeginAddress;
	DWORD SizeOfCode;

}STUB;



#endif