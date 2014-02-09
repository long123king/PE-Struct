// PE_Struct.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include "PEFormat.h"

void Usage()
{
	printf("PE_Struct PEFilename\n");
}

PBYTE GetLoadedBase()
{
	PBYTE start = 0;
	//	if (hProcess != INVALID_HANDLE_VALUE)
	{
		HMODULE modules[1024];
		DWORD dwNeed = 0;
		if (EnumProcessModules(GetCurrentProcess(),
			modules,
			1024 * sizeof(HMODULE),
			&dwNeed))
		{
			if (dwNeed > 1024 * sizeof(HMODULE))
			{
				return NULL;
			}

			DWORD dwNumbers = dwNeed / sizeof(HMODULE);
			for (int i=0;i<dwNumbers;i++)
			{
				TCHAR name[1024] = {0};
				if (GetModuleBaseName(GetCurrentProcess(),
					modules[i],
					name,
					1024 * sizeof(TCHAR)))
				{
					//__asm{int 03h};
					MODULEINFO moduleInfo;
					if (_wcsnicmp(name, L"PE_Struct.exe", sizeof(L"PE_Struct.exe")) == 0)
					{
						if (GetModuleInformation(GetCurrentProcess(),
							modules[i],
							&moduleInfo,
							sizeof(moduleInfo)))
						{
							return (PBYTE)moduleInfo.lpBaseOfDll;
						}
					}
				}	
			}
		}
 	}

	return NULL;
}

PBYTE GetKernel32Base()
{
	return (PBYTE)GetModuleHandle(L"Kernel32.dll");
}

PBYTE GetNtdllBase()
{
	return (PBYTE)GetModuleHandle(L"ntdll.dll");
}

PBYTE GetPsapiBase()
{
	return (PBYTE)GetModuleHandle(L"Psapi.dll");
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc != 2)
	{
		Usage();
	}

	//char* p = new char[200];

	HANDLE hFile = CreateFile
		(argv[1],
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_NO_BUFFERING,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	HANDLE hFileMapping = CreateFileMapping(
		hFile,
		NULL,
		PAGE_READONLY,
		0,
		0,	// should be zero, because we do not need to allocate memory from pagefile
		NULL);

	if (hFileMapping == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		return 0;
	}

	PVOID pBuffer = MapViewOfFile(
		hFileMapping,
		FILE_MAP_READ,
		0,
		0,
		0);

	PBYTE pImageBase = (PBYTE)pBuffer;

	PEFormat format_static(pImageBase, true);

	PEFormat format_loaded(GetLoadedBase());

	PEFormat format_kernel32(GetKernel32Base());

	PEFormat format_ntdll(GetNtdllBase());

	PEFormat format_psapi(GetPsapiBase());

	if (pBuffer == NULL)
	{		
		goto END;
	}

	// Do parsing here

END:

	if (pBuffer != NULL)
	{
		UnmapViewOfFile(pBuffer);
	}

	if ( hFileMapping != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFileMapping);
		hFileMapping = INVALID_HANDLE_VALUE;
	}
	
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}

	return 0;
}

