#ifndef __PE_STRUCT_PE_FORMAT_H__
#define __PE_STRUCT_PE_FORMAT_H__

#include <Windows.h>
#include <vector>
#include <string>

#include <Psapi.h>

typedef struct _SECTION_INFO
{
	PBYTE name;
	IMAGE_SECTION_HEADER* header;
	PBYTE map_start;	// file offset
	PBYTE load_start;	// RVA
	DWORD delta;		// delta
	DWORD length;
}SECTION_INFO;

typedef struct _MEMORY_REGION_INFO
{
	MEMORY_BASIC_INFORMATION* region;
	TCHAR imageName[1024];
	std::string prop;
	_MEMORY_REGION_INFO()
		:region(NULL)
	{
		memset((void*)&imageName, 0, sizeof(TCHAR) * 1024);
	}
}MEMORY_REGION_INFO;

typedef struct _THUNK_INFO
{
	IMAGE_THUNK_DATA* data;
	IMAGE_IMPORT_BY_NAME* name;
	DWORD function;
	DWORD num;
	bool bName;
	_THUNK_INFO()
		:data(NULL)
		,name(NULL)
		,function(0)
		,num(0)
		,bName(false)
	{
	}
}THUNK_INFO;

typedef struct _EXPORT_INFO
{
	PBYTE name;
	PBYTE function;
	PBYTE dllName;
	DWORD ordinal;
	DWORD funcRVA;
	bool bRedirect;
	_EXPORT_INFO()
		:name(NULL)
		,function(NULL)
		,dllName(NULL)
		,ordinal(0)
		,funcRVA(0)
		,bRedirect(false)
	{
	}
	static bool Compare(_EXPORT_INFO& op1, _EXPORT_INFO& op2)
	{
		return (op1.ordinal < op2.ordinal);
	}
}EXPORT_INFO;

class PEFormat
{
public:
	PEFormat(PBYTE pImageBase, bool bStatic = false);
	~PEFormat();

	static std::string ProtectString(DWORD protect)
	{
		switch (protect)
		{
		case 0x10:
			return "EXECUTE";
			break;
		case 0x20:	
			return "EXECUTE | READ";
			break;
		case 0x40:
			return "EXECUTE | READ | WRITE";
			break;
		case 0x80:
			return "EXECUTE | READ | WRITE | COPY-ON-WRITE";
			break;
		case 0x01:
			return "NO ACCESS";
			break;
		case 0x02:
			return "READ";
			break;
		case 0x04:
			return "READ | WRITE";
			break;
		case 0x08:
			return "READ | WRITE | COPY-ON-WRITE";
			break;
		default:
			return "";
		}
	}
private:
	PBYTE m_pImageBase;

	struct {
		DWORD SizeOfCode;
		DWORD SizeOfInitializedData;
		DWORD SizeOfUninitializedData;
		DWORD SizeOfImage;
		DWORD SizeOfStackReserve;
		DWORD SizeOfStackCommit;
		DWORD SizeOfHeapReserve;
		DWORD SizeOfHeapCommit;
	}m_sizes;

	struct{
		PBYTE AddressOfEntryPoint;
		PBYTE BaseOfCode;
		PBYTE BaseOfData;
	}m_addrs;

	IMAGE_DATA_DIRECTORY m_dataDirs[16];

	IMAGE_IMPORT_DESCRIPTOR* m_import_descriptors;
	IMAGE_EXPORT_DIRECTORY* m_export_directories;

	IMAGE_OPTIONAL_HEADER* m_opt_header;
	IMAGE_DOS_HEADER* m_dos_header;
	IMAGE_FILE_HEADER* m_file_header;

	std::vector<SECTION_INFO> m_sections;

	std::vector<THUNK_INFO> m_orgThunks;
	std::vector<THUNK_INFO> m_Thunks;

	std::vector<EXPORT_INFO> m_exportFuns;

	PBYTE m_current_pos;
};

#endif//__PE_STRUCT_PE_FORMAT_H__