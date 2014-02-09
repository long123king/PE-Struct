#include "PEFormat.h"
#include <algorithm>

#pragma comment(lib, "Psapi.lib")

PEFormat::PEFormat( PBYTE pImageBase , bool bStatic)
	:m_pImageBase(pImageBase)
{
	m_dos_header =
		(IMAGE_DOS_HEADER*)(m_pImageBase);

	m_file_header =
		(IMAGE_FILE_HEADER*)(m_pImageBase + m_dos_header->e_lfanew + 4);

	m_opt_header = 
		(IMAGE_OPTIONAL_HEADER*)(m_pImageBase + m_dos_header->e_lfanew + 24);

	m_sizes.SizeOfCode = m_opt_header->SizeOfCode;
	m_sizes.SizeOfInitializedData = m_opt_header->SizeOfInitializedData;
	m_sizes.SizeOfUninitializedData = m_opt_header->SizeOfUninitializedData;

	m_sizes.SizeOfImage = m_opt_header->SizeOfImage;

	m_sizes.SizeOfStackReserve = m_opt_header->SizeOfStackReserve;
	m_sizes.SizeOfStackCommit = m_opt_header->SizeOfStackCommit;

	m_sizes.SizeOfHeapReserve = m_opt_header->SizeOfHeapReserve;
	m_sizes.SizeOfHeapCommit = m_opt_header->SizeOfHeapCommit;	

	DWORD NumberOfDataDirectories = m_opt_header->NumberOfRvaAndSizes;

	for (int i=0;
		i<16;
		i++)
	{
		m_dataDirs[i] = m_opt_header->DataDirectory[i];
	}

	DWORD marginOffset = 0;
	if (bStatic)
	{
		marginOffset = m_sizes.SizeOfImage - 
			(m_sizes.SizeOfCode + m_sizes.SizeOfInitializedData) - 
			m_opt_header->BaseOfCode;
	}

	m_addrs.AddressOfEntryPoint = (PBYTE)(m_pImageBase + m_opt_header->AddressOfEntryPoint - marginOffset);
	m_addrs.BaseOfCode = (PBYTE)(m_pImageBase + m_opt_header->BaseOfCode);
	m_addrs.BaseOfData = (PBYTE)(m_pImageBase + m_opt_header->BaseOfData);

	IMAGE_DATA_DIRECTORY import_directory = 
		m_opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_DATA_DIRECTORY export_directory =
		m_opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];	

	

	m_current_pos = m_pImageBase + m_dos_header->e_lfanew + 24 + m_file_header->SizeOfOptionalHeader;

	for (int i=0;
		i<m_file_header->NumberOfSections;
		i++)
	{
		IMAGE_SECTION_HEADER* pSection = (IMAGE_SECTION_HEADER*)(m_current_pos);
		SECTION_INFO Section_Info;
		Section_Info.name = pSection->Name;
		Section_Info.header = pSection;
		Section_Info.map_start = (PBYTE)(m_pImageBase + pSection->PointerToRawData);
		Section_Info.load_start = (PBYTE)(m_pImageBase + pSection->VirtualAddress);
		Section_Info.delta = Section_Info.load_start - Section_Info.map_start;
		Section_Info.length = pSection->SizeOfRawData;
		m_sections.push_back(Section_Info);
		m_current_pos += sizeof(IMAGE_SECTION_HEADER);
	}

	bool bHasImportSection = false;
	if (bStatic)
	{
		for (int i=0;i<m_sections.size();i++)
		{
			if (strncmp((const char*)m_sections.at(i).name, ".idata", strlen(".idata")) == 0)
			{
				bHasImportSection = true;
				marginOffset = import_directory.VirtualAddress - m_sections.at(i).header->PointerToRawData;				
			}
		}
	}

	if (bHasImportSection)
	{
		m_import_descriptors = 
			(IMAGE_IMPORT_DESCRIPTOR*)(m_pImageBase + import_directory.VirtualAddress - marginOffset);
	}


	m_export_directories = 
		(IMAGE_EXPORT_DIRECTORY*)(m_pImageBase + export_directory.VirtualAddress - marginOffset);

	IMAGE_THUNK_DATA zeroThunk;
	memset((void *)&zeroThunk, 0, sizeof(zeroThunk));

	if (bHasImportSection)
	{
		IMAGE_THUNK_DATA* orgThunk = (IMAGE_THUNK_DATA*)(m_pImageBase + m_import_descriptors->OriginalFirstThunk - marginOffset);

		while (memcmp((void*)orgThunk, (void *)&zeroThunk, sizeof(IMAGE_THUNK_DATA)) != 0)
		{
			THUNK_INFO ThunkInfo;
			if ((orgThunk->u1.ForwarderString & 0x80000000) == 0)
			{
				ThunkInfo.name = (IMAGE_IMPORT_BY_NAME*)(m_pImageBase + orgThunk->u1.ForwarderString - marginOffset);
				ThunkInfo.bName = true;
			}
			else
			{
				ThunkInfo.num = orgThunk->u1.Ordinal & 0x7FFFFFFF;
				ThunkInfo.bName = false;
			}
			ThunkInfo.data = orgThunk;
			m_orgThunks.push_back(ThunkInfo);
			orgThunk ++;
		}

		if (!bStatic)
		{

			IMAGE_THUNK_DATA* Thunk = 
				(IMAGE_THUNK_DATA*)(m_pImageBase + m_dataDirs[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress - marginOffset);

			while (memcmp((void*)Thunk, (void *)&zeroThunk, sizeof(IMAGE_THUNK_DATA)) != 0)
			{
				THUNK_INFO ThunkInfo;
				ThunkInfo.function = Thunk->u1.Function;
				ThunkInfo.data = Thunk;
				m_Thunks.push_back(ThunkInfo);
				Thunk ++;
			}
		}
		else
		{
			IMAGE_THUNK_DATA* Thunk = (IMAGE_THUNK_DATA*)(m_pImageBase + m_import_descriptors->OriginalFirstThunk - marginOffset);

			while (memcmp((void*)Thunk, (void *)&zeroThunk, sizeof(IMAGE_THUNK_DATA)) != 0)
			{
				THUNK_INFO ThunkInfo;
				if ((Thunk->u1.ForwarderString & 0x80000000) == 0)
				{
					ThunkInfo.name = (IMAGE_IMPORT_BY_NAME* )(m_pImageBase + Thunk->u1.ForwarderString - marginOffset);
					ThunkInfo.bName = true;
					//printf("%s\n", ThunkInfo.name->Name);
				}
				else
				{
					ThunkInfo.num = orgThunk->u1.Ordinal & 0x7FFFFFFF;
					ThunkInfo.bName = false;
				}
				ThunkInfo.data = Thunk;
				m_Thunks.push_back(ThunkInfo);
				Thunk ++;
			}
		}
	}	

	PBYTE start = 0;
	MEMORY_BASIC_INFORMATION mbi;
	while(VirtualQueryEx(GetCurrentProcess(),
		start,
		&mbi,
		sizeof(mbi)) > 0)
	{
		if (mbi.Type & MEM_IMAGE)
		{
			TCHAR name[1024];
			if (GetModuleFileName(
				(HMODULE)mbi.AllocationBase,
				name,
				1024 * sizeof(TCHAR)) > 0)
			{
				wprintf(L"%s 0x%08X %d\n", name, mbi.BaseAddress, mbi.RegionSize);
			}
		}

		start += mbi.RegionSize;
	}

	std::vector<DWORD> funcRVAs;
	if (!bStatic && m_export_directories->NumberOfFunctions != 0)
	{
		for (int i=0;i<m_export_directories->NumberOfFunctions;i++)
		{
			DWORD* functionOffset = (DWORD*)(m_pImageBase + m_export_directories->AddressOfFunctions + 4*i);
			DWORD functionRVA = (DWORD)(/*m_pImageBase + */*functionOffset);
			funcRVAs.push_back(functionRVA);
		}
	}

	if (!bStatic && m_export_directories->NumberOfFunctions != 0)
	{
		for (int i=0;i<m_export_directories->NumberOfFunctions;i++)
		{
			EXPORT_INFO info;
			info.dllName = (PBYTE)(m_pImageBase + m_export_directories->Name);

			unsigned short* numOffset = (unsigned short*)(m_pImageBase + m_export_directories->AddressOfNameOrdinals);
			info.ordinal = (unsigned short)(m_pImageBase + *(numOffset+i));

			if (info.ordinal > m_export_directories->NumberOfFunctions)
			{
				break;
			}
			info.funcRVA = funcRVAs.at(info.ordinal);
			if (info.funcRVA > export_directory.VirtualAddress && info.funcRVA < export_directory.VirtualAddress + export_directory.Size)
			{
				info.bRedirect = true;
			}

			info.function = (PBYTE)(m_pImageBase + info.funcRVA);

			DWORD* nameOffset = (DWORD*)(m_pImageBase + m_export_directories->AddressOfNames + 4*i);
			info.name = (PBYTE)(m_pImageBase + *nameOffset);

			m_exportFuns.push_back(info);
		}
	}

	std::sort(m_exportFuns.begin(), m_exportFuns.end(), EXPORT_INFO::Compare);
}

PEFormat::~PEFormat()
{

}

