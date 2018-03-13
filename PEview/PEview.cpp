// PEview.cpp : definisce il punto di ingresso dell'applicazione console.
//

#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>



/*Convert Virtual Address to File Offset */
DWORD Rva2Offset(DWORD rva, IMAGE_SECTION_HEADER *ish, IMAGE_NT_HEADERS *inh)
{
	size_t i = 0;
	IMAGE_SECTION_HEADER *pSeh;
	if (rva == 0)
	{
		return (rva);
	}
	pSeh = ish;
	for (i = 0; i < inh->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
			pSeh->Misc.VirtualSize)
		{
			break;
		}
		pSeh++;
	}
	return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}

void printDosHeader(BYTE* buffer)
{
	// Get the IMAGE_DOS_HEADER, this works ok..
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *)buffer;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE)
		_tprintf(L"DOS signature: NOT VERIFIED %x\n", idh->e_magic);
	else {
		_tprintf(L" ----------DOS_HEADER----------\n\n");
		_tprintf(L"  [IMAGE_DOS_HEADER]\n");
				     
		_tprintf(L"   [*] e_magic     : 0x%x [%c%c]\n", idh->e_magic, (idh->e_magic & 0xFF), ((idh->e_magic>>8) & 0xFF) );
		_tprintf(L"       e_cblp      : 0x%x\n", idh->e_cblp);
		_tprintf(L"       e_cp        : 0x%x\n", idh->e_cp);
		_tprintf(L"       e_crlc      : 0x%x\n", idh->e_crlc);
		_tprintf(L"       e_cparhdr   : 0x%x\n", idh->e_cparhdr);
		_tprintf(L"       e_minalloc  : 0x%x\n", idh->e_minalloc);
		_tprintf(L"       e_maxalloc  : 0x%x\n", idh->e_maxalloc);
		_tprintf(L"       e_ss        : 0x%x\n", idh->e_ss);
		_tprintf(L"       e_sp        : 0x%x\n", idh->e_sp);
		_tprintf(L"       e_csum      : 0x%x\n", idh->e_csum);
		_tprintf(L"       e_ip        : 0x%x\n", idh->e_ip);
		_tprintf(L"       e_cs        : 0x%x\n", idh->e_cs);
		_tprintf(L"       e_lfarlc    : 0x%x\n", idh->e_lfarlc);
		_tprintf(L"       e_ovno      : 0x%x\n", idh->e_ovno);
		_tprintf(L"       e_res[4]    : \n");
		_tprintf(L"       e_oemid     : 0x%x\n", idh->e_oemid);
		_tprintf(L"       e_oeminfo   : 0x%x\n", idh->e_oeminfo);
		_tprintf(L"       e_res2[10]  : \n");
		_tprintf(L"   [*] e_lfanew    : 0x%x [%d]\n", idh->e_lfanew, idh->e_lfanew);
	}

}

// rappresenta il layout fisico su disco del file
void printFileHeader(IMAGE_FILE_HEADER* ifh)
{
	_tprintf(L"  [IMAGE_FILE_HEADERS]\n");

	switch (ifh->Machine)
	{
	case 0x014c:
		_tprintf(L"   [*] Machine              : 0x%x [I386]\n", ifh->Machine);
		break;
	case 0x0200:
		_tprintf(L"   [*] Machine              : 0x%x [IA64]\n", ifh->Machine);
		break;
	case 0x8664:
		_tprintf(L"   [*] Machine              : 0x%x [AMD64]\n", ifh->Machine);
		break;
	}
	
	_tprintf(L"   [*] NumberOfSections     : 0x%x\n", ifh->NumberOfSections);
	_tprintf(L"       TimeDateStamp        : 0x%x\n", ifh->TimeDateStamp);
	_tprintf(L"       PointerToSymbolTable : 0x%x\n", ifh->PointerToSymbolTable);
	_tprintf(L"       NumberOfSymbols      : 0x%x\n", ifh->NumberOfSymbols);
	_tprintf(L"   [*] SizeOfOptionalHeader : 0x%x\n", ifh->SizeOfOptionalHeader);
	_tprintf(L"   [*] Characteristics      : 0x%x\n", ifh->Characteristics);
	_tprintf(L"       [ ");
	if (ifh->Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		_tprintf(L"IMAGE_FILE_RELOCS_STRIPPED ");
	if (ifh->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
		_tprintf(L" IMAGE_FILE_EXECUTABLE_IMAGE ");
	if (ifh->Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)
		_tprintf(L" IMAGE_FILE_LINE_NUMS_STRIPPED ");
	if (ifh->Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)
		_tprintf(L" IMAGE_FILE_LOCAL_SYMS_STRIPPED ");
	if (ifh->Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM)
		_tprintf(L" IMAGE_FILE_AGGRESIVE_WS_TRIM ");
	if (ifh->Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
		_tprintf(L" IMAGE_FILE_LARGE_ADDRESS_AWARE ");
	if (ifh->Characteristics & IMAGE_FILE_BYTES_REVERSED_LO)
		_tprintf(L" IMAGE_FILE_BYTES_REVERSED_LO ");
	if (ifh->Characteristics & IMAGE_FILE_32BIT_MACHINE)
		_tprintf(L" IMAGE_FILE_32BIT_MACHINE ");
	if (ifh->Characteristics & IMAGE_FILE_DEBUG_STRIPPED)
		_tprintf(L" IMAGE_FILE_DEBUG_STRIPPED ");
	if (ifh->Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP)
		_tprintf(L" IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP ");
	if (ifh->Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP)
		_tprintf(L" IMAGE_FILE_NET_RUN_FROM_SWAP ");
	if (ifh->Characteristics & IMAGE_FILE_SYSTEM)
		_tprintf(L" IMAGE_FILE_SYSTEM ");
	if (ifh->Characteristics & IMAGE_FILE_DLL)
		_tprintf(L" IMAGE_FILE_DLL ");
	if (ifh->Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY)
		_tprintf(L" IMAGE_FILE_UP_SYSTEM_ONLY ");
	if (ifh->Characteristics & IMAGE_FILE_BYTES_REVERSED_HI)
		_tprintf(L" IMAGE_FILE_BYTES_REVERSED_HI ");
	_tprintf(L" ]\n\n");

}

// rappresenta il layout logico del file
void printOptionalHeader(IMAGE_OPTIONAL_HEADER* ioh)
{
	_tprintf(L"  [IMAGE_OPTIONAL_HEADERS]\n");
	_tprintf(L"       Magic                       : 0x%x\n", ioh->Magic);
	_tprintf(L"       MajorLinkerVersion          : 0x%x\n", ioh->MajorLinkerVersion);
	_tprintf(L"       MinorLinkerVersion          : 0x%x\n", ioh->MinorLinkerVersion);
	_tprintf(L"       SizeOfCode                  : 0x%x\n", ioh->SizeOfCode);
	_tprintf(L"       SizeOfInitializedData       : 0x%x\n", ioh->SizeOfInitializedData);
	_tprintf(L"       SizeOfUninitializedData     : 0x%x\n", ioh->SizeOfUninitializedData);
	_tprintf(L"   [*] AddressOfEntryPoint         : 0x%x\n", ioh->AddressOfEntryPoint);
	_tprintf(L"       BaseOfCode                  : 0x%x\n", ioh->BaseOfCode);
	_tprintf(L"       BaseOfData                  : 0x%x\n", ioh->BaseOfData);
	_tprintf(L"   [*] ImageBase                   : 0x%x\n", ioh->ImageBase);
	_tprintf(L"   [*] SectionAlignment            : 0x%x\n", ioh->SectionAlignment);
	_tprintf(L"   [*] FileAlignment               : 0x%x\n", ioh->FileAlignment);
	_tprintf(L"       MajorOperatingSystemVersion : 0x%x\n", ioh->MajorOperatingSystemVersion);
	_tprintf(L"       MinorOperatingSystemVersion : 0x%x\n", ioh->MinorOperatingSystemVersion);
	_tprintf(L"       MajorImageVersion           : 0x%x\n", ioh->MajorImageVersion);
	_tprintf(L"       MinorImageVersion           : 0x%x\n", ioh->MinorImageVersion);
	_tprintf(L"       MajorSubsystemVersion       : 0x%x\n", ioh->MajorSubsystemVersion);
	_tprintf(L"       MinorSubsystemVersion       : 0x%x\n", ioh->MinorSubsystemVersion);
	_tprintf(L"       Win32VersionValue           : 0x%x\n", ioh->Win32VersionValue);
	_tprintf(L"   [*] SizeOfImage                 : 0x%x\n", ioh->SizeOfImage);
	_tprintf(L"   [*] SizeOfHeaders               : 0x%x\n", ioh->SizeOfHeaders);
	_tprintf(L"       CheckSum                    : 0x%x\n", ioh->CheckSum);
	_tprintf(L"   [*] Subsystem                   : 0x%x\n", ioh->Subsystem);
	_tprintf(L"       DllCharacteristics          : 0x%x\n", ioh->DllCharacteristics);
	_tprintf(L"       SizeOfStackReserve          : 0x%x\n", ioh->SizeOfStackReserve);
	_tprintf(L"       SizeOfStackCommit           : 0x%x\n", ioh->SizeOfStackCommit);
	_tprintf(L"       SizeOfHeapReserve           : 0x%x\n", ioh->SizeOfHeapReserve);
	_tprintf(L"       SizeOfHeapCommit            : 0x%x\n", ioh->SizeOfHeapCommit);
	_tprintf(L"       LoaderFlags                 : 0x%x\n", ioh->LoaderFlags);
	_tprintf(L"       NumberOfRvaAndSizes         : 0x%x\n", ioh->NumberOfRvaAndSizes);

}

void printNtHeader(BYTE* buffer)
{
	// Get the IMAGE_DOS_HEADER, this works ok..
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)buffer;
	IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS*)(buffer + idh->e_lfanew);
	if (inh->Signature != IMAGE_NT_SIGNATURE)
		_tprintf(L"NT signature: NOT VERIFIED %x\n", inh->Signature);
	else {
		_tprintf(L"\n ----------NT_HEADERS----------\n\n");
		_tprintf(L"  [IMAGE_NT_HEADERS]\n");

		_tprintf(L"   [*] Signature            : 0x%x [%c%c]\n\n", inh->Signature, (inh->Signature & 0xFF), ((inh->Signature >> 8) & 0xFF));

		printFileHeader(&(inh->FileHeader));

		printOptionalHeader(&inh->OptionalHeader);
	}

}


void printSectionTable(BYTE* buffer)
{
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)buffer;
	IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS*)(buffer + idh->e_lfanew);
	IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER*)(buffer + idh->e_lfanew + sizeof(inh->Signature) + sizeof(IMAGE_FILE_HEADER) + inh->FileHeader.SizeOfOptionalHeader);


	_tprintf(L"\n ----------PE SECTIONS----------\n\n");
	_tprintf(L"  [IMAGE_SECTION_HEADERS]\n");

	IMAGE_SECTION_HEADER *current = ish;
	for (int i = 0; i < inh->FileHeader.NumberOfSections; i++)
	{
		    printf("       Name                   : %s\n", current->Name);
		 _tprintf(L"       Misc_PhysicalAddress   : 0x%x\n", current->Misc.PhysicalAddress);
		 _tprintf(L"       Misc_VirtualSize       : 0x%x\n", current->Misc.VirtualSize);
		 _tprintf(L"       VirtualAddress         : 0x%x\n", current->VirtualAddress);
		 _tprintf(L"       SizeOfRawData          : 0x%x\n", current->SizeOfRawData);
		 _tprintf(L"       PointerToRawData       : 0x%x\n", current->PointerToRawData);
		 _tprintf(L"       PointerToRelocations   : 0x%x\n", current->PointerToRelocations);
		 _tprintf(L"       PointerToLinenumbers   : 0x%x\n", current->PointerToLinenumbers);
		 _tprintf(L"       NumberOfRelocations    : 0x%x\n", current->NumberOfRelocations);
		 _tprintf(L"       NumberOfLinenumbers    : 0x%x\n", current->NumberOfLinenumbers);
		 _tprintf(L"       Characteristics        : 0x%x\n", current->Characteristics);
		 _tprintf(L"       [ ");
		 if (current->Characteristics & IMAGE_SCN_TYPE_NO_PAD)
			 _tprintf(L"IMAGE_SCN_TYPE_NO_PAD ");
		 if (current->Characteristics & IMAGE_SCN_CNT_CODE)
			 _tprintf(L" IMAGE_SCN_CNT_CODE ");
		 if (current->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
			 _tprintf(L" IMAGE_SCN_CNT_INITIALIZED_DATA ");
		 if (current->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			 _tprintf(L" IMAGE_SCN_CNT_UNINITIALIZED_DATA ");
		 if (current->Characteristics & IMAGE_SCN_LNK_INFO)
			 _tprintf(L" IMAGE_SCN_LNK_INFO ");
		 if (current->Characteristics & IMAGE_SCN_LNK_REMOVE)
			 _tprintf(L" IMAGE_SCN_LNK_REMOVE ");
		 if (current->Characteristics & IMAGE_SCN_LNK_COMDAT)
			 _tprintf(L" IMAGE_SCN_LNK_COMDAT ");
		 if (current->Characteristics & IMAGE_SCN_NO_DEFER_SPEC_EXC)
			 _tprintf(L" IMAGE_SCN_NO_DEFER_SPEC_EXC ");
		 if (current->Characteristics & IMAGE_SCN_GPREL)
			 _tprintf(L" IMAGE_SCN_GPREL ");
		 if (current->Characteristics & IMAGE_SCN_MEM_PURGEABLE)
			 _tprintf(L" IMAGE_SCN_MEM_PURGEABLE ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_1BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_1BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_2BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_2BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_4BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_4BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_8BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_8BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_16BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_16BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_32BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_32BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_64BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_64BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_128BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_128BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_256BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_256BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_512BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_512BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_1024BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_1024BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_2048BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_2048BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_4096BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_4096BYTES ");
		 if (current->Characteristics & IMAGE_SCN_ALIGN_8192BYTES)
			 _tprintf(L" IMAGE_SCN_ALIGN_8192BYTES ");
		 if (current->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)
			 _tprintf(L" IMAGE_SCN_LNK_NRELOC_OVFL ");
		 if (current->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
			 _tprintf(L" IMAGE_SCN_MEM_DISCARDABLE ");
		 if (current->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
			 _tprintf(L" IMAGE_SCN_MEM_NOT_CACHED ");
		 if (current->Characteristics & IMAGE_SCN_MEM_NOT_PAGED)
			 _tprintf(L" IMAGE_SCN_MEM_NOT_PAGED ");
		 if (current->Characteristics & IMAGE_SCN_MEM_SHARED)
			 _tprintf(L" IMAGE_SCN_MEM_SHARED ");
		 if (current->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			 _tprintf(L" IMAGE_SCN_MEM_EXECUTE ");
		 if (current->Characteristics & IMAGE_SCN_MEM_READ)
			 _tprintf(L" IMAGE_SCN_MEM_READ ");
		 if (current->Characteristics & IMAGE_SCN_MEM_WRITE)
			 _tprintf(L" IMAGE_SCN_MEM_WRITE ");
		 _tprintf(L" ]\n\n");
		 current++;
	}

}


void printExportedSymbols(BYTE* buffer)
{
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)buffer;
	IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS*)(buffer + idh->e_lfanew);
	IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER*)(buffer + idh->e_lfanew + sizeof(inh->Signature) + sizeof(IMAGE_FILE_HEADER) + inh->FileHeader.SizeOfOptionalHeader);
	IMAGE_IMPORT_DESCRIPTOR *pImportDescriptor = NULL;
	IMAGE_EXPORT_DIRECTORY *pExportDirectory = NULL;

	DWORD exportTableVA = inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportTableOffset = Rva2Offset(inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, ish, inh);
	pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(buffer + exportTableOffset);

	if (inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)/*if size of the table is 0 - Import Table does not exist */
	{
		_tprintf(L"\n ----------EXPORTED SYMBOLS----------\n\n");
		_tprintf(L"  [IMAGE_EXPORT_DIRECTORY]\n");
		char * pName = (char *)(((pExportDirectory->Name) - exportTableVA) + exportTableOffset + buffer);
		printf("       Name                  : %s\n", pName);
		printf("       rvaName               : 0x%p\n", pExportDirectory->Name);
		printf("       Base                  : 0x%x\n", pExportDirectory->Base);
		printf("       NumberOfFunctions     : 0x%x\n", pExportDirectory->NumberOfFunctions);
		printf("       NumberOfNames         : 0x%x\n", pExportDirectory->NumberOfNames);
		printf("       AddressOfFunctions    : 0x%p\n", pExportDirectory->AddressOfFunctions);
		printf("       AddressOfNameOrdinals : 0x%p\n", pExportDirectory->AddressOfNames);

		DWORD * addressOfFunctionsArray = (DWORD *)(((pExportDirectory->AddressOfFunctions) - exportTableVA) + exportTableOffset + buffer);
		DWORD * addressOfNamesArray = (DWORD *)(((pExportDirectory->AddressOfNames) - exportTableVA) + exportTableOffset + buffer);
		WORD * addressOfNameOrdinalsArray = (WORD *)(((pExportDirectory->AddressOfNameOrdinals) - exportTableVA) + exportTableOffset + buffer);
		char * name;
		DWORD functionAddressRVA;
		DWORD functionOrdinal;
		printf("       ---- Exported functions with name: -----\n");
		for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
		{
			name = (char*)(((addressOfNamesArray[i]) - exportTableVA) + exportTableOffset + buffer);
			functionAddressRVA = addressOfFunctionsArray[addressOfNameOrdinalsArray[i]];
			functionOrdinal = (addressOfNameOrdinalsArray[i] + pExportDirectory->Base);
			printf("           0x%.3x) %s - RVA: 0x%p\n", i+1, name, functionAddressRVA);
		}

		if (pExportDirectory->NumberOfNames != pExportDirectory->NumberOfFunctions)
		{
			printf("\nExported functions without name:\n");
			for (DWORD i = 0; i < pExportDirectory->NumberOfFunctions; i++)
			{
				bool withoutName = true;
				for (DWORD j = 0; j < pExportDirectory->NumberOfNames; j++)
				{
					if (addressOfNameOrdinalsArray[j] == i)
					{
						withoutName = false;
						break;
					}
				}
				if (withoutName && addressOfFunctionsArray[i] != 0)
				{
					printf("Function Ordinal: %X - Address (RVA): %X\n", (i + pExportDirectory->Base), addressOfFunctionsArray[i]);
				}
			}
		}

	}
	else
	{
		printf("No Import Table!\n");
	}

}

void printImportedSymbols(BYTE* buffer)
{
	IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)buffer;
	IMAGE_NT_HEADERS *inh = (IMAGE_NT_HEADERS*)(buffer + idh->e_lfanew);
	IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER*)(buffer + idh->e_lfanew + sizeof(inh->Signature) + sizeof(IMAGE_FILE_HEADER) + inh->FileHeader.SizeOfOptionalHeader);
	IMAGE_IMPORT_DESCRIPTOR *pImportTable = NULL;
	PIMAGE_IMPORT_BY_NAME pImportName = 0;
	PIMAGE_THUNK_DATA32 pIAT = 0;

	DWORD importTableVA = inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD importTableOffset = Rva2Offset(inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, ish, inh);
	pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(importTableOffset + buffer);

	int countIID = 0;
	int countImports = 0;

	_tprintf(L"\n ----------IMPORTED SYMBOLS----------\n\n");
	do {
		countIID++;
		_tprintf(L"  [IMAGE_IMPORT_DIRECTORY %d]\n", countIID);
		char * pName = (char *)(((pImportTable->Name) - importTableVA) + importTableOffset + buffer);
		printf("       Name                     : %s\n", pName);
		printf("       rvaName                  : 0x%X\n", pImportTable->Name);
		printf("       FirstThunk (IAT)         : 0x%X\n", pImportTable->FirstThunk);
		printf("       OriginalFirstThunk (INT) : 0x%X\n", pImportTable->OriginalFirstThunk);
		printf("       TimeDateStamp            : 0x%X\n", pImportTable->TimeDateStamp);
		printf("       ForwarderChain           : 0x%X\n", pImportTable->ForwarderChain);

		DWORD rvaINT = pImportTable->OriginalFirstThunk;
		DWORD rvaIAT = pImportTable->FirstThunk;

		printf("\n       IMAGE_THUNK_DATA ARRAY:\n");

		pIAT = (PIMAGE_THUNK_DATA32)((rvaIAT - importTableVA) + importTableOffset + buffer);

		if (pIAT->u1.Ordinal) //maybe no imports from dll
		{
			do
			{
				countImports++;
				if (IMAGE_SNAP_BY_ORDINAL32(pIAT->u1.Ordinal))
				{
					//by ordinal
					printf("       Ordinal: %X\n", IMAGE_ORDINAL32(pIAT->u1.Ordinal));
					printf("       API Address: %X\n",GetProcAddress(GetModuleHandle((LPCWSTR)pName), (char *)IMAGE_ORDINAL32(pIAT->u1.Ordinal)));
					//GetProcAddress(GetModuleHandle(pName), (char *)IMAGE_ORDINAL32(pIAT->u1.Ordinal));
				}
				else {
					//by name
					pImportName = (PIMAGE_IMPORT_BY_NAME)(((pIAT->u1.AddressOfData) - importTableVA) + importTableOffset + buffer);
					printf("          Name: %s \t - Hint: %X\n", pImportName->Name, pImportName->Hint);
				}

				pIAT++;
			} while (pIAT->u1.AddressOfData != 0);
		}

		pImportTable++;
	} while (pImportTable->Name);

	//printf("\n       DLL Count: %d \t Import Count: %d\n", countIID, countImports);
}



BYTE* readFile(TCHAR* file)
{
	HANDLE hFile = CreateFile((LPCWSTR)file,               // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, // normal file
		NULL);                 // no attr. template

	if (hFile == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("Terminal failure: Unable to open file \"%s\" for write.\n"), file);
		getchar();
		return NULL;
	}

	DWORD dwFileSize = GetFileSize(hFile, NULL);

	BYTE *buffer = new BYTE[dwFileSize];
	DWORD bytesRead = 0;
	OVERLAPPED ovRead = {};
	ReadFile(hFile, buffer, dwFileSize, &bytesRead, &ovRead);

	CloseHandle(hFile);
	return buffer;
}

void __cdecl _tmain(int argc, TCHAR* argv[])
{
	if (argc < 2)
	{
		_tprintf(L"PEview v. 0.1\n");
		_tprintf(L"Usage: \n");
		_tprintf(L"%s <pe-file>\n", argv[0]);
		getchar();
		return;
	}

	BYTE* buffer = readFile(argv[1]);
	
	printDosHeader(buffer);
	printNtHeader(buffer); // Signature / FileHeader / OptionalHeader
	printSectionTable(buffer);
	printExportedSymbols(buffer);
	printImportedSymbols(buffer);
	
	delete []buffer;
	

	getchar();
    return;
}



