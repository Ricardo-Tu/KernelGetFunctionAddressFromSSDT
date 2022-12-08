#ifdef __cplusplus
extern "C"
{

#include <ntddk.h>	

#include <windef.h>	

#include <intrin.h>

}
#endif // __cplusplus

#include "Class.h"


// "NtWriteFile"
DWORD64 GetFunctionAddress::GetFunctionSSDTAddressByName(
	_In_	PDRIVER_OBJECT	pDriverObject,
	_In_	PCHAR	szApiName
)
{
	PServiceDescriptorTableEntry64 ssdt_Address = (PServiceDescriptorTableEntry64)GetSSDTPtr(pDriverObject);

	ULONG id = GetSSDTFunctionIndex(szApiName);

	//KdPrint(("id : --<%d>--\n", id));

	PULONG ssdtStart = (PULONG)ssdt_Address->ServiceTableBase;

	DWORD64 apiAddress = (DWORD64)ssdtStart + (DWORD64)(ssdtStart[id] >> 4);

	return apiAddress;
}


ULONG_PTR GetFunctionAddress::GetSSDTPtr(
	PDRIVER_OBJECT pDriver
)
{
	ULONG_PTR uret = 0;
	PUCHAR kernelbase = NULL;
	ULONG kernelSize = 0;

	kernelbase = (PUCHAR)GetKernelModuleBase(pDriver, &kernelSize, L"ntoskrnl.exe");
	if (!kernelbase)
		return uret;

	//KdPrint(("kernel base:--<%p>-- kernelbase size:--<%x>--\n", kernelbase, kernelSize));

	BYTE KiSystemServiceStartPattern[] = { 0x8b,0xf8,0xc1,0xef,0x07,0x83,0xe7,0x20,0x25,0xff,0x0f,0x00,0x00 };

	ULONG signatureSize = sizeof(KiSystemServiceStartPattern);

	LONG KiSSSOffset = 0;

	BOOLEAN bfound = FALSE;

	for (KiSSSOffset = 0; KiSSSOffset < kernelSize - signatureSize; KiSSSOffset++)
		if (RtlCompareMemory((kernelbase + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
		{
			bfound = TRUE;
			break;
		}

	if (!bfound)
		return uret;

	//
	//	这里就是 lea r10，KeServiceDescriptorTable
	//
	PUCHAR address = kernelbase + KiSSSOffset + signatureSize;

	LONG jmpoffset = 0;

	if (*(address) == 0x4c && *(address + 1) == 0x8d && *(address + 2) == 0x15)
		jmpoffset = *(PLONG)(address + 3); //	lea r10，KeServiceDescriptorTable

	if (!jmpoffset)
		return uret;

	uret = (ULONG_PTR)(address + jmpoffset + 7);

	return uret;
}


ULONG_PTR GetFunctionAddress::GetKernelModuleBase(
	PDRIVER_OBJECT pDriver,
	PULONG pimagesize, 
	PWCHAR modulename
)
{
	UNICODE_STRING kernelname = { 0 };
	
	ULONG_PTR uret = 0;
	
	PLDR_DATA_TABLE_ENTRY64 pentry = (PLDR_DATA_TABLE_ENTRY64)pDriver->DriverSection;
	
	PLDR_DATA_TABLE_ENTRY64 first = NULL;

	RtlInitUnicodeString(&kernelname, modulename);

	__try
	{
		do
		{
			if (pentry->BaseDllName.Buffer != NULL)
			{
				if (RtlCompareUnicodeString(&pentry->BaseDllName, &kernelname, TRUE) == 0)
				{
					uret = (ULONG_PTR)pentry->DllBase;
					if (pimagesize)
					{
						*pimagesize = pentry->SizeOfImage;
					}
					break;
				}
				pentry = (PLDR_DATA_TABLE_ENTRY64)pentry->InLoadOrderLinks.Blink;
			}
		} while (pentry->InLoadOrderLinks.Blink != (ULONGLONG)first);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KdPrint(("Error Get ntoskrnl.exe"));
		
		return uret;
	}
	return uret;
}


ULONG GetFunctionAddress::GetSSDTFunctionIndex(
	PCCHAR funname
)
{
	ULONG_PTR tempfunaddr = 0;

	ULONG  	 funaddrid = 0;

	PVOID    ntdll = 0;

	ntdll = KernelLoadDllLibrary(L"\\SystemRoot\\System32\\ntdll.dll");

	if (!ntdll)
	{
		KdPrint(("Load Library Error!\n"));

		return 0;
	}

	tempfunaddr = (ULONG_PTR)GetModuleExport(ntdll, funname);

	if (!tempfunaddr)
	{
		KdPrint(("GetModuleExport Error!\n"));

		return 0;
	}

	funaddrid = *(PULONG)((PUCHAR)tempfunaddr + 4);

	// KdPrint(("--ntdll--<%p>-- function id: --<%d>--\n", ntdll, funaddrid));

	ZwUnmapViewOfSection(NtCurrentProcess(), ntdll);

	return funaddrid;
}


PVOID GetFunctionAddress::KernelLoadDllLibrary(
	const wchar_t* full_dll_path
)
{
	HANDLE hSection = NULL, hFile = NULL;

	UNICODE_STRING dllName = { 0 };

	PVOID BaseAddress = NULL;

	SIZE_T size = 0;

	NTSTATUS stat = 0;

	OBJECT_ATTRIBUTES obja = { sizeof(obja),0,&dllName,OBJ_CASE_INSENSITIVE };

	IO_STATUS_BLOCK iosb = { 0 };

	RtlInitUnicodeString(&dllName, full_dll_path);
	
	stat = ZwOpenFile(
			&hFile, 
			FILE_EXECUTE | SYNCHRONIZE, 
			&obja, 
			&iosb, 
			FILE_SHARE_READ, 
			FILE_SYNCHRONOUS_IO_ALERT
		    );

	if (!NT_SUCCESS(stat))
	{
		KdPrint(("Open File Error! Error Code :<%x>\n", stat));

		return 0;
	}

	obja.ObjectName = 0;

	stat = ZwCreateSection(
		&hSection, 
		SECTION_ALL_ACCESS, 
		&obja, 
		0, 
		PAGE_EXECUTE,
		0x1000000, 
		hFile
	);

	if (!NT_SUCCESS(stat))
	{
		KdPrint(("1--<%x>--", stat));

		return (PVOID)stat;
	}


	stat = ZwMapViewOfSection(
		hSection, 
		NtCurrentProcess(), 
		&BaseAddress, 
		0, 
		1000, 
		0, 
		&size, 
		(SECTION_INHERIT)1, 
		MEM_TOP_DOWN, 
		PAGE_READWRITE
		);

	if (!NT_SUCCESS(stat))
	{
		KdPrint(("2--<%x>--", stat));

		return (PVOID)stat;
	}

	ZwClose(hSection);

	ZwClose(hFile);

	return BaseAddress;

}


//···········································
//	内核中装载 ntoskrnl.exe 后，通过函数名称，和 ntoskrnl   的地址查找函数的地址
//··········································
PVOID GetFunctionAddress::GetModuleExport(
	IN PVOID pBase, 
	IN PCCHAR name_ord
)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;

	PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;

	PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;

	PIMAGE_EXPORT_DIRECTORY pExport = NULL;

	ULONG expSize = 0;

	ULONG_PTR pAddress = 0;

	PUSHORT pAddressOfOrds;

	PULONG pAddressOfNames;

	PULONG pAddressOfFuncs;

	LONG i;

	ASSERT(pBase != NULL);
	if (pBase == NULL)
		return NULL;

	// Not a PE filebuf
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
	
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

	// Not a PE filebuf

	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// 64 bit image
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		
		expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	// 32 Bibt image
	else
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		
		expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);

	pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);

	pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

	for (i = 0; i < pExport->NumberOfFunctions; i++)
	{
		USHORT OrdIndex = 0xffff;
		PUCHAR pName = NULL;

		// Find by index

		if ((ULONG_PTR)name_ord <= 0xffff)
		{
			OrdIndex = (USHORT)i;
		}
		else if ((ULONG_PTR)name_ord > 0xffff && i < pExport->NumberOfNames)
		{
			pName = (PUCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
			OrdIndex = pAddressOfOrds[i];
		}
		else
		{
			return NULL;
		}
		if (((ULONG_PTR)name_ord <= 0xffff && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) || ((ULONG_PTR)name_ord > 0xffff && strcmp((LPCSTR)pName, name_ord) == 0))
		{
			pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;

			// Check forwarded export	
			if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize)
			{
				return NULL;
			}
			break;
		}
	}
	return (PVOID)pAddress;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void* __cdecl operator new(size_t size) {
	if (size == 0) {
		size = 1;
	}
	return ExAllocatePoolWithTag(NonPagedPool, size, 'newC');
}


_IRQL_requires_max_(DISPATCH_LEVEL)
void __cdecl operator delete(void* p, SIZE_T size) {
	UNREFERENCED_PARAMETER(size);
	if (p) {
		ExFreePoolWithTag(p, 'delC');
	}
}
