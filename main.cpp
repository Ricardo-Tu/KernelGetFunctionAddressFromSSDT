#ifdef __cplusplus
extern "C"
{

#include <ntddk.h>	

#include <windef.h>	

#include <intrin.h>


}
#endif // __cplusplus




#include "Class.h"




VOID	UnloadMyDriver(
	_In_ PDRIVER_OBJECT	pDriverObject
)
{

	KdPrint(("My Driver:Unload...\n"));
	
}



extern "C"
NTSTATUS	
DriverEntry(
	_In_	PDRIVER_OBJECT	pDriverObject,
	_In_	PUNICODE_STRING	pRegistryPath
)
{

	GetFunctionAddress* MyClass;

	MyClass = new	GetFunctionAddress;

	PVOID	address =  (PVOID)MyClass->GetFunctionSSDTAddressByName(pDriverObject, "NtWriteFile");

	KdPrint(("<%llx>\n", address));

	pDriverObject->DriverUnload = UnloadMyDriver;


	return STATUS_SUCCESS;
}



















