#include <ntifs.h>
#include <wdm.h>
#include <stdlib.h>
#include <ntddk.h>
#include "IOCTLDump.h"

#pragma warning( disable : 4267)
#pragma warning( disable : 4533)

#define METHOD_FROM_CTL_CODE(ctrlCode)         ((ULONG)(ctrlCode & 3))

#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3


typedef bool(__stdcall* fastIoCallD)(
	struct _FILE_OBJECT* FileObject,
	BOOLEAN Wait,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength,
	ULONG IoControlCode,
	PIO_STATUS_BLOCK IoStatus,
	struct _DEVICE_OBJECT* DeviceObject
	);

typedef bool(__stdcall* fastIoCallRW) (
	struct _FILE_OBJECT* FileObject,
	PLARGE_INTEGER FileOffset,
	ULONG Length,
	BOOLEAN Wait,
	ULONG LockKey,
	PVOID Buffer,
	PIO_STATUS_BLOCK IoStatus,
	struct _DEVICE_OBJECT* DeviceObject
	);

typedef bool (__stdcall* devIoCallRWD)(
	PDEVICE_OBJECT pDeviceObject, 
	PIRP Irp
);




struct IoHooks
{
	UNICODE_STRING driverName;
	PVOID originalFunction;
	PVOID hookedAddress;
};

IoHooks* fastIoHooksDArray = NULL;
ULONGLONG fastIoHooksDArrayLen = 0;
ULONGLONG fastIoHooksDArrayEntries = 0;

IoHooks* fastIoHooksRArray = NULL;
ULONGLONG fastIoHooksRArrayLen = 0;
ULONGLONG fastIoHooksRArrayEntries = 0;

IoHooks* fastIoHooksWArray = NULL;
ULONGLONG fastIoHooksWArrayLen = 0;
ULONGLONG fastIoHooksWArrayEntries = 0;

IoHooks* deviceIoHooksDArray = NULL;
ULONGLONG deviceIoHooksDArrayLen = 0;
ULONGLONG deviceIoHooksDArrayEntries = 0;

IoHooks* deviceIoHooksWArray = NULL;
ULONGLONG deviceIoHooksWArrayLen = 0;
ULONGLONG deviceIoHooksWArrayEntries = 0;

IoHooks* deviceIoHooksRArray = NULL;
ULONGLONG deviceIoHooksRArrayLen = 0;
ULONGLONG deviceIoHooksRArrayEntries = 0;

IoHooks* fileIoHooksDArray = NULL;
ULONGLONG fileIoHooksDArrayLen = 0;
ULONGLONG fileIoHooksDArrayEntries = 0;


// TODO: Create file and return result
NTSTATUS CreateFileHelper(LPWSTR filePath, ACCESS_MASK DesiredAccess, ULONG CreationDisposition, PHANDLE fileHandle)
{
	UNREFERENCED_PARAMETER(DesiredAccess);
	UNREFERENCED_PARAMETER(CreationDisposition);
	NTSTATUS status;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING fPath = { 0 };
	RtlCreateUnicodeString(&fPath, filePath);
	InitializeObjectAttributes(&objAttr, &fPath, OBJ_KERNEL_HANDLE, NULL, NULL);
	IO_STATUS_BLOCK statBlock = { 0 };
	status = ZwCreateFile(fileHandle, GENERIC_WRITE | GENERIC_READ | SYNCHRONIZE, &objAttr, &statBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
	RtlFreeUnicodeString(&fPath);
	return status;
}


NTSTATUS CreateFolder(LPWSTR folderPath)
{
	HANDLE hFolder = 0;
	NTSTATUS status;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING fPath = { 0 };
	RtlCreateUnicodeString(&fPath, folderPath);
	InitializeObjectAttributes(&objAttr, &fPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	IO_STATUS_BLOCK statBlock = { 0 };
	status = ZwCreateFile(&hFolder, GENERIC_ALL, &objAttr, &statBlock, NULL, FILE_ATTRIBUTE_NORMAL | SYNCHRONIZE, FILE_SHARE_READ, FILE_OPEN_IF, FILE_DIRECTORY_FILE, NULL, 0);
	RtlFreeUnicodeString(&fPath);
	ZwClose(hFolder);
	return status;
}


bool FastIoHookD(IN struct _FILE_OBJECT* FileObject,
	IN BOOLEAN Wait,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	IN ULONG IoControlCode,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN struct _DEVICE_OBJECT* DeviceObject)
{

	NTSTATUS status;
	LPWSTR pathSeperator = L"\\\0\0";
	LPCWSTR nullByteW = L"\0\0";
	UNICODE_STRING drvName = DeviceObject->DriverObject->DriverName;
	LPWSTR pDrvName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, drvName.Length + 2);
	RtlZeroMemory(pDrvName, drvName.Length + 2);
	memcpy(pDrvName, drvName.Buffer+8, drvName.Length+1-8);
	ULONG nameLen = 0;
	status = ObQueryNameString(DeviceObject, NULL, NULL, &nameLen);
	POBJECT_NAME_INFORMATION pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPoolNx, nameLen+4);
	status = ObQueryNameString(DeviceObject, pObjName, nameLen+4, &nameLen);
	if (pObjName->Name.Length == 0)
	{
		ExFreePool(pObjName);
	}
	LPWSTR pDevName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pObjName->Name.Length + 2);
	RtlZeroMemory(pDevName, pObjName->Name.Length+2);
	// TODO, check if we need to skip bytes
	memcpy(pDevName, pObjName->Name.Buffer, pObjName->Name.Length + 1);
	LPWSTR pCFolder = L"C:\\DriverHooks\\\0\0";
	// Careful here with hardcoded buffer copies!
	LPWSTR pFullPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(pFullPath, 2048 * sizeof(WCHAR));
	LPWSTR dosDevicesPath = L"\\DosDevices\\\0\0";
	wcsncpy(pFullPath, dosDevicesPath, 15);
	wcsncat(pFullPath, pCFolder,16);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pDevName);
		ExFreePool(pFullPath);
		goto End;
	}
	wcsncat(pFullPath, pDrvName,drvName.Length+1-8);
	wcsncat(pFullPath, nullByteW, 1);
	ExFreePool(pDevName);
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pFullPath);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	// Convert IOCTL to LPWSTR
	// Warning again with hardcoded lengths
	DECLARE_UNICODE_STRING_SIZE(pIoctlStringUni, 12);
	status = RtlIntegerToUnicodeString(IoControlCode, 16, &pIoctlStringUni);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	LPWSTR pIoctlString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pIoctlStringUni.Length +2);
	RtlZeroMemory(pIoctlString, pIoctlStringUni.Length + 2);
	memcpy(pIoctlString, pIoctlStringUni.Buffer, pIoctlStringUni.Length+1);
	LPWSTR hookTypeStr = L"fastIOD\0\0";
	// Concat ioctl string to full path
	wcsncat(pFullPath, pathSeperator,4);
	wcsncat(pFullPath, hookTypeStr, 10);
	wcsncat(pFullPath, pathSeperator, 4);
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pIoctlString);
		ExFreePool(pDrvName);
		goto End;
	}
	wcsncat(pFullPath, pIoctlString,pIoctlStringUni.Length);
	wcsncat(pFullPath, nullByteW, 1);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%s.\n",pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pIoctlString);
		ExFreePool(pDrvName);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));
	// Convert inputBufLen to LPWSTR
	// Warning again with hardcoded lengths
	DECLARE_UNICODE_STRING_SIZE(pInputBufLenStringUni, 12);
	status = RtlIntegerToUnicodeString(InputBufferLength, 16, &pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pDrvName);
		ExFreePool(pIoctlString);
		goto End;
	}
	LPWSTR pInputBufLenString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pInputBufLenStringUni.Length + 2);
	RtlZeroMemory(pInputBufLenString, pInputBufLenStringUni.Length + 2);
	memcpy(pInputBufLenString, pInputBufLenStringUni.Buffer,pInputBufLenStringUni.Length+1);
	if (InputBufferLength > 0)
	{
		// Dump memory
		LPWSTR pDataPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
		RtlZeroMemory(pDataPath, 1024 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, pathSeperator,4);
		wcsncat(pDataPath, pInputBufLenString, pInputBufLenStringUni.Length);
		wcsncat(pDataPath, nullByteW, 1);
		LPWSTR dataTerminator = L".data\0\0";
		wcsncat(pDataPath, dataTerminator,8);
		// Create handle to pDataPath
		HANDLE hDataFile = 0; 
		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			ExFreePool(pObjName);
			ExFreePool(pFullPath);
			ExFreePool(pDataPath);
			ExFreePool(pInputBufLenString);
			ExFreePool(pDrvName);
			ExFreePool(pIoctlString);
			goto End;
		}
		ExFreePool(pDataPath);
		// Write data to pDataFile handle
		IO_STATUS_BLOCK statBlock;
		status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, InputBuffer, InputBufferLength, NULL, NULL);
		
		ZwClose(hDataFile);
		if (!NT_SUCCESS(status))
		{
			// Error writing file
			ExFreePool(pObjName);
			ExFreePool(pFullPath);
			ExFreePool(pInputBufLenString);
			ExFreePool(pDrvName);
			ExFreePool(pIoctlString);
			goto End;
		}
	}
	// Write conf
	LPWSTR pConfPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
	RtlZeroMemory(pConfPath, 1024 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, pathSeperator,4);
	wcsncat(pConfPath, pInputBufLenString, pInputBufLenStringUni.Length);
	wcsncat(pConfPath, nullByteW, 1);
	LPWSTR confTerminator = L".conf\0\0";
	wcsncat(pConfPath, confTerminator,8);
	HANDLE hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pConfPath);
		ExFreePool(pInputBufLenString);
		ExFreePool(pDrvName);
		ExFreePool(pIoctlString);
		goto End;
	}
	ExFreePool(pConfPath);
	// Write data to pConfFile handle
	LPWSTR confFileString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048*sizeof(WCHAR));
	RtlZeroMemory(confFileString, 2048 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:\0\0";
	wcsncpy(confFileString, drvHeader,14);
	wcsncat(confFileString, pDrvName, drvName.Length+1-8);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pDrvName);
	LPWSTR newLine = L"\n\0\0";
	wcsncat(confFileString, newLine,4);
	LPWSTR typeHeader = L"Type:FASTIOD\n\0\0";
	wcsncat(confFileString, typeHeader,15);
	LPWSTR ioctlHeader = L"IOCTL:\0\0";
	wcsncat(confFileString, ioctlHeader,9);
	wcsncat(confFileString, pIoctlString, pIoctlStringUni.Length+1);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pIoctlString);
	wcsncat(confFileString, newLine,4);
	LPWSTR inputLenHeader = L"InputBufferLength:\0\0";
	wcsncat(confFileString, inputLenHeader,21);
	wcsncat(confFileString, pInputBufLenString, pInputBufLenStringUni.Length+1);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pInputBufLenString);
	wcsncat(confFileString, newLine,4);
	LPWSTR outputLenHeader = L"OutputBufferLength:\0\0";
	wcsncat(confFileString, outputLenHeader,22);

	DECLARE_UNICODE_STRING_SIZE(pOutputBufLenStringUni, 12);
	status = RtlIntegerToUnicodeString(OutputBufferLength, 16, &pOutputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hConfFile);
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	LPWSTR pOutputBufLenString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pOutputBufLenStringUni.Length + 2);
	RtlZeroMemory(pOutputBufLenString, pOutputBufLenStringUni.Length + 2);
	memcpy(pOutputBufLenString, pOutputBufLenStringUni.Buffer, pOutputBufLenStringUni.Length+2);
	wcsncat(confFileString, pOutputBufLenString, pOutputBufLenStringUni.Length+2);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pOutputBufLenString);
	IO_STATUS_BLOCK statBlock;
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString), NULL, NULL);
	ZwClose(hConfFile);
	if (!NT_SUCCESS(status))
	{
		// Error writing file
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	ExFreePool(pObjName);
	ExFreePool(pFullPath);
	goto End;
End:
	// Call original overwritten address
	for (int i = 0; i < fastIoHooksDArrayEntries; i++)
	{
		if (RtlEqualUnicodeString(&fastIoHooksDArray[i].driverName, &drvName, false))
		{
			fastIoCallD origFuncCall = (fastIoCallD)fastIoHooksDArray[i].originalFunction;
			return origFuncCall(FileObject,
				Wait,
				InputBuffer,
				InputBufferLength,
				OutputBuffer,
				OutputBufferLength,
				IoControlCode,
				IoStatus,
				DeviceObject);
		}
	}
	// Oops, cant find original device ioctl address. Return something!
	return false;
}


bool FastIoHookW(IN struct _FILE_OBJECT* FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN BOOLEAN Wait,
	IN ULONG LockKey,
	OUT PVOID Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN struct _DEVICE_OBJECT* DeviceObject)
{
	HANDLE hDataFile = 0;
	NTSTATUS status;
	LPWSTR pathSeperator = L"\\\0\0";
	LPCWSTR nullByteW = L"\0\0";
	UNICODE_STRING drvName = DeviceObject->DriverObject->DriverName;
	LPWSTR pDrvName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, drvName.Length + 2);
	RtlZeroMemory(pDrvName, drvName.Length + 2);
	memcpy(pDrvName, drvName.Buffer + 8, drvName.Length + 1 - 8);
	ULONG nameLen = 0;
	status = ObQueryNameString(DeviceObject, NULL, NULL, &nameLen);
	POBJECT_NAME_INFORMATION pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPoolNx, nameLen + 4);
	status = ObQueryNameString(DeviceObject, pObjName, nameLen + 4, &nameLen);
	if (pObjName->Name.Length == 0)
	{
		ExFreePool(pObjName);
	}
	LPWSTR pDevName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pObjName->Name.Length + 2);
	RtlZeroMemory(pDevName, pObjName->Name.Length + 2);
	// TODO, check if we need to skip bytes
	memcpy(pDevName, pObjName->Name.Buffer, pObjName->Name.Length + 1);
	LPWSTR pCFolder = L"C:\\DriverHooks\\\0\0";
	
	// Careful here with hardcoded buffer copies!
	LPWSTR pFullPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(pFullPath, 2048 * sizeof(WCHAR));
	LPWSTR dosDevicesPath = L"\\DosDevices\\\0\0";
	wcsncpy(pFullPath, dosDevicesPath, 15);
	wcsncat(pFullPath, pCFolder, 16);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pDevName);
		ExFreePool(pFullPath);
		goto End;
	}
	wcsncat(pFullPath, pDrvName, drvName.Length + 1 - 8);
	wcsncat(pFullPath, nullByteW, 1);
	ExFreePool(pDevName);
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{

		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pFullPath);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	LPWSTR hookTypeStr = L"fastIOW\0\0";
	// Concat ioctl string to full path
	wcsncat(pFullPath, pathSeperator, 4);
	wcsncat(pFullPath, hookTypeStr, 10);
	wcsncat(pFullPath, pathSeperator, 4);
	wcsncat(pFullPath, nullByteW, 1);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%s.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pDrvName);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));
	// Convert inputBufLen to LPWSTR
	// Warning again with hardcoded lengths
	DECLARE_UNICODE_STRING_SIZE(pInputBufLenStringUni, 12);
	status = RtlIntegerToUnicodeString(Length, 16, &pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pDrvName);
		goto End;
	}
	LPWSTR pInputBufLenString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pInputBufLenStringUni.Length + 2);
	RtlZeroMemory(pInputBufLenString, pInputBufLenStringUni.Length + 2);
	memcpy(pInputBufLenString, pInputBufLenStringUni.Buffer, pInputBufLenStringUni.Length + 1);
	
	LPWSTR pDataPath = NULL;
	LPWSTR dataTerminator = NULL;
	IO_STATUS_BLOCK statBlock;
	if (Length > 0)
	{
		// Dump memory
		pDataPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
		RtlZeroMemory(pDataPath, 1024 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, pathSeperator, 4);
		wcsncat(pDataPath, pInputBufLenString, pInputBufLenStringUni.Length);
		wcsncat(pDataPath, nullByteW, 1);
		dataTerminator = L".data\0\0";
		wcsncat(pDataPath, dataTerminator, 8);
		// Create handle to pDataPath

		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			ExFreePool(pObjName);
			ExFreePool(pFullPath);
			ExFreePool(pDataPath);
			ExFreePool(pInputBufLenString);
			ExFreePool(pDrvName);
			goto End;
		}
		ExFreePool(pDataPath);

	}

	// Write conf
	LPWSTR pConfPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
	RtlZeroMemory(pConfPath, 1024 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, pathSeperator, 4);
	wcsncat(pConfPath, pInputBufLenString, pInputBufLenStringUni.Length);
	wcsncat(pConfPath, nullByteW, 1);
	LPWSTR confTerminator = L".conf\0\0";
	wcsncat(pConfPath, confTerminator, 8);
	HANDLE hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pConfPath);
		ExFreePool(pInputBufLenString);
		ExFreePool(pDrvName);
		goto End;
	}
	ExFreePool(pConfPath);
	// Write data to pConfFile handle
	LPWSTR confFileString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(confFileString, 2048 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:\0\0";
	wcsncpy(confFileString, drvHeader, 14);
	wcsncat(confFileString, pDrvName, drvName.Length + 1 - 8);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pDrvName);
	LPWSTR newLine = L"\n\0\0";
	wcsncat(confFileString, newLine, 4);
	LPWSTR typeHeader = L"Type:FASTIOW\n\0\0";
	wcsncat(confFileString, typeHeader, 15);
	LPWSTR ioctlHeader = L"IOCTL:\0\0";
	wcsncat(confFileString, ioctlHeader, 9);
	wcsncat(confFileString, nullByteW, 1);
	wcsncat(confFileString, newLine, 4);
	LPWSTR inputLenHeader = L"InputBufferLength:\0\0";
	wcsncat(confFileString, inputLenHeader, 21);
	wcsncat(confFileString, pInputBufLenString, pInputBufLenStringUni.Length + 1);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pInputBufLenString);
	wcsncat(confFileString, newLine, 4);
	LPWSTR outputLenHeader = L"OutputBufferLength:\0\0";
	wcsncat(confFileString, outputLenHeader, 22);
	wcsncat(confFileString, nullByteW, 1);
	
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString), NULL, NULL);
	ZwClose(hConfFile);
	if (!NT_SUCCESS(status))
	{
		// Error writing file
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	ExFreePool(pObjName);
	ExFreePool(pFullPath);
	goto End;
End:
	// Call original overwritten address
	for (int i = 0; i < fastIoHooksWArrayEntries; i++)
	{
		if (RtlEqualUnicodeString(&fastIoHooksWArray[i].driverName, &drvName, false))
		{
			fastIoCallRW origFuncCall = (fastIoCallRW)fastIoHooksWArray[i].originalFunction;
			bool res = origFuncCall(FileObject,
				FileOffset,
				Length,
				Wait,
				LockKey,
				Buffer,
				IoStatus,
				DeviceObject);
			if (hDataFile > 0)
			{
				status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, Buffer, Length, NULL, NULL);
				ZwClose(hDataFile);
			}
			
			return res;
		}

	}
	// Oops, cant find original device ioctl address. Return something!
	return false;
}






bool FastIoHookR(IN struct _FILE_OBJECT* FileObject,
	IN PLARGE_INTEGER FileOffset,
	IN ULONG Length,
	IN BOOLEAN Wait,
	IN ULONG LockKey,
	OUT PVOID Buffer,
	OUT PIO_STATUS_BLOCK IoStatus,
	IN struct _DEVICE_OBJECT* DeviceObject)
{
	HANDLE hDataFile = 0;
	NTSTATUS status;
	LPWSTR pathSeperator = L"\\\0\0";
	LPCWSTR nullByteW = L"\0\0";
	UNICODE_STRING drvName = DeviceObject->DriverObject->DriverName;
	LPWSTR pDrvName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, drvName.Length + 2);
	RtlZeroMemory(pDrvName, drvName.Length + 2);
	memcpy(pDrvName, drvName.Buffer + 8, drvName.Length + 1 - 8);
	ULONG nameLen = 0;
	status = ObQueryNameString(DeviceObject, NULL, NULL, &nameLen);
	POBJECT_NAME_INFORMATION pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPoolNx, nameLen + 4);
	status = ObQueryNameString(DeviceObject, pObjName, nameLen + 4, &nameLen);
	if (pObjName->Name.Length == 0)
	{
		ExFreePool(pObjName);
	}
	LPWSTR pDevName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pObjName->Name.Length + 2);
	RtlZeroMemory(pDevName, pObjName->Name.Length + 2);
	// TODO, check if we need to skip bytes
	memcpy(pDevName, pObjName->Name.Buffer, pObjName->Name.Length + 1);
	LPWSTR pCFolder = L"C:\\DriverHooks\\\0\0";

	// Careful here with hardcoded buffer copies!
	LPWSTR pFullPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(pFullPath, 2048 * sizeof(WCHAR));
	LPWSTR dosDevicesPath = L"\\DosDevices\\\0\0";
	wcsncpy(pFullPath, dosDevicesPath, 15);
	wcsncat(pFullPath, pCFolder, 16);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pDevName);
		ExFreePool(pFullPath);
		goto End;
	}
	wcsncat(pFullPath, pDrvName, drvName.Length + 1 - 8);
	wcsncat(pFullPath, nullByteW, 1);
	ExFreePool(pDevName);
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pFullPath);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	LPWSTR hookTypeStr = L"fastIOR\0\0";
	// Concat ioctl string to full path
	wcsncat(pFullPath, pathSeperator, 4);
	wcsncat(pFullPath, hookTypeStr, 10);
	wcsncat(pFullPath, pathSeperator, 4);
	wcsncat(pFullPath, nullByteW, 1);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%s.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pDrvName);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));
	// Convert inputBufLen to LPWSTR
	// Warning again with hardcoded lengths
	DECLARE_UNICODE_STRING_SIZE(pInputBufLenStringUni, 12);
	status = RtlIntegerToUnicodeString(Length, 16, &pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pDrvName);
		goto End;
	}
	LPWSTR pInputBufLenString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pInputBufLenStringUni.Length + 2);
	RtlZeroMemory(pInputBufLenString, pInputBufLenStringUni.Length + 2);
	memcpy(pInputBufLenString, pInputBufLenStringUni.Buffer, pInputBufLenStringUni.Length + 1);
	
	LPWSTR pDataPath = NULL;
	LPWSTR dataTerminator = NULL;
	IO_STATUS_BLOCK statBlock;
	if (Length > 0)
	{
		// Dump memory
		pDataPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
		RtlZeroMemory(pDataPath, 1024 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, pathSeperator, 4);
		wcsncat(pDataPath, pInputBufLenString, pInputBufLenStringUni.Length);
		wcsncat(pDataPath, nullByteW, 1);
		dataTerminator = L".data\0\0";
		wcsncat(pDataPath, dataTerminator, 8);
		// Create handle to pDataPath
		
		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			ExFreePool(pObjName);
			ExFreePool(pFullPath);
			ExFreePool(pDataPath);
			ExFreePool(pInputBufLenString);
			ExFreePool(pDrvName);
			goto End;
		}
		ExFreePool(pDataPath);
		
	}
	
	// Write conf
	LPWSTR pConfPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
	RtlZeroMemory(pConfPath, 1024 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, pathSeperator, 4);
	wcsncat(pConfPath, pInputBufLenString, pInputBufLenStringUni.Length);
	wcsncat(pConfPath, nullByteW, 1);
	LPWSTR confTerminator = L".conf\0\0";
	wcsncat(pConfPath, confTerminator, 8);
	HANDLE hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pConfPath);
		ExFreePool(pInputBufLenString);
		ExFreePool(pDrvName);
		goto End;
	}
	ExFreePool(pConfPath);
	// Write data to pConfFile handle
	LPWSTR confFileString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(confFileString, 2048 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:\0\0";
	wcsncpy(confFileString, drvHeader, 14);
	wcsncat(confFileString, pDrvName, drvName.Length + 1 - 8);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pDrvName);
	LPWSTR newLine = L"\n\0\0";
	wcsncat(confFileString, newLine, 4);
	LPWSTR typeHeader = L"Type:FASTIOR\n\0\0";
	wcsncat(confFileString, typeHeader, 15);
	LPWSTR ioctlHeader = L"IOCTL:\0\0";
	wcsncat(confFileString, ioctlHeader, 9);
	wcsncat(confFileString, nullByteW, 1);
	wcsncat(confFileString, newLine, 4);
	LPWSTR inputLenHeader = L"InputBufferLength:\0\0";
	wcsncat(confFileString, inputLenHeader, 21);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pInputBufLenString);
	wcsncat(confFileString, newLine, 4);
	LPWSTR outputLenHeader = L"OutputBufferLength:\0\0";
	wcsncat(confFileString, outputLenHeader, 22);

	DECLARE_UNICODE_STRING_SIZE(pOutputBufLenStringUni, 12);
	status = RtlIntegerToUnicodeString(Length, 16, &pOutputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hConfFile);
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	LPWSTR pOutputBufLenString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pOutputBufLenStringUni.Length + 2);
	RtlZeroMemory(pOutputBufLenString, pOutputBufLenStringUni.Length + 2);
	memcpy(pOutputBufLenString, pOutputBufLenStringUni.Buffer, pOutputBufLenStringUni.Length + 1);
	wcsncat(confFileString, pOutputBufLenString, pOutputBufLenStringUni.Length + 1);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pOutputBufLenString);
	
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString), NULL, NULL);
	ZwClose(hConfFile);
	if (!NT_SUCCESS(status))
	{
		// Error writing file
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	ExFreePool(pObjName);
	ExFreePool(pFullPath);
	goto End;
End:
	// Call original overwritten address
	for (int i = 0; i < fastIoHooksRArrayEntries; i++)
	{
		if (RtlEqualUnicodeString(&fastIoHooksRArray[i].driverName, &drvName, false))
		{
			fastIoCallRW origFuncCall = (fastIoCallRW)fastIoHooksRArray[i].originalFunction;
			bool res = origFuncCall(FileObject,
				FileOffset,
				Length,
				Wait,
				LockKey,
				Buffer,
				IoStatus,
				DeviceObject);
			if (hDataFile > 0)
			{
				status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, Buffer, Length, NULL, NULL);
				ZwClose(hDataFile);
			}
			
			return res;
		}
		
	}
	// Oops, cant find original device ioctl address. Return something!
	return false;
}


NTSTATUS DeviceIoHookW(_DEVICE_OBJECT* DeviceObject,
	_IRP* Irp)
{
	HANDLE hDataFile = 0;
	PIO_STACK_LOCATION pIoStackLocation;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status;
	LPWSTR pathSeperator = L"\\\0\0";
	LPCWSTR nullByteW = L"\0\0";
	UNICODE_STRING drvName = DeviceObject->DriverObject->DriverName;
	LPWSTR pDrvName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, drvName.Length + 2);
	RtlZeroMemory(pDrvName, drvName.Length + 2);
	memcpy(pDrvName, drvName.Buffer + 8, drvName.Length + 1 - 8);
	ULONG nameLen = 0;
	status = ObQueryNameString(DeviceObject, NULL, NULL, &nameLen);
	POBJECT_NAME_INFORMATION pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPoolNx, nameLen + 4);
	status = ObQueryNameString(DeviceObject, pObjName, nameLen + 4, &nameLen);
	if (pObjName->Name.Length == 0)
	{
		ExFreePool(pObjName);
	}
	LPWSTR pDevName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pObjName->Name.Length + 2);
	RtlZeroMemory(pDevName, pObjName->Name.Length + 2);
	// TODO, check if we need to skip bytes
	memcpy(pDevName, pObjName->Name.Buffer, pObjName->Name.Length + 1);
	LPWSTR pCFolder = L"C:\\DriverHooks\\\0\0";

	// Careful here with hardcoded buffer copies!
	LPWSTR pFullPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(pFullPath, 2048 * sizeof(WCHAR));
	LPWSTR dosDevicesPath = L"\\DosDevices\\\0\0";
	wcsncpy(pFullPath, dosDevicesPath, 15);
	wcsncat(pFullPath, pCFolder, 16);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pDevName);
		ExFreePool(pFullPath);
		goto End;
	}
	wcsncat(pFullPath, pDrvName, drvName.Length + 1 - 8);
	wcsncat(pFullPath, nullByteW, 1);
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pFullPath);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	LPWSTR hookTypeStr = L"devIOW\0\0";
	// Concat ioctl string to full path
	wcsncat(pFullPath, pathSeperator, 4);
	wcsncat(pFullPath, hookTypeStr, 9);
	wcsncat(pFullPath, pathSeperator, 4);

	wcsncat(pFullPath, nullByteW, 1);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%s.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pDrvName);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));
	// Convert inputBufLen to LPWSTR
	// Warning again with hardcoded lengths
	DECLARE_UNICODE_STRING_SIZE(pInputBufLenStringUni, 12);
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.Write.Length, 16, &pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pDrvName);
		goto End;
	}
	LPWSTR pInputBufLenString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pInputBufLenStringUni.Length + 2);
	RtlZeroMemory(pInputBufLenString, pInputBufLenStringUni.Length + 2);
	memcpy(pInputBufLenString, pInputBufLenStringUni.Buffer, pInputBufLenStringUni.Length + 1);
	
	LPWSTR pDataPath = NULL;
	LPWSTR dataTerminator = NULL;
	IO_STATUS_BLOCK statBlock;
	if (pIoStackLocation->Parameters.Write.Length > 0)
	{
		// Dump memory
		pDataPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
		RtlZeroMemory(pDataPath, 1024 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, pathSeperator, 4);
		wcsncat(pDataPath, pInputBufLenString, pInputBufLenStringUni.Length);
		wcsncat(pDataPath, nullByteW, 1);
		dataTerminator = L".data\0\0";
		wcsncat(pDataPath, dataTerminator, 8);
		// Create handle to pDataPath

		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			ExFreePool(pObjName);
			ExFreePool(pFullPath);
			ExFreePool(pDataPath);
			ExFreePool(pInputBufLenString);
			ExFreePool(pDrvName);
			goto End;
		}
		ExFreePool(pDataPath);

	}

	// Write conf
	LPWSTR pConfPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
	RtlZeroMemory(pConfPath, 1024 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, pathSeperator, 4);
	wcsncat(pConfPath, pInputBufLenString, pInputBufLenStringUni.Length);
	wcsncat(pConfPath, nullByteW, 1);
	LPWSTR confTerminator = L".conf\0\0";
	wcsncat(pConfPath, confTerminator, 8);
	HANDLE hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pConfPath);
		ExFreePool(pInputBufLenString);
		ExFreePool(pDrvName);
		goto End;
	}
	ExFreePool(pConfPath);
	// Write data to pConfFile handle
	LPWSTR confFileString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(confFileString, 2048 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:\0\0";
	wcsncpy(confFileString, drvHeader, 14);
	wcsncat(confFileString, pDrvName, drvName.Length + 1 - 8);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pDrvName);
	LPWSTR newLine = L"\n\0\0";
	wcsncat(confFileString, newLine, 4);
	LPWSTR typeHeader = L"Type:devIOW\n\0\0";
	wcsncat(confFileString, typeHeader, 15);
	LPWSTR ioctlHeader = L"IOCTL:\0\0";
	wcsncat(confFileString, ioctlHeader, 9);
	wcsncat(confFileString, nullByteW, 1);
	wcsncat(confFileString, newLine, 4);
	LPWSTR inputLenHeader = L"InputBufferLength:\0\0";
	wcsncat(confFileString, inputLenHeader, 21);
	wcsncat(confFileString, nullByteW, 1);
	wcsncat(confFileString, pInputBufLenString, pInputBufLenStringUni.Length + 1);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pInputBufLenString);
	wcsncat(confFileString, newLine, 4);
	LPWSTR outputLenHeader = L"OutputBufferLength:\0\0";
	wcsncat(confFileString, outputLenHeader, 22);

	wcsncat(confFileString, nullByteW, 1);
	
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString), NULL, NULL);
	ZwClose(hConfFile);
	if (!NT_SUCCESS(status))
	{
		// Error writing file
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	ExFreePool(pObjName);
	ExFreePool(pFullPath);
	goto End;
End:
	// Call original overwritten address
	for (int i = 0; i < deviceIoHooksRArrayEntries; i++)
	{
		if (RtlEqualUnicodeString(&deviceIoHooksRArray[i].driverName, &drvName, false))
		{
			devIoCallRWD origFuncCall = (devIoCallRWD)deviceIoHooksRArray[i].originalFunction;
			NTSTATUS res = origFuncCall(DeviceObject, Irp);
			if (hDataFile > 0)
			{
				status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, Irp->AssociatedIrp.SystemBuffer, pIoStackLocation->Parameters.Read.Length, NULL, NULL);
				ZwClose(hDataFile);
			}

			return res;
		}

	}
	// Oops, cant find original device ioctl address. Return something!
	return false;
}


NTSTATUS DeviceIoHookR(_DEVICE_OBJECT* DeviceObject,
	_IRP* Irp)
{
	HANDLE hDataFile = 0;
	PIO_STACK_LOCATION pIoStackLocation;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status;
	LPWSTR pathSeperator = L"\\\0\0";
	LPCWSTR nullByteW = L"\0\0";
	UNICODE_STRING drvName = DeviceObject->DriverObject->DriverName;
	LPWSTR pDrvName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, drvName.Length + 2);
	RtlZeroMemory(pDrvName, drvName.Length + 2);
	memcpy(pDrvName, drvName.Buffer + 8, drvName.Length + 1 - 8);
	ULONG nameLen = 0;
	status = ObQueryNameString(DeviceObject, NULL, NULL, &nameLen);
	POBJECT_NAME_INFORMATION pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPoolNx, nameLen + 4);
	status = ObQueryNameString(DeviceObject, pObjName, nameLen + 4, &nameLen);
	if (pObjName->Name.Length == 0)
	{
		ExFreePool(pObjName);
	}
	LPWSTR pDevName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pObjName->Name.Length + 2);
	RtlZeroMemory(pDevName, pObjName->Name.Length + 2);
	// TODO, check if we need to skip bytes
	memcpy(pDevName, pObjName->Name.Buffer, pObjName->Name.Length + 1);
	LPWSTR pCFolder = L"C:\\DriverHooks\\\0\0";

	// Careful here with hardcoded buffer copies!
	LPWSTR pFullPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(pFullPath, 2048 * sizeof(WCHAR));
	LPWSTR dosDevicesPath = L"\\DosDevices\\\0\0";
	wcsncpy(pFullPath, dosDevicesPath, 15);
	wcsncat(pFullPath, pCFolder, 16);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pDevName);
		ExFreePool(pFullPath);
		goto End;
	}
	wcsncat(pFullPath, pDrvName, drvName.Length + 1 - 8);
	wcsncat(pFullPath, nullByteW, 1);
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pFullPath);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	LPWSTR hookTypeStr = L"devIOR\0\0";
	// Concat ioctl string to full path
	wcsncat(pFullPath, pathSeperator, 4);
	wcsncat(pFullPath, hookTypeStr, 10);
	wcsncat(pFullPath, pathSeperator, 4);
	wcsncat(pFullPath, nullByteW, 1);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%s.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pDrvName);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));
	// Convert inputBufLen to LPWSTR
	// Warning again with hardcoded lengths
	DECLARE_UNICODE_STRING_SIZE(pInputBufLenStringUni, 12);
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.Read.Length, 16, &pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pDrvName);
		goto End;
	}
	LPWSTR pInputBufLenString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pInputBufLenStringUni.Length + 2);
	RtlZeroMemory(pInputBufLenString, pInputBufLenStringUni.Length + 2);
	memcpy(pInputBufLenString, pInputBufLenStringUni.Buffer, pInputBufLenStringUni.Length + 1);
	
	LPWSTR pDataPath = NULL;
	LPWSTR dataTerminator = NULL;
	IO_STATUS_BLOCK statBlock;
	if (pIoStackLocation->Parameters.Read.Length > 0)
	{
		// Dump memory
		pDataPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
		RtlZeroMemory(pDataPath, 1024 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, pathSeperator, 4);
		wcsncat(pDataPath, pInputBufLenString, pInputBufLenStringUni.Length);
		wcsncat(pDataPath, nullByteW, 1);
		dataTerminator = L".data\0\0";
		wcsncat(pDataPath, dataTerminator, 8);
		// Create handle to pDataPath

		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			ExFreePool(pObjName);
			ExFreePool(pFullPath);
			ExFreePool(pDataPath);
			ExFreePool(pInputBufLenString);
			ExFreePool(pDrvName);
			goto End;
		}
		ExFreePool(pDataPath);

	}

	// Write conf
	LPWSTR pConfPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
	RtlZeroMemory(pConfPath, 1024 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, pathSeperator, 4);
	wcsncat(pConfPath, pInputBufLenString, pInputBufLenStringUni.Length);
	wcsncat(pConfPath, nullByteW, 1);
	LPWSTR confTerminator = L".conf\0\0";
	wcsncat(pConfPath, confTerminator, 8);
	HANDLE hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pConfPath);
		ExFreePool(pInputBufLenString);
		ExFreePool(pDrvName);
		goto End;
	}
	ExFreePool(pConfPath);
	// Write data to pConfFile handle
	LPWSTR confFileString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(confFileString, 2048 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:\0\0";
	wcsncpy(confFileString, drvHeader, 14);
	wcsncat(confFileString, pDrvName, drvName.Length + 1 - 8);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pDrvName);
	LPWSTR newLine = L"\n\0\0";
	wcsncat(confFileString, newLine, 4);
	LPWSTR typeHeader = L"Type:devIOR\n\0\0";
	wcsncat(confFileString, typeHeader, 15);
	LPWSTR ioctlHeader = L"IOCTL:\0\0";
	wcsncat(confFileString, ioctlHeader, 9);
	wcsncat(confFileString, nullByteW, 1);
	wcsncat(confFileString, newLine, 4);
	LPWSTR inputLenHeader = L"InputBufferLength:\0\0";
	wcsncat(confFileString, inputLenHeader, 21);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pInputBufLenString);
	wcsncat(confFileString, newLine, 4);
	LPWSTR outputLenHeader = L"OutputBufferLength:\0\0";
	wcsncat(confFileString, outputLenHeader, 22);

	DECLARE_UNICODE_STRING_SIZE(pOutputBufLenStringUni, 12);
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.Read.Length, 16, &pOutputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hConfFile);
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	LPWSTR pOutputBufLenString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pOutputBufLenStringUni.Length + 2);
	RtlZeroMemory(pOutputBufLenString, pOutputBufLenStringUni.Length + 2);
	memcpy(pOutputBufLenString, pOutputBufLenStringUni.Buffer, pOutputBufLenStringUni.Length + 1);
	wcsncat(confFileString, pOutputBufLenString, pOutputBufLenStringUni.Length + 1);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pOutputBufLenString);

	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString), NULL, NULL);
	ZwClose(hConfFile);
	if (!NT_SUCCESS(status))
	{
		// Error writing file
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	ExFreePool(pObjName);
	ExFreePool(pFullPath);
	goto End;
End:
	// Call original overwritten address
	for (int i = 0; i < deviceIoHooksRArrayEntries; i++)
	{
		if (RtlEqualUnicodeString(&deviceIoHooksRArray[i].driverName, &drvName, false))
		{
			devIoCallRWD origFuncCall = (devIoCallRWD)deviceIoHooksRArray[i].originalFunction;
			NTSTATUS res = origFuncCall(DeviceObject,Irp);
			if (hDataFile > 0)
			{
				status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, Irp->AssociatedIrp.SystemBuffer, pIoStackLocation->Parameters.Read.Length, NULL, NULL);
				ZwClose(hDataFile);
			}
			
			return res;
		}

	}
	// Oops, cant find original device ioctl address. Return something!
	return false;
}

NTSTATUS DeviceIoHookD(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	PVOID inBuf;
	PVOID outBuf;
	NTSTATUS status;
	LPWSTR pathSeperator = L"\\\0\0";
	LPCWSTR nullByteW = L"\0\0";
	UNICODE_STRING drvName = pDeviceObject->DriverObject->DriverName;
	LPWSTR pDrvName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, drvName.Length + 2);
	RtlZeroMemory(pDrvName, drvName.Length + 2);
	memcpy(pDrvName, drvName.Buffer + 8, drvName.Length + 1 - 8);
	ULONG nameLen = 0;
	status = ObQueryNameString(pDeviceObject, NULL, NULL, &nameLen);
	POBJECT_NAME_INFORMATION pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPoolNx, nameLen + 4);
	status = ObQueryNameString(pDeviceObject, pObjName, nameLen + 4, &nameLen);
	if (pObjName->Name.Length == 0)
	{
		ExFreePool(pObjName);
	}

	LPWSTR pDevName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pObjName->Name.Length + 2);
	RtlZeroMemory(pDevName, pObjName->Name.Length + 2);
	// TODO, check if we need to skip bytes
	memcpy(pDevName, pObjName->Name.Buffer, pObjName->Name.Length + 1);
	LPWSTR pCFolder = L"C:\\DriverHooks\\\0\0";

	// Careful here with hardcoded buffer copies!
	LPWSTR pFullPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(pFullPath, 2048 * sizeof(WCHAR));
	LPWSTR dosDevicesPath = L"\\DosDevices\\\0\0";
	wcsncpy(pFullPath, dosDevicesPath, 15);
	wcsncat(pFullPath, pCFolder, 16);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pDevName);
		ExFreePool(pFullPath);
		goto End;
	}
	wcsncat(pFullPath, pDrvName, drvName.Length + 1 - 8);
	wcsncat(pFullPath, nullByteW, 1);
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pFullPath);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	// Convert IOCTL to LPWSTR
	// Warning again with hardcoded lengths
	DECLARE_UNICODE_STRING_SIZE(pIoctlStringUni, 12);
	PIO_STACK_LOCATION pIoStackLocation;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode, 16, &pIoctlStringUni);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	switch (METHOD_FROM_CTL_CODE(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode))
	{
	case METHOD_BUFFERED:
		inBuf = Irp->AssociatedIrp.SystemBuffer; outBuf = Irp->AssociatedIrp.SystemBuffer; break;
	case METHOD_IN_DIRECT:
		inBuf = Irp->AssociatedIrp.SystemBuffer; outBuf = Irp->MdlAddress; break;
	case METHOD_OUT_DIRECT:
		inBuf = Irp->AssociatedIrp.SystemBuffer; outBuf = Irp->MdlAddress; break;
	case METHOD_NEITHER:
		inBuf = pIoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer; outBuf = Irp->UserBuffer; break;
	default:
		ExFreePool(pObjName); ExFreePool(pFullPath); goto End;
	}
	LPWSTR pIoctlString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pIoctlStringUni.Length + 2);
	RtlZeroMemory(pIoctlString, pIoctlStringUni.Length + 2);
	memcpy(pIoctlString, pIoctlStringUni.Buffer, pIoctlStringUni.Length + 1);
	LPWSTR hookTypeStr = L"devIOD\0\0";
	// Concat ioctl string to full path
	wcsncat(pFullPath, pathSeperator, 4);
	wcsncat(pFullPath, hookTypeStr, 9);
	wcsncat(pFullPath, pathSeperator, 4);
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pIoctlString);
		ExFreePool(pDrvName);
		goto End;
	}
	wcsncat(pFullPath, pIoctlString, pIoctlStringUni.Length);
	wcsncat(pFullPath, nullByteW, 1);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%s.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pIoctlString);
		ExFreePool(pDrvName);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));
	// Convert inputBufLen to LPWSTR
	// Warning again with hardcoded lengths
	DECLARE_UNICODE_STRING_SIZE(pInputBufLenStringUni, 12);
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength, 16, &pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pDrvName);
		ExFreePool(pIoctlString);
		goto End;
	}
	LPWSTR pInputBufLenString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pInputBufLenStringUni.Length + 2);
	RtlZeroMemory(pInputBufLenString, pInputBufLenStringUni.Length + 2);
	memcpy(pInputBufLenString, pInputBufLenStringUni.Buffer, pInputBufLenStringUni.Length + 1);
	if (pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength > 0)
	{
		// Dump memory
		LPWSTR pDataPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
		RtlZeroMemory(pDataPath, 1024 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, pathSeperator, 4);
		wcsncat(pDataPath, pInputBufLenString, pInputBufLenStringUni.Length);
		wcsncat(pDataPath, nullByteW, 1);
		LPWSTR dataTerminator = L".data\0\0";
		wcsncat(pDataPath, dataTerminator, 8);
		// Create handle to pDataPath
		HANDLE hDataFile = 0;
		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			ExFreePool(pObjName);
			ExFreePool(pFullPath);
			ExFreePool(pDataPath);
			ExFreePool(pInputBufLenString);
			ExFreePool(pDrvName);
			ExFreePool(pIoctlString);
			goto End;
		}
		ExFreePool(pDataPath);
		// Write data to pDataFile handle
		IO_STATUS_BLOCK statBlock;
		status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, inBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength, NULL, NULL);

		ZwClose(hDataFile);
		if (!NT_SUCCESS(status))
		{
			// Error writing file
			ExFreePool(pObjName);
			ExFreePool(pFullPath);
			ExFreePool(pInputBufLenString);
			ExFreePool(pDrvName);
			ExFreePool(pIoctlString);
			goto End;
		}
	}
	// Write conf
	LPWSTR pConfPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
	RtlZeroMemory(pConfPath, 1024 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, pathSeperator, 4);
	wcsncat(pConfPath, pInputBufLenString, pInputBufLenStringUni.Length);
	wcsncat(pConfPath, nullByteW, 1);
	LPWSTR confTerminator = L".conf\0\0";
	wcsncat(pConfPath, confTerminator, 8);
	HANDLE hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pConfPath);
		ExFreePool(pInputBufLenString);
		ExFreePool(pDrvName);
		ExFreePool(pIoctlString);
		goto End;
	}
	ExFreePool(pConfPath);
	// Write data to pConfFile handle
	LPWSTR confFileString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(confFileString, 2048 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:\0\0";
	wcsncpy(confFileString, drvHeader, 14);
	wcsncat(confFileString, pDrvName, drvName.Length + 1 - 8);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pDrvName);
	LPWSTR newLine = L"\n\0\0";
	wcsncat(confFileString, newLine, 4);
	LPWSTR typeHeader = L"Type:devIOD\n\0\0";
	wcsncat(confFileString, typeHeader, 15);
	LPWSTR type2Header = L"BuffType:\0\0";
	LPWSTR buffHeader = L"METHOD_BUFFERED\n\0\0";
	LPWSTR inDir = L"METHOD_IN_DIRECT\n\0\0";
	LPWSTR outDir = L"METHOD_OUT_DIRECT\n\0\0";
	LPWSTR neiDir = L"METHOD_NEITHER\n\0\0";
	wcsncat(confFileString, type2Header, 12);
	switch (METHOD_FROM_CTL_CODE(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode))
	{
	case METHOD_BUFFERED:
		wcsncat(confFileString, buffHeader, 19); break;
	case METHOD_IN_DIRECT:
		wcsncat(confFileString, inDir, 20); break;
	case METHOD_OUT_DIRECT:
		wcsncat(confFileString, outDir, 21); break;
	case METHOD_NEITHER:
		wcsncat(confFileString, neiDir, 18); break;
	default:
		break;
	}
	LPWSTR ioctlHeader = L"IOCTL:\0\0";
	wcsncat(confFileString, ioctlHeader, 9);
	wcsncat(confFileString, pIoctlString, pIoctlStringUni.Length + 1);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pIoctlString);
	wcsncat(confFileString, newLine, 4);
	LPWSTR inputLenHeader = L"InputBufferLength:\0\0";
	wcsncat(confFileString, inputLenHeader, 21);
	wcsncat(confFileString, pInputBufLenString, pInputBufLenStringUni.Length + 1);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pInputBufLenString);
	wcsncat(confFileString, newLine, 4);
	LPWSTR outputLenHeader = L"OutputBufferLength:\0\0";
	wcsncat(confFileString, outputLenHeader, 22);

	DECLARE_UNICODE_STRING_SIZE(pOutputBufLenStringUni, 12);
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength, 16, &pOutputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hConfFile);
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	LPWSTR pOutputBufLenString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pOutputBufLenStringUni.Length + 2);
	RtlZeroMemory(pOutputBufLenString, pOutputBufLenStringUni.Length + 2);
	memcpy(pOutputBufLenString, pOutputBufLenStringUni.Buffer, pOutputBufLenStringUni.Length + 1);
	wcsncat(confFileString, pOutputBufLenString, pOutputBufLenStringUni.Length + 1);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pOutputBufLenString);
	IO_STATUS_BLOCK statBlock;
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString), NULL, NULL);
	ZwClose(hConfFile);
	if (!NT_SUCCESS(status))
	{
		// Error writing file
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	ExFreePool(pObjName);
	ExFreePool(pFullPath);
	goto End;
End:
	// Call original overwritten address
	for (int i = 0; i < deviceIoHooksDArrayEntries; i++)
	{
		if (RtlEqualUnicodeString(&deviceIoHooksDArray[i].driverName, &drvName, false))
		{
			devIoCallRWD origFuncCall = (devIoCallRWD)deviceIoHooksDArray[i].originalFunction;
			return origFuncCall(pDeviceObject,Irp);
		}
	}
	// Oops, cant find original device ioctl address. Return something!
	return false;
}


NTSTATUS FileIoHookD(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	PVOID inBuf;
	PVOID outBuf;
	NTSTATUS status;
	LPWSTR pathSeperator = L"\\\0\0";
	LPCWSTR nullByteW = L"\0\0";
	UNICODE_STRING drvName = pDeviceObject->DriverObject->DriverName;
	LPWSTR pDrvName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, drvName.Length + 2);
	RtlZeroMemory(pDrvName, drvName.Length + 2);
	memcpy(pDrvName, drvName.Buffer + 8, drvName.Length + 1 - 8);
	ULONG nameLen = 0;
	status = ObQueryNameString(pDeviceObject, NULL, NULL, &nameLen);
	POBJECT_NAME_INFORMATION pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPoolNx, nameLen + 4);
	status = ObQueryNameString(pDeviceObject, pObjName, nameLen + 4, &nameLen);
	if (pObjName->Name.Length == 0)
	{
		ExFreePool(pObjName);
	}
	LPWSTR pDevName = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pObjName->Name.Length + 2);
	RtlZeroMemory(pDevName, pObjName->Name.Length + 2);
	// TODO, check if we need to skip bytes
	memcpy(pDevName, pObjName->Name.Buffer, pObjName->Name.Length + 1);
	LPWSTR pCFolder = L"C:\\DriverHooks\\\0\0";

	// Careful here with hardcoded buffer copies!
	LPWSTR pFullPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(pFullPath, 2048 * sizeof(WCHAR));
	LPWSTR dosDevicesPath = L"\\DosDevices\\\0\0";
	wcsncpy(pFullPath, dosDevicesPath, 15);
	wcsncat(pFullPath, pCFolder, 16);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pDevName);
		ExFreePool(pFullPath);
		goto End;
	}
	wcsncat(pFullPath, pDrvName, drvName.Length + 1 - 8);
	wcsncat(pFullPath, nullByteW, 1);
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pDrvName);
		ExFreePool(pFullPath);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	// Convert IOCTL to LPWSTR
	// Warning again with hardcoded lengths
	DECLARE_UNICODE_STRING_SIZE(pIoctlStringUni, 12);
	PIO_STACK_LOCATION pIoStackLocation;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode, 16, &pIoctlStringUni);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	switch (METHOD_FROM_CTL_CODE(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode))
	{
	case METHOD_BUFFERED:
		inBuf = Irp->AssociatedIrp.SystemBuffer; outBuf = Irp->AssociatedIrp.SystemBuffer; break;
	case METHOD_IN_DIRECT:
		inBuf = Irp->AssociatedIrp.SystemBuffer; outBuf = Irp->MdlAddress; break;
	case METHOD_OUT_DIRECT:
		inBuf = Irp->AssociatedIrp.SystemBuffer; outBuf = Irp->MdlAddress; break;
	case METHOD_NEITHER:
		inBuf = pIoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer; outBuf = Irp->UserBuffer; break;
	default:
		ExFreePool(pObjName); ExFreePool(pFullPath); goto End;
	}
	LPWSTR pIoctlString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pIoctlStringUni.Length + 2);
	RtlZeroMemory(pIoctlString, pIoctlStringUni.Length + 2);
	memcpy(pIoctlString, pIoctlStringUni.Buffer, pIoctlStringUni.Length + 1);
	LPWSTR hookTypeStr = L"fileIOD\0\0";
	// Concat ioctl string to full path
	wcsncat(pFullPath, pathSeperator, 4);
	wcsncat(pFullPath, hookTypeStr, 10);
	wcsncat(pFullPath, pathSeperator, 4);
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pIoctlString);
		ExFreePool(pDrvName);
		goto End;
	}
	wcsncat(pFullPath, pIoctlString, pIoctlStringUni.Length);
	wcsncat(pFullPath, nullByteW, 1);
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%s.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pIoctlString);
		ExFreePool(pDrvName);
		goto End;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));
	// Convert inputBufLen to LPWSTR
	// Warning again with hardcoded lengths
	DECLARE_UNICODE_STRING_SIZE(pInputBufLenStringUni, 12);
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength, 16, &pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pDrvName);
		ExFreePool(pIoctlString);
		goto End;
	}
	LPWSTR pInputBufLenString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pInputBufLenStringUni.Length + 2);
	RtlZeroMemory(pInputBufLenString, pInputBufLenStringUni.Length + 2);
	memcpy(pInputBufLenString, pInputBufLenStringUni.Buffer, pInputBufLenStringUni.Length + 1);
	if (pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength > 0)
	{
		// Dump memory
		LPWSTR pDataPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
		RtlZeroMemory(pDataPath, 1024 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, pathSeperator, 4);
		wcsncat(pDataPath, pInputBufLenString, pInputBufLenStringUni.Length);
		wcsncat(pDataPath, nullByteW, 1);
		LPWSTR dataTerminator = L".data\0\0";
		wcsncat(pDataPath, dataTerminator, 8);
		// Create handle to pDataPath
		HANDLE hDataFile = 0;
		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			ExFreePool(pObjName);
			ExFreePool(pFullPath);
			ExFreePool(pDataPath);
			ExFreePool(pInputBufLenString);
			ExFreePool(pDrvName);
			ExFreePool(pIoctlString);
			goto End;
		}
		ExFreePool(pDataPath);
		// Write data to pDataFile handle
		IO_STATUS_BLOCK statBlock;
		status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, inBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength, NULL, NULL);

		ZwClose(hDataFile);
		if (!NT_SUCCESS(status))
		{
			// Error writing file
			ExFreePool(pObjName);
			ExFreePool(pFullPath);
			ExFreePool(pInputBufLenString);
			ExFreePool(pDrvName);
			ExFreePool(pIoctlString);
			goto End;
		}
	}
	// Write conf
	LPWSTR pConfPath = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 1024 * sizeof(WCHAR));
	RtlZeroMemory(pConfPath, 1024 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, pathSeperator, 4);
	wcsncat(pConfPath, pInputBufLenString, pInputBufLenStringUni.Length);
	wcsncat(pConfPath, nullByteW, 1);
	LPWSTR confTerminator = L".conf\0\0";
	wcsncat(pConfPath, confTerminator, 8);
	HANDLE hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		ExFreePool(pConfPath);
		ExFreePool(pInputBufLenString);
		ExFreePool(pDrvName);
		ExFreePool(pIoctlString);
		goto End;
	}
	ExFreePool(pConfPath);
	// Write data to pConfFile handle
	LPWSTR confFileString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, 2048 * sizeof(WCHAR));
	RtlZeroMemory(confFileString, 2048 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:\0\0";
	wcsncpy(confFileString, drvHeader, 14);
	wcsncat(confFileString, pDrvName, drvName.Length + 1 - 8);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pDrvName);
	LPWSTR newLine = L"\n\0\0";
	wcsncat(confFileString, newLine, 4);
	LPWSTR typeHeader = L"Type:devIOD\n\0\0";
	wcsncat(confFileString, typeHeader, 15);
	LPWSTR type2Header = L"BuffType:\0\0";
	LPWSTR buffHeader = L"METHOD_BUFFERED\n\0\0";
	LPWSTR inDir = L"METHOD_IN_DIRECT\n\0\0";
	LPWSTR outDir = L"METHOD_OUT_DIRECT\n\0\0";
	LPWSTR neiDir = L"METHOD_NEITHER\n\0\0";
	wcsncat(confFileString, type2Header, 12);
	switch (METHOD_FROM_CTL_CODE(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode))
	{
	case METHOD_BUFFERED:
		wcsncat(confFileString, buffHeader, 19); break;
	case METHOD_IN_DIRECT:
		wcsncat(confFileString, inDir, 20); break;
	case METHOD_OUT_DIRECT:
		wcsncat(confFileString, outDir, 21); break;
	case METHOD_NEITHER:
		wcsncat(confFileString, neiDir, 18); break;
	default:
		break;
	}
	LPWSTR ioctlHeader = L"IOCTL:\0\0";
	wcsncat(confFileString, ioctlHeader, 9);
	wcsncat(confFileString, pIoctlString, pIoctlStringUni.Length + 1);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pIoctlString);
	wcsncat(confFileString, newLine, 4);
	LPWSTR inputLenHeader = L"InputBufferLength:\0\0";
	wcsncat(confFileString, inputLenHeader, 21);
	wcsncat(confFileString, pInputBufLenString, pInputBufLenStringUni.Length + 1);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pInputBufLenString);
	wcsncat(confFileString, newLine, 4);
	LPWSTR outputLenHeader = L"OutputBufferLength:\0\0";
	wcsncat(confFileString, outputLenHeader, 22);

	DECLARE_UNICODE_STRING_SIZE(pOutputBufLenStringUni, 12);
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength, 16, &pOutputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		ZwClose(hConfFile);
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	LPWSTR pOutputBufLenString = (LPWSTR)ExAllocatePool(NonPagedPoolNx, pOutputBufLenStringUni.Length + 2);
	RtlZeroMemory(pOutputBufLenString, pOutputBufLenStringUni.Length + 2);
	memcpy(pOutputBufLenString, pOutputBufLenStringUni.Buffer, pOutputBufLenStringUni.Length + 1);
	wcsncat(confFileString, pOutputBufLenString, pOutputBufLenStringUni.Length + 1);
	wcsncat(confFileString, nullByteW, 1);
	ExFreePool(pOutputBufLenString);
	IO_STATUS_BLOCK statBlock;
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString), NULL, NULL);
	ZwClose(hConfFile);
	if (!NT_SUCCESS(status))
	{
		// Error writing file
		ExFreePool(pObjName);
		ExFreePool(pFullPath);
		goto End;
	}
	ExFreePool(pObjName);
	ExFreePool(pFullPath);
	goto End;
End:
	// Call original overwritten address
	for (int i = 0; i < deviceIoHooksDArrayEntries; i++)
	{
		if (RtlEqualUnicodeString(&deviceIoHooksDArray[i].driverName, &drvName, false))
		{
			devIoCallRWD origFuncCall = (devIoCallRWD)deviceIoHooksDArray[i].originalFunction;
			return origFuncCall(pDeviceObject, Irp);
		}
	}
	// Oops, cant find original device ioctl address. Return something!
	return false;
}







// TODO > Check if hook already exists
NTSTATUS AddFastIOHookD(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{
	
	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;
	if (fastIoHooksDArray == NULL)
	{
		int tmpLen = 20;
		fastIoHooksDArray = (IoHooks*)ExAllocatePool(NonPagedPoolNx, tmpLen*sizeof(IoHooks));
		RtlZeroMemory(fastIoHooksDArray, tmpLen * sizeof(IoHooks));
		fastIoHooksDArrayLen = tmpLen;
	}
	else if (fastIoHooksDArrayLen == (fastIoHooksDArrayEntries - 1))
	{
		ULONGLONG newLen = fastIoHooksDArrayLen + 20;
		IoHooks* tmpArr = (IoHooks*)ExAllocatePool(NonPagedPoolNx, newLen);
		RtlZeroMemory(tmpArr, newLen);
		memcpy(tmpArr, fastIoHooksDArray, fastIoHooksDArrayLen);
		ExFreePool(fastIoHooksDArray);
		fastIoHooksDArray = tmpArr;
		fastIoHooksDArrayLen = newLen;
	}
	fastIoHooksDArray[fastIoHooksDArrayEntries] = newHook;
	fastIoHooksDArrayEntries += 1;
	*originalFunc = hookDumpFunc;
	return STATUS_SUCCESS;
}

// TODO > Check if hook already exists
NTSTATUS AddFastIOHookR(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{

	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;
	if (fastIoHooksRArray == NULL)
	{
		int tmpLen = 20;
		fastIoHooksRArray = (IoHooks*)ExAllocatePool(NonPagedPoolNx, tmpLen * sizeof(IoHooks));
		RtlZeroMemory(fastIoHooksRArray, tmpLen * sizeof(IoHooks));
		fastIoHooksRArrayLen = tmpLen;
	}
	else if (fastIoHooksRArrayLen == (fastIoHooksRArrayEntries - 1))
	{
		ULONGLONG newLen = fastIoHooksRArrayLen + 20;
		IoHooks* tmpArr = (IoHooks*)ExAllocatePool(NonPagedPoolNx, newLen);
		RtlZeroMemory(tmpArr, newLen);
		memcpy(tmpArr, fastIoHooksRArray, fastIoHooksRArrayLen);
		ExFreePool(fastIoHooksRArray);
		fastIoHooksRArray = tmpArr;
		fastIoHooksRArrayLen = newLen;
	}
	fastIoHooksRArray[fastIoHooksRArrayEntries] = newHook;
	fastIoHooksRArrayEntries += 1;
	*originalFunc = hookDumpFunc;
	return STATUS_SUCCESS;
}


// TODO > Check if hook already exists
NTSTATUS AddFastIOHookW(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{

	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;
	if (fastIoHooksWArray == NULL)
	{
		int tmpLen = 20;
		fastIoHooksWArray = (IoHooks*)ExAllocatePool(NonPagedPoolNx, tmpLen * sizeof(IoHooks));
		RtlZeroMemory(fastIoHooksWArray, tmpLen * sizeof(IoHooks));
		fastIoHooksWArrayLen = tmpLen;
	}
	else if (fastIoHooksWArrayLen == (fastIoHooksWArrayEntries - 1))
	{
		ULONGLONG newLen = fastIoHooksWArrayLen + 20;
		IoHooks* tmpArr = (IoHooks*)ExAllocatePool(NonPagedPoolNx, newLen);
		RtlZeroMemory(tmpArr, newLen);
		memcpy(tmpArr, fastIoHooksWArray, fastIoHooksWArrayLen);
		ExFreePool(fastIoHooksWArray);
		fastIoHooksWArray = tmpArr;
		fastIoHooksWArrayLen = newLen;
	}
	fastIoHooksWArray[fastIoHooksWArrayEntries] = newHook;
	fastIoHooksWArrayEntries += 1;
	*originalFunc = hookDumpFunc;
	return STATUS_SUCCESS;
}

// TODO > Check if hook already exists
NTSTATUS AddDeviceIOHookD(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{

	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;
	if (deviceIoHooksDArray == NULL)
	{
		int tmpLen = 20;
		deviceIoHooksDArray = (IoHooks*)ExAllocatePool(NonPagedPoolNx, tmpLen * sizeof(IoHooks));
		RtlZeroMemory(deviceIoHooksDArray, tmpLen * sizeof(IoHooks));
		deviceIoHooksDArrayLen = tmpLen;
	}
	else if (deviceIoHooksDArrayLen == (deviceIoHooksDArrayEntries - 1))
	{
		ULONGLONG newLen = deviceIoHooksDArrayLen + 20;
		IoHooks* tmpArr = (IoHooks*)ExAllocatePool(NonPagedPoolNx, newLen);
		RtlZeroMemory(tmpArr, newLen);
		memcpy(tmpArr, deviceIoHooksDArray, deviceIoHooksDArrayLen);
		ExFreePool(deviceIoHooksDArray);
		deviceIoHooksDArray = tmpArr;
		deviceIoHooksDArrayLen = newLen;
	}
	deviceIoHooksDArray[deviceIoHooksDArrayEntries] = newHook;
	deviceIoHooksDArrayEntries += 1;
	*originalFunc = hookDumpFunc;
	return STATUS_SUCCESS;
}

// TODO > Check if hook already exists
NTSTATUS AddDeviceIOHookR(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{

	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;
	if (deviceIoHooksRArray == NULL)
	{
		int tmpLen = 20;
		deviceIoHooksRArray = (IoHooks*)ExAllocatePool(NonPagedPoolNx, tmpLen * sizeof(IoHooks));
		RtlZeroMemory(deviceIoHooksRArray, tmpLen * sizeof(IoHooks));
		deviceIoHooksRArrayLen = tmpLen;
	}
	else if (deviceIoHooksRArrayLen == (deviceIoHooksRArrayEntries - 1))
	{
		ULONGLONG newLen = deviceIoHooksRArrayLen + 20;
		IoHooks* tmpArr = (IoHooks*)ExAllocatePool(NonPagedPoolNx, newLen);
		RtlZeroMemory(tmpArr, newLen);
		memcpy(tmpArr, deviceIoHooksRArray, deviceIoHooksRArrayLen);
		ExFreePool(deviceIoHooksRArray);
		deviceIoHooksRArray = tmpArr;
		deviceIoHooksRArrayLen = newLen;
	}
	deviceIoHooksRArray[deviceIoHooksRArrayEntries] = newHook;
	deviceIoHooksRArrayEntries += 1;
	*originalFunc = hookDumpFunc;
	return STATUS_SUCCESS;
}

// TODO > Check if hook already exists
NTSTATUS AddDeviceIOHookW(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{

	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;
	if (deviceIoHooksWArray == NULL)
	{
		int tmpLen = 20;
		deviceIoHooksWArray = (IoHooks*)ExAllocatePool(NonPagedPoolNx, tmpLen * sizeof(IoHooks));
		RtlZeroMemory(deviceIoHooksWArray, tmpLen * sizeof(IoHooks));
		deviceIoHooksWArrayLen = tmpLen;
	}
	else if (deviceIoHooksWArrayLen == (deviceIoHooksWArrayEntries - 1))
	{
		ULONGLONG newLen = deviceIoHooksWArrayLen + 20;
		IoHooks* tmpArr = (IoHooks*)ExAllocatePool(NonPagedPoolNx, newLen);
		RtlZeroMemory(tmpArr, newLen);
		memcpy(tmpArr, deviceIoHooksWArray, deviceIoHooksWArrayLen);
		ExFreePool(deviceIoHooksWArray);
		deviceIoHooksWArray = tmpArr;
		deviceIoHooksWArrayLen = newLen;
	}
	deviceIoHooksWArray[deviceIoHooksWArrayEntries] = newHook;
	deviceIoHooksWArrayEntries += 1;
	*originalFunc = hookDumpFunc;
	return STATUS_SUCCESS;
}

// TODO > Check if hook already exists
NTSTATUS AddFileIOHookD(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{

	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;
	if (fileIoHooksDArray == NULL)
	{
		int tmpLen = 20;
		fileIoHooksDArray = (IoHooks*)ExAllocatePool(NonPagedPoolNx, tmpLen * sizeof(IoHooks));
		RtlZeroMemory(fileIoHooksDArray, tmpLen * sizeof(IoHooks));
		fileIoHooksDArrayLen = tmpLen;
	}
	else if (fileIoHooksDArrayLen == (fileIoHooksDArrayEntries - 1))
	{
		ULONGLONG newLen = fileIoHooksDArrayLen + 20;
		IoHooks* tmpArr = (IoHooks*)ExAllocatePool(NonPagedPoolNx, newLen);
		RtlZeroMemory(tmpArr, newLen);
		memcpy(tmpArr, fileIoHooksDArray, fileIoHooksDArrayLen);
		ExFreePool(fileIoHooksDArray);
		fileIoHooksDArray = tmpArr;
		fileIoHooksDArrayLen = newLen;
	}
	fileIoHooksDArray[fileIoHooksDArrayEntries] = newHook;
	fileIoHooksDArrayEntries += 1;
	*originalFunc = hookDumpFunc;
	return STATUS_SUCCESS;
}


NTSTATUS DoManualHook(PVOID* address, short type, UNICODE_STRING driverName)
{
	NTSTATUS status;
	PVOID hookDumpFunc;
	PVOID* originalFunc = address;
	switch (type)
	{
	case TYPE_FASTIOD:
		hookDumpFunc = FastIoHookD; status = AddFastIOHookD(originalFunc, hookDumpFunc, driverName); break;
	case TYPE_FASTIOR:
		hookDumpFunc = FastIoHookR; status = AddFastIOHookR(originalFunc, hookDumpFunc, driverName); break;
	case TYPE_FASTIOW:
		hookDumpFunc = FastIoHookW; status = AddFastIOHookW(originalFunc, hookDumpFunc, driverName); break;
	case TYPE_DEVICEIOD:
		hookDumpFunc = DeviceIoHookD; status = AddDeviceIOHookD(originalFunc, hookDumpFunc, driverName); break;
	case TYPE_DEVICEIOR:
		hookDumpFunc = DeviceIoHookR; status = AddDeviceIOHookR(originalFunc, hookDumpFunc, driverName); break;
	case TYPE_DEVICEIOW:
		hookDumpFunc = DeviceIoHookW; status = AddDeviceIOHookW(originalFunc, hookDumpFunc, driverName); break;
	case TYPE_FILEIOD:
		hookDumpFunc = FileIoHookD; status = AddFileIOHookD(originalFunc, hookDumpFunc, driverName); break;
	default:
		return STATUS_INVALID_PARAMETER;
	}

	return status;

}

// Uses offsets, lets hope they dont change. Or add version checks
NTSTATUS DoAutoHook(UNICODE_STRING driverName)
{
	NTSTATUS status;
	PFILE_OBJECT phFile = NULL;
	PDEVICE_OBJECT phDev = NULL;

	status = IoGetDeviceObjectPointer(&driverName, FILE_ALL_ACCESS, &phFile, &phDev);
	if (!NT_SUCCESS(status))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Error: Failed to find driver:%wZ. ",driverName));
		switch (status)
		{
		case STATUS_OBJECT_TYPE_MISMATCH:
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "STATUS_OBJECT_TYPE_MISMATCH.\n")); break;
		case STATUS_INVALID_PARAMETER:
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "STATUS_INVALID_PARAMETER.\n")); break;
		case STATUS_PRIVILEGE_NOT_HELD:
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "STATUS_PRIVILEGE_NOT_HELD.\n")); break;
		case STATUS_INSUFFICIENT_RESOURCES:
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "STATUS_INSUFFICIENT_RESOURCES.\n")); break;
		case STATUS_OBJECT_NAME_INVALID:
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "STATUS_OBJECT_NAME_INVALID.\n")); break;
		default:
			KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Unknown error:%x.\n", status)); break;
		}
		
		return status;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Info: Attempting to hook:%wZ.\n", driverName));
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Info: Device object:%p\n. ", phDev));
	PDRIVER_OBJECT phDriv = phDev->DriverObject;
	PFAST_IO_DISPATCH fastIoDispatch = phDriv->FastIoDispatch;
	if (fastIoDispatch != NULL)
	{
		status = DoManualHook((PVOID*)&fastIoDispatch->FastIoDeviceControl, TYPE_FASTIOD, phDriv->DriverName);
		status = DoManualHook((PVOID*)&fastIoDispatch->FastIoRead, TYPE_FASTIOR, phDriv->DriverName);
		status = DoManualHook((PVOID*)&fastIoDispatch->FastIoWrite, TYPE_FASTIOW, phDriv->DriverName);
	}
	
	status = DoManualHook((PVOID*)&phDriv->MajorFunction[IRP_MJ_DEVICE_CONTROL], TYPE_DEVICEIOD, phDriv->DriverName);
	status = DoManualHook((PVOID*)&phDriv->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL], TYPE_FILEIOD, phDriv->DriverName);
	status = DoManualHook((PVOID*)&phDriv->MajorFunction[IRP_MJ_READ], TYPE_DEVICEIOR, phDriv->DriverName);
	status = DoManualHook((PVOID*)&phDriv->MajorFunction[IRP_MJ_WRITE], TYPE_DEVICEIOW, phDriv->DriverName);
	return status;
}

NTSTATUS DoHook(HookRequest* hookRequest)
{
	NTSTATUS status;
	if (hookRequest->mode == MODE_MANUAL)
	{
		status = DoManualHook(hookRequest->address, hookRequest->type, hookRequest->driverName);
		return status;
	}
	else if (hookRequest->mode == MODE_AUTO)
	{
		// TODO
		status = DoAutoHook(hookRequest->driverName);
		return status;
	}
	else {
		status = STATUS_ILLEGAL_FUNCTION;
	}
	return status;
}

// TODO
NTSTATUS
IoDeviceControlFunc(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpSp;
	irpSp = IoGetCurrentIrpStackLocation(Irp);
	ULONG inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (!inBufLength)
	{
		status = STATUS_INVALID_PARAMETER;
		goto End;
	}
	if (inBufLength != sizeof(HookRequest))
	{
		status = STATUS_INVALID_PARAMETER;
		goto End;
	}
	HookRequest* hookRequest;
	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_DUMP_METHOD_BUFFERED:
		hookRequest = (HookRequest*)Irp->AssociatedIrp.SystemBuffer;
		status = DoHook(hookRequest); goto End;

	default:
		status = STATUS_INVALID_PARAMETER; goto End;

	}

End:
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}



// TODO
VOID
UnloadDriver(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	DECLARE_UNICODE_STRING_SIZE(DosDeviceName, 40);
	RtlInitUnicodeString(&DosDeviceName, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&DosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);

	if (fastIoHooksDArray != NULL)
	{
		for (int i = 0; i < fastIoHooksDArrayEntries; i++)
		{
			fastIoHooksDArray[i].hookedAddress = fastIoHooksDArray[i].originalFunction;
		}
		fastIoHooksDArrayEntries = 0;
		fastIoHooksDArrayLen = 0;
		ExFreePool(fastIoHooksDArray);
		
	}
	

	if (fastIoHooksWArray != NULL)
	{
		for (int i = 0; i < fastIoHooksWArrayEntries; i++)
		{
			fastIoHooksWArray[i].hookedAddress = fastIoHooksWArray[i].originalFunction;
		}
		fastIoHooksWArrayEntries = 0;
		fastIoHooksWArrayLen = 0;
		ExFreePool(fastIoHooksWArray);
		
	}
	
	if (fastIoHooksRArray != NULL)
	{
		for (int i = 0; i < fastIoHooksRArrayEntries; i++)
		{
			fastIoHooksRArray[i].hookedAddress = fastIoHooksRArray[i].originalFunction;
		}
		fastIoHooksRArrayEntries = 0;
		fastIoHooksRArrayLen = 0;
		ExFreePool(fastIoHooksRArray);
		
	}
	if (deviceIoHooksRArray != NULL)
	{
		for (int i = 0; i < deviceIoHooksRArrayEntries; i++)
		{
			deviceIoHooksRArray[i].hookedAddress = deviceIoHooksRArray[i].originalFunction;
		}
		deviceIoHooksRArrayEntries = 0;
		deviceIoHooksRArrayLen = 0;
		ExFreePool(deviceIoHooksRArray);
		
	}
	if (deviceIoHooksWArray != NULL)
	{
		for (int i = 0; i < deviceIoHooksWArrayEntries; i++)
		{
			deviceIoHooksWArray[i].hookedAddress = deviceIoHooksWArray[i].originalFunction;
		}
		deviceIoHooksWArrayEntries = 0;
		deviceIoHooksWArrayLen = 0;
		ExFreePool(deviceIoHooksWArray);
		
	}
	if (deviceIoHooksDArray != NULL)
	{
		for (int i = 0; i < deviceIoHooksDArrayEntries; i++)
		{
			deviceIoHooksDArray[i].hookedAddress = deviceIoHooksDArray[i].originalFunction;
		}
		deviceIoHooksDArrayEntries = 0;
		deviceIoHooksDArrayLen = 0;
		ExFreePool(deviceIoHooksDArray);
		
	}
	if (fileIoHooksDArray != NULL)
	{
		for (int i = 0; i < fileIoHooksDArrayEntries; i++)
		{
			fileIoHooksDArray[i].hookedAddress = fileIoHooksDArray[i].originalFunction;
		}
		fileIoHooksDArrayEntries = 0;
		fileIoHooksDArrayLen = 0;
		ExFreePool(fileIoHooksDArray);
		
	}
	
	return;
}


NTSTATUS
ioctlCreateClose(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PAGED_CODE();

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
ioctlCleanup(
	_In_ PDEVICE_OBJECT DeviceObject,
	_Inout_ PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
	PDRIVER_OBJECT drvObj,
	PUNICODE_STRING regPath
)
{
	UNREFERENCED_PARAMETER(regPath);

	NTSTATUS status;
	PDEVICE_OBJECT deviceObject;
	UNICODE_STRING ntUnicodeString;
	RtlInitUnicodeString(&ntUnicodeString, NT_DEVICE_NAME);
	status = IoCreateDevice(drvObj, 0, &ntUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Error: Failed to create device.\n"));
		RtlFreeUnicodeString(&ntUnicodeString);
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	UNICODE_STRING ntWin32NameString;
	RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);
	status = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);
	if (!NT_SUCCESS(status))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Error: Failed to create symbolink link for device.\n"));
		IoDeleteDevice(deviceObject);
		RtlFreeUnicodeString(&ntWin32NameString);
		RtlFreeUnicodeString(&ntUnicodeString);
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	drvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoDeviceControlFunc;
	drvObj->MajorFunction[IRP_MJ_CREATE] = ioctlCreateClose;
	drvObj->MajorFunction[IRP_MJ_CLOSE] = ioctlCreateClose;
	drvObj->MajorFunction[IRP_MJ_CLEANUP] = ioctlCleanup;
	drvObj->DriverUnload = UnloadDriver;
	RtlFreeUnicodeString(&ntUnicodeString);
	RtlFreeUnicodeString(&ntWin32NameString);
	return STATUS_SUCCESS;
}
