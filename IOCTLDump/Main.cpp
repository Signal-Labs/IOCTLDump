#include <ntifs.h>
#include <wdm.h>
#include <stdlib.h>
#include <ntddk.h>
#include "IOCTLDump.h"
#include "IOCTLDump_Kern.h"

#define METHOD_FROM_CTL_CODE(ctrlCode)         ((ULONG)(ctrlCode & 3))

#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3


IoHookList* fastIoHooksDArray = NULL;

IoHookList* fastIoHooksRArray = NULL;

IoHookList* fastIoHooksWArray = NULL;

IoHookList* deviceIoHooksDArray = NULL;

IoHookList* deviceIoHooksWArray = NULL;

IoHookList* deviceIoHooksRArray = NULL;

IoHookList* fileIoHooksDArray = NULL;


KIRQL LowerAndCheckIRQL()
{
	KIRQL current = KeGetCurrentIrql();
	if (current > PASSIVE_LEVEL) {
		KeLowerIrql(PASSIVE_LEVEL);
	}
	return current;
}

void RaiseAndCheckIRQL(KIRQL old)
{
	KIRQL current = KeGetCurrentIrql();
	if (current != old)
	{
		KfRaiseIrql(old);
	}
}



/// <summary>
/// File creation helper, creates a file on disk and returns the handle in `fileHandle`
/// </summary>
/// <param name="filePath">
/// File path of the file to create
/// </param>
/// <param name="DesiredAccess">
/// Access mask of the file to create
/// </param>
/// <param name="CreationDisposition">
/// Creation disposition of the file
/// </param>
/// <param name="fileHandle">
/// Pointer that will receive the file handle on a successful file creation
/// </param>
/// <returns>
/// Status of the ZwCreateFile call
/// </returns>
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

/// <summary>
/// Creates a folder at the provided path if it does not exist, note this is not recursive (e.g. if path/fold1 does not exist, then creation of path/fold1/fold2 will fail)
/// </summary>
/// <param name="folderPath">
/// Path of the folder to create
/// </param>
/// <returns>
/// Status of the ZwCreateFile call
/// </returns>
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
	if (status != STATUS_SUCCESS) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ERROR: Failed to create folder:%ws.\n", folderPath));
	}
	return status;
}

/// <summary>
/// Our hook function that replaces a target's FastIoControl function, we dump the input buffer and 
/// log the metadata of this call
/// </summary>
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
	// We need to operate in PASSIVE_IRQL due to our file operations, ensure we're at that IRQL and save the current
	// IRQL so we can restore it later
	KIRQL oldIRQL = LowerAndCheckIRQL();
	// Initialize all our pointers to NULL, this allows us to check if they're non-null in our
	// cleanup phase without concerns of accessing non-initialized pointers.
	// Ensure whenever we free these pointers, we reset it back to NULL
	PUNICODE_STRING pOutputBufLenStringUni = NULL;
	LPWSTR confFileString = NULL;
	HANDLE hConfFile = NULL;
	LPWSTR pConfPath = NULL;
	HANDLE hDataFile = NULL;
	LPWSTR pDataPath = NULL;
	PUNICODE_STRING pInputBufLenStringUni = NULL;
	PUNICODE_STRING pIoctlStringUni = NULL;
	LPWSTR pFullPath = NULL;
	POBJECT_NAME_INFORMATION pObjName = NULL;
	PUNICODE_STRING pDevName = NULL;

	NTSTATUS status;
	// Debugging print 
	UNICODE_STRING drvName = DeviceObject->DriverObject->DriverName;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Driver Name:%wZ.\n", drvName));

	// Check if the device also has a name
	ULONG nameLen = 0;
	// ObQueryNameString will return the required size in nameLen if exists
	status = ObQueryNameString(DeviceObject, NULL, NULL, &nameLen);
	if (nameLen != 0) {
		// Name exists, lets allocate enough room for it
		pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, nameLen,'PMDI');
		if (pObjName != NULL) {
			status = ObQueryNameString(DeviceObject, pObjName, nameLen, &nameLen);
			if (status == STATUS_SUCCESS) {
				if (pObjName->Name.Length == 0)
				{
					ExFreePool(pObjName);
				}
				else {
					// Name exists, lets copy it into pDevName and free the object_name_information object
					pDevName = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
					if (pDevName != NULL) {
						pDevName->Length = pObjName->Name.Length;
						pDevName->MaximumLength = pObjName->Name.MaximumLength;
						pDevName->Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, pObjName->Name.MaximumLength, 'PMDI');
						if (pDevName->Buffer != NULL) {
							memcpy(pDevName->Buffer, pObjName->Name.Buffer, pObjName->Name.Length);
						}
						// Copy finished, lets free pObjName
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
						// Detect if the copy failed due to a failed allocation
						if (pDevName->Buffer == NULL) {
							// Buffer failed to allocate, free pDevName and set it to NULL so we can detect the failure later
							ExFreePool2(pDevName, 'PMDI', NULL, NULL);
							pDevName = NULL;
						}
					}
					else {
						// pDevName failed to allocate, free pObjName and continue
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
					}
					
				}

			}
			
		}
		
	}
	// Now, pDevName will either be NULL or point to a UNICODE_STRING, If it's NULL, the device name did not exist, or failed to copy
	



	// Base folder for our driver hooks
	LPWSTR pCFolder = L"\\DosDevices\\C:\\DriverHooks";

	// Quick workaround instead of properly parsing slashes and creating the nested
	// folder structure. Ideally in CreateFolder we would check for the existence of each folder
	// in the path and create them if required
	LPWSTR pCFolder_tmp2 = L"\\DosDevices\\C:\\DriverHooks\\Driver";

	SIZE_T fullPathSz = 2048 * sizeof(WCHAR);

	// Used to hold the eventual full path of our data dump, with a max of 2048 characters
	pFullPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, fullPathSz, 'PMDI');
	if (pFullPath == NULL) {
		goto cleanup;
	}
	wcsncpy_s(pFullPath, fullPathSz, pCFolder,wcslen(pCFolder));
	
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	status = CreateFolder(pCFolder_tmp2);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder2.\n"));

	
	wcsncat(pFullPath, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	


	pIoctlStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED,  sizeof(UNICODE_STRING), 'PMDI');
	if (pIoctlStringUni == NULL) {
		goto cleanup;
	}
	pIoctlStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  30, 'PMDI');
	if (pIoctlStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pIoctlStringUni->MaximumLength = 30;
	status = RtlIntegerToUnicodeString(IoControlCode, 16, pIoctlStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	LPWSTR hookTypeStr = L"\\fastIOD";
	// Concat ioctl string to full path
	wcsncat(pFullPath, hookTypeStr, wcslen(hookTypeStr));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	wcsncat(pFullPath, L"\\", wcslen(L"\\"));
	wcsncat(pFullPath, pIoctlStringUni->Buffer,pIoctlStringUni->Length / sizeof(WCHAR));

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ls.\n",pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));
	
	pInputBufLenStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
	if (pInputBufLenStringUni == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  30, 'PMDI');
	if (pInputBufLenStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->MaximumLength = 30;

	status = RtlIntegerToUnicodeString(InputBufferLength, 16, pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	
	if (InputBufferLength > 0)
	{
		// Dump memory
		pDataPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR),'PMDI');
		RtlZeroMemory(pDataPath, 4096 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, L"\\", wcslen(L"\\"));
		wcsncat(pDataPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / 2);
		LPWSTR dataTerminator = L".data";
		wcsncat(pDataPath, dataTerminator, wcslen(dataTerminator));
		// Create handle to pDataPath
		hDataFile = 0; 
		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			goto cleanup;
		}
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
		pDataPath = NULL;
		// Write data to pDataFile handle
		IO_STATUS_BLOCK statBlock;
		status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, InputBuffer, InputBufferLength, NULL, NULL);
		ZwClose(hDataFile);
		hDataFile = NULL;
		if (!NT_SUCCESS(status))
		{
			// Error writing file
			goto cleanup;
		}
	}
	// Write conf
	pConfPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR),'PMDI');
	RtlZeroMemory(pConfPath, 4096 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, L"\\", wcslen(L"\\"));
	wcsncat(pConfPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	LPWSTR confTerminator = L".conf";
	wcsncat(pConfPath, confTerminator, wcslen(confTerminator));
	hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		goto cleanup;
	}
	ExFreePool2(pConfPath,'PMDI', NULL, NULL);
	pConfPath = NULL;
	// Write data to pConfFile handle
	confFileString = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096*sizeof(WCHAR),'PMDI');
	RtlZeroMemory(confFileString, 4096 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:";
	wcsncpy(confFileString, drvHeader, wcslen(drvHeader));
	wcsncat(confFileString, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	LPWSTR newLine = L"\r\n";
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR typeHeader = L"Type:FASTIOD\r\n";
	wcsncat(confFileString, typeHeader, wcslen(typeHeader));
	LPWSTR ioctlHeader = L"IOCTL:";
	wcsncat(confFileString, ioctlHeader, wcslen(ioctlHeader));
	wcsncat(confFileString, pIoctlStringUni->Buffer, pIoctlStringUni->Length / sizeof(WCHAR));
	ExFreePool2(pIoctlStringUni->Buffer, 'PMDI',NULL,NULL);
	ExFreePool2(pIoctlStringUni,'PMDI', NULL, NULL);
	pIoctlStringUni = NULL;
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR inputLenHeader = L"InputBufferLength:";
	wcsncat(confFileString, inputLenHeader, wcslen(inputLenHeader));
	wcsncat(confFileString, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	ExFreePool2(pInputBufLenStringUni->Buffer,'PMDI', NULL, NULL);
	ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	pInputBufLenStringUni = NULL;
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR outputLenHeader = L"OutputBufferLength:";
	wcsncat(confFileString, outputLenHeader, wcslen(outputLenHeader));

	pOutputBufLenStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
	if (pOutputBufLenStringUni == NULL) {
		goto cleanup;
	}
	pOutputBufLenStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  60, 'PMDI');
	if (pOutputBufLenStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pOutputBufLenStringUni->MaximumLength = 60;
	status = RtlIntegerToUnicodeString(OutputBufferLength, 16, pOutputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	wcsncat(confFileString, pOutputBufLenStringUni->Buffer, pOutputBufLenStringUni->Length / sizeof(WCHAR));

	ExFreePool2(pOutputBufLenStringUni->Buffer, 'PMDI',NULL,NULL);
	ExFreePool2(pOutputBufLenStringUni, 'PMDI',NULL,NULL);
	pOutputBufLenStringUni = NULL;

	IO_STATUS_BLOCK statBlock;
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString) * sizeof(WCHAR), NULL, NULL);
	ZwClose(hConfFile);
	hConfFile = NULL;
	goto cleanup;
cleanup:
	// Check for NULL pointers and skip them, if we have a pointer that's non-null we free it, or if its a UNICODE type, we check if ->Buffer is NULL,
	// if not then we free that internal buffer first, then the UNICODE pointer.
	// Make sure we initialize all pointers as NULL at the start of this function, so that they may exist here for checking if we hit an error path and 
	// jump here early.
	if (confFileString != NULL) {
		ExFreePool2(confFileString, 'PMDI', NULL, NULL);
	}
	if (pConfPath != NULL) {
		ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	}
	if (pDataPath != NULL) {
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
	}
	if (pFullPath != NULL) {
		ExFreePool2(pFullPath, 'PMDI', NULL, NULL);
	}
	if (pObjName != NULL) {
		ExFreePool2(pObjName, 'PMDI', NULL, NULL);
	}
	if (pOutputBufLenStringUni != NULL) {
		if (pOutputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pOutputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pOutputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pInputBufLenStringUni != NULL) {
		if (pInputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pIoctlStringUni != NULL) {
		if (pIoctlStringUni->Buffer != NULL) {
			ExFreePool2(pIoctlStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pIoctlStringUni, 'PMDI', NULL, NULL);
	}
	if (pDevName != NULL) {
		if (pDevName->Buffer != NULL) {
			ExFreePool2(pDevName->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pDevName, 'PMDI', NULL, NULL);
	}
	// Check and close handles
	if (hConfFile != NULL) {
		ZwClose(hConfFile);
	}
	if (hDataFile != NULL) {
		ZwClose(hDataFile);
	}
	goto End;

End:
	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = fastIoHooksDArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);

	// Call original overwritten address
	for (int i = 0; i < hookList->entry_count; i++)
	{
		if (RtlEqualUnicodeString(&hookList->entries[i].driverName, &drvName, false))
		{
			fastIoCallD origFuncCall = (fastIoCallD)hookList->entries[i].originalFunction;
			// Release lock
			ExReleaseFastMutex(hookList->lock);
			// Revert IRQL to value when we were called
			RaiseAndCheckIRQL(oldIRQL);
			// Call the original function now that we've logged it, then
			// return to caller
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
	// Release lock
	ExReleaseFastMutex(hookList->lock);
	// Rever IRQL
	RaiseAndCheckIRQL(oldIRQL);
	// Oops, cant find original hook address as something went wrong. We should never hit here, for debug purposes we crash the system. Alternatively, return 
	// a fake result to continue system execution
	__debugbreak();
	//return false;
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
	// We need to operate in PASSIVE_IRQL due to our file operations, ensure we're at that IRQL and save the current
	// IRQL so we can restore it later
	KIRQL oldIRQL = LowerAndCheckIRQL();
	// Initialize all our pointers to NULL, this allows us to check if they're non-null in our
	// cleanup phase without concerns of accessing non-initialized pointers.
	// Ensure whenever we free these pointers, we reset it back to NULL
	PUNICODE_STRING pOutputBufLenStringUni = NULL;
	LPWSTR confFileString = NULL;
	HANDLE hConfFile = NULL;
	LPWSTR pConfPath = NULL;
	HANDLE hDataFile = NULL;
	LPWSTR pDataPath = NULL;
	PUNICODE_STRING pInputBufLenStringUni = NULL;
	PUNICODE_STRING pIoctlStringUni = NULL;
	LPWSTR pFullPath = NULL;
	POBJECT_NAME_INFORMATION pObjName = NULL;
	PUNICODE_STRING pDevName = NULL;

	NTSTATUS status;
	// Debugging print 
	UNICODE_STRING drvName = DeviceObject->DriverObject->DriverName;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Driver Name:%wZ.\n", drvName));

	// Check if the device also has a name
	ULONG nameLen = 0;
	// ObQueryNameString will return the required size in nameLen if exists
	status = ObQueryNameString(DeviceObject, NULL, NULL, &nameLen);
	if (nameLen != 0) {
		// Name exists, lets allocate enough room for it
		pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, nameLen, 'PMDI');
		if (pObjName != NULL) {
			status = ObQueryNameString(DeviceObject, pObjName, nameLen, &nameLen);
			if (status == STATUS_SUCCESS) {
				if (pObjName->Name.Length == 0)
				{
					ExFreePool(pObjName);
				}
				else {
					// Name exists, lets copy it into pDevName and free the object_name_information object
					pDevName = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
					if (pDevName != NULL) {
						pDevName->Length = pObjName->Name.Length;
						pDevName->MaximumLength = pObjName->Name.MaximumLength;
						pDevName->Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, pObjName->Name.MaximumLength, 'PMDI');
						if (pDevName->Buffer != NULL) {
							memcpy(pDevName->Buffer, pObjName->Name.Buffer, pObjName->Name.Length);
						}
						// Copy finished, lets free pObjName
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
						// Detect if the copy failed due to a failed allocation
						if (pDevName->Buffer == NULL) {
							// Buffer failed to allocate, free pDevName and set it to NULL so we can detect the failure later
							ExFreePool2(pDevName, 'PMDI', NULL, NULL);
							pDevName = NULL;
						}
					}
					else {
						// pDevName failed to allocate, free pObjName and continue
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
					}

				}

			}

		}

	}
	// Now, pDevName will either be NULL or point to a UNICODE_STRING, If it's NULL, the device name did not exist, or failed to copy




	// Base folder for our driver hooks
	LPWSTR pCFolder = L"\\DosDevices\\C:\\DriverHooks";

	// Quick workaround instead of properly parsing slashes and creating the nested
	// folder structure. Ideally in CreateFolder we would check for the existence of each folder
	// in the path and create them if required
	LPWSTR pCFolder_tmp2 = L"\\DosDevices\\C:\\DriverHooks\\Driver";

	SIZE_T fullPathSz = 2048 * sizeof(WCHAR);

	// Used to hold the eventual full path of our data dump, with a max of 2048 characters
	pFullPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  fullPathSz, 'PMDI');
	if (pFullPath == NULL) {
		goto cleanup;
	}
	wcsncpy_s(pFullPath, fullPathSz, pCFolder, wcslen(pCFolder));

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	status = CreateFolder(pCFolder_tmp2);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder2.\n"));

	
	wcsncat(pFullPath, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	

	LPWSTR hookTypeStr = L"\\fastIOW";
	// Concat ioctl string to full path
	wcsncat(pFullPath, hookTypeStr, wcslen(hookTypeStr));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%s.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));

	pInputBufLenStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
	if (pInputBufLenStringUni == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  30, 'PMDI');
	if (pInputBufLenStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->MaximumLength = 30;

	status = RtlIntegerToUnicodeString(Length, 16, pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}


	if (Length > 0)
	{
		// Dump memory
		pDataPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
		RtlZeroMemory(pDataPath, 4096 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, L"\\", wcslen(L"\\"));
		wcsncat(pDataPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / 2);
		LPWSTR dataTerminator = L".data";
		wcsncat(pDataPath, dataTerminator, wcslen(dataTerminator));
		// Create handle to pDataPath
		hDataFile = 0;
		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			goto cleanup;
		}
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
		pDataPath = NULL;
		// Write data to pDataFile handle
		IO_STATUS_BLOCK statBlock;
		status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, Buffer, Length, NULL, NULL);
		ZwClose(hDataFile);
		hDataFile = NULL;
		if (!NT_SUCCESS(status))
		{
			// Error writing file
			goto cleanup;
		}
	}
	// Write conf
	pConfPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
	RtlZeroMemory(pConfPath, 4096 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, L"\\", wcslen(L"\\"));
	wcsncat(pConfPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	LPWSTR confTerminator = L".conf";
	wcsncat(pConfPath, confTerminator, wcslen(confTerminator));
	hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		goto cleanup;
	}
	ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	pConfPath = NULL;
	// Write data to pConfFile handle
	confFileString = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
	RtlZeroMemory(confFileString, 4096 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:";
	wcsncpy(confFileString, drvHeader, wcslen(drvHeader));
	wcsncat(confFileString, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	LPWSTR newLine = L"\r\n";
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR typeHeader = L"Type:FASTIOW\r\n";
	wcsncat(confFileString, typeHeader, wcslen(typeHeader));
	LPWSTR ioctlHeader = L"IOCTL:";
	wcsncat(confFileString, ioctlHeader, wcslen(ioctlHeader));
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR inputLenHeader = L"InputBufferLength:";
	wcsncat(confFileString, inputLenHeader, wcslen(inputLenHeader));
	wcsncat(confFileString, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
	ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	pInputBufLenStringUni = NULL;
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR outputLenHeader = L"OutputBufferLength:";
	wcsncat(confFileString, outputLenHeader, wcslen(outputLenHeader));

	IO_STATUS_BLOCK statBlock;
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString) * sizeof(WCHAR), NULL, NULL);
	ZwClose(hConfFile);
	hConfFile = NULL;
	goto cleanup;
cleanup:
	// Check for NULL pointers and skip them, if we have a pointer that's non-null we free it, or if its a UNICODE type, we check if ->Buffer is NULL,
	// if not then we free that internal buffer first, then the UNICODE pointer.
	// Make sure we initialize all pointers as NULL at the start of this function, so that they may exist here for checking if we hit an error path and 
	// jump here early.
	if (confFileString != NULL) {
		ExFreePool2(confFileString, 'PMDI', NULL, NULL);
	}
	if (pConfPath != NULL) {
		ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	}
	if (pDataPath != NULL) {
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
	}
	if (pFullPath != NULL) {
		ExFreePool2(pFullPath, 'PMDI', NULL, NULL);
	}
	if (pObjName != NULL) {
		ExFreePool2(pObjName, 'PMDI', NULL, NULL);
	}
	if (pOutputBufLenStringUni != NULL) {
		if (pOutputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pOutputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pOutputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pInputBufLenStringUni != NULL) {
		if (pInputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pIoctlStringUni != NULL) {
		if (pIoctlStringUni->Buffer != NULL) {
			ExFreePool2(pIoctlStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pIoctlStringUni, 'PMDI', NULL, NULL);
	}
	if (pDevName != NULL) {
		if (pDevName->Buffer != NULL) {
			ExFreePool2(pDevName->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pDevName, 'PMDI', NULL, NULL);
	}
	// Check and close handles
	if (hConfFile != NULL) {
		ZwClose(hConfFile);
	}
	if (hDataFile != NULL) {
		ZwClose(hDataFile);
	}
	goto End;

End:
	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = fastIoHooksWArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);

	// Call original overwritten address
	for (int i = 0; i < hookList->entry_count; i++)
	{
		if (RtlEqualUnicodeString(&hookList->entries[i].driverName, &drvName, false))
		{
			fastIoCallRW origFuncCall = (fastIoCallRW)hookList->entries[i].originalFunction;
			// Release lock
			ExReleaseFastMutex(hookList->lock);
			// Revert IRQL to value when we were called
			RaiseAndCheckIRQL(oldIRQL);
			// Call the original function now that we've logged it, then
			// return to caller
			return origFuncCall(FileObject,
				FileOffset,
				Length,
				Wait,
				LockKey,
				Buffer,
				IoStatus,
				DeviceObject);
		}
	}
	// Release lock
	ExReleaseFastMutex(hookList->lock);
	// Rever IRQL
	RaiseAndCheckIRQL(oldIRQL);
	// Oops, cant find original hook address as something went wrong. We should never hit here, for debug purposes we crash the system. Alternatively, return 
	// a fake result to continue system execution
	__debugbreak();
	//return false;
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
	// We need to operate in PASSIVE_IRQL due to our file operations, ensure we're at that IRQL and save the current
	// IRQL so we can restore it later
	KIRQL oldIRQL = LowerAndCheckIRQL();
	// Initialize all our pointers to NULL, this allows us to check if they're non-null in our
	// cleanup phase without concerns of accessing non-initialized pointers.
	// Ensure whenever we free these pointers, we reset it back to NULL
	PUNICODE_STRING pOutputBufLenStringUni = NULL;
	LPWSTR confFileString = NULL;
	HANDLE hConfFile = NULL;
	LPWSTR pConfPath = NULL;
	HANDLE hDataFile = NULL;
	LPWSTR pDataPath = NULL;
	PUNICODE_STRING pInputBufLenStringUni = NULL;
	PUNICODE_STRING pIoctlStringUni = NULL;
	LPWSTR pFullPath = NULL;
	POBJECT_NAME_INFORMATION pObjName = NULL;
	PUNICODE_STRING pDevName = NULL;

	NTSTATUS status;
	// Debugging print 
	UNICODE_STRING drvName = DeviceObject->DriverObject->DriverName;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Driver Name:%wZ.\n", drvName));

	// Check if the device also has a name
	ULONG nameLen = 0;
	// ObQueryNameString will return the required size in nameLen if exists
	status = ObQueryNameString(DeviceObject, NULL, NULL, &nameLen);
	if (nameLen != 0) {
		// Name exists, lets allocate enough room for it
		pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, nameLen, 'PMDI');
		if (pObjName != NULL) {
			status = ObQueryNameString(DeviceObject, pObjName, nameLen, &nameLen);
			if (status == STATUS_SUCCESS) {
				if (pObjName->Name.Length == 0)
				{
					ExFreePool(pObjName);
				}
				else {
					// Name exists, lets copy it into pDevName and free the object_name_information object
					pDevName = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
					if (pDevName != NULL) {
						pDevName->Length = pObjName->Name.Length;
						pDevName->MaximumLength = pObjName->Name.MaximumLength;
						pDevName->Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, pObjName->Name.MaximumLength, 'PMDI');
						if (pDevName->Buffer != NULL) {
							memcpy(pDevName->Buffer, pObjName->Name.Buffer, pObjName->Name.Length);
						}
						// Copy finished, lets free pObjName
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
						// Detect if the copy failed due to a failed allocation
						if (pDevName->Buffer == NULL) {
							// Buffer failed to allocate, free pDevName and set it to NULL so we can detect the failure later
							ExFreePool2(pDevName, 'PMDI', NULL, NULL);
							pDevName = NULL;
						}
					}
					else {
						// pDevName failed to allocate, free pObjName and continue
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
					}

				}

			}

		}

	}
	// Now, pDevName will either be NULL or point to a UNICODE_STRING, If it's NULL, the device name did not exist, or failed to copy




	// Base folder for our driver hooks
	LPWSTR pCFolder = L"\\DosDevices\\C:\\DriverHooks";

	// Quick workaround instead of properly parsing slashes and creating the nested
	// folder structure. Ideally in CreateFolder we would check for the existence of each folder
	// in the path and create them if required
	LPWSTR pCFolder_tmp2 = L"\\DosDevices\\C:\\DriverHooks\\Driver";

	SIZE_T fullPathSz = 2048 * sizeof(WCHAR);

	// Used to hold the eventual full path of our data dump, with a max of 2048 characters
	pFullPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  fullPathSz, 'PMDI');
	if (pFullPath == NULL) {
		goto cleanup;
	}
	wcsncpy_s(pFullPath, fullPathSz, pCFolder, wcslen(pCFolder));

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	status = CreateFolder(pCFolder_tmp2);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder2.\n"));

	
	wcsncat(pFullPath, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	

	LPWSTR hookTypeStr = L"\\fastIOR";
	// Concat ioctl string to full path
	wcsncat(pFullPath, hookTypeStr, wcslen(hookTypeStr));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%s.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));

	pInputBufLenStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING),'PMDI');
	if (pInputBufLenStringUni == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  30, 'PMDI');
	if (pInputBufLenStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->MaximumLength = 30;

	status = RtlIntegerToUnicodeString(Length, 16, pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}


	if (Length > 0)
	{
		// Dump memory
		pDataPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
		RtlZeroMemory(pDataPath, 4096 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, L"\\", wcslen(L"\\"));
		wcsncat(pDataPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / 2);
		LPWSTR dataTerminator = L".data";
		wcsncat(pDataPath, dataTerminator, wcslen(dataTerminator));
		// Create handle to pDataPath
		hDataFile = 0;
		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			goto cleanup;
		}
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
		pDataPath = NULL;
		// We dump the buffer later, as we need the target to fill in the buffer first.
	}
	// Write conf
	pConfPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
	RtlZeroMemory(pConfPath, 4096 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, L"\\", wcslen(L"\\"));
	wcsncat(pConfPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	LPWSTR confTerminator = L".conf";
	wcsncat(pConfPath, confTerminator, wcslen(confTerminator));
	hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		goto cleanup;
	}
	ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	pConfPath = NULL;
	// Write data to pConfFile handle
	confFileString = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
	RtlZeroMemory(confFileString, 4096 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:";
	wcsncpy(confFileString, drvHeader, wcslen(drvHeader));
	wcsncat(confFileString, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	LPWSTR newLine = L"\r\n";
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR typeHeader = L"Type:FASTIOR\r\n";
	wcsncat(confFileString, typeHeader, wcslen(typeHeader));
	LPWSTR ioctlHeader = L"IOCTL:";
	wcsncat(confFileString, ioctlHeader, wcslen(ioctlHeader));
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR inputLenHeader = L"InputBufferLength:";
	wcsncat(confFileString, inputLenHeader, wcslen(inputLenHeader));
	wcsncat(confFileString, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
	ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	pInputBufLenStringUni = NULL;
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR outputLenHeader = L"OutputBufferLength:";
	wcsncat(confFileString, outputLenHeader, wcslen(outputLenHeader));

	IO_STATUS_BLOCK statBlock;
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString) * sizeof(WCHAR), NULL, NULL);
	ZwClose(hConfFile);
	hConfFile = NULL;
	goto cleanup;
cleanup:
	// Check for NULL pointers and skip them, if we have a pointer that's non-null we free it, or if its a UNICODE type, we check if ->Buffer is NULL,
	// if not then we free that internal buffer first, then the UNICODE pointer.
	// Make sure we initialize all pointers as NULL at the start of this function, so that they may exist here for checking if we hit an error path and 
	// jump here early.
	if (confFileString != NULL) {
		ExFreePool2(confFileString, 'PMDI', NULL, NULL);
	}
	if (pConfPath != NULL) {
		ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	}
	if (pDataPath != NULL) {
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
	}
	if (pFullPath != NULL) {
		ExFreePool2(pFullPath, 'PMDI', NULL, NULL);
	}
	if (pObjName != NULL) {
		ExFreePool2(pObjName, 'PMDI', NULL, NULL);
	}
	if (pOutputBufLenStringUni != NULL) {
		if (pOutputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pOutputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pOutputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pInputBufLenStringUni != NULL) {
		if (pInputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pIoctlStringUni != NULL) {
		if (pIoctlStringUni->Buffer != NULL) {
			ExFreePool2(pIoctlStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pIoctlStringUni, 'PMDI', NULL, NULL);
	}
	if (pDevName != NULL) {
		if (pDevName->Buffer != NULL) {
			ExFreePool2(pDevName->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pDevName, 'PMDI', NULL, NULL);
	}
	// Check and close handles
	if (hConfFile != NULL) {
		ZwClose(hConfFile);
	}
	
	goto End;

End:
	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = fastIoHooksRArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);

	// Call original overwritten address
	for (int i = 0; i < hookList->entry_count; i++)
	{
		if (RtlEqualUnicodeString(&hookList->entries[i].driverName, &drvName, false))
		{
			fastIoCallRW origFuncCall = (fastIoCallRW)hookList->entries[i].originalFunction;
			// Release lock
			ExReleaseFastMutex(hookList->lock);
			// Revert IRQL to value when we were called
			RaiseAndCheckIRQL(oldIRQL);
			// Call the original function now that we've logged it, then
			// return to caller
			bool res = origFuncCall(FileObject,
				FileOffset,
				Length,
				Wait,
				LockKey,
				Buffer,
				IoStatus,
				DeviceObject);
			if (Length > 0 && hDataFile != NULL) {

				LowerAndCheckIRQL();
				// Write data to pDataFile handle
				IO_STATUS_BLOCK statBlock;
				status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, Buffer, Length, NULL, NULL);
				ZwClose(hDataFile);
				hDataFile = NULL;
				RaiseAndCheckIRQL(oldIRQL);
			}
			return res;
			

		}
	}
	// Release lock
	ExReleaseFastMutex(hookList->lock);
	// Rever IRQL
	RaiseAndCheckIRQL(oldIRQL);
	// Oops, cant find original hook address as something went wrong. We should never hit here, for debug purposes we crash the system. Alternatively, return 
	// a fake result to continue system execution
	__debugbreak();
	//return false;
}


NTSTATUS DeviceIoHookW(_DEVICE_OBJECT* DeviceObject,
	_IRP* Irp)
{
	// We need to operate in PASSIVE_IRQL due to our file operations, ensure we're at that IRQL and save the current
	// IRQL so we can restore it later
	KIRQL oldIRQL = LowerAndCheckIRQL();
	PIO_STACK_LOCATION pIoStackLocation;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	// Initialize all our pointers to NULL, this allows us to check if they're non-null in our
	// cleanup phase without concerns of accessing non-initialized pointers.
	// Ensure whenever we free these pointers, we reset it back to NULL
	PUNICODE_STRING pOutputBufLenStringUni = NULL;
	LPWSTR confFileString = NULL;
	HANDLE hConfFile = NULL;
	LPWSTR pConfPath = NULL;
	HANDLE hDataFile = NULL;
	LPWSTR pDataPath = NULL;
	PUNICODE_STRING pInputBufLenStringUni = NULL;
	PUNICODE_STRING pIoctlStringUni = NULL;
	LPWSTR pFullPath = NULL;
	POBJECT_NAME_INFORMATION pObjName = NULL;
	PUNICODE_STRING pDevName = NULL;

	NTSTATUS status;
	// Debugging print 
	UNICODE_STRING drvName = DeviceObject->DriverObject->DriverName;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Driver Name:%wZ.\n", drvName));

	// Check if the device also has a name
	ULONG nameLen = 0;
	// ObQueryNameString will return the required size in nameLen if exists
	status = ObQueryNameString(DeviceObject, NULL, NULL, &nameLen);
	if (nameLen != 0) {
		// Name exists, lets allocate enough room for it
		pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, nameLen, 'PMDI');
		if (pObjName != NULL) {
			status = ObQueryNameString(DeviceObject, pObjName, nameLen, &nameLen);
			if (status == STATUS_SUCCESS) {
				if (pObjName->Name.Length == 0)
				{
					ExFreePool(pObjName);
				}
				else {
					// Name exists, lets copy it into pDevName and free the object_name_information object
					pDevName = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
					if (pDevName != NULL) {
						pDevName->Length = pObjName->Name.Length;
						pDevName->MaximumLength = pObjName->Name.MaximumLength;
						pDevName->Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, pObjName->Name.MaximumLength, 'PMDI');
						if (pDevName->Buffer != NULL) {
							memcpy(pDevName->Buffer, pObjName->Name.Buffer, pObjName->Name.Length);
						}
						// Copy finished, lets free pObjName
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
						// Detect if the copy failed due to a failed allocation
						if (pDevName->Buffer == NULL) {
							// Buffer failed to allocate, free pDevName and set it to NULL so we can detect the failure later
							ExFreePool2(pDevName, 'PMDI', NULL, NULL);
							pDevName = NULL;
						}
					}
					else {
						// pDevName failed to allocate, free pObjName and continue
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
					}

				}

			}

		}

	}
	// Now, pDevName will either be NULL or point to a UNICODE_STRING, If it's NULL, the device name did not exist, or failed to copy




	// Base folder for our driver hooks
	LPWSTR pCFolder = L"\\DosDevices\\C:\\DriverHooks";

	// Quick workaround instead of properly parsing slashes and creating the nested
	// folder structure. Ideally in CreateFolder we would check for the existence of each folder
	// in the path and create them if required
	LPWSTR pCFolder_tmp2 = L"\\DosDevices\\C:\\DriverHooks\\Driver";

	SIZE_T fullPathSz = 2048 * sizeof(WCHAR);

	// Used to hold the eventual full path of our data dump, with a max of 2048 characters
	pFullPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  fullPathSz, 'PMDI');
	if (pFullPath == NULL) {
		goto cleanup;
	}
	wcsncpy_s(pFullPath, fullPathSz, pCFolder, wcslen(pCFolder));

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	status = CreateFolder(pCFolder_tmp2);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder2.\n"));

	
	wcsncat(pFullPath, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	

	LPWSTR hookTypeStr = L"\\devIOW";
	// Concat ioctl string to full path
	wcsncat(pFullPath, hookTypeStr, wcslen(hookTypeStr));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ls.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));

	pInputBufLenStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
	if (pInputBufLenStringUni == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  30, 'PMDI');
	if (pInputBufLenStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->MaximumLength = 30;

	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.Write.Length, 16, pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}


	if (pIoStackLocation->Parameters.Write.Length > 0)
	{
		// Dump memory
		pDataPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
		RtlZeroMemory(pDataPath, 4096 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, L"\\", wcslen(L"\\"));
		wcsncat(pDataPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / 2);
		LPWSTR dataTerminator = L".data";
		wcsncat(pDataPath, dataTerminator, wcslen(dataTerminator));
		// Create handle to pDataPath
		hDataFile = 0;
		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			goto cleanup;
		}
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
		pDataPath = NULL;
		// Write data to pDataFile handle
		IO_STATUS_BLOCK statBlock;
		status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, Irp->AssociatedIrp.SystemBuffer, pIoStackLocation->Parameters.Write.Length, NULL, NULL);
		ZwClose(hDataFile);
		hDataFile = NULL;
		if (!NT_SUCCESS(status))
		{
			// Error writing file
			goto cleanup;
		}
	}
	// Write conf
	pConfPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
	RtlZeroMemory(pConfPath, 4096 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, L"\\", wcslen(L"\\"));
	wcsncat(pConfPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	LPWSTR confTerminator = L".conf";
	wcsncat(pConfPath, confTerminator, wcslen(confTerminator));
	hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		goto cleanup;
	}
	ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	pConfPath = NULL;
	// Write data to pConfFile handle
	confFileString = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
	RtlZeroMemory(confFileString, 4096 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:";
	wcsncpy(confFileString, drvHeader, wcslen(drvHeader));
	wcsncat(confFileString, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	LPWSTR newLine = L"\r\n";
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR typeHeader = L"Type:DEVIOW\r\n";
	wcsncat(confFileString, typeHeader, wcslen(typeHeader));
	LPWSTR ioctlHeader = L"IOCTL:";
	wcsncat(confFileString, ioctlHeader, wcslen(ioctlHeader));
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR inputLenHeader = L"InputBufferLength:";
	wcsncat(confFileString, inputLenHeader, wcslen(inputLenHeader));
	wcsncat(confFileString, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
	ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	pInputBufLenStringUni = NULL;
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR outputLenHeader = L"OutputBufferLength:";
	wcsncat(confFileString, outputLenHeader, wcslen(outputLenHeader));

	IO_STATUS_BLOCK statBlock;
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString) * sizeof(WCHAR), NULL, NULL);
	ZwClose(hConfFile);
	hConfFile = NULL;
	goto cleanup;
cleanup:
	// Check for NULL pointers and skip them, if we have a pointer that's non-null we free it, or if its a UNICODE type, we check if ->Buffer is NULL,
	// if not then we free that internal buffer first, then the UNICODE pointer.
	// Make sure we initialize all pointers as NULL at the start of this function, so that they may exist here for checking if we hit an error path and 
	// jump here early.
	if (confFileString != NULL) {
		ExFreePool2(confFileString, 'PMDI', NULL, NULL);
	}
	if (pConfPath != NULL) {
		ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	}
	if (pDataPath != NULL) {
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
	}
	if (pFullPath != NULL) {
		ExFreePool2(pFullPath, 'PMDI', NULL, NULL);
	}
	if (pObjName != NULL) {
		ExFreePool2(pObjName, 'PMDI', NULL, NULL);
	}
	if (pOutputBufLenStringUni != NULL) {
		if (pOutputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pOutputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pOutputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pInputBufLenStringUni != NULL) {
		if (pInputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pIoctlStringUni != NULL) {
		if (pIoctlStringUni->Buffer != NULL) {
			ExFreePool2(pIoctlStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pIoctlStringUni, 'PMDI', NULL, NULL);
	}
	if (pDevName != NULL) {
		if (pDevName->Buffer != NULL) {
			ExFreePool2(pDevName->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pDevName, 'PMDI', NULL, NULL);
	}
	// Check and close handles
	if (hConfFile != NULL) {
		ZwClose(hConfFile);
	}
	if (hDataFile != NULL) {
		ZwClose(hDataFile);
	}
	goto End;

End:
	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = deviceIoHooksWArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);

	// Call original overwritten address
	for (int i = 0; i < hookList->entry_count; i++)
	{
		if (RtlEqualUnicodeString(&hookList->entries[i].driverName, &drvName, false))
		{
			devIoCallRWD  origFuncCall = (devIoCallRWD)hookList->entries[i].originalFunction;
			// Release lock
			ExReleaseFastMutex(hookList->lock);
			// Revert IRQL to value when we were called
			RaiseAndCheckIRQL(oldIRQL);
			// Call the original function now that we've logged it, then
			// return to caller
			return origFuncCall(DeviceObject, Irp);
		}
	}
	// Release lock
	ExReleaseFastMutex(hookList->lock);
	// Rever IRQL
	RaiseAndCheckIRQL(oldIRQL);
	// Oops, cant find original hook address as something went wrong. We should never hit here, for debug purposes we crash the system. Alternatively, return 
	// a fake result to continue system execution
	__debugbreak();
	//return false;
}


NTSTATUS DeviceIoHookR(_DEVICE_OBJECT* DeviceObject,
	_IRP* Irp)
{
	// We need to operate in PASSIVE_IRQL due to our file operations, ensure we're at that IRQL and save the current
	// IRQL so we can restore it later
	KIRQL oldIRQL = LowerAndCheckIRQL();
	PIO_STACK_LOCATION pIoStackLocation;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	// Initialize all our pointers to NULL, this allows us to check if they're non-null in our
	// cleanup phase without concerns of accessing non-initialized pointers.
	// Ensure whenever we free these pointers, we reset it back to NULL
	PUNICODE_STRING pOutputBufLenStringUni = NULL;
	LPWSTR confFileString = NULL;
	HANDLE hConfFile = NULL;
	LPWSTR pConfPath = NULL;
	HANDLE hDataFile = NULL;
	LPWSTR pDataPath = NULL;
	PUNICODE_STRING pInputBufLenStringUni = NULL;
	PUNICODE_STRING pIoctlStringUni = NULL;
	LPWSTR pFullPath = NULL;
	POBJECT_NAME_INFORMATION pObjName = NULL;
	PUNICODE_STRING pDevName = NULL;

	NTSTATUS status;
	// Debugging print 
	UNICODE_STRING drvName = DeviceObject->DriverObject->DriverName;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Driver Name:%wZ.\n", drvName));

	// Check if the device also has a name
	ULONG nameLen = 0;
	// ObQueryNameString will return the required size in nameLen if exists
	status = ObQueryNameString(DeviceObject, NULL, NULL, &nameLen);
	if (nameLen != 0) {
		// Name exists, lets allocate enough room for it
		pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, nameLen, 'PMDI');
		if (pObjName != NULL) {
			status = ObQueryNameString(DeviceObject, pObjName, nameLen, &nameLen);
			if (status == STATUS_SUCCESS) {
				if (pObjName->Name.Length == 0)
				{
					ExFreePool(pObjName);
				}
				else {
					// Name exists, lets copy it into pDevName and free the object_name_information object
					pDevName = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
					if (pDevName != NULL) {
						pDevName->Length = pObjName->Name.Length;
						pDevName->MaximumLength = pObjName->Name.MaximumLength;
						pDevName->Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, pObjName->Name.MaximumLength, 'PMDI');
						if (pDevName->Buffer != NULL) {
							memcpy(pDevName->Buffer, pObjName->Name.Buffer, pObjName->Name.Length);
						}
						// Copy finished, lets free pObjName
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
						// Detect if the copy failed due to a failed allocation
						if (pDevName->Buffer == NULL) {
							// Buffer failed to allocate, free pDevName and set it to NULL so we can detect the failure later
							ExFreePool2(pDevName, 'PMDI', NULL, NULL);
							pDevName = NULL;
						}
					}
					else {
						// pDevName failed to allocate, free pObjName and continue
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
					}

				}

			}

		}

	}
	// Now, pDevName will either be NULL or point to a UNICODE_STRING, If it's NULL, the device name did not exist, or failed to copy




	// Base folder for our driver hooks
	LPWSTR pCFolder = L"\\DosDevices\\C:\\DriverHooks";

	// Quick workaround instead of properly parsing slashes and creating the nested
	// folder structure. Ideally in CreateFolder we would check for the existence of each folder
	// in the path and create them if required
	LPWSTR pCFolder_tmp2 = L"\\DosDevices\\C:\\DriverHooks\\Driver";

	SIZE_T fullPathSz = 2048 * sizeof(WCHAR);

	// Used to hold the eventual full path of our data dump, with a max of 2048 characters
	pFullPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  fullPathSz, 'PMDI');
	if (pFullPath == NULL) {
		goto cleanup;
	}
	wcsncpy_s(pFullPath, fullPathSz, pCFolder, wcslen(pCFolder));

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	status = CreateFolder(pCFolder_tmp2);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder2.\n"));

	
	wcsncat(pFullPath, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	

	LPWSTR hookTypeStr = L"\\devIOR";
	// Concat ioctl string to full path
	wcsncat(pFullPath, hookTypeStr, wcslen(hookTypeStr));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ls.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));

	pInputBufLenStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED,  sizeof(UNICODE_STRING), 'PMDI');
	if (pInputBufLenStringUni == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  30, 'PMDI');
	if (pInputBufLenStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->MaximumLength = 30;

	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.Read.Length, 16, pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}


	if (pIoStackLocation->Parameters.Read.Length > 0)
	{
		// Dump memory
		pDataPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
		RtlZeroMemory(pDataPath, 4096 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, L"\\", wcslen(L"\\"));
		wcsncat(pDataPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / 2);
		LPWSTR dataTerminator = L".data";
		wcsncat(pDataPath, dataTerminator, wcslen(dataTerminator));
		// Create handle to pDataPath
		hDataFile = 0;
		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			goto cleanup;
		}
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
		pDataPath = NULL;
		// We dump the buffer later, as we need the target to fill in the buffer first.
	}
	// Write conf
	pConfPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
	RtlZeroMemory(pConfPath, 4096 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, L"\\", wcslen(L"\\"));
	wcsncat(pConfPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	LPWSTR confTerminator = L".conf";
	wcsncat(pConfPath, confTerminator, wcslen(confTerminator));
	hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		goto cleanup;
	}
	ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	pConfPath = NULL;
	// Write data to pConfFile handle
	confFileString = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
	RtlZeroMemory(confFileString, 4096 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:";
	wcsncpy(confFileString, drvHeader, wcslen(drvHeader));
	wcsncat(confFileString, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	LPWSTR newLine = L"\r\n";
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR typeHeader = L"Type:DEVIOR\r\n";
	wcsncat(confFileString, typeHeader, wcslen(typeHeader));
	LPWSTR ioctlHeader = L"IOCTL:";
	wcsncat(confFileString, ioctlHeader, wcslen(ioctlHeader));
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR inputLenHeader = L"InputBufferLength:";
	wcsncat(confFileString, inputLenHeader, wcslen(inputLenHeader));
	wcsncat(confFileString, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
	ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	pInputBufLenStringUni = NULL;
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR outputLenHeader = L"OutputBufferLength:";
	wcsncat(confFileString, outputLenHeader, wcslen(outputLenHeader));

	IO_STATUS_BLOCK statBlock;
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString) * sizeof(WCHAR), NULL, NULL);
	ZwClose(hConfFile);
	hConfFile = NULL;
	goto cleanup;
cleanup:
	// Check for NULL pointers and skip them, if we have a pointer that's non-null we free it, or if its a UNICODE type, we check if ->Buffer is NULL,
	// if not then we free that internal buffer first, then the UNICODE pointer.
	// Make sure we initialize all pointers as NULL at the start of this function, so that they may exist here for checking if we hit an error path and 
	// jump here early.
	if (confFileString != NULL) {
		ExFreePool2(confFileString, 'PMDI', NULL, NULL);
	}
	if (pConfPath != NULL) {
		ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	}
	if (pDataPath != NULL) {
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
	}
	if (pFullPath != NULL) {
		ExFreePool2(pFullPath, 'PMDI', NULL, NULL);
	}
	if (pObjName != NULL) {
		ExFreePool2(pObjName, 'PMDI', NULL, NULL);
	}
	if (pOutputBufLenStringUni != NULL) {
		if (pOutputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pOutputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pOutputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pInputBufLenStringUni != NULL) {
		if (pInputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pIoctlStringUni != NULL) {
		if (pIoctlStringUni->Buffer != NULL) {
			ExFreePool2(pIoctlStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pIoctlStringUni, 'PMDI', NULL, NULL);
	}
	if (pDevName != NULL) {
		if (pDevName->Buffer != NULL) {
			ExFreePool2(pDevName->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pDevName, 'PMDI', NULL, NULL);
	}
	// Check and close handles
	if (hConfFile != NULL) {
		ZwClose(hConfFile);
	}

	goto End;

End:
	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = deviceIoHooksRArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);

	// Call original overwritten address
	for (int i = 0; i < hookList->entry_count; i++)
	{
		if (RtlEqualUnicodeString(&hookList->entries[i].driverName, &drvName, false))
		{
			devIoCallRWD origFuncCall = (devIoCallRWD)hookList->entries[i].originalFunction;
			// Release lock
			ExReleaseFastMutex(hookList->lock);
			// Revert IRQL to value when we were called
			RaiseAndCheckIRQL(oldIRQL);
			// Call the original function now that we've logged it, then
			// return to caller
			NTSTATUS res = origFuncCall(DeviceObject, Irp);
	
			if (pIoStackLocation->Parameters.Read.Length > 0 && hDataFile != NULL) {

				LowerAndCheckIRQL();
				// Write data to pDataFile handle
				IO_STATUS_BLOCK statBlock;
				status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, Irp->AssociatedIrp.SystemBuffer, pIoStackLocation->Parameters.Read.Length, NULL, NULL);
				ZwClose(hDataFile);
				hDataFile = NULL;
				RaiseAndCheckIRQL(oldIRQL);
			}
			return res;


		}
	}
	// Release lock
	ExReleaseFastMutex(hookList->lock);
	// Rever IRQL
	RaiseAndCheckIRQL(oldIRQL);
	// Oops, cant find original hook address as something went wrong. We should never hit here, for debug purposes we crash the system. Alternatively, return 
	// a fake result to continue system execution
	__debugbreak();
	//return false;
}

NTSTATUS DeviceIoHookD(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	// We need to operate in PASSIVE_IRQL due to our file operations, ensure we're at that IRQL and save the current
	// IRQL so we can restore it later
	KIRQL oldIRQL = LowerAndCheckIRQL();
	// Initialize all our pointers to NULL, this allows us to check if they're non-null in our
	// cleanup phase without concerns of accessing non-initialized pointers.
	// Ensure whenever we free these pointers, we reset it back to NULL
	PUNICODE_STRING pOutputBufLenStringUni = NULL;
	LPWSTR confFileString = NULL;
	HANDLE hConfFile = NULL;
	LPWSTR pConfPath = NULL;
	HANDLE hDataFile = NULL;
	LPWSTR pDataPath = NULL;
	PUNICODE_STRING pInputBufLenStringUni = NULL;
	PUNICODE_STRING pIoctlStringUni = NULL;
	LPWSTR pFullPath = NULL;
	POBJECT_NAME_INFORMATION pObjName = NULL;
	PUNICODE_STRING pDevName = NULL;

	PVOID inBuf = NULL;
	PVOID outBuf = NULL;

	PIO_STACK_LOCATION pIoStackLocation;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);

	NTSTATUS status;
	// Debugging print 
	UNICODE_STRING drvName = DeviceObject->DriverObject->DriverName;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Driver Name:%wZ.\n", drvName));

	// Check if the device also has a name
	ULONG nameLen = 0;
	// ObQueryNameString will return the required size in nameLen if exists
	status = ObQueryNameString(DeviceObject, NULL, NULL, &nameLen);
	if (nameLen != 0) {
		// Name exists, lets allocate enough room for it
		pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, nameLen, 'PMDI');
		if (pObjName != NULL) {
			status = ObQueryNameString(DeviceObject, pObjName, nameLen, &nameLen);
			if (status == STATUS_SUCCESS) {
				if (pObjName->Name.Length == 0)
				{
					ExFreePool(pObjName);
				}
				else {
					// Name exists, lets copy it into pDevName and free the object_name_information object
					pDevName = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
					if (pDevName != NULL) {
						pDevName->Length = pObjName->Name.Length;
						pDevName->MaximumLength = pObjName->Name.MaximumLength;
						pDevName->Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, pObjName->Name.MaximumLength, 'PMDI');
						if (pDevName->Buffer != NULL) {
							memcpy(pDevName->Buffer, pObjName->Name.Buffer, pObjName->Name.Length);
						}
						// Copy finished, lets free pObjName
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
						// Detect if the copy failed due to a failed allocation
						if (pDevName->Buffer == NULL) {
							// Buffer failed to allocate, free pDevName and set it to NULL so we can detect the failure later
							ExFreePool2(pDevName, 'PMDI', NULL, NULL);
							pDevName = NULL;
						}
					}
					else {
						// pDevName failed to allocate, free pObjName and continue
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
					}

				}

			}

		}

	}
	// Now, pDevName will either be NULL or point to a UNICODE_STRING, If it's NULL, the device name did not exist, or failed to copy




	// Base folder for our driver hooks
	LPWSTR pCFolder = L"\\DosDevices\\C:\\DriverHooks";

	// Quick workaround instead of properly parsing slashes and creating the nested
	// folder structure. Ideally in CreateFolder we would check for the existence of each folder
	// in the path and create them if required
	LPWSTR pCFolder_tmp2 = L"\\DosDevices\\C:\\DriverHooks\\Driver";

	SIZE_T fullPathSz = 2048 * sizeof(WCHAR);

	// Used to hold the eventual full path of our data dump, with a max of 2048 characters
	pFullPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, fullPathSz, 'PMDI');
	if (pFullPath == NULL) {
		goto cleanup;
	}
	wcsncpy_s(pFullPath, fullPathSz, pCFolder, wcslen(pCFolder));

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	status = CreateFolder(pCFolder_tmp2);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder2.\n"));

	
	wcsncat(pFullPath, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	


	pIoctlStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(UNICODE_STRING), 'PMDI');
	if (pIoctlStringUni == NULL) {
		goto cleanup;
	}
	pIoctlStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  30, 'PMDI');
	if (pIoctlStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pIoctlStringUni->MaximumLength = 30;
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode, 16, pIoctlStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	LPWSTR hookTypeStr = L"\\devIOD";
	// Concat ioctl string to full path
	wcsncat(pFullPath, hookTypeStr, wcslen(hookTypeStr));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	wcsncat(pFullPath, L"\\", wcslen(L"\\"));
	wcsncat(pFullPath, pIoctlStringUni->Buffer, pIoctlStringUni->Length / sizeof(WCHAR));


	// Input & output buffer location will differ based on IoControlCode
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
		// This should never be hit, something went wrong if so. Print an error and go to cleanup
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ERROR: Unknown IOCTL method: %lu.\n", pIoStackLocation->Parameters.DeviceIoControl.IoControlCode));
		goto cleanup;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ls.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));

	pInputBufLenStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
	if (pInputBufLenStringUni == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  30, 'PMDI');
	if (pInputBufLenStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->MaximumLength = 30;

	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength, 16, pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}


	if (pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength > 0 && inBuf != NULL)
	{
		// Dump memory
		pDataPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
		RtlZeroMemory(pDataPath, 4096 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, L"\\", wcslen(L"\\"));
		wcsncat(pDataPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / 2);
		LPWSTR dataTerminator = L".data";
		wcsncat(pDataPath, dataTerminator, wcslen(dataTerminator));
		// Create handle to pDataPath
		hDataFile = 0;
		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			goto cleanup;
		}
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
		pDataPath = NULL;
		// Write data to pDataFile handle
		IO_STATUS_BLOCK statBlock;
		status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, inBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength, NULL, NULL);
		ZwClose(hDataFile);
		hDataFile = NULL;
		if (!NT_SUCCESS(status))
		{
			// Error writing file
			goto cleanup;
		}
	}
	// Write conf
	pConfPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
	RtlZeroMemory(pConfPath, 4096 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, L"\\", wcslen(L"\\"));
	wcsncat(pConfPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	LPWSTR confTerminator = L".conf";
	wcsncat(pConfPath, confTerminator, wcslen(confTerminator));
	hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		goto cleanup;
	}
	ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	pConfPath = NULL;
	// Write data to pConfFile handle
	confFileString = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
	RtlZeroMemory(confFileString, 4096 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:";
	wcsncpy(confFileString, drvHeader, wcslen(drvHeader));
	wcsncat(confFileString, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	LPWSTR newLine = L"\r\n";
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR typeHeader = L"Type:DEVIOD\r\n";
	wcsncat(confFileString, typeHeader, wcslen(typeHeader));
	LPWSTR type2Header = L"BuffType:";
	LPWSTR buffHeader = L"METHOD_BUFFERED\r\n";
	LPWSTR inDir = L"METHOD_IN_DIRECT\r\n";
	LPWSTR outDir = L"METHOD_OUT_DIRECT\r\n";
	LPWSTR neiDir = L"METHOD_NEITHER\r\n";
	wcsncat(confFileString, type2Header, wcslen(type2Header));
	switch (METHOD_FROM_CTL_CODE(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode))
	{
	case METHOD_BUFFERED:
		wcsncat(confFileString, buffHeader, wcslen(buffHeader)); break;
	case METHOD_IN_DIRECT:
		wcsncat(confFileString, inDir, wcslen(inDir)); break;
	case METHOD_OUT_DIRECT:
		wcsncat(confFileString, outDir, wcslen(outDir)); break;
	case METHOD_NEITHER:
		wcsncat(confFileString, neiDir, wcslen(neiDir)); break;
	default:
		goto cleanup;
	}
	LPWSTR ioctlHeader = L"IOCTL:";
	wcsncat(confFileString, ioctlHeader, wcslen(ioctlHeader));
	wcsncat(confFileString, pIoctlStringUni->Buffer, pIoctlStringUni->Length / sizeof(WCHAR));
	ExFreePool2(pIoctlStringUni->Buffer, 'PMDI', NULL, NULL);
	ExFreePool2(pIoctlStringUni, 'PMDI', NULL, NULL);
	pIoctlStringUni = NULL;
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR inputLenHeader = L"InputBufferLength:";
	wcsncat(confFileString, inputLenHeader, wcslen(inputLenHeader));
	wcsncat(confFileString, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
	ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	pInputBufLenStringUni = NULL;
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR outputLenHeader = L"OutputBufferLength:";
	wcsncat(confFileString, outputLenHeader, wcslen(outputLenHeader));

	pOutputBufLenStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
	if (pOutputBufLenStringUni == NULL) {
		goto cleanup;
	}
	pOutputBufLenStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  60, 'PMDI');
	if (pOutputBufLenStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pOutputBufLenStringUni->MaximumLength = 60;
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength, 16, pOutputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	wcsncat(confFileString, pOutputBufLenStringUni->Buffer, pOutputBufLenStringUni->Length / sizeof(WCHAR));

	ExFreePool2(pOutputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
	ExFreePool2(pOutputBufLenStringUni, 'PMDI', NULL, NULL);
	pOutputBufLenStringUni = NULL;

	IO_STATUS_BLOCK statBlock;
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString) * sizeof(WCHAR), NULL, NULL);
	ZwClose(hConfFile);
	hConfFile = NULL;
	goto cleanup;
cleanup:
	// Check for NULL pointers and skip them, if we have a pointer that's non-null we free it, or if its a UNICODE type, we check if ->Buffer is NULL,
	// if not then we free that internal buffer first, then the UNICODE pointer.
	// Make sure we initialize all pointers as NULL at the start of this function, so that they may exist here for checking if we hit an error path and 
	// jump here early.
	if (confFileString != NULL) {
		ExFreePool2(confFileString, 'PMDI', NULL, NULL);
	}
	if (pConfPath != NULL) {
		ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	}
	if (pDataPath != NULL) {
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
	}
	if (pFullPath != NULL) {
		ExFreePool2(pFullPath, 'PMDI', NULL, NULL);
	}
	if (pObjName != NULL) {
		ExFreePool2(pObjName, 'PMDI', NULL, NULL);
	}
	if (pOutputBufLenStringUni != NULL) {
		if (pOutputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pOutputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pOutputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pInputBufLenStringUni != NULL) {
		if (pInputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pIoctlStringUni != NULL) {
		if (pIoctlStringUni->Buffer != NULL) {
			ExFreePool2(pIoctlStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pIoctlStringUni, 'PMDI', NULL, NULL);
	}
	if (pDevName != NULL) {
		if (pDevName->Buffer != NULL) {
			ExFreePool2(pDevName->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pDevName, 'PMDI', NULL, NULL);
	}
	// Check and close handles
	if (hConfFile != NULL) {
		ZwClose(hConfFile);
	}
	if (hDataFile != NULL) {
		ZwClose(hDataFile);
	}
	goto End;

End:
	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = deviceIoHooksDArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);

	// Call original overwritten address
	for (int i = 0; i < hookList->entry_count; i++)
	{
		if (RtlEqualUnicodeString(&hookList->entries[i].driverName, &drvName, false))
		{
			devIoCallRWD origFuncCall = (devIoCallRWD)hookList->entries[i].originalFunction;
			// Release lock
			ExReleaseFastMutex(hookList->lock);
			// Revert IRQL to value when we were called
			RaiseAndCheckIRQL(oldIRQL);
			// Call the original function now that we've logged it, then
			// return to caller
			return origFuncCall(DeviceObject, Irp);
		}
	}
	// Release lock
	ExReleaseFastMutex(hookList->lock);
	// Rever IRQL
	RaiseAndCheckIRQL(oldIRQL);
	// Oops, cant find original hook address as something went wrong. We should never hit here, for debug purposes we crash the system. Alternatively, return 
	// a fake result to continue system execution
	__debugbreak();
	//return false;
}


NTSTATUS FileIoHookD(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	// We need to operate in PASSIVE_IRQL due to our file operations, ensure we're at that IRQL and save the current
	// IRQL so we can restore it later
	KIRQL oldIRQL = LowerAndCheckIRQL();
	// Initialize all our pointers to NULL, this allows us to check if they're non-null in our
	// cleanup phase without concerns of accessing non-initialized pointers.
	// Ensure whenever we free these pointers, we reset it back to NULL
	PUNICODE_STRING pOutputBufLenStringUni = NULL;
	LPWSTR confFileString = NULL;
	HANDLE hConfFile = NULL;
	LPWSTR pConfPath = NULL;
	HANDLE hDataFile = NULL;
	LPWSTR pDataPath = NULL;
	PUNICODE_STRING pInputBufLenStringUni = NULL;
	PUNICODE_STRING pIoctlStringUni = NULL;
	LPWSTR pFullPath = NULL;
	POBJECT_NAME_INFORMATION pObjName = NULL;
	PUNICODE_STRING pDevName = NULL;

	PVOID inBuf = NULL;
	PVOID outBuf = NULL;

	PIO_STACK_LOCATION pIoStackLocation;
	pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);

	NTSTATUS status;
	// Debugging print 
	UNICODE_STRING drvName = DeviceObject->DriverObject->DriverName;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Driver Name:%wZ.\n", drvName));

	// Check if the device also has a name
	ULONG nameLen = 0;
	// ObQueryNameString will return the required size in nameLen if exists
	status = ObQueryNameString(DeviceObject, NULL, NULL, &nameLen);
	if (nameLen != 0) {
		// Name exists, lets allocate enough room for it
		pObjName = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, nameLen, 'PMDI');
		if (pObjName != NULL) {
			status = ObQueryNameString(DeviceObject, pObjName, nameLen, &nameLen);
			if (status == STATUS_SUCCESS) {
				if (pObjName->Name.Length == 0)
				{
					ExFreePool(pObjName);
				}
				else {
					// Name exists, lets copy it into pDevName and free the object_name_information object
					pDevName = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
					if (pDevName != NULL) {
						pDevName->Length = pObjName->Name.Length;
						pDevName->MaximumLength = pObjName->Name.MaximumLength;
						pDevName->Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, pObjName->Name.MaximumLength, 'PMDI');
						if (pDevName->Buffer != NULL) {
							memcpy(pDevName->Buffer, pObjName->Name.Buffer, pObjName->Name.Length);
						}
						// Copy finished, lets free pObjName
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
						// Detect if the copy failed due to a failed allocation
						if (pDevName->Buffer == NULL) {
							// Buffer failed to allocate, free pDevName and set it to NULL so we can detect the failure later
							ExFreePool2(pDevName, 'PMDI', NULL, NULL);
							pDevName = NULL;
						}
					}
					else {
						// pDevName failed to allocate, free pObjName and continue
						ExFreePool2(pObjName, 'PMDI', NULL, NULL);
						pObjName = NULL;
					}

				}

			}

		}

	}
	// Now, pDevName will either be NULL or point to a UNICODE_STRING, If it's NULL, the device name did not exist, or failed to copy




	// Base folder for our driver hooks
	LPWSTR pCFolder = L"\\DosDevices\\C:\\DriverHooks";

	// Quick workaround instead of properly parsing slashes and creating the nested
	// folder structure. Ideally in CreateFolder we would check for the existence of each folder
	// in the path and create them if required
	LPWSTR pCFolder_tmp2 = L"\\DosDevices\\C:\\DriverHooks\\Driver";

	SIZE_T fullPathSz = 2048 * sizeof(WCHAR);

	// Used to hold the eventual full path of our data dump, with a max of 2048 characters
	pFullPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  fullPathSz, 'PMDI');
	if (pFullPath == NULL) {
		goto cleanup;
	}
	wcsncpy_s(pFullPath, fullPathSz, pCFolder, wcslen(pCFolder));

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ws.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	status = CreateFolder(pCFolder_tmp2);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder2.\n"));

	
	wcsncat(pFullPath, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created initial folder.\n"));

	



	pIoctlStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
	if (pIoctlStringUni == NULL) {
		goto cleanup;
	}
	pIoctlStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  30, 'PMDI');
	if (pIoctlStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pIoctlStringUni->MaximumLength = 30;
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode, 16, pIoctlStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	LPWSTR hookTypeStr = L"\\fileIOD";
	// Concat ioctl string to full path
	wcsncat(pFullPath, hookTypeStr, wcslen(hookTypeStr));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	wcsncat(pFullPath, L"\\", wcslen(L"\\"));
	wcsncat(pFullPath, pIoctlStringUni->Buffer, pIoctlStringUni->Length / sizeof(WCHAR));


	// Input & output buffer location will differ based on IoControlCode
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
		// This should never be hit, something went wrong if so. Print an error and go to cleanup
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ERROR: Unknown IOCTL method: %lu.\n", pIoStackLocation->Parameters.DeviceIoControl.IoControlCode));
		goto cleanup;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Creating folder:%ls.\n", pFullPath));
	status = CreateFolder(pFullPath);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "INFO: Created folder 2.\n"));

	pInputBufLenStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
	if (pInputBufLenStringUni == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED,  30, 'PMDI');
	if (pInputBufLenStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pInputBufLenStringUni->MaximumLength = 30;

	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength, 16, pInputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}


	if (pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength > 0 && inBuf != NULL)
	{
		// Dump memory
		pDataPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
		RtlZeroMemory(pDataPath, 4096 * sizeof(WCHAR));
		wcscat(pDataPath, pFullPath);
		wcsncat(pDataPath, L"\\", wcslen(L"\\"));
		wcsncat(pDataPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / 2);
		LPWSTR dataTerminator = L".data";
		wcsncat(pDataPath, dataTerminator, wcslen(dataTerminator));
		// Create handle to pDataPath
		hDataFile = 0;
		status = CreateFileHelper(pDataPath, GENERIC_WRITE, FILE_CREATE, &hDataFile);
		if (!NT_SUCCESS(status))
		{
			// File probably exists already, lets quit
			goto cleanup;
		}
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
		pDataPath = NULL;
		// Write data to pDataFile handle
		IO_STATUS_BLOCK statBlock;
		status = ZwWriteFile(hDataFile, NULL, NULL, NULL, &statBlock, inBuf, pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength, NULL, NULL);
		ZwClose(hDataFile);
		hDataFile = NULL;
		if (!NT_SUCCESS(status))
		{
			// Error writing file
			goto cleanup;
		}
	}
	// Write conf
	pConfPath = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
	RtlZeroMemory(pConfPath, 4096 * sizeof(WCHAR));
	wcscpy(pConfPath, pFullPath);
	wcsncat(pConfPath, L"\\", wcslen(L"\\"));
	wcsncat(pConfPath, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	LPWSTR confTerminator = L".conf";
	wcsncat(pConfPath, confTerminator, wcslen(confTerminator));
	hConfFile = 0;
	status = CreateFileHelper(pConfPath, GENERIC_WRITE, FILE_CREATE, &hConfFile);
	if (!NT_SUCCESS(status))
	{
		// File probably exists already, lets quit
		goto cleanup;
	}
	ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	pConfPath = NULL;
	// Write data to pConfFile handle
	confFileString = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 4096 * sizeof(WCHAR), 'PMDI');
	RtlZeroMemory(confFileString, 4096 * sizeof(WCHAR));
	LPWSTR drvHeader = L"DriverName:";
	wcsncpy(confFileString, drvHeader, wcslen(drvHeader));
	wcsncat(confFileString, drvName.Buffer, drvName.Length / sizeof(WCHAR));
	LPWSTR newLine = L"\r\n";
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR typeHeader = L"Type:FILEIOD\r\n";
	wcsncat(confFileString, typeHeader, wcslen(typeHeader));
	LPWSTR type2Header = L"BuffType:";
	LPWSTR buffHeader = L"METHOD_BUFFERED\r\n";
	LPWSTR inDir = L"METHOD_IN_DIRECT\r\n";
	LPWSTR outDir = L"METHOD_OUT_DIRECT\r\n";
	LPWSTR neiDir = L"METHOD_NEITHER\r\n";
	wcsncat(confFileString, type2Header, wcslen(type2Header));
	switch (METHOD_FROM_CTL_CODE(pIoStackLocation->Parameters.DeviceIoControl.IoControlCode))
	{
	case METHOD_BUFFERED:
		wcsncat(confFileString, buffHeader, wcslen(buffHeader)); break;
	case METHOD_IN_DIRECT:
		wcsncat(confFileString, inDir, wcslen(inDir)); break;
	case METHOD_OUT_DIRECT:
		wcsncat(confFileString, outDir, wcslen(outDir)); break;
	case METHOD_NEITHER:
		wcsncat(confFileString, neiDir, wcslen(neiDir)); break;
	default:
		goto cleanup;
	}
	LPWSTR ioctlHeader = L"IOCTL:";
	wcsncat(confFileString, ioctlHeader, wcslen(ioctlHeader));
	wcsncat(confFileString, pIoctlStringUni->Buffer, pIoctlStringUni->Length / sizeof(WCHAR));
	ExFreePool2(pIoctlStringUni->Buffer, 'PMDI', NULL, NULL);
	ExFreePool2(pIoctlStringUni, 'PMDI', NULL, NULL);
	pIoctlStringUni = NULL;
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR inputLenHeader = L"InputBufferLength:";
	wcsncat(confFileString, inputLenHeader, wcslen(inputLenHeader));
	wcsncat(confFileString, pInputBufLenStringUni->Buffer, pInputBufLenStringUni->Length / sizeof(WCHAR));
	ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
	ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	pInputBufLenStringUni = NULL;
	wcsncat(confFileString, newLine, wcslen(newLine));
	LPWSTR outputLenHeader = L"OutputBufferLength:";
	wcsncat(confFileString, outputLenHeader, wcslen(outputLenHeader));

	pOutputBufLenStringUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'PMDI');
	if (pOutputBufLenStringUni == NULL) {
		goto cleanup;
	}
	pOutputBufLenStringUni->Buffer = (LPWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 60, 'PMDI');
	if (pOutputBufLenStringUni->Buffer == NULL) {
		goto cleanup;
	}
	pOutputBufLenStringUni->MaximumLength = 60;
	status = RtlIntegerToUnicodeString(pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength, 16, pOutputBufLenStringUni);
	if (!NT_SUCCESS(status))
	{
		goto cleanup;
	}

	wcsncat(confFileString, pOutputBufLenStringUni->Buffer, pOutputBufLenStringUni->Length / sizeof(WCHAR));

	ExFreePool2(pOutputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
	ExFreePool2(pOutputBufLenStringUni, 'PMDI', NULL, NULL);
	pOutputBufLenStringUni = NULL;

	IO_STATUS_BLOCK statBlock;
	status = ZwWriteFile(hConfFile, NULL, NULL, NULL, &statBlock, confFileString, wcslen(confFileString) * sizeof(WCHAR), NULL, NULL);
	ZwClose(hConfFile);
	hConfFile = NULL;
	goto cleanup;
cleanup:
	// Check for NULL pointers and skip them, if we have a pointer that's non-null we free it, or if its a UNICODE type, we check if ->Buffer is NULL,
	// if not then we free that internal buffer first, then the UNICODE pointer.
	// Make sure we initialize all pointers as NULL at the start of this function, so that they may exist here for checking if we hit an error path and 
	// jump here early.
	if (confFileString != NULL) {
		ExFreePool2(confFileString, 'PMDI', NULL, NULL);
	}
	if (pConfPath != NULL) {
		ExFreePool2(pConfPath, 'PMDI', NULL, NULL);
	}
	if (pDataPath != NULL) {
		ExFreePool2(pDataPath, 'PMDI', NULL, NULL);
	}
	if (pFullPath != NULL) {
		ExFreePool2(pFullPath, 'PMDI', NULL, NULL);
	}
	if (pObjName != NULL) {
		ExFreePool2(pObjName, 'PMDI', NULL, NULL);
	}
	if (pOutputBufLenStringUni != NULL) {
		if (pOutputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pOutputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pOutputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pInputBufLenStringUni != NULL) {
		if (pInputBufLenStringUni->Buffer != NULL) {
			ExFreePool2(pInputBufLenStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pInputBufLenStringUni, 'PMDI', NULL, NULL);
	}
	if (pIoctlStringUni != NULL) {
		if (pIoctlStringUni->Buffer != NULL) {
			ExFreePool2(pIoctlStringUni->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pIoctlStringUni, 'PMDI', NULL, NULL);
	}
	if (pDevName != NULL) {
		if (pDevName->Buffer != NULL) {
			ExFreePool2(pDevName->Buffer, 'PMDI', NULL, NULL);
		}
		ExFreePool2(pDevName, 'PMDI', NULL, NULL);
	}
	// Check and close handles
	if (hConfFile != NULL) {
		ZwClose(hConfFile);
	}
	if (hDataFile != NULL) {
		ZwClose(hDataFile);
	}
	goto End;

End:
	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = fileIoHooksDArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);

	// Call original overwritten address
	for (int i = 0; i < hookList->entry_count; i++)
	{
		if (RtlEqualUnicodeString(&hookList->entries[i].driverName, &drvName, false))
		{
			devIoCallRWD origFuncCall = (devIoCallRWD)hookList->entries[i].originalFunction;
			// Release lock
			ExReleaseFastMutex(hookList->lock);
			// Revert IRQL to value when we were called
			RaiseAndCheckIRQL(oldIRQL);
			// Call the original function now that we've logged it, then
			// return to caller
			return origFuncCall(DeviceObject, Irp);
		}
	}
	// Release lock
	ExReleaseFastMutex(hookList->lock);
	// Rever IRQL
	RaiseAndCheckIRQL(oldIRQL);
	// Oops, cant find original hook address as something went wrong. We should never hit here, for debug purposes we crash the system. Alternatively, return 
	// a fake result to continue system execution
	__debugbreak();
	//return false;
}







/// <summary>
/// Hooks the target function as a `FastIoHookD` type,
/// </summary>
/// <param name="originalFunc">
/// Pointer to the original function we're overwriting
/// </param>
/// <param name="hookDumpFunc">
/// Our function that will replace the original target function
/// </param>
/// <param name="driverName">
/// The name of the device driver we're hooking
/// </param>
/// <returns></returns>
NTSTATUS AddFastIOHookD(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{
	
	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;

	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = fastIoHooksDArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);
	// Execution has resumed, meaning we have obtained the lock, we can continue processing and ensure we release the lock
	// before returning from this function

	// Check if there is room to add a new hook
	if (hookList->entry_count == hookList->entry_max) {
		// No room to add hook, release the lock and return an error
		ExReleaseFastMutex(hookList->lock);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// We have room to add a new hook, the array is always sorted such that there are no gaps between hooks, this means
	// the next free index in the array is always the count of elements (we ensure we don't remove hooks, or if we do, we re-sort the array to eliminate gaps between entries)

	// Before we add the entry, lets ensure the entry doesn't already exist
	for (int i = 0; i < hookList->entry_count; i++) {
		if (hookList->entries[i].originalFunction == originalFunc) {
			// Target function is already hooked, release lock and return error
			ExReleaseFastMutex(hookList->lock);
			return STATUS_INVALID_PARAMETER;
		}
	}
	// If we reach here, hook doesn't exist, we can add our new hook
	hookList->entries[hookList->entry_count] = newHook;
	// Increment entry_count to the next free index
	hookList->entry_count += 1;
	
	InterlockedExchangePointer(originalFunc, hookDumpFunc);

	// release hook
	ExReleaseFastMutex(hookList->lock);

	return STATUS_SUCCESS;
}

/// <summary>
/// Hooks the target function as a `FastIoHookR` type,
/// </summary>
/// <param name="originalFunc">
/// Pointer to the original function we're overwriting
/// </param>
/// <param name="hookDumpFunc">
/// Our function that will replace the original target function
/// </param>
/// <param name="driverName">
/// The name of the device driver we're hooking
/// </param>
/// <returns></returns>
NTSTATUS AddFastIOHookR(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{

	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;

	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = fastIoHooksRArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);
	// Execution has resumed, meaning we have obtained the lock, we can continue processing and ensure we release the lock
	// before returning from this function

	// Check if there is room to add a new hook
	if (hookList->entry_count == hookList->entry_max) {
		// No room to add hook, release the lock and return an error
		ExReleaseFastMutex(hookList->lock);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// We have room to add a new hook, the array is always sorted such that there are no gaps between hooks, this means
	// the next free index in the array is always the count of elements (we ensure we don't remove hooks, or if we do, we re-sort the array to eliminate gaps between entries)

	// Before we add the entry, lets ensure the entry doesn't already exist
	for (int i = 0; i < hookList->entry_count; i++) {
		if (hookList->entries[i].originalFunction == originalFunc) {
			// Target function is already hooked, release lock and return error
			ExReleaseFastMutex(hookList->lock);
			return STATUS_INVALID_PARAMETER;
		}
	}
	// If we reach here, hook doesn't exist, we can add our new hook
	hookList->entries[hookList->entry_count] = newHook;
	// Increment entry_count to the next free index
	hookList->entry_count += 1;

	InterlockedExchangePointer(originalFunc, hookDumpFunc);;

	// release hook
	ExReleaseFastMutex(hookList->lock);

	return STATUS_SUCCESS;
}


/// <summary>
/// Hooks the target function as a `FastIoHookW` type,
/// </summary>
/// <param name="originalFunc">
/// Pointer to the original function we're overwriting
/// </param>
/// <param name="hookDumpFunc">
/// Our function that will replace the original target function
/// </param>
/// <param name="driverName">
/// The name of the device driver we're hooking
/// </param>
/// <returns></returns>
NTSTATUS AddFastIOHookW(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{

	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;

	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = fastIoHooksWArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);
	// Execution has resumed, meaning we have obtained the lock, we can continue processing and ensure we release the lock
	// before returning from this function

	// Check if there is room to add a new hook
	if (hookList->entry_count == hookList->entry_max) {
		// No room to add hook, release the lock and return an error
		ExReleaseFastMutex(hookList->lock);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// We have room to add a new hook, the array is always sorted such that there are no gaps between hooks, this means
	// the next free index in the array is always the count of elements (we ensure we don't remove hooks, or if we do, we re-sort the array to eliminate gaps between entries)

	// Before we add the entry, lets ensure the entry doesn't already exist
	for (int i = 0; i < hookList->entry_count; i++) {
		if (hookList->entries[i].originalFunction == originalFunc) {
			// Target function is already hooked, release lock and return error
			ExReleaseFastMutex(hookList->lock);
			return STATUS_INVALID_PARAMETER;
		}
	}
	// If we reach here, hook doesn't exist, we can add our new hook
	hookList->entries[hookList->entry_count] = newHook;
	// Increment entry_count to the next free index
	hookList->entry_count += 1;

	InterlockedExchangePointer(originalFunc, hookDumpFunc);;

	// release hook
	ExReleaseFastMutex(hookList->lock);

	return STATUS_SUCCESS;
}

/// <summary>
/// Hooks the target function as a `DeviceIoHookD` type,
/// </summary>
/// <param name="originalFunc">
/// Pointer to the original function we're overwriting
/// </param>
/// <param name="hookDumpFunc">
/// Our function that will replace the original target function
/// </param>
/// <param name="driverName">
/// The name of the device driver we're hooking
/// </param>
/// <returns></returns>
NTSTATUS AddDeviceIOHookD(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{

	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;

	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = deviceIoHooksDArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);
	// Execution has resumed, meaning we have obtained the lock, we can continue processing and ensure we release the lock
	// before returning from this function

	// Check if there is room to add a new hook
	if (hookList->entry_count == hookList->entry_max) {
		// No room to add hook, release the lock and return an error
		ExReleaseFastMutex(hookList->lock);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// We have room to add a new hook, the array is always sorted such that there are no gaps between hooks, this means
	// the next free index in the array is always the count of elements (we ensure we don't remove hooks, or if we do, we re-sort the array to eliminate gaps between entries)

	// Before we add the entry, lets ensure the entry doesn't already exist
	for (int i = 0; i < hookList->entry_count; i++) {
		if (hookList->entries[i].originalFunction == originalFunc) {
			// Target function is already hooked, release lock and return error
			ExReleaseFastMutex(hookList->lock);
			return STATUS_INVALID_PARAMETER;
		}
	}
	// If we reach here, hook doesn't exist, we can add our new hook
	hookList->entries[hookList->entry_count] = newHook;
	// Increment entry_count to the next free index
	hookList->entry_count += 1;

	InterlockedExchangePointer(originalFunc, hookDumpFunc);;

	// release hook
	ExReleaseFastMutex(hookList->lock);

	return STATUS_SUCCESS;
}

/// <summary>
/// Hooks the target function as a `DeviceIoHookR` type,
/// </summary>
/// <param name="originalFunc">
/// Pointer to the original function we're overwriting
/// </param>
/// <param name="hookDumpFunc">
/// Our function that will replace the original target function
/// </param>
/// <param name="driverName">
/// The name of the device driver we're hooking
/// </param>
/// <returns></returns>
NTSTATUS AddDeviceIOHookR(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{

	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;

	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = deviceIoHooksRArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);
	// Execution has resumed, meaning we have obtained the lock, we can continue processing and ensure we release the lock
	// before returning from this function

	// Check if there is room to add a new hook
	if (hookList->entry_count == hookList->entry_max) {
		// No room to add hook, release the lock and return an error
		ExReleaseFastMutex(hookList->lock);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// We have room to add a new hook, the array is always sorted such that there are no gaps between hooks, this means
	// the next free index in the array is always the count of elements (we ensure we don't remove hooks, or if we do, we re-sort the array to eliminate gaps between entries)

	// Before we add the entry, lets ensure the entry doesn't already exist
	for (int i = 0; i < hookList->entry_count; i++) {
		if (hookList->entries[i].originalFunction == originalFunc) {
			// Target function is already hooked, release lock and return error
			ExReleaseFastMutex(hookList->lock);
			return STATUS_INVALID_PARAMETER;
		}
	}
	// If we reach here, hook doesn't exist, we can add our new hook
	hookList->entries[hookList->entry_count] = newHook;
	// Increment entry_count to the next free index
	hookList->entry_count += 1;

	InterlockedExchangePointer(originalFunc, hookDumpFunc);;

	// release hook
	ExReleaseFastMutex(hookList->lock);

	return STATUS_SUCCESS;
}

/// <summary>
/// Hooks the target function as a `DeviceIoHookW` type,
/// </summary>
/// <param name="originalFunc">
/// Pointer to the original function we're overwriting
/// </param>
/// <param name="hookDumpFunc">
/// Our function that will replace the original target function
/// </param>
/// <param name="driverName">
/// The name of the device driver we're hooking
/// </param>
/// <returns></returns>
NTSTATUS AddDeviceIOHookW(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{

	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;

	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = deviceIoHooksWArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);
	// Execution has resumed, meaning we have obtained the lock, we can continue processing and ensure we release the lock
	// before returning from this function

	// Check if there is room to add a new hook
	if (hookList->entry_count == hookList->entry_max) {
		// No room to add hook, release the lock and return an error
		ExReleaseFastMutex(hookList->lock);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// We have room to add a new hook, the array is always sorted such that there are no gaps between hooks, this means
	// the next free index in the array is always the count of elements (we ensure we don't remove hooks, or if we do, we re-sort the array to eliminate gaps between entries)

	// Before we add the entry, lets ensure the entry doesn't already exist
	for (int i = 0; i < hookList->entry_count; i++) {
		if (hookList->entries[i].originalFunction == originalFunc) {
			// Target function is already hooked, release lock and return error
			ExReleaseFastMutex(hookList->lock);
			return STATUS_INVALID_PARAMETER;
		}
	}
	// If we reach here, hook doesn't exist, we can add our new hook
	hookList->entries[hookList->entry_count] = newHook;
	// Increment entry_count to the next free index
	hookList->entry_count += 1;

	InterlockedExchangePointer(originalFunc, hookDumpFunc);;

	// release hook
	ExReleaseFastMutex(hookList->lock);

	return STATUS_SUCCESS;
}

/// <summary>
/// Hooks the target function as a `FileIoHookD` type,
/// </summary>
/// <param name="originalFunc">
/// Pointer to the original function we're overwriting
/// </param>
/// <param name="hookDumpFunc">
/// Our function that will replace the original target function
/// </param>
/// <param name="driverName">
/// The name of the device driver we're hooking
/// </param>
/// <returns></returns>
NTSTATUS AddFileIOHookD(PVOID* originalFunc, PVOID hookDumpFunc, UNICODE_STRING driverName)
{

	IoHooks newHook = { 0 };
	newHook.driverName = driverName;
	newHook.originalFunction = *originalFunc;
	newHook.hookedAddress = originalFunc;

	// Use the `hookList` var for the rest of this function instead of the global, to mitigate typos
	IoHookList* hookList = fileIoHooksDArray;

	// Obtain lock to our IoHookList to prevent concurrency issues
	ExAcquireFastMutex(hookList->lock);
	// Execution has resumed, meaning we have obtained the lock, we can continue processing and ensure we release the lock
	// before returning from this function

	// Check if there is room to add a new hook
	if (hookList->entry_count == hookList->entry_max) {
		// No room to add hook, release the lock and return an error
		ExReleaseFastMutex(hookList->lock);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// We have room to add a new hook, the array is always sorted such that there are no gaps between hooks, this means
	// the next free index in the array is always the count of elements (we ensure we don't remove hooks, or if we do, we re-sort the array to eliminate gaps between entries)

	// Before we add the entry, lets ensure the entry doesn't already exist
	for (int i = 0; i < hookList->entry_count; i++) {
		if (hookList->entries[i].originalFunction == originalFunc) {
			// Target function is already hooked, release lock and return error
			ExReleaseFastMutex(hookList->lock);
			return STATUS_INVALID_PARAMETER;
		}
	}
	// If we reach here, hook doesn't exist, we can add our new hook
	hookList->entries[hookList->entry_count] = newHook;
	// Increment entry_count to the next free index
	hookList->entry_count += 1;

	InterlockedExchangePointer(originalFunc, hookDumpFunc);;

	// release hook
	ExReleaseFastMutex(hookList->lock);

	return STATUS_SUCCESS;
}

/// <summary>
/// Hook the target `address`, saving the hook metadata into the appropriate global depending on the `type` parameter.
/// </summary>
/// <param name="address">
/// Kernel address to hook, should be a FastIo or DeviceIo function for the target driver
/// </param>
/// <param name="type">
/// Type of function we're hooking, should be a FastIo* or DeviceIo* type
/// </param>
/// <param name="driverName">
/// Name of the device driver we're hooking, used for bookkeeping purposes
/// </param>
/// <returns>
/// Success, unless the hook type is invalid
/// </returns>
NTSTATUS DoManualHook(PVOID* address, short type, UNICODE_STRING driverName)
{
	NTSTATUS status;
	PVOID hookDumpFunc;
	PVOID* originalFunc = address;
	// If type is valid, we call the appropriate hook function that will hook the address and save the hook metadata based
	// on the type.
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

/// <summary>
/// Find the IOCTL handlers for a target device driver and hook them
/// </summary>
/// <param name="driverName">
/// The name of a target device driver to hook
/// </param>
/// <returns>
/// Status code indicating success or failure
/// </returns>
NTSTATUS DoAutoHook(UNICODE_STRING driverName)
{
	NTSTATUS status;
	PFILE_OBJECT phFile = NULL;
	PDEVICE_OBJECT phDev = NULL;
	// Use IoGetDeviceObjectPointer to get the associated Device (then, Driver) object
	// for the target, once we obtain the object we can find the IOCTL handlers inside the
	// object struct.
	status = IoGetDeviceObjectPointer(&driverName, FILE_READ_ACCESS, &phFile, &phDev);
	// Check if we succeeded, if not then print an error to any attached kernel debugger and return the appropriate
	// status to the user.
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
	// Check if FastIoDispatch routines are set for our target, if they are then we ensure we hook them too
	PFAST_IO_DISPATCH fastIoDispatch = phDriv->FastIoDispatch;
	if (fastIoDispatch != NULL)
	{
		status = DoManualHook((PVOID*)&fastIoDispatch->FastIoDeviceControl, TYPE_FASTIOD, phDriv->DriverName);
		status = DoManualHook((PVOID*)&fastIoDispatch->FastIoRead, TYPE_FASTIOR, phDriv->DriverName);
		status = DoManualHook((PVOID*)&fastIoDispatch->FastIoWrite, TYPE_FASTIOW, phDriv->DriverName);
	}
	// The handlers below should always be set for any driver (if they're unimplemeneted, they'll be still be set to a dummy
	// handler, therefore its always safe to hook without checking for their existance, unlike their FastIo counterparts)
	// We hook each function, passing the address to hook and the function type & driver name to our `DoManualHook` function.
	status = DoManualHook((PVOID*)&phDriv->MajorFunction[IRP_MJ_DEVICE_CONTROL], TYPE_DEVICEIOD, phDriv->DriverName);
	status = DoManualHook((PVOID*)&phDriv->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL], TYPE_FILEIOD, phDriv->DriverName);
	status = DoManualHook((PVOID*)&phDriv->MajorFunction[IRP_MJ_READ], TYPE_DEVICEIOR, phDriv->DriverName);
	status = DoManualHook((PVOID*)&phDriv->MajorFunction[IRP_MJ_WRITE], TYPE_DEVICEIOW, phDriv->DriverName);
	return status;
}

/// <summary>
/// Parse the `HookRequest` provided by user via IOCTL.
/// We will determine what the mode is, and hook as appropriate.
/// Manual hooks will hook the user provided address and interpret it as the `HookRequest.Type` function.
/// Auto hooks will use the user-provided driverName and our knowledge of the driver structure to 
/// automatically find and hook the target driver's IOCTLs.
/// For most cases, the AutoHook mode is expected.
/// </summary>
/// <param name="hookRequest"></param>
/// <returns></returns>
NTSTATUS DoHook(HookRequest* hookRequest)
{
	NTSTATUS status;
	if (hookRequest->mode == MODE_MANUAL)
	{
		// Manual hook mode proivded, we pass the address, type, and name to perform the manual hook
		status = DoManualHook(hookRequest->address, hookRequest->type, hookRequest->driverName);
		return status;
	}
	else if (hookRequest->mode == MODE_AUTO)
	{
		// Auto hook mode provided, we pass the target driver name to our next function that will automatically find 
		// and hook the IOCTL interfaces for the target.
		status = DoAutoHook(hookRequest->driverName);
		return status;
	}
	else {
		// Invalid `HookRequest` mode passed, we return an error to the client.
		status = STATUS_ILLEGAL_FUNCTION;
	}
	return status;
}

/// <summary>
/// This function receives input from user-mode programs, here we pass the input as a `HookRequest` struct, and
/// we hook the IOCTL functions for the driver specified in the `HookRequest`. All hooks are managed in an array
/// where we can unhook them on driver unload.
/// When a hook is hit, we log the IOCTL call and input, then call the original target function for the hooked device driver.
/// </summary>
/// <param name="DeviceObject"></param>
/// <param name="Irp"></param>
/// <returns></returns>
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
	// Validate the input buffer length, it should be the size of a `HookRequest` struct only.
	ULONG inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	if (inBufLength != sizeof(HookRequest))
	{
		// Invalid size, return invalid parameter status to notify the client/user
		status = STATUS_INVALID_PARAMETER;
		goto End;
	}
	HookRequest* hookRequest;
	// Check the IoControlCode method, we only expect parameters to be passed via METHOD_BUFFERED, this is the only
	// ioctl we expect
	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_DUMP_METHOD_BUFFERED:
		// The parameter passing method was as expected, we can interpret the input from the user as a `HookRequest` and process this
		// in our `DoHook` function and return the status obtained from processing the input.
		// Note that since we are using METHOD_BUFFERED, it is safe to use the `SystemBuffer` directly as it is safely in kernel-memory and 
		// no longer modifiable by the user.
		hookRequest = (HookRequest*)Irp->AssociatedIrp.SystemBuffer;
		status = DoHook(hookRequest); goto End;
	
	default:
		// If we hit this code, the ioctl received did not provide the right parameter passing method we expected,
		// we return invalid parameter to notify the client.
		status = STATUS_INVALID_PARAMETER; goto End;

	}

End:
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}



/// <summary>
/// Unloads our driver, if we have hooks applied we will enumerate our hooks and restore
/// them to their original code (i.e unhook).
/// </summary>
/// <param name="DriverObject"></param>
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
		// Obtain lock to our IoHookList to prevent concurrency issues
		ExAcquireFastMutex(fastIoHooksDArray->lock);
		for (int i = 0; i < fastIoHooksDArray->entry_count; i++)
		{
			InterlockedExchangePointer((volatile PVOID*)fastIoHooksDArray->entries[i].hookedAddress,fastIoHooksDArray->entries[i].originalFunction);
		}
		ExReleaseFastMutex(fastIoHooksDArray->lock);
		ExFreePool2(fastIoHooksDArray->lock, 'PMDI', NULL, NULL);
		ExFreePool2(fastIoHooksDArray,'PMDI',NULL,NULL);
		
	}
	

	if (fastIoHooksWArray != NULL)
	{
		// Obtain lock to our IoHookList to prevent concurrency issues
		ExAcquireFastMutex(fastIoHooksWArray->lock);
		for (int i = 0; i < fastIoHooksWArray->entry_count; i++)
		{
			InterlockedExchangePointer((volatile PVOID*)fastIoHooksWArray->entries[i].hookedAddress,fastIoHooksWArray->entries[i].originalFunction);
		}
		ExReleaseFastMutex(fastIoHooksWArray->lock);
		ExFreePool2(fastIoHooksWArray->lock, 'PMDI', NULL, NULL);
		ExFreePool2(fastIoHooksWArray,'PMDI',NULL,NULL);
		
	}
	
	if (fastIoHooksRArray != NULL)
	{
		// Obtain lock to our IoHookList to prevent concurrency issues
		ExAcquireFastMutex(fastIoHooksRArray->lock);
		for (int i = 0; i < fastIoHooksRArray->entry_count; i++)
		{
			InterlockedExchangePointer((volatile PVOID*)fastIoHooksRArray->entries[i].hookedAddress, fastIoHooksRArray->entries[i].originalFunction);
		}
		ExReleaseFastMutex(fastIoHooksRArray->lock);
		ExFreePool2(fastIoHooksRArray->lock, 'PMDI', NULL, NULL);
		ExFreePool2(fastIoHooksRArray,'PMDI',NULL,NULL);
		
	}
	if (deviceIoHooksRArray != NULL)
	{
		// Obtain lock to our IoHookList to prevent concurrency issues
		ExAcquireFastMutex(deviceIoHooksRArray->lock);
		for (int i = 0; i < deviceIoHooksRArray->entry_count; i++)
		{
			InterlockedExchangePointer((volatile PVOID*)deviceIoHooksRArray->entries[i].hookedAddress, deviceIoHooksRArray->entries[i].originalFunction);
		}
		ExReleaseFastMutex(deviceIoHooksRArray->lock);
		ExFreePool2(deviceIoHooksRArray->lock, 'PMDI', NULL, NULL);
		ExFreePool2(deviceIoHooksRArray,'PMDI',NULL,NULL);
		
	}
	if (deviceIoHooksWArray != NULL)
	{
		// Obtain lock to our IoHookList to prevent concurrency issues
		ExAcquireFastMutex(deviceIoHooksWArray->lock);
		for (int i = 0; i < deviceIoHooksWArray->entry_count; i++)
		{
			InterlockedExchangePointer((volatile PVOID*)deviceIoHooksWArray->entries[i].hookedAddress, deviceIoHooksWArray->entries[i].originalFunction);
		}
		ExReleaseFastMutex(deviceIoHooksWArray->lock);
		ExFreePool2(deviceIoHooksWArray->lock, 'PMDI', NULL, NULL);
		ExFreePool2(deviceIoHooksWArray,'PMDI',NULL,NULL);
		
	}
	if (deviceIoHooksDArray != NULL)
	{
		// Obtain lock to our IoHookList to prevent concurrency issues
		ExAcquireFastMutex(deviceIoHooksDArray->lock);
		for (int i = 0; i < deviceIoHooksDArray->entry_count; i++)
		{
			InterlockedExchangePointer((volatile PVOID*)deviceIoHooksDArray->entries[i].hookedAddress,deviceIoHooksDArray->entries[i].originalFunction);
		}
		ExReleaseFastMutex(deviceIoHooksDArray->lock);
		ExFreePool2(deviceIoHooksDArray->lock, 'PMDI', NULL, NULL);
		ExFreePool2(deviceIoHooksDArray,'PMDI',NULL,NULL);
		
	}
	if (fileIoHooksDArray != NULL)
	{
		// Obtain lock to our IoHookList to prevent concurrency issues
		ExAcquireFastMutex(fileIoHooksDArray->lock);
		for (int i = 0; i < fileIoHooksDArray->entry_count; i++)
		{
			InterlockedExchangePointer((volatile PVOID*)fileIoHooksDArray->entries[i].hookedAddress, fileIoHooksDArray->entries[i].originalFunction);
		}
		ExReleaseFastMutex(fileIoHooksDArray->lock);
		ExFreePool2(fileIoHooksDArray->lock, 'PMDI', NULL, NULL);
		ExFreePool2(fileIoHooksDArray,'PMDI',NULL,NULL);
		
	}
	
	return;
}

/// <summary>
/// This function is called when a program attempts to open or close a handle to our device driver. We allow any program
/// that can reach this code to obtain or close handles to it.
/// </summary>
/// <param name="DeviceObject"></param>
/// <param name="Irp"></param>
/// <returns></returns>
NTSTATUS
ioctlCreateClose(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	// This code can be paged as it should only be run in PASSIVE_IRQL
	PAGED_CODE();
	// Arbitrarly allow programs to obtain/close handles
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	// Complete the requesting IRP and return success
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

DRIVER_INITIALIZE DriverEntry;

/// <summary>
/// Entry point for the Driver, will initialize the device for user->driver comms.
/// </summary>
/// <param name="drvObj">
/// Pointer to this Driver's `DRIVER_OBJECT` as provided by the OS
/// </param>
/// <param name="regPath">
/// Pointer to this Driver's Regpath as provided by the OS
/// </param>
/// <returns>
/// Success if there was no errors creating the associated Ioctld device. This function should always be successful unless
/// the device name has been taken (likely by another instance of this driver).
/// </returns>
NTSTATUS DriverEntry(
	PDRIVER_OBJECT drvObj,
	PUNICODE_STRING regPath
)
{
	UNREFERENCED_PARAMETER(regPath);

	NTSTATUS status;
	PDEVICE_OBJECT deviceObject;
	UNICODE_STRING ntUnicodeString;
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Info: In DriverEntry\n"));
	// Initialize the global structs used for saving hook metadata
	// Allow at most 20 hooks per hook-type, configure this number as-per your requirements
	ULONGLONG entry_max_len = 20;
	SIZE_T entry_array_size = entry_max_len * sizeof(IoHooks);
	// Allocate enough space for our IoHookList struct + the size of our entries array
	fastIoHooksDArray = (IoHookList*) ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(IoHookList) + entry_array_size, 'PMDI');
	if (fastIoHooksDArray == NULL) {
		goto failed_allocation;
	}
	fastIoHooksRArray = (IoHookList*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(IoHookList) + entry_array_size, 'PMDI');
	if (fastIoHooksRArray == NULL) {
		goto failed_allocation;
	}
	fastIoHooksWArray = (IoHookList*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(IoHookList) + entry_array_size, 'PMDI');
	if (fastIoHooksWArray == NULL) {
		goto failed_allocation;
	}
	deviceIoHooksDArray = (IoHookList*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(IoHookList) + entry_array_size, 'PMDI');
	if (deviceIoHooksDArray == NULL) {
		goto failed_allocation;
	}
	deviceIoHooksWArray = (IoHookList*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(IoHookList) + entry_array_size, 'PMDI');
	if (deviceIoHooksWArray == NULL) {
		goto failed_allocation;
	}
	deviceIoHooksRArray = (IoHookList*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(IoHookList) + entry_array_size, 'PMDI');
	if (deviceIoHooksRArray == NULL) {
		goto failed_allocation;
	}
	fileIoHooksDArray = (IoHookList*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(IoHookList) + entry_array_size, 'PMDI');
	if (fileIoHooksDArray == NULL) {
		goto failed_allocation;
	}

	// Initialize the max len and entry count in our IoHookLists
	fastIoHooksDArray->entry_max = entry_max_len;
	fastIoHooksDArray->entry_count = 0;
	
	fastIoHooksRArray->entry_max = entry_max_len;
	fastIoHooksRArray->entry_count = 0;

	fastIoHooksWArray->entry_max = entry_max_len;
	fastIoHooksWArray->entry_count = 0;
	
	deviceIoHooksDArray->entry_max = entry_max_len;
	deviceIoHooksDArray->entry_count = 0;

	deviceIoHooksWArray->entry_max = entry_max_len;
	deviceIoHooksWArray->entry_count = 0;

	deviceIoHooksRArray->entry_max = entry_max_len;
	deviceIoHooksRArray->entry_count = 0;

	fileIoHooksDArray->entry_max = entry_max_len;
	fileIoHooksDArray->entry_count = 0;

	// Initialize the locks for each IoHookList
	PFAST_MUTEX fastIoHooksDMutex = (PFAST_MUTEX)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FAST_MUTEX), 'PMDI');
	if (fastIoHooksDMutex == NULL) {
		goto failed_allocation;
	}

	PFAST_MUTEX fastIoHooksRMutex = (PFAST_MUTEX)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FAST_MUTEX), 'PMDI');
	if (fastIoHooksRMutex == NULL) {
		ExFreePool2(fastIoHooksDMutex, 'PMDI', NULL, NULL);
		goto failed_allocation;
	}

	PFAST_MUTEX fastIoHooksWMutex = (PFAST_MUTEX)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FAST_MUTEX), 'PMDI');
	if (fastIoHooksWMutex == NULL) {
		ExFreePool2(fastIoHooksDMutex, 'PMDI', NULL, NULL);
		ExFreePool2(fastIoHooksRMutex, 'PMDI', NULL, NULL);
		goto failed_allocation;
	}

	PFAST_MUTEX deviceIoHooksDMutex = (PFAST_MUTEX)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FAST_MUTEX), 'PMDI');
	if (deviceIoHooksDMutex == NULL) {
		ExFreePool2(fastIoHooksDMutex, 'PMDI', NULL, NULL);
		ExFreePool2(fastIoHooksRMutex, 'PMDI', NULL, NULL);
		ExFreePool2(fastIoHooksWMutex, 'PMDI', NULL, NULL);
		goto failed_allocation;
	}

	PFAST_MUTEX deviceIoHooksWMutex = (PFAST_MUTEX)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FAST_MUTEX), 'PMDI');
	if (deviceIoHooksWMutex == NULL) {
		ExFreePool2(fastIoHooksDMutex, 'PMDI', NULL, NULL);
		ExFreePool2(fastIoHooksRMutex, 'PMDI', NULL, NULL);
		ExFreePool2(fastIoHooksWMutex, 'PMDI', NULL, NULL);
		ExFreePool2(deviceIoHooksDMutex, 'PMDI', NULL, NULL);
		goto failed_allocation;
	}

	PFAST_MUTEX deviceIoHooksRMutex = (PFAST_MUTEX)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FAST_MUTEX), 'PMDI');
	if (deviceIoHooksRMutex == NULL) {
		ExFreePool2(fastIoHooksDMutex, 'PMDI', NULL, NULL);
		ExFreePool2(fastIoHooksRMutex, 'PMDI', NULL, NULL);
		ExFreePool2(fastIoHooksWMutex, 'PMDI', NULL, NULL);
		ExFreePool2(deviceIoHooksDMutex, 'PMDI', NULL, NULL);
		ExFreePool2(deviceIoHooksWMutex, 'PMDI', NULL, NULL);
		goto failed_allocation;
	}

	PFAST_MUTEX fileIoHooksDMutex = (PFAST_MUTEX)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FAST_MUTEX), 'PMDI');
	if (fileIoHooksDMutex == NULL) {
		ExFreePool2(fastIoHooksDMutex, 'PMDI', NULL, NULL);
		ExFreePool2(fastIoHooksRMutex, 'PMDI', NULL, NULL);
		ExFreePool2(fastIoHooksWMutex, 'PMDI', NULL, NULL);
		ExFreePool2(deviceIoHooksDMutex, 'PMDI', NULL, NULL);
		ExFreePool2(deviceIoHooksWMutex, 'PMDI', NULL, NULL);
		ExFreePool2(deviceIoHooksRMutex, 'PMDI', NULL, NULL);
		goto failed_allocation;
	}
	
	// Initialize Mutex, these mutexes must be held/locked when operating
	// on their respective IoHookList
	ExInitializeFastMutex(fastIoHooksDMutex);
	ExInitializeFastMutex(fastIoHooksRMutex);
	ExInitializeFastMutex(fastIoHooksWMutex);
	ExInitializeFastMutex(deviceIoHooksDMutex);
	ExInitializeFastMutex(deviceIoHooksWMutex);
	ExInitializeFastMutex(deviceIoHooksRMutex);
	ExInitializeFastMutex(fileIoHooksDMutex);

	// Set mutex in their respective IoHookList
	fastIoHooksDArray->lock = fastIoHooksDMutex;
	fastIoHooksRArray->lock = fastIoHooksRMutex;
	fastIoHooksWArray->lock = fastIoHooksWMutex;
	deviceIoHooksDArray->lock = deviceIoHooksDMutex;
	deviceIoHooksWArray->lock = deviceIoHooksWMutex;
	deviceIoHooksRArray->lock = deviceIoHooksRMutex;
	fileIoHooksDArray->lock = fileIoHooksDMutex;


	// Create the device object for user->driver communcation
	RtlInitUnicodeString(&ntUnicodeString, NT_DEVICE_NAME);
	status = IoCreateDevice(drvObj, 0, &ntUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		// Likely only hit this path if the device name is taken
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Error: Failed to create device.\n"));
		RtlFreeUnicodeString(&ntUnicodeString);
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	UNICODE_STRING ntWin32NameString;
	// Create the associated DosDevice name, again for user->driver communication
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
	// Create a link to our IOCTL handler as we use this for user->driver communication
	drvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoDeviceControlFunc;
	// We create links to our create/close handlers to permit user programs to open and close handles
	// to our device driver.
	drvObj->MajorFunction[IRP_MJ_CREATE] = ioctlCreateClose;
	drvObj->MajorFunction[IRP_MJ_CLOSE] = ioctlCreateClose;
	// Link our cleanup routine for when the driver is unloaded
	drvObj->MajorFunction[IRP_MJ_CLEANUP] = ioctlCleanup;
	// Set the unload function to permit driver unloads
	drvObj->DriverUnload = UnloadDriver;
	// Initialization is completed, we can return success and expect calls to our create/close and IOCTL handler
	// after this point.
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Info: Finished DriverEntry\n"));
	return STATUS_SUCCESS;

failed_allocation:
	// An allocation for one of our global IoHookLists failed, lets cleanup and return an error
	// Check if any of the allocations succeeded, and free their allocated memory.
	if (fastIoHooksDArray != NULL){
		ExFreePool2(fastIoHooksDArray, 'PMDI', NULL, NULL);
	}
	if (fastIoHooksRArray != NULL) {
		ExFreePool2(fastIoHooksRArray, 'PMDI', NULL, NULL);
	}
	if (fastIoHooksWArray != NULL) {
		ExFreePool2(fastIoHooksWArray, 'PMDI', NULL, NULL);
	}
	if (deviceIoHooksDArray != NULL) {
		ExFreePool2(deviceIoHooksDArray, 'PMDI', NULL, NULL);
	}
	if (deviceIoHooksWArray != NULL) {
		ExFreePool2(deviceIoHooksWArray, 'PMDI', NULL, NULL);
	}
	if (deviceIoHooksRArray != NULL) {
		ExFreePool2(deviceIoHooksRArray, 'PMDI', NULL, NULL);
	}
	if (fileIoHooksDArray != NULL) {
		ExFreePool2(fileIoHooksDArray, 'PMDI', NULL, NULL);
	}
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ERROR: Failed DriverEntry\n"));
	// Return an error
	return STATUS_INSUFFICIENT_RESOURCES;
}
