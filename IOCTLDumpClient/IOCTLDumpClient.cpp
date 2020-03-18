#include <iostream>
#include <Windows.h>
#include "..\..\Shared\Headers\ntdll.h"
#include "..\IOCTLDump\IOCTLDump.h"


#pragma warning( disable : 4996)


// No security checks, careful
int main(int argc, char* argv[])
{
	if (argc < 1)
	{
		std::cout << "Incorrect Parameters.\n";
		return 1;
	}
	HookRequest hookRequest = { 0 };
	char* devName = argv[1];
	int len = strlen(devName);
	WCHAR* devNameW = NULL;
	int req = MultiByteToWideChar(0, 0, devName, -1, devNameW, 0);
	devNameW = new WCHAR[req];
	MultiByteToWideChar(0, 0, devName, -1, devNameW, req);
	UNICODE_STRING  devNameU;
	RtlInitUnicodeString pRtlInitUnicodeString = (RtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll"), "RtlInitUnicodeString");
	pRtlInitUnicodeString(&devNameU, devNameW);
	printf("Sending request for driver:%wZ\n",devNameU);
	hookRequest.driverName = devNameU;
	hookRequest.address = NULL;
	hookRequest.mode = MODE_AUTO;
	hookRequest.type = NULL;
	HANDLE hDevice = CreateFileW(USR_DEVICE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		std::cout << "Failed to obtain device handle, error:" << std::hex << GetLastError();
		std::cout << "\n";
		return 2;
	}
	DWORD junk = 0;
	BOOL bResult = DeviceIoControl(hDevice,
		IOCTL_DUMP_METHOD_BUFFERED,
		&hookRequest,
		sizeof(hookRequest),
		NULL,
		0,
		&junk,
		0);
	CloseHandle(hDevice);
	if (!bResult)
	{
		std::cout << "DeviceIoControl failed, error:" << std::hex << GetLastError();
		std::cout << "\n";
		return 2;
	}
	else {
		std::cout << "Success.\n";
		return 0;
	}
}
