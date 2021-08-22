#pragma once
#define DUMP_TYPE 40000
#define IOCTL_DUMP_METHOD_BUFFERED \
    CTL_CODE( DUMP_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define MODE_MANUAL 1
#define MODE_AUTO 2
#define TYPE_FASTIOD 1
#define TYPE_FASTIOR 3
#define TYPE_FASTIOW 4
#define TYPE_DEVICEIOD 2
#define TYPE_DEVICEIOR 5
#define TYPE_DEVICEIOW 6
#define TYPE_FILEIOD 7
#define FUZZ_COUNT 200
#define NT_DEVICE_NAME      L"\\Device\\dIoctl"
#define DOS_DEVICE_NAME     L"\\DosDevices\\dIoctl"
#define USR_DEVICE_NAME		L"\\\\.\\dIoctl"
#define METHOD_FROM_CTL_CODE(ctrlCode)        ((ULONG)(ctrlCode & 3))



struct HookRequest
{
	UNICODE_STRING driverName;
	short mode;
	bool fuzz;
	short type;
	PVOID* address;
};

