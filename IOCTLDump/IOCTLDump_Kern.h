#pragma once

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

typedef bool(__stdcall* devIoCallRWD)(
	PDEVICE_OBJECT pDeviceObject,
	PIRP Irp
	);




struct IoHooks
{
	UNICODE_STRING driverName;
	PVOID originalFunction;
	PVOID hookedAddress;
};

struct IoHookList
{
	PFAST_MUTEX lock;
	ULONGLONG entry_count;
	ULONGLONG entry_max;
	IoHooks entries[];
};