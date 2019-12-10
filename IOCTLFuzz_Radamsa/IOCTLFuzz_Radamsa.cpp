#include <iostream>
#include <Windows.h>
#include <stdlib.h>


HANDLE hDev;

BOOL singleTest = false;


void fuzz(char* folder, const char* filename, char* fullPath)
{
	if (folder == NULL || filename == NULL || fullPath == NULL)
	{
		return;
	}
	char foldercln[MAX_PATH];
	strcpy(foldercln, folder);
	char* token = strtok(foldercln, "\\");
	char* drvName;
	char* sIoctl;
	ULONG ioctl;
	token = strtok(NULL, "\\");
	drvName = token;
	token = strtok(NULL, "\\");
	sIoctl = token;
	ioctl = strtoul(sIoctl, NULL, 16);
	
	DWORD fLen = 0;
	int count = 0;
	const int outBufSize = 20000;
	char outBuf[outBufSize];
	DWORD bytesRet = 0;
	
	HANDLE hFile = CreateFileA(fullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	LARGE_INTEGER fs;
	GetFileSizeEx(hFile, &fs);
	unsigned long long fSize = fs.QuadPart;
	char* strVal = new char[fSize];
	memset(strVal, 0, fSize);
	DWORD dwNoByteRead = 0;
	//reading the content
	BOOL readwriFile = ReadFile(hFile, strVal, fSize, &dwNoByteRead, NULL);
	CloseHandle(hFile);
	char* buf = (char*)calloc(1,dwNoByteRead);
	memcpy(buf, strVal, dwNoByteRead);
	printf("Fuzz: p=%s, ioctl=%x size=%d\n", fullPath, ioctl, dwNoByteRead);
	BOOL bResult = DeviceIoControl(hDev,
		ioctl,
		buf,
		fLen,
		outBuf,
		outBufSize,
		&bytesRet,
		0);
	free(buf);
	return;
}

void fuzzgen(char* folder, const char* filename, char* fullPath, char* n)
{
	if (folder == NULL || filename == NULL || fullPath == NULL)
	{
		return;
	}
	char cmd[MAX_PATH];
	const char* cmd2 = "mkdir \"";
	strcpy(cmd, cmd2);
	strcat(cmd, folder);
	const char* cmd3 = "\\fuzzme\"";
	strcat(cmd, cmd3);
	system(cmd);
	char foldercln[MAX_PATH];
	strcpy(foldercln, folder);
	char* token = strtok(foldercln, "\\");
	char* drvName;
	char* sIoctl;
	ULONG ioctl;
	token = strtok(NULL, "\\");
	drvName = token;
	token = strtok(NULL, "\\");
	sIoctl = token;
	ioctl = strtoul(sIoctl, NULL, 16);

	DWORD fLen = 0;
	int count = 0;
	const int outBufSize = 20000;
	char outBuf[outBufSize];
	DWORD bytesRet = 0;

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	const char* cmdLine = "\"C:\\Fuzz\\radamsa.exe\" ";
	char cmdLine2[MAX_PATH];
	strcpy(cmdLine2, cmdLine);
	const char* o = "-o \"";
	strcat(cmdLine2, o);
	const char* n1 = "-n ";
	char n2[MAX_PATH];
	strcpy(n2, n1);
	strcat(n2, n);
	char oa[MAX_PATH];
	const char* oa1 = "\\fuzzme\\";
	strcpy(oa, oa1);
	strcat(oa, filename);
	const char* oa2 = "-%n.fuzz";
	strcat(oa, oa2);
	const char* q = "\"";
	strcat(cmdLine2, folder);
	strcat(cmdLine2, oa);
	const char* q1 = " \"";
	const char* sp = " ";
	strcat(cmdLine2, q);
	strcat(cmdLine2, sp);
	strcat(cmdLine2, n2);
	strcat(cmdLine2, q1);
	strcat(cmdLine2, fullPath);
	
	strcat(cmdLine2, q);
	printf("cmdline:%s\n", cmdLine2);



	if (!CreateProcessA(NULL,   // No module name (use command line)
		cmdLine2,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
		return;
	}

	// Wait until child process exits.
	WaitForSingleObject(pi.hProcess, INFINITE);
	return;
}


int findfiles_recursive_gen(char* folder, char* n)
{
	char wildcard[MAX_PATH];
	sprintf(wildcard, "%s\\*", folder);
	WIN32_FIND_DATAA fd;
	HANDLE handle = FindFirstFileA(wildcard, &fd);
	if (handle == INVALID_HANDLE_VALUE) return 0;
	do
	{
		if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
			continue;
		char path[MAX_PATH];
		sprintf(path, "%s\\%s", folder, fd.cFileName);
		if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			findfiles_recursive_gen(path, n);
		else if (strstr(fd.cFileName, ".fuzz") != 0)
			continue;
		else if (strstr(fd.cFileName, ".data") != 0)
		{
			fuzzgen(folder, fd.cFileName, path, n);
			if (singleTest == true)
			{
				return 0;
			}
		}
			
	} while (FindNextFileA(handle, &fd));
	FindClose(handle);

	return 0;
}

int findfiles_recursive(char* folder)
{
	char wildcard[MAX_PATH];
	sprintf(wildcard, "%s\\*", folder);
	WIN32_FIND_DATAA fd;
	HANDLE handle = FindFirstFileA(wildcard, &fd);
	if (handle == INVALID_HANDLE_VALUE) return 0;
	do
	{
		if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
			continue;
		char path[MAX_PATH];
		sprintf(path, "%s\\%s", folder, fd.cFileName);
		if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			findfiles_recursive(path);
		else if (strstr(fd.cFileName, ".fuzz") != 0)
			fuzz(folder, fd.cFileName, path);
	} while (FindNextFileA(handle, &fd));
	FindClose(handle);
	return 0;
}

void test_basic_overflow(char* folder)
{
	char wildcard[MAX_PATH];
	sprintf(wildcard, "%s\\*", folder);
	WIN32_FIND_DATAA fd;
	HANDLE handle = FindFirstFileA(wildcard, &fd);
	char buf[2048];
	RtlFillMemory(buf, 2048, 0xCC);
	char outBuf[2048];
	do
	{
		if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
			continue;
		char path[MAX_PATH];
		sprintf(path, "%s\\%s", folder, fd.cFileName);
		if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			DWORD ioctl = strtoul(fd.cFileName, NULL, 16);
			printf("Testing IOCTL:%x\n", ioctl);
			DWORD fLen = 9999999;
			DWORD outBufSize = 9999999;
			DWORD bytesRet = 0;
			BOOL bResult = DeviceIoControl(hDev,
				ioctl,
				buf,
				fLen,
				outBuf,
				outBufSize,
				&bytesRet,
				0);
			fLen = -9999;
			outBufSize = -9999;
			bResult = DeviceIoControl(hDev,
				ioctl,
				buf,
				fLen,
				outBuf,
				outBufSize,
				&bytesRet,
				0);
			fLen = 1;
			outBufSize = 1;
			bResult = DeviceIoControl(hDev,
				ioctl,
				buf,
				fLen,
				outBuf,
				outBufSize,
				&bytesRet,
				0);
			fLen = 0;
			outBufSize = 0;
			bResult = DeviceIoControl(hDev,
				ioctl,
				buf,
				fLen,
				outBuf,
				outBufSize,
				&bytesRet,
				0);
		}
		else {
			continue;
		}
	} while (FindNextFileA(handle, &fd));
}

int main(int argc, char* argv[])
{
	
	
	//char folder[] = "C:\\mfehidk";
	char* folder = argv[1];
	if (argc > 3)
	{
		if (strstr(argv[3], "overflow"))
		{
			test_basic_overflow(folder);
			return 0;
		}
		if (strstr(argv[3], "single"))
		{
			singleTest = true;
		}
	}
	char* devNameT = argv[4];
	hDev = CreateFileA(devNameT,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (hDev == INVALID_HANDLE_VALUE)
	{
		std::cout << "Failed to obtain device handle, error:" << std::hex << GetLastError();
		std::cout << "\n";
		return 2;
	}
	char* n = argv[2];
	while (true)
	{
		findfiles_recursive_gen(folder,n);
		findfiles_recursive(folder);
	}
	return 0;
}
