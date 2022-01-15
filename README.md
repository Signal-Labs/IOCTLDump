# IOCTLDump

IOCTLDump is a driver that can be used for hooking and dumping IOCTLS (including FastIO & RW interactions) of other device drivers.

It will log the IOCTL request information in a .conf file (the IOCTL code, whether its from DeviceIO or FastIO or RW, the input & output buffer sizes).

It will also log the input buffer contents in a .data file.

Note that for each (IOCTL & Input Buffer Size) combination, only one will be saved (e.g. if a hooked IOCTL recieves a request for an IOCTL we've seen before, and with the exact same input buffer size we've seen before, we don't log it).

## Usage

Install the driver on your system 
` sc create ioctld binPath= c:\tmp\IOCTLDump.sys type= kernel `
` sc start ioctld`

Then, use IOCTLDumpClient.exe to interact with the driver to hook another driver, e.g.

` IOCTLDumpClient.exe \Device\SomeDeviceToHook `

Then, intercepted IOCTLs will be dumped as per the design.txt file in C:\DriverHooks
