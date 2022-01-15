# IOCTLDump

IOCTLDump is a driver that can be used for hooking and dumping IOCTLS (including FastIO & RW interactions) of other device drivers.

## Usage

Install the driver on your system 
` sc create ioctld binPath= c:\tmp\IOCTLDump.sys type= kernel `
` sc start ioctld`

Then, use IOCTLDumpClient.exe to interact with the driver to hook another driver, e.g.

` IOCTLDumpClient.exe \Device\SomeDeviceToHook `

Then, intercepted IOCTLs will be dumped as per the design.txt file in C:\DriverHooks
