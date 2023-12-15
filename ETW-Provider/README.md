# ETW-CustomProvider_PoC

Step By Step Instructions:

- Use the `WinSdkInstaller.ps1` script to install the Windows SDK
- Compile the manifest using the `mc -css Namespace PersistenceSniper.man` command
- Run the Resuource Compiler with the `rc PersistenceSniper.rc` command
- Compile the library using the CSC command: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /unsafe /win32res:PersistenceSniper.res PersistenceSniper.cs`
- Install the custom provider with the `wevtutil im PersistenceSniper.man`
- Add a simple log entry executing the `new-customproviderevent.ps1` or compile the cs file with `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /t:exe /out:new-customproviderevent.exe new-customproviderevent.cs`
- To remove the custom provider use `wevtutil um PersistenceSniper.man`.


> REMEMBER: Close and reopen the Event Viewer to view the new custom provider.
