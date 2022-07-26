#Requires -RunAsAdministrator
function Find-AllPersistence
{ 
  <#
      .SYNOPSIS

      This script tries to enumerate all the persistence methods implanted on a compromised machine.

      Function: Find-AllPersistence
      Authors: Federico `last` Lagrasta, Twitter: @last0x00; Riccardo Ancarani, Twitter: @dottor_morte
      License: https://creativecommons.org/publicdomain/zero/1.0/
      Required Dependencies: None
      Optional Dependencies: None

      .DESCRIPTION

      Enumerate all the persistence methods found on a machine and print them for the user to see.

      .PARAMETER DiffCSV

      String: Take a CSV as input and exclude from the output all the local persistences which match the ones in the input CSV. 
	    
      .PARAMETER OutputCSV

      String: Output to a CSV file for later consumption.

      .PARAMETER IncludeHighFalsePositivesChecks

      Switch: Forces Persistence Sniper to also call a number of functions with checks which are more difficult to filter and in turn can cause a lot of false positives.

      .EXAMPLE

      Enumerate low false positive persistence techniques implanted on the local machine.
      Find-AllPersistence

      .EXAMPLE

      Enumerate low false positive persistence techniques implanted on the local machine and output to a CSV.
      Find-AllPersistence -OutputCSV .\persistences.csv

      .EXAMPLE

      Enumerate low false positive persistence techniques implanted on the local machine but show us only the persistences which are not in an input CSV.
      Find-AllPersistence -DiffCSV .\persistences.csv

      .EXAMPLE

      Enumerate all persistence techniques implanted on the local machine but show us only the persistences which are not in an input CSV and output the findings on a CSV.
      Find-AllPersistence -DiffCSV .\persistences.csv -OutputCSV .\findings.csv -IncludeHighFalsePositivesChecks

      .NOTES

      This script tries to enumerate all persistence techniques that may have been deployed on a compromised machine. New techniques may take some time before they are implemented in this script, so don't assume that because the script didn't find anything the machine is clean.
     
      .LINK

      https://github.com/last-byte/PersistenceSniper
  #>
  
  
  Param(
    [Parameter(Mandatory = $false, Position = 0)]
    [System.String]
    $DiffCSV = $null, 
    
    [Parameter(Mandatory = $false, Position = 2)]
    [System.String]
    $OutputCSV = $null,  
    
    [Parameter(Mandatory = $false, Position = 1)]
    [Switch]
    $IncludeHighFalsePositivesChecks
  )  
  
  $persistenceObjectArray = New-Object -TypeName System.Collections.ArrayList
  $psProperties = @('PSChildName', 'PSDrive', 'PSParentPath', 'PSPath', 'PSProvider')
  function New-PersistenceObject
  {
    param(
      [Parameter(Mandatory=$true)]$Technique, 
      [Parameter(Mandatory=$true)]$Classification, 
      [Parameter(Mandatory=$true)]$Path, 
      [Parameter(Mandatory=$true)]$Value, 
      [Parameter(Mandatory=$true)]$AccessGained,
      [Parameter(Mandatory=$true)]$Note,
      [Parameter(Mandatory=$true)]$Reference
    )
    $PersistenceObject = [PSCustomObject]@{
      'Technique'    = $Technique
      'Classification' = $Classification
      'Path'         = $Path
      'Value'        = $Value
      'Access Gained' = $AccessGained
      'Note'         = $Note
      'Reference'    = $Reference
    } 
    return $PersistenceObject
  }
  
  $W10ServiceDllTable = '#TYPE System.Collections.DictionaryEntry
    "Name","Key","Value"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgrx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgrx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmwefifw","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmwefifw",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WINUSB","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WINUSB",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinVerbs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinVerbs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Msfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Msfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS3i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS3i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iagpio","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iagpio",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc","%SystemRoot%\System32\MixedRealityRuntime.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_GLK","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_GLK",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvraid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvraid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthMini","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthMini",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcaSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcaSvc","%SystemRoot%\System32\ncasvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PushToInstall","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PushToInstall","%SystemRoot%\system32\PushToInstall.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DcomLaunch","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DcomLaunch","%SystemRoot%\system32\rpcss.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SstpSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SstpSvc","%SystemRoot%\system32\sstpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fhsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fhsvc","%SystemRoot%\system32\fhsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMTools","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMTools",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensrSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensrSvc","%SystemRoot%\system32\sensrsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc","%SystemRoot%\System32\WaaSMedicSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IndirectKmd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IndirectKmd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceInstall","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceInstall","%SystemRoot%\system32\umpnpmgr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TieringEngineService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TieringEngineService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srv2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srv2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp-stats","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp-stats",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\shpamsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\shpamsvc","%systemroot%\system32\Windows.SharedPC.AccountManager.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess","%SystemRoot%\System32\mprdim.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE","%SystemRoot%\System32\bfe.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv","%SystemRoot%\system32\bthserv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\exfat","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\exfat",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbip","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbip",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\genericusbfn","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\genericusbfn",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicRender","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicRender",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rhproxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rhproxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ldap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ldap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthAvctpSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthAvctpSvc","%SystemRoot%\System32\BthAvctpSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsCx01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsCx01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_GLK","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_GLK",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserManager","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserManager","%SystemRoot%\System32\usermgr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vds","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vds",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MMCSS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MMCSS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ACPI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ACPI",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearchIdxPi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearchIdxPi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tdx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tdx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhdmp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhdmp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbser","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbser",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHUSB","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHUSB",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2psvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2psvc","%SystemRoot%\system32\p2psvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6TUNNEL","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6TUNNEL",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CNG","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CNG",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xmlprov","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xmlprov",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCardSvr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCardSvr","%SystemRoot%\System32\SCardSvr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HwNClx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HwNClx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sfloppy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sfloppy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiCx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiCx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReFSv1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReFSv1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FltMgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FltMgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidIr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidIr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mlx4_bus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mlx4_bus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdstor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdstor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdeCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdeCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DusmSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DusmSvc","%SystemRoot%\System32\dusmsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks","%SystemRoot%\System32\trkwks.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Schedule","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Schedule","%systemroot%\system32\schedsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode","%SystemRoot%\System32\embeddedmodesvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC Bridge 4.0.0.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC Bridge 4.0.0.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc","%SystemRoot%\System32\unistore.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mssmbios","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mssmbios",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Power","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Power","%SystemRoot%\system32\umpo.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\3ware","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\3ware",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthHFEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthHFEnum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentDriver","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentDriver",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost","%SystemRoot%\system32\wdi.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wcmsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wcmsvc","%SystemRoot%\System32\wcmsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{912A4CB7-F58C-42C9-9966-5E8EF14C531A}","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{912A4CB7-F58C-42C9-9966-5E8EF14C531A}",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidinterrupt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidinterrupt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPNP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPNP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc","%SystemRoot%\system32\cryptsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Beep","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Beep",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBHUB3","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBHUB3",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvdimm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvdimm",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time","%systemroot%\system32\w32time.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dam","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dam",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmartSAMD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmartSAMD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NaturalAuthentication","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NaturalAuthentication","%SystemRoot%\System32\NaturalAuth.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc","%SystemRoot%\System32\TimeBrokerServer.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHMODEM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHMODEM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\npsvctrig","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\npsvctrig",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Mup","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Mup",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gencounter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gencounter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpitime","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpitime",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_BXT_P","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_BXT_P",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrustedInstaller","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrustedInstaller",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSTXRAID","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSTXRAID",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPDR","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPDR",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiDev","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiDev",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC","%systemroot%\system32\wephostsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc","%SystemRoot%\System32\windowsudk.shellcommon.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc","%SystemRoot%\System32\wscsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevQueryBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevQueryBroker","%SystemRoot%\system32\DevQueryBroker.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\icssvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\icssvc","%SystemRoot%\System32\tetheringservice.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_GPIO","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_GPIO",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{9EAB773D-70D1-40C9-8B1B-0732FFC6C894}","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{9EAB773D-70D1-40C9-8B1B-0732FFC6C894}",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4iscsi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4iscsi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsmraid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsmraid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdyboost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdyboost",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VGAuthService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VGAuthService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lmhosts","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lmhosts","%SystemRoot%\System32\lmhsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp","%SystemRoot%\system32\dhcpcore.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vpci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vpci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndproxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndproxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarpv6","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarpv6",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Data","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Data",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmusbmouse","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmusbmouse",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain","%systemroot%\system32\sysmain.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinMad","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinMad",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smbdirect","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smbdirect",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scfilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scfilter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SSS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SSS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNPMEM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNPMEM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\adsi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\adsi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Microsoft_Bluetooth_AvrcpTransport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Microsoft_Bluetooth_AvrcpTransport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc","%SystemRoot%\System32\lfsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter","%SystemRoot%\System32\KeyboardFilterSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msgpiowin32","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msgpiowin32",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport","%SystemRoot%\System32\wercplsupport.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HpSAMD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HpSAMD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\udfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\udfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv","%systemroot%\system32\wuaueng.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_BXT_P","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_BXT_P",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FDResPub","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FDResPub","%SystemRoot%\system32\fdrespub.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfNet","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfNet",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas35i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas35i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvumis","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvumis",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Psched","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Psched",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vdrvroot","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vdrvroot",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicshutdown","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicshutdown","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BITS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BITS","%SystemRoot%\System32\qmgr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netvscvfpp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netvscvfpp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\atapi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\atapi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcmcia","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcmcia",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcnfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcnfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService","%SystemRoot%\System32\WpnUserService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\perceptionsimulation","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\perceptionsimulation",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pdc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pdc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwifibus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwifibus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Processor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Processor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess","%SystemRoot%\System32\ipnathlp.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSKSSRV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSKSSRV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VerifierExt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VerifierExt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFPLWFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFPLWFS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\workfolderssvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\workfolderssvc","%systemroot%\system32\workfolderssvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvcrash","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvcrash",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDRSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDRSVC","%Systemroot%\System32\SDRSVC.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Memory Cache 4.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Memory Cache 4.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\afunix","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\afunix",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wdiwifi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wdiwifi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdPPM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdPPM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\inetaccs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\inetaccs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eaphost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eaphost","%SystemRoot%\System32\eapsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecPkg","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecPkg",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CscService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CscService","%SystemRoot%\System32\cscsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbcir","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbcir",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcLocator","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcLocator",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\applockerfltr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\applockerfltr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc","%SystemRoot%\system32\XboxNetApiSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdPHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdPHost","%SystemRoot%\system32\fdPHost.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder","%SystemRoot%\System32\AudioEndpointBuilder.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MpKslf927bedc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MpKslf927bedc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM","%SystemRoot%\system32\WsmSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan","%SystemRoot%\System32\rasmans.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService","%SystemRoot%\System32\Microsoft.Bluetooth.UserService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\circlass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\circlass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SessionEnv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SessionEnv","%SystemRoot%\system32\sessenv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Fs_Rec","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Fs_Rec",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlidsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlidsvc","%SystemRoot%\system32\wlidsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc","%SystemRoot%\System32\wiaservc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\isapnp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\isapnp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KtmRm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KtmRm","%systemroot%\system32\msdtckrm.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc","%SystemRoot%\System32\gpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ShellHWDetection","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ShellHWDetection","%SystemRoot%\System32\shsvcs.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DXGKrnl","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DXGKrnl",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WUDFRd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WUDFRd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WIMMount","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WIMMount",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp-debug","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp-debug",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EntAppSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EntAppSvc","%SystemRoot%\system32\EnterpriseAppMgmtSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\seclogon","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\seclogon","%windir%\system32\seclogon.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\luafv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\luafv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdgpio2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdgpio2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlpasvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlpasvc","%SystemRoot%\System32\lpasvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CLFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CLFS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdhid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdhid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmhgfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmhgfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MRxDAV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MRxDAV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\portcfg","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\portcfg",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpiex","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpiex",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\svsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\svsvc","%SystemRoot%\system32\svsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPAutoReg","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPAutoReg","%SystemRoot%\system32\pnrpauto.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetSetupSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetSetupSvc","%SystemRoot%\System32\NetSetupSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SENS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SENS","%SystemRoot%\System32\sens.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PEAUTH","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PEAUTH",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ALG","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ALG",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WudfPf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WudfPf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcifs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcifs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDKPing","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDKPing",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDIS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDIS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ScDeviceEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ScDeviceEnum","%SystemRoot%\System32\ScDeviceEnum.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReFS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HomeGroupProvider","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HomeGroupProvider","%SystemRoot%\system32\provsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidserv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidserv","%SystemRoot%\system32\hidserv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GPIOClx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GPIOClx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cnghwassist","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cnghwassist",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS","%SystemRoot%\system32\dps.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas2i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas2i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EFS","%SystemRoot%\system32\efssvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ramdisk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ramdisk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hyperkbd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hyperkbd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc","%SystemRoot%\System32\CDPUserSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPQM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPQM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc","%SystemRoot%\System32\certprop.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\napagent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\napagent",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pvscsi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pvscsi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache","%SystemRoot%\system32\FntCache.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Windows Workflow Foundation 4.0.0.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Windows Workflow Foundation 4.0.0.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventSystem","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventSystem","%systemroot%\system32\es.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRTProxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRTProxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice","%SystemRoot%\system32\dmwappushsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo","%SystemRoot%\system32\RDXService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdK8","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdK8",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\condrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\condrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBth","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBth",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FsDepends","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FsDepends",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbuhci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbuhci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbprint","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbprint",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WazuhSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WazuhSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvStrm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvStrm",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LicenseManager","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LicenseManager","%SystemRoot%\system32\LicenseManagerSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc","%SystemRoot%\System32\IpxlatCfg.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpipagr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpipagr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\drmkaud","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\drmkaud",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmgid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmgid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smphost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smphost","%Systemroot%\System32\smphost.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DCLocator","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DCLocator",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msiserver","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msiserver",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NativeWifiP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NativeWifiP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AxInstSV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AxInstSV","%SystemRoot%\System32\AxInstSV.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RFCOMM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RFCOMM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WPDBusEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WPDBusEnum","%SystemRoot%\system32\wpdbusenum.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MTConfig","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MTConfig",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmTcpciCx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmTcpciCx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsyncMac","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsyncMac",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc","%systemroot%\system32\usosvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iai2c","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iai2c",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fastfat","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fastfat",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvservice","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvservice",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spectrum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spectrum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volsnap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volsnap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthEnum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbldfltr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbldfltr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wbengine","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wbengine",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winsock","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winsock",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsSvc","%SystemRoot%\System32\DsSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwififlt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwififlt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicguestinterface","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicguestinterface","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdio","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdio",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorClass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorClass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService","%SystemRoot%\System32\termsrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsock","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsock",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Synth3dVsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Synth3dVsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WarpJITSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WarpJITSvc","%SystemRoot%\System32\Windows.WARP.JITService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kdnic","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kdnic",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PktMon","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PktMon",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WacomPen","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WacomPen",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc","%SystemRoot%\System32\wfdsconmgrsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TokenBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TokenBroker","%SystemRoot%\System32\TokenBroker.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storqosflt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storqosflt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cloudidsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cloudidsvc","%SystemRoot%\system32\cloudidsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsChipidea","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsChipidea",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ebdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ebdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\uhssvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\uhssvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bowser","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bowser",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreUI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreUI",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc","%SystemRoot%\System32\WerSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ssh-agent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ssh-agent",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService","%SystemRoot%\System32\MessagingService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_CNL","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_CNL",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvstor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvstor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsLldp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsLldp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CimFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CimFS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VaultSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VaultSvc","C:\Windows\System32\vaultsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationService","%SystemRoot%\system32\das.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc","%SystemRoot%\System32\nlasvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfDisk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfDisk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pla","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pla","%systemroot%\system32\pla.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvmsession","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvmsession","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPsvc","%SystemRoot%\system32\pnrpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicheartbeat","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicheartbeat","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsata","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsata",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tcpipreg","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tcpipreg",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndfltr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndfltr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAgileVpn","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAgileVpn",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVEdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVEdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc","%SystemRoot%\System32\wbiosrvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisVirtualBus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisVirtualBus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InstallService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InstallService","%SystemRoot%\system32\InstallService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService","%SystemRoot%\System32\umrdp.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiAcpi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiAcpi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WlanSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WlanSvc","%SystemRoot%\System32\wlansvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bttflt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bttflt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsRPC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsRPC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ahcache","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ahcache",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pciide","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pciide",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SMSvcHost 4.0.0.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SMSvcHost 4.0.0.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bindflt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bindflt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache","%SystemRoot%\System32\dnsrslvr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dservice","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dservice",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas2i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas2i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netprofm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netprofm","%SystemRoot%\System32\netprofmsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetbiosSmb","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetbiosSmb",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KeyIso","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KeyIso","%SystemRoot%\system32\keyiso.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StorSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StorSvc","%SystemRoot%\system32\storsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swenum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swenum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer","%SystemRoot%\system32\srvsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wof","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wof",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetAdapterCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetAdapterCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiPmi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiPmi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBatt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBatt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fvevol","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fvevol",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iphlpsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iphlpsvc","%SystemRoot%\System32\iphlpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_CNL","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_CNL",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msisadrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msisadrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcSvc","%SystemRoot%\system32\ngcsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc","%SystemRoot%\system32\winhttp.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbFlt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbFlt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc","%SystemRoot%\System32\Windows.Devices.Picker.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpsdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpsdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Fax","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Fax",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CmBatt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CmBatt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netvsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netvsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc","%SystemRoot%\System32\GraphicsPerfSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService","%SystemRoot%\system32\Microsoft.Graphics.Display.DisplayEnhancementService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV","%SystemRoot%\System32\ssdpsrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2pimsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2pimsvc","%SystemRoot%\system32\pnrpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBXHCI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBXHCI",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Null","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Null",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADOVMPPackage","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADOVMPPackage",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iScsiPrt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iScsiPrt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\b06bdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\b06bdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdbss","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdbss",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileCrypt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileCrypt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc","%SystemRoot%\System32\AarSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\camsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\camsvc","%SystemRoot%\system32\CapabilityAccessManager.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdmCompanionFilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdmCompanionFilter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc","%SystemRoot%\System32\DispBroker.Desktop.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppVClient","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppVClient",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasSstp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasSstp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\partmgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\partmgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ksthunk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ksthunk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidi2c","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidi2c",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpatialGraphFilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpatialGraphFilter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxpSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxpSvc","%SystemRoot%\System32\LanguageOverlayServer.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\s3cap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\s3cap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CompositeBus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CompositeBus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc","%SystemRoot%\System32\NgcCtnrSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto","%SystemRoot%\System32\rasauto.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ItSas35i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ItSas35i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbGD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbGD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS2i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS2i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\terminpt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\terminpt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ErrDev","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ErrDev",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsi","%systemroot%\system32\nsisvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcdAutoSetup","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcdAutoSetup","%SystemRoot%\System32\NcdAutoSetup.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RdpVideoMiniport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RdpVideoMiniport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\autotimesvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\autotimesvc","%SystemRoot%\System32\autotimesvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSTEE","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSTEE",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UGTHRSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UGTHRSVC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tunnel","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tunnel",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVemgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVemgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xboxgip","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xboxgip",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\disk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\disk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost","%SystemRoot%\system32\wdi.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srvnet","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srvnet",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iorate","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iorate",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSM","%SystemRoot%\System32\lsm.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClipSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClipSVC","%SystemRoot%\System32\ClipSVC.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcSs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcSs","%SystemRoot%\system32\rpcss.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc","%systemroot%\system32\DiagSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinNat","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinNat",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rspndr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rspndr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbhub","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbhub",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc","%SystemRoot%\System32\deviceaccess.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmsRouter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmsRouter","%SystemRoot%\system32\SmsRouterSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmPass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmPass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc","%SystemRoot%\System32\assignedaccessmanagersvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelpmax","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelpmax",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthLEEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthLEEnum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService","%SystemRoot%\system32\WpnService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppMgmt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppMgmt","%SystemRoot%\System32\appmgmts.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SystemEventsBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SystemEventsBroker","%SystemRoot%\System32\SystemEventsBrokerServer.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicrdv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicrdv","%SystemRoot%\System32\icsvcext.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService","%SystemRoot%\System32\BcastDVRUserService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog","%SystemRoot%\System32\wevtsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Networking","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Networking",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPUDD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPUDD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Data Provider for SqlServer","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Data Provider for SqlServer",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Npfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Npfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon","%SystemRoot%\system32\netlogon.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WManSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WManSvc","%systemroot%\system32\Windows.Management.Service.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry","%SystemRoot%\system32\regsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppID","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppID",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppReadiness","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppReadiness","%SystemRoot%\system32\AppReadiness.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\crypt32","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\crypt32",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winmgmt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winmgmt","%SystemRoot%\system32\wbem\WMIsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMBusHID","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMBusHID",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StateRepository","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StateRepository","%SystemRoot%\system32\windows.staterepository.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbhost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbhost",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\1394ohci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\1394ohci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netman","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netman","%SystemRoot%\System32\netman.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc","%SystemRoot%\System32\userdataservice.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dfsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dfsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthA2dp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthA2dp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sppsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sppsvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpdUpFltr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpdUpFltr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TabletInputService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TabletInputService","%SystemRoot%\System32\TabSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\e1i65x64","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\e1i65x64",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WiaRpc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WiaRpc","%SystemRoot%\System32\wiarpc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent","%SystemRoot%\System32\ipsecsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService","%SystemRoot%\System32\BTAGService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmvss","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmvss",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TapiSrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TapiSrv","%SystemRoot%\System32\tapisrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdpbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdpbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\flpydisk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\flpydisk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\monitor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\monitor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSave","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSave","%SystemRoot%\System32\XblGameSave.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Modem","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Modem",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidspi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidspi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmickvpexchange","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmickvpexchange","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storahci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storahci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIPTUNNEL","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIPTUNNEL",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager","%SystemRoot%\System32\XblAuthManager.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stexstor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stexstor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Rasl2tp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Rasl2tp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidkmdf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidkmdf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Lsa","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Lsa",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dot3svc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dot3svc","%SystemRoot%\System32\dot3svc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc","%systemroot%\system32\MitigationClient.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBIOS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBIOS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4vbd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4vbd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sbp2port","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sbp2port",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc","%SystemRoot%\System32\DevicesFlowBroker.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc","%SystemRoot%\system32\wecsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serenum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serenum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper","%SystemRoot%\System32\RpcEpMap.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidumdf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidumdf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Appinfo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Appinfo","%SystemRoot%\System32\appinfo.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDFRd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDFRd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsbs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsbs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbccgp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbccgp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\clr_optimization_v4.0.30319_32","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\clr_optimization_v4.0.30319_32",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService","%SystemRoot%\System32\CaptureService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UEFI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UEFI",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Networking 4.0.0.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Networking 4.0.0.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelppm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelppm",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsiproxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsiproxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmvsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmvsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedRealitySvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedRealitySvc","%SystemRoot%\System32\SharedRealitySvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisTapi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisTapi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wisvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wisvc","%systemroot%\system32\flightsettings.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp_loader","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp_loader",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CldFlt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CldFlt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker","%SystemRoot%\System32\moshost.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc","%SystemRoot%\System32\PrintWorkflowService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc","%SystemRoot%\System32\cbdhsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WLMS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WLMS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcw","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcw",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PlugPlay","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PlugPlay","%SystemRoot%\system32\umpnpmgr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmxnet3ndis6","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmxnet3ndis6",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmCx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmCx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ufx01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ufx01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpcMonSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpcMonSvc","%SystemRoot%\System32\WpcDesktopMonSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPMIDRV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPMIDRV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Acx01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Acx01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisImPlatform","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisImPlatform",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndisuio","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndisuio",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcbService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcbService","%SystemRoot%\System32\ncbservice.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HomeGroupListener","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HomeGroupListener","%SystemRoot%\system32\ListSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BattC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BattC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CSC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CSC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BDESVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BDESVC","%SystemRoot%\System32\bdesvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FrameServer","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FrameServer","%SystemRoot%\system32\FrameServer.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsSynopsys","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsSynopsys",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPSvc","%SystemRoot%\System32\CDPSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NETFramework","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NETFramework",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mountmgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mountmgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorTcgDrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorTcgDrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PeerDistSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PeerDistSvc","%SystemRoot%\system32\peerdistsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Parport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Parport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorService","%SystemRoot%\system32\SensorService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\umbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\umbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTRAP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTRAP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSSCNTRS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSSCNTRS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation","%SystemRoot%\System32\wkssvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bcmfn2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bcmfn2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidUsb","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidUsb",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wmiApSrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wmiApSrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas3i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas3i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpbCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpbCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc","%SystemRoot%\System32\PimIndexMaintenance.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintNotify","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintNotify","C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UASPStor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UASPStor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc","%SystemRoot%\System32\appidsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tsusbhub","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tsusbhub",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HdAudAddService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HdAudAddService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc","%SystemRoot%\System32\lltdsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdxata","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdxata",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure","%SystemRoot%\System32\psmsrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc","%SystemRoot%\system32\appxdeploymentserver.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfOS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfOS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDMANDK","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDMANDK",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc","%SystemRoot%\System32\XboxGipSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdrom","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdrom",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmictimesync","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmictimesync","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Filetrace","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Filetrace",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SEMgrSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SEMgrSvc","%SystemRoot%\system32\SEMgrSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPCLOCK","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPCLOCK",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UfxChipidea","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UfxChipidea",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xinputhid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xinputhid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DialogBlockingService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DialogBlockingService","%SystemRoot%\System32\DialogBlockingService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMMemCtl","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMMemCtl",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorDataService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorDataService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc","%SystemRoot%\System32\pcasvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVE","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVE","%windir%\system32\qwave.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceparser","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceparser",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate","%SystemRoot%\system32\tzautoupdate.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storflt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storflt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiApRpl","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiApRpl",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasPppoe","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasPppoe",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\buttonconverter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\buttonconverter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcncsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcncsvc","%SystemRoot%\System32\wcncsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ucx01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ucx01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TSDDD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TSDDD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc","%SystemRoot%\System32\ConsentUxClient.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IKEEXT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IKEEXT","%SystemRoot%\System32\ikeext.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SamSs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SamSs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfHost",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AJRouter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AJRouter","%SystemRoot%\System32\AJRouter.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAVC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ntfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ntfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Data Provider for Oracle","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Data Provider for Oracle",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsQuic","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsQuic",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndiswanlegacy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndiswanlegacy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI","%systemroot%\system32\iscsiexe.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CAD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CAD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HvHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HvHost","%SystemRoot%\System32\hvhostsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmmouse","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmmouse",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VacSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VacSvc","%SystemRoot%\System32\vac.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar","%SystemRoot%\system32\coremessaging.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvss","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvss","%SystemRoot%\System32\icsvcext.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UGatherer","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UGatherer",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WalletService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WalletService","%SystemRoot%\system32\WalletService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\arcsas","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\arcsas",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ufxsynopsys","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ufxsynopsys",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\COMSysApp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\COMSysApp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADP80XX","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADP80XX",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpFilterDriver","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpFilterDriver",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pmem","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pmem",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Telemetry","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Telemetry",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\defragsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\defragsvc","%Systemroot%\System32\defragsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc","%SystemRoot%\System32\APHostService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\clr_optimization_v4.0.30319_64","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\clr_optimization_v4.0.30319_64",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PhoneSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PhoneSvc","%SystemRoot%\System32\PhoneService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc_6e8d5","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc_6e8d5",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volume","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volume",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scmbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scmbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelpep","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelpep",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdi2c","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdi2c",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthPan","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthPan",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicDisplay","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicDisplay",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost","%SystemRoot%\System32\upnphost.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wdf01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wdf01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsBridge","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsBridge",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sermouse","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sermouse",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisCap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisCap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecDD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecDD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serial","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serial",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ESENT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ESENT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc","%systemroot%\system32\Windows.Internal.Management.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storvsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storvsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb20","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb20",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storufs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storufs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MbbCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MbbCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdate","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdate",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPNAT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPNAT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WwanSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WwanSvc","%SystemRoot%\System32\wwansvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\workerdd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\workerdd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ws2ifsl","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ws2ifsl",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PptpMiniport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PptpMiniport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCPolicySvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCPolicySvc","%SystemRoot%\System32\certprop.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hwpolicy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hwpolicy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HyperVideo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HyperVideo",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swprv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swprv","%Systemroot%\System32\swprv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_I2C","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_I2C",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfProc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfProc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VirtualRender","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VirtualRender",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RmSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RmSvc","%SystemRoot%\System32\RMapi.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpssvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpssvc","%SystemRoot%\system32\mpssvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient","%SystemRoot%\System32\webclnt.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileInfo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileInfo",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouhid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouhid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ProfSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ProfSvc","%systemroot%\system32\profsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbehci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbehci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\i8042prt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\i8042prt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Themes","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Themes","%SystemRoot%\system32\themeservice.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsmSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsmSvc","%SystemRoot%\System32\DeviceSetupManager.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HDAudBus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HDAudBus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack","%SystemRoot%\system32\diagtrack.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Audiosrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Audiosrv","%SystemRoot%\System32\Audiosrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbohci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbohci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelide","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelide",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisWan","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisWan",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiAcpiClient","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiAcpiClient",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmrawdsk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmrawdsk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAcd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAcd",
  '
  $W11ServiceDllTable = '#TYPE System.Collections.DictionaryEntry
    "Name","Key","Value"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MbbCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MbbCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NPSMSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NPSMSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache","%SystemRoot%\System32\dnsrslvr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppVClient","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppVClient",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dam","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dam",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smbdirect","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smbdirect",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc","%SystemRoot%\System32\assignedaccessmanagersvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc","%SystemRoot%\system32\wecsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidspi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidspi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Networking","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Networking",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelpmax","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelpmax",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Beep","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Beep",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserManager","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserManager","%SystemRoot%\System32\usermgr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADP80XX","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADP80XX",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvmsession","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvmsession","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDKPing","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDKPing",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bcmfn2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bcmfn2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess","%SystemRoot%\System32\mprdim.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PptpMiniport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PptpMiniport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IndirectKmd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IndirectKmd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv","%SystemRoot%\system32\bthserv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Hsp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Hsp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\luafv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\luafv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicDisplay","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicDisplay",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsBridge","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsBridge",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_CNL","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_CNL",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc","%SystemRoot%\system32\appxdeploymentserver.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc","%SystemRoot%\System32\netprofmsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvservice","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvservice",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WINUSB","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WINUSB",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WudfPf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WudfPf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IntelPMT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IntelPMT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBth","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBth",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smphost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smphost","%Systemroot%\System32\smphost.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks","%SystemRoot%\System32\trkwks.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc","%systemroot%\system32\DiagSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetSetupSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetSetupSvc","%SystemRoot%\System32\NetSetupSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbccgp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbccgp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HyperVideo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HyperVideo",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCardSvr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCardSvr","%SystemRoot%\System32\SCardSvr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kdnic","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kdnic",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc","%SystemRoot%\system32\cryptsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHMODEM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHMODEM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CompositeBus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CompositeBus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MTConfig","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MTConfig",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient","%SystemRoot%\System32\webclnt.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorService","%SystemRoot%\system32\SensorService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\adsi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\adsi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\b06bdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\b06bdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppReadiness","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppReadiness","%SystemRoot%\system32\AppReadiness.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMTools","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMTools",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\applockerfltr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\applockerfltr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReFSv1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReFSv1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmvss","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmvss",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StiSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StiSvc","%SystemRoot%\System32\wiaservc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc","%SystemRoot%\System32\IpxlatCfg.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scmbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scmbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpsdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpsdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPSvc","%SystemRoot%\System32\CDPSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdbss","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdbss",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\E1G60","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\E1G60",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsKeyboardFilter","%SystemRoot%\System32\KeyboardFilterSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisWan","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisWan",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dservice","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dservice",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidumdf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidumdf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmusbmouse","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmusbmouse",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WiaRpc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WiaRpc","%SystemRoot%\System32\wiarpc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService","%SystemRoot%\System32\termsrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlpasvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlpasvc","%SystemRoot%\System32\lpasvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serenum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serenum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker","%SystemRoot%\System32\moshost.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Npfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Npfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lxss","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lxss",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vdrvroot","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vdrvroot",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc","%SystemRoot%\System32\Windows.Devices.Picker.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport","%SystemRoot%\System32\wercplsupport.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorClass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorClass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\isapnp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\isapnp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdxata","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdxata",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc","%SystemRoot%\System32\PimIndexMaintenance.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp_loader","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp_loader",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc","%SystemRoot%\system32\winhttp.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas2i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas2i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\1394ohci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\1394ohci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\crypt32","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\crypt32",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ksthunk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ksthunk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UEFI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UEFI",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StateRepository","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StateRepository","%SystemRoot%\system32\windows.staterepository.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xboxgip","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xboxgip",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UGatherer","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UGatherer",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmgid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmgid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PhoneSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PhoneSvc","%SystemRoot%\System32\PhoneService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Appinfo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Appinfo","%SystemRoot%\System32\appinfo.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ntfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ntfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidSpiCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidSpiCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmickvpexchange","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmickvpexchange","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDFRd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDFRd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iorate","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iorate",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WwanSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WwanSvc","%SystemRoot%\System32\wwansvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\workfolderssvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\workfolderssvc","%systemroot%\system32\workfolderssvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdPHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdPHost","%SystemRoot%\system32\fdPHost.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppMgmt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppMgmt","%SystemRoot%\System32\appmgmts.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\condrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\condrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SQLWriter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SQLWriter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stexstor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stexstor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsSvc","%SystemRoot%\System32\DsSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPUDD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPUDD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidkmdf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidkmdf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiPmi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiPmi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvstor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvstor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\autotimesvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\autotimesvc","%SystemRoot%\System32\autotimesvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsLldp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsLldp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DusmSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DusmSvc","%SystemRoot%\System32\dusmsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppleSSD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppleSSD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceparser","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceparser",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDMANDK","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDMANDK",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Audiosrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Audiosrv","%SystemRoot%\System32\Audiosrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvss","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvss","%SystemRoot%\System32\icsvcvss.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storvsp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storvsp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wmiApSrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wmiApSrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode","%SystemRoot%\System32\embeddedmodesvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevQueryBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevQueryBroker","%SystemRoot%\system32\DevQueryBroker.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTAGService","%SystemRoot%\System32\BTAGService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc","%SystemRoot%\System32\CDPUserSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcLocator","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcLocator",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hwpolicy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hwpolicy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BDESVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BDESVC","%SystemRoot%\System32\bdesvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbip","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbip",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvumis","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvumis",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mlx4_bus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mlx4_bus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VmsProxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VmsProxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc","%SystemRoot%\System32\PrintWorkflowService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdstor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdstor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiAcpiClient","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiAcpiClient",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelpep","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelpep",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2psvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2psvc","%SystemRoot%\system32\p2psvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBIOS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBIOS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\udfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\udfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsi","%systemroot%\system32\nsisvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vpcivsp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vpcivsp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisImPlatform","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisImPlatform",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvraid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvraid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdgpio2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdgpio2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfHost",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache","%SystemRoot%\system32\FntCache.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsyncMac","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsyncMac",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AJRouter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AJRouter","%SystemRoot%\System32\AJRouter.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicshutdown","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicshutdown","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fvevol","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fvevol",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msiserver","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msiserver",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbFlt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbFlt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cloudidsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cloudidsvc","%SystemRoot%\system32\cloudidsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpiex","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpiex",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2pimsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2pimsvc","%SystemRoot%\system32\pnrpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcncsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcncsvc","%SystemRoot%\System32\wcncsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiDev","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiDev",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HDAudBus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HDAudBus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\genericusbfn","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\genericusbfn",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthEnum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\perceptionsimulation","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\perceptionsimulation",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_CNL","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_CNL",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iai2c","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iai2c",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4iscsi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4iscsi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSNPXY","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSNPXY",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dot3svc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dot3svc","%SystemRoot%\System32\dot3svc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinVerbs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinVerbs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iagpio","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iagpio",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FltMgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FltMgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc","%SystemRoot%\System32\XboxGipSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\afunix","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\afunix",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc","%systemroot%\system32\usosvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Power","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Power","%SystemRoot%\system32\umpo.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetbiosSmb","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetbiosSmb",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecDD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecDD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Schedule","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Schedule","%systemroot%\system32\schedsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\3ware","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\3ware",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NPSMSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NPSMSvc","%SystemRoot%\System32\npsm.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vpci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vpci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SstpSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SstpSvc","%SystemRoot%\system32\sstpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidIr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidIr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vds","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vds",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpdUpFltr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpdUpFltr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbcir","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbcir",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsata","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsata",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scfilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scfilter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwifibus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwifibus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpi3drvi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpi3drvi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdhid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdhid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreUI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreUI",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\P9Rdr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\P9Rdr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService","%SystemRoot%\System32\MessagingService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc","%SystemRoot%\System32\certprop.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bindflt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bindflt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_BXT_P","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_BXT_P",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdrom","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdrom",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService","%SystemRoot%\system32\WpnService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msgpiowin32","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msgpiowin32",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceInstall","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceInstall","%SystemRoot%\system32\umpnpmgr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Processor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Processor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\icssvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\icssvc","%SystemRoot%\System32\tetheringservice.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinMad","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinMad",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc","%SystemRoot%\System32\lltdsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Parport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Parport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc","%SystemRoot%\System32\TimeBrokerServer.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winsock","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winsock",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmTcpciCx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmTcpciCx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volsnap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volsnap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\portcfg","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\portcfg",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdi2c","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdi2c",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CimFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CimFS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsbs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsbs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xinputhid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xinputhid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DialogBlockingService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DialogBlockingService","%SystemRoot%\System32\DialogBlockingService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NETFramework","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NETFramework",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EntAppSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EntAppSvc","%SystemRoot%\system32\EnterpriseAppMgmtSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmcompute","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmcompute",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiCx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiCx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndproxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndproxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AxInstSV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AxInstSV","%SystemRoot%\System32\AxInstSV.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvagent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvagent","%SystemRoot%\System32\NvAgent.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation","%SystemRoot%\System32\wkssvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmrawdsk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmrawdsk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack","%SystemRoot%\system32\diagtrack.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\McpManagementService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\McpManagementService","%SystemRoot%\System32\McpManagementService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netprofm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netprofm","%SystemRoot%\System32\netprofmsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\clr_optimization_v4.0.30319_64","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\clr_optimization_v4.0.30319_64",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Fax","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Fax",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarpv6","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarpv6",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\atapi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\atapi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DcomLaunch","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DcomLaunch","%SystemRoot%\system32\rpcss.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pmem","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pmem",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FrameServer","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FrameServer","%SystemRoot%\system32\FrameServer.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS","%SystemRoot%\system32\dps.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\umbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\umbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc","%SystemRoot%\System32\pcasvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess","%SystemRoot%\System32\ipnathlp.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storvsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storvsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RmSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RmSvc","%SystemRoot%\System32\RMapi.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRTProxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRTProxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsCx01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsCx01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DXGKrnl","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DXGKrnl",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdK8","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdK8",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan","%SystemRoot%\System32\rasmans.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsock","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsock",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADOVMPPackage","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADOVMPPackage",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer","%SystemRoot%\system32\srvsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CNG","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CNG",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Mup","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Mup",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintNotify","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintNotify","C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder","%SystemRoot%\System32\AudioEndpointBuilder.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HwNClx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HwNClx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msisadrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msisadrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VaultSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VaultSvc","C:\Windows\System32\vaultsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVE","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVE","%windir%\system32\qwave.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto","%SystemRoot%\System32\rasauto.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecPkg","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecPkg",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc","%SystemRoot%\System32\DevicesFlowBroker.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar","%SystemRoot%\system32\coremessaging.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srvnet","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srvnet",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVemgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVemgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pciide","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pciide",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VirtualRender","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VirtualRender",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService","%SystemRoot%\System32\BcastDVRUserService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper","%SystemRoot%\System32\RpcEpMap.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\P9NP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\P9NP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearchIdxPi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearchIdxPi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SENS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SENS","%SystemRoot%\System32\sens.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdeCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdeCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService","%SystemRoot%\system32\Microsoft.Graphics.Display.DisplayEnhancementService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WarpJITSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WarpJITSvc","%SystemRoot%\System32\Windows.WARP.JITService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcw","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcw",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMMemCtl","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMMemCtl",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Data Provider for Oracle","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Data Provider for Oracle",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPNAT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPNAT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FDResPub","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FDResPub","%SystemRoot%\system32\fdrespub.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PushToInstall","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PushToInstall","%SystemRoot%\system32\PushToInstall.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dfsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dfsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\exfat","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\exfat",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS2i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS2i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc","%SystemRoot%\System32\cbdhsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TokenBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TokenBroker","%SystemRoot%\System32\TokenBroker.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GPIOClx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GPIOClx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost","%SystemRoot%\system32\wdi.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthLEEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthLEEnum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBXHCI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBXHCI",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpssvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpssvc","%SystemRoot%\system32\mpssvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Usb4HostRouter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Usb4HostRouter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MRxDAV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MRxDAV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdPPM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdPPM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIPTUNNEL","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIPTUNNEL",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sermouse","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sermouse",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\circlass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\circlass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HdAudAddService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HdAudAddService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDRSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDRSVC","%Systemroot%\System32\SDRSVC.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndfltr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndfltr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidinterrupt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidinterrupt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc","%SystemRoot%\System32\appidsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IKEEXT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IKEEXT","%SystemRoot%\System32\ikeext.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSTEE","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSTEE",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmxnet3ndis6","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmxnet3ndis6",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxssManager","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxssManager","%SystemRoot%\system32\lxss\LxssManager.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mountmgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mountmgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_GPIO","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_GPIO",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ufxsynopsys","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ufxsynopsys",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KeyIso","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KeyIso","%SystemRoot%\system32\keyiso.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpatialGraphFilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpatialGraphFilter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TieringEngineService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TieringEngineService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFDSConMgrSvc","%SystemRoot%\System32\wfdsconmgrsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfOS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfOS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Vid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WalletService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WalletService","%SystemRoot%\system32\WalletService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rspndr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rspndr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfProc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfProc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WIMMount","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WIMMount",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSave","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSave","%SystemRoot%\System32\XblGameSave.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storqosflt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storqosflt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6TUNNEL","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6TUNNEL",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb20","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb20",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iScsiPrt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iScsiPrt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ufx01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ufx01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlidsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlidsvc","%SystemRoot%\system32\wlidsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\napagent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\napagent",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsmSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsmSvc","%SystemRoot%\System32\DeviceSetupManager.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventSystem","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventSystem","%systemroot%\system32\es.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost","%SystemRoot%\system32\wdi.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc","%SystemRoot%\System32\wscsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VGAuthService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VGAuthService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lmhosts","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lmhosts","%SystemRoot%\System32\lmhsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Memory Cache 4.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Memory Cache 4.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CLFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CLFS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wbengine","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wbengine",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ScDeviceEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ScDeviceEnum","%SystemRoot%\System32\ScDeviceEnum.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\disk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\disk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthMini","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthMini",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPQM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPQM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ssh-agent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ssh-agent",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpcMonSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpcMonSvc","%SystemRoot%\System32\WpcDesktopMonSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisVirtualBus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisVirtualBus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WLMS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WLMS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc","%SystemRoot%\System32\windowsudkservices.shellcommon.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcbService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcbService","%SystemRoot%\System32\ncbservice.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicheartbeat","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicheartbeat","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PlugPlay","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PlugPlay","%SystemRoot%\system32\umpnpmgr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrustedInstaller","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrustedInstaller",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ahcache","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ahcache",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvmedisk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvmedisk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Rasl2tp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Rasl2tp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpipagr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpipagr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WlanSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WlanSvc","%SystemRoot%\System32\wlansvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI","%systemroot%\system32\iscsiexe.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClipSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClipSVC","%SystemRoot%\System32\ClipSVC.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KtmRm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KtmRm","%systemroot%\system32\msdtckrm.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EapHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EapHost","%SystemRoot%\System32\eapsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmsRouter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmsRouter","%SystemRoot%\system32\SmsRouterSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ebdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ebdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure","%SystemRoot%\System32\psmsrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SEMgrSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SEMgrSvc","%SystemRoot%\system32\SEMgrSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\buttonconverter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\buttonconverter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WManSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WManSvc","%systemroot%\system32\Windows.Management.Service.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNPMEM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNPMEM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_GLK","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_GLK",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EFS","%SystemRoot%\system32\efssvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ALG","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ALG",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmbusr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmbusr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcifs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcifs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPCLOCK","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPCLOCK",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Filetrace","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Filetrace",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbGD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbGD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc","%SystemRoot%\System32\ConsentUxClient.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wof","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wof",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgrx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgrx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisTapi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisTapi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wcmsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wcmsvc","%SystemRoot%\System32\wcmsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc","%SystemRoot%\System32\APHostService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ErrDev","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ErrDev",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sfloppy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sfloppy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ramdisk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ramdisk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UGTHRSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UGTHRSVC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinNat","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinNat",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swprv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swprv","%Systemroot%\System32\swprv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelide","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelide",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ebdrv0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ebdrv0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCPolicySvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCPolicySvc","%SystemRoot%\System32\certprop.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiAcpi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiAcpi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CldFlt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CldFlt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rhproxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rhproxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsSynopsys","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsSynopsys",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcmcia","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcmcia",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorDataService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorDataService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Data Provider for SqlServer","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Data Provider for SqlServer",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc","%SystemRoot%\System32\deviceaccess.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wdf01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wdf01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc","%SystemRoot%\System32\userdataservice.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_I2C","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_I2C",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hyperkbd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hyperkbd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc","%SystemRoot%\System32\wbiosrvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CAD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CAD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time","%systemroot%\system32\w32time.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PeerDistSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PeerDistSvc","%SystemRoot%\system32\peerdistsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc","%SystemRoot%\System32\AarSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sppsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sppsvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PktMon","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PktMon",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TroubleshootingSvc","%systemroot%\system32\MitigationClient.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ShellHWDetection","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ShellHWDetection","%SystemRoot%\System32\shsvcs.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC Bridge 4.0.0.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC Bridge 4.0.0.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Data","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Data",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_GLK","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2_GLK",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdmCompanionFilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdmCompanionFilter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcSvc","%SystemRoot%\system32\ngcsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsChipidea","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsChipidea",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WUDFRd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WUDFRd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swenum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swenum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcaSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcaSvc","%SystemRoot%\System32\ncasvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SystemEventsBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SystemEventsBroker","%SystemRoot%\System32\SystemEventsBrokerServer.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Networking 4.0.0.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Networking 4.0.0.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicRender","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicRender",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Null","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Null",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PenService_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PenService_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdyboost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdyboost",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFPLWFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFPLWFS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\npsvctrig","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\npsvctrig",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain","%systemroot%\system32\sysmain.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdio","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdio",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas35i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas35i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SamSs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SamSs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\arcsas","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\arcsas",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\COMSysApp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\COMSysApp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAgileVpn","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAgileVpn",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetAdapterCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetAdapterCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\monitor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\monitor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CSC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CSC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcdAutoSetup","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcdAutoSetup","%SystemRoot%\System32\NcdAutoSetup.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tunnel","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tunnel",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorTcgDrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorTcgDrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbldfltr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbldfltr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsmraid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsmraid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSKSSRV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSKSSRV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4vbd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4vbd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pla","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pla","%systemroot%\system32\pla.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelppm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelppm",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS3i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS3i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbprint","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbprint",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ldap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ldap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxpSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LxpSvc","%SystemRoot%\System32\LanguageOverlayServer.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\passthruparser","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\passthruparser",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndiswanlegacy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndiswanlegacy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fastfat","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fastfat",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ACPI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ACPI",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbhub","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbhub",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPsvc","%SystemRoot%\system32\pnrpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\clr_optimization_v4.0.30319_32","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\clr_optimization_v4.0.30319_32",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Themes","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Themes","%SystemRoot%\system32\themeservice.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpitime","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpitime",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WPDBusEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WPDBusEnum","%SystemRoot%\system32\wpdbusenum.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp-debug","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp-debug",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hnswfpdriver","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hnswfpdriver",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netvsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netvsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv","%systemroot%\system32\wuaueng.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon","%SystemRoot%\system32\netlogon.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ws2ifsl","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ws2ifsl",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhdmp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhdmp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storflt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storflt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PRM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PRM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry","%SystemRoot%\system32\regsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SessionEnv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SessionEnv","%SystemRoot%\system32\sessenv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ItSas35i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ItSas35i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RdpVideoMiniport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RdpVideoMiniport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CmBatt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CmBatt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvdimm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvdimm",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tsusbhub","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tsusbhub",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xmlprov","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xmlprov",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwififlt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwififlt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSStandardCollectorService150","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSStandardCollectorService150",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV","%SystemRoot%\System32\ssdpsrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Acx01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Acx01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wdiwifi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wdiwifi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\drmkaud","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\drmkaud",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbuhci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbuhci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbehci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbehci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storufs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storufs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InstallService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InstallService","%SystemRoot%\system32\InstallService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Psched","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Psched",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iphlpsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iphlpsvc","%SystemRoot%\System32\iphlpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MixedRealityOpenXRSvc","%SystemRoot%\System32\MixedRealityRuntime.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wisvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wisvc","%systemroot%\system32\flightsettings.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RetailDemo","%SystemRoot%\system32\RDXService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Microsoft_Bluetooth_AvrcpTransport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Microsoft_Bluetooth_AvrcpTransport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fse","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fse",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMBusHID","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMBusHID",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ucx01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ucx01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HvHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HvHost","%SystemRoot%\System32\hvhostsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicguestinterface","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicguestinterface","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmCx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmCx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvStrm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvStrm",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSVSF","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSVSF",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Msfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Msfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc","%SystemRoot%\System32\gpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpbCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpbCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReFS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp","%SystemRoot%\system32\dhcpcore.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhdparser","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhdparser",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppID","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppID",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Fs_Rec","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Fs_Rec",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndisuio","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndisuio",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TSDDD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TSDDD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidi2c","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidi2c",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gencounter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gencounter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsRPC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsRPC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdpbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdpbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationService","%SystemRoot%\system32\das.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\terminpt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\terminpt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\P9RdrService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\P9RdrService","%SystemRoot%\system32\p9rdrservice.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\seclogon","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\seclogon","%windir%\system32\seclogon.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpFilterDriver","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpFilterDriver",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAVC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tcpipreg","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tcpipreg",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MMCSS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MMCSS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvcrash","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvcrash",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmsmp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmsmp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensrSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensrSvc","%SystemRoot%\system32\sensrsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBatt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBatt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasPppoe","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasPppoe",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidUsb","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidUsb",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\workerdd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\workerdd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\inetaccs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\inetaccs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_GPIO2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfDisk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfDisk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmbusproxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmbusproxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srv2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srv2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AarSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiApRpl","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiApRpl",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsQuic","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsQuic",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netman","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netman","%SystemRoot%\System32\netman.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbser","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbser",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WifiCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WifiCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SMSvcHost 4.0.0.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SMSvcHost 4.0.0.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthHFEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthHFEnum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp-stats","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp-stats",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ExecutionContext","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ExecutionContext",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BITS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BITS","%SystemRoot%\System32\qmgr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouhid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouhid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\s3cap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\s3cap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbhost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbhost",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FrameServerMonitor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FrameServerMonitor","%SystemRoot%\system32\FrameServerMonitor.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\camsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\camsvc","%SystemRoot%\system32\CapabilityAccessManager.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fhsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fhsvc","%SystemRoot%\system32\fhsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc","%SystemRoot%\System32\WaaSMedicSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VerifierExt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VerifierExt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPAutoReg","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPAutoReg","%SystemRoot%\system32\pnrpauto.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hns","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hns","%SystemRoot%\System32\HostNetSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NaturalAuthentication","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NaturalAuthentication","%SystemRoot%\System32\NaturalAuth.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serial","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serial",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DCLocator","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DCLocator",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pdc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pdc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UASPStor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UASPStor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasSstp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasSstp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BattC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BattC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager","%SystemRoot%\System32\XblAuthManager.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CscService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CscService","%SystemRoot%\System32\cscsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NativeWifiP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NativeWifiP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\defragsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\defragsvc","%Systemroot%\System32\defragsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSM","%SystemRoot%\System32\lsm.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvsocketcontrol","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvsocketcontrol",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\i8042prt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\i8042prt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfNet","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfNet",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost","%SystemRoot%\System32\upnphost.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spectrum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spectrum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTrap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTrap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PEAUTH","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PEAUTH",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmhgfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmhgfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicrdv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicrdv","%SystemRoot%\System32\icsvcext.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cnghwassist","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cnghwassist",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TapiSrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TapiSrv","%SystemRoot%\System32\tapisrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM","%SystemRoot%\system32\WsmSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StorSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StorSvc","%SystemRoot%\system32\storsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UfxChipidea","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UfxChipidea",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmPass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmPass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\svsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\svsvc","%SystemRoot%\system32\svsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WacomPen","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WacomPen",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAcd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAcd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc","%SystemRoot%\system32\XboxNetApiSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog","%SystemRoot%\System32\wevtsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FsDepends","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FsDepends",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentDriver","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentDriver",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc","%systemroot%\system32\Windows.Internal.Management.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\uhssvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\uhssvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService","%SystemRoot%\System32\CaptureService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthAvctpSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthAvctpSvc","%SystemRoot%\System32\BthAvctpSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPDR","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPDR",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Modem","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Modem",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmmouse","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmmouse",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileInfo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileInfo",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE","%SystemRoot%\System32\bfe.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmartSAMD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmartSAMD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmwefifw","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmwefifw",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSTXRAID","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSTXRAID",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ProfSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ProfSvc","%systemroot%\system32\profsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileCrypt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileCrypt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volume","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volume",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc","%SystemRoot%\System32\unistore.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc","%SystemRoot%\System32\NgcCtnrSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDIS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDIS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc","%SystemRoot%\System32\lfsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc","%SystemRoot%\System32\DispBroker.Desktop.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HpSAMD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HpSAMD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidserv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidserv","%SystemRoot%\system32\hidserv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsiproxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsiproxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPMIDRV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPMIDRV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_BXT_P","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSS2i_I2C_BXT_P",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcSs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcSs","%SystemRoot%\system32\rpcss.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc","%SystemRoot%\System32\GraphicsPerfSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHUSB","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHUSB",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winmgmt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winmgmt","%SystemRoot%\system32\wbem\WMIsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Usb4DeviceRouter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Usb4DeviceRouter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Windows Workflow Foundation 4.0.0.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Windows Workflow Foundation 4.0.0.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice","%SystemRoot%\system32\dmwappushsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bowser","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bowser",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ESENT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ESENT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbohci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbohci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas3i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas3i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedRealitySvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedRealitySvc","%SystemRoot%\System32\SharedRealitySvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mssmbios","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mssmbios",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RFCOMM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RFCOMM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService","%SystemRoot%\System32\umrdp.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\flpydisk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\flpydisk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService_7f7f4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBHUB3","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBHUB3",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent","%SystemRoot%\System32\ipsecsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sbp2port","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sbp2port",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdate","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdate",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmictimesync","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmictimesync","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storahci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storahci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSVSP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMSVSP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VacSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VacSvc","%SystemRoot%\System32\vac.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPNP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPNP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TabletInputService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TabletInputService","%SystemRoot%\System32\TabSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc","%SystemRoot%\System32\WerSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate","%SystemRoot%\system32\tzautoupdate.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\partmgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\partmgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDKPerf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDKPerf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PenService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PenService","%SystemRoot%\System32\PenService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthA2dp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthA2dp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService","%SystemRoot%\System32\Microsoft.Bluetooth.UserService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC","%systemroot%\system32\wephostsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisCap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisCap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pvhdparser","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pvhdparser",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tdx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tdx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVEdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVEdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LicenseManager","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LicenseManager","%SystemRoot%\system32\LicenseManagerSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\l2bridge","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\l2bridge",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService","%SystemRoot%\System32\WpnUserService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\shpamsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\shpamsvc","%systemroot%\system32\Windows.SharedPC.AccountManager.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmvsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmvsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bttflt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bttflt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas2i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas2i",
  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\P9RdrService_7f7f4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\P9RdrService_7f7f4",'
  $W2022ServiceDllTable = '#TYPE System.Collections.DictionaryEntry
    "Name","Key","Value"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CNG","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CNG",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tzautoupdate","%SystemRoot%\system32\tzautoupdate.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sppsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sppsvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LicenseManager","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LicenseManager","%SystemRoot%\system32\LicenseManagerSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppVClient","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppVClient",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthEnum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcmcia","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcmcia",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pdc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pdc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srvnet","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srvnet",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RmSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RmSvc","%SystemRoot%\System32\RMapi.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicRender","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicRender",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisImPlatform","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisImPlatform",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pvscsi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pvscsi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost","%SystemRoot%\system32\wdi.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouhid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouhid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ucx01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ucx01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\qefcoe","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\qefcoe",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasSstp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasSstp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelppm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelppm",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmTcpciCx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmTcpciCx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EapHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EapHost","%SystemRoot%\System32\eapsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msisadrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msisadrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthMini","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthMini",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ItSas35i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ItSas35i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ebdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ebdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPQM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPQM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMTools","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMTools",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetAdapterCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetAdapterCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMBusHID","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMBusHID",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCardSvr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCardSvr","%SystemRoot%\System32\SCardSvr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentDriver","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentDriver",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RFCOMM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RFCOMM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storvsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storvsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Null","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Null",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdxata","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdxata",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mssmbios","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mssmbios",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hyperkbd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hyperkbd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsRoleSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsRoleSvc","%SystemRoot%\system32\dsrolesrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceInstall","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceInstall","%SystemRoot%\system32\umpnpmgr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicheartbeat","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicheartbeat","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensrSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensrSvc","%SystemRoot%\system32\sensrsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc","%SystemRoot%\System32\unistore.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\1394ohci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\1394ohci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6TUNNEL","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6TUNNEL",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KeyIso","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KeyIso","%SystemRoot%\system32\keyiso.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcEptMapper","%SystemRoot%\System32\RpcEpMap.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc","%SystemRoot%\System32\windowsudkservices.shellcommon.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ql40xx2i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ql40xx2i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BFE","%SystemRoot%\System32\bfe.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WLMS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WLMS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Networking 4.0.0.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Networking 4.0.0.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VerifierExt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VerifierExt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhdmp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhdmp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bindflt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bindflt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bxfcoe","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bxfcoe",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc","%SystemRoot%\System32\GraphicsPerfSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\flpydisk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\flpydisk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serial","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serial",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS2i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS2i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndisuio","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndisuio",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisCap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisCap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc","%SystemRoot%\System32\cbdhsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDKPing","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDKPing",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BattC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BattC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsyncMac","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AsyncMac",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ShellHWDetection","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ShellHWDetection","%SystemRoot%\System32\shsvcs.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sfloppy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sfloppy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSTXRAID","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSTXRAID",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelpep","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelpep",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFPLWFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WFPLWFS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmPass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmPass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storflt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storflt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IndirectKmd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IndirectKmd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SENS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SENS","%SystemRoot%\System32\sens.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsiproxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsiproxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvStrm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvStrm",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdhid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdhid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netvscvfpp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netvscvfpp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KtmRm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KtmRm","%systemroot%\system32\msdtckrm.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FltMgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FltMgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice","%SystemRoot%\system32\dmwappushsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpi3drvi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpi3drvi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storahci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storahci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcCtnrSvc","%SystemRoot%\System32\NgcCtnrSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Psched","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Psched",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbGD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbGD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdmCompanionFilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdmCompanionFilter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\elxfcoe","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\elxfcoe",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tapisrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tapisrv","%SystemRoot%\System32\tapisrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UALSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UALSVC","%SystemRoot%\System32\ualsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiDev","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiDev",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfDisk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfDisk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IISADMIN","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IISADMIN",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcaSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcaSvc","%SystemRoot%\System32\ncasvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IsmServ","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IsmServ",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\i8042prt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\i8042prt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Modem","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Modem",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TabletInputService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TabletInputService","%SystemRoot%\System32\TabSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lfsvc","%SystemRoot%\System32\lfsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\condrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\condrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain","%systemroot%\system32\sysmain.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC Bridge 4.0.0.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC Bridge 4.0.0.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC","%windir%\system32\inetsrv\iisw3adm.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\camsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\camsvc","%SystemRoot%\system32\CapabilityAccessManager.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sermouse","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sermouse",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfHost",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinRM","%SystemRoot%\system32\WsmSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb20","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb20",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdstor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdstor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UGTHRSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UGTHRSVC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService","%SystemRoot%\system32\WpnService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiAcpi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiAcpi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SamSs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SamSs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SstpSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SstpSvc","%SystemRoot%\system32\sstpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMMemCtl","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMMemCtl",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sacdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sacdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rhproxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rhproxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HdAudAddService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HdAudAddService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WacomPen","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WacomPen",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDIS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDIS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc","%SystemRoot%\System32\pcasvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gencounter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gencounter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisWan","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisWan",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdeCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdeCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GPIOClx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GPIOClx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PptpMiniport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PptpMiniport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasPppoe","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasPppoe",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\s3cap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\s3cap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPSvc","%SystemRoot%\System32\CDPSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI","%systemroot%\system32\iscsiexe.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsSvc","%SystemRoot%\System32\DsSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StateRepository","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StateRepository","%SystemRoot%\system32\windows.staterepository.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc","%SystemRoot%\System32\TimeBrokerServer.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DcomLaunch","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DcomLaunch","%SystemRoot%\system32\rpcss.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wmiApSrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wmiApSrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pmem","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pmem",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ASP.NET","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ASP.NET",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpFilterDriver","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IpFilterDriver",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache","%SystemRoot%\System32\dnsrslvr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kdnic","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kdnic",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WiaRpc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WiaRpc","%SystemRoot%\System32\wiarpc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClipSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ClipSVC","%SystemRoot%\System32\ClipSVC.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ufx01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ufx01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS3i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS3i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Power","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Power","%SystemRoot%\system32\umpo.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVEdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVEdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winmgmt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winmgmt","%SystemRoot%\system32\wbem\WMIsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarpv6","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wanarpv6",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicguestinterface","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicguestinterface","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess","%SystemRoot%\System32\ipnathlp.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\buttonconverter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\buttonconverter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserManager","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserManager","%SystemRoot%\System32\usermgr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsSynopsys","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsSynopsys",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecPkg","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecPkg",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ntfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ntfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelide","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelide",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{3CAA2FAC-649B-4C0C-9167-4C502C888143}","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{3CAA2FAC-649B-4C0C-9167-4C502C888143}",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dot3svc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dot3svc","%SystemRoot%\System32\dot3svc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\partmgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\partmgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp-debug","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp-debug",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBIOS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBIOS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmvsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmvsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UGatherer","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UGatherer",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsCx01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsCx01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VaultSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VaultSvc","C:\Windows\System32\vaultsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WazuhSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WazuhSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CldFlt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CldFlt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srv2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\srv2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IKEEXT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IKEEXT","%SystemRoot%\System32\ikeext.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\napagent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\napagent",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfOS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfOS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IntelPMT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IntelPMT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmictimesync","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmictimesync","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Data","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Data",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreUI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreUI",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc","%SystemRoot%\System32\WaaSMedicSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnUserService","%SystemRoot%\System32\WpnUserService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dfsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dfsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsLbfoProvider","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsLbfoProvider",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StiSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StiSvc","%SystemRoot%\System32\wiaservc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ScDeviceEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ScDeviceEnum","%SystemRoot%\System32\ScDeviceEnum.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KPSSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KPSSVC","%systemroot%\system32\kpssvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Rasl2tp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Rasl2tp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSI_SAS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CSC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CSC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearch",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc","%SystemRoot%\System32\Windows.Devices.Picker.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Processor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Processor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcbService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcbService","%SystemRoot%\System32\ncbservice.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{5F505D9D-5D29-4064-A2B1-3189358C1B36}","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{5F505D9D-5D29-4064-A2B1-3189358C1B36}",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bowser","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bowser",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsbs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsbs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsock","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsock",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PlugPlay","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PlugPlay","%SystemRoot%\system32\umpnpmgr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBXHCI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBXHCI",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FsDepends","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FsDepends",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sbp2port","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sbp2port",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdPHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdPHost","%SystemRoot%\system32\fdPHost.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppIDSvc","%SystemRoot%\System32\appidsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WAS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WAS","%windir%\system32\inetsrv\iisw3adm.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcw","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pcw",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpbCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SpbCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNPMEM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNPMEM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc","%SystemRoot%\system32\winhttp.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmxnet3ndis6","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmxnet3ndis6",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess","%SystemRoot%\System32\mprdim.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tdx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tdx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Beep","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Beep",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp_loader","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp_loader",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ASP.NET_4.0.30319","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ASP.NET_4.0.30319",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgrx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgrx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintNotify","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintNotify","C:\Windows\system32\spool\drivers\x64\3\PrintConfig.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSDTC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileInfo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileInfo",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HvHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HvHost","%SystemRoot%\System32\hvhostsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmusbmouse","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmusbmouse",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UmRdpService","%SystemRoot%\System32\umrdp.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\arcsas","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\arcsas",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UevAgentService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\exfat","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\exfat",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas2i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas2i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InetInfo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InetInfo",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDKPerf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NDKPerf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swenum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swenum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fdc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stornvme",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndiswanlegacy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndiswanlegacy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceparser","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceparser",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\npsvctrig","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\npsvctrig",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PushToInstall","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PushToInstall","%SystemRoot%\system32\PushToInstall.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WEPHOSTSVC","%systemroot%\system32\wephostsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADWS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADWS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVE","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\QWAVE","%windir%\system32\qwave.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPMIDRV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPMIDRV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gpsvc","%SystemRoot%\System32\gpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ufxsynopsys","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ufxsynopsys",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbser","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbser",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid4","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid4",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiApRpl","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WmiApRpl",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xmlprov","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xmlprov",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\inetaccs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\inetaccs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vdrvroot","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vdrvroot",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry","%SystemRoot%\system32\regsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\isapnp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\isapnp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_GPIO","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_GPIO",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicDisplay","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BasicDisplay",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisVirtualBus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisVirtualBus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\portcfg","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\portcfg",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationService","%SystemRoot%\system32\das.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mountmgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mountmgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CLFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CLFS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\genericusbfn","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\genericusbfn",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FrameServerMonitor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FrameServerMonitor","%SystemRoot%\system32\FrameServerMonitor.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fcvsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fcvsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ebdrv0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ebdrv0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iScsiPrt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iScsiPrt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan","%SystemRoot%\System32\rasmans.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSKSSRV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSKSSRV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tcpipreg","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tcpipreg",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBHUB3","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBHUB3",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsmSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DsmSvc","%SystemRoot%\System32\DeviceSetupManager.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetSetupSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetSetupSvc","%SystemRoot%\System32\NetSetupSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CimFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CimFS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ws2ifsl","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ws2ifsl",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon","%SystemRoot%\system32\netlogon.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADP80XX","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADP80XX",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SSDPSRV","%SystemRoot%\System32\ssdpsrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ACPI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ACPI",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Memory Cache 4.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Memory Cache 4.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\clr_optimization_v4.0.30319_32","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\clr_optimization_v4.0.30319_32",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_I2C","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaLPSSi_I2C",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dservice","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dservice",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hwpolicy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hwpolicy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsQuic","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsQuic",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc","%systemroot%\system32\Windows.Internal.Management.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DCLocator","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DCLocator",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost","%SystemRoot%\system32\wdi.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPNAT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IPNAT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Filetrace","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Filetrace",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PktMon","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PktMon",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppReadiness","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppReadiness","%SystemRoot%\system32\AppReadiness.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CryptSvc","%SystemRoot%\system32\cryptsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpiex","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpiex",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\luafv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\luafv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBatt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidBatt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ASP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ASP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ramdisk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ramdisk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\aspnet_state","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\aspnet_state",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\drmkaud","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\drmkaud",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc","%SystemRoot%\system32\appxdeploymentserver.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndproxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndproxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PRM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PRM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidinterrupt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidinterrupt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ssh-agent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ssh-agent",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BrokerInfrastructure","%SystemRoot%\System32\psmsrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbFlt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TsUsbFlt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sacsvr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sacsvr","%SystemRoot%\system32\sacsvr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SessionEnv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SessionEnv","%SystemRoot%\system32\sessenv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iorate","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iorate",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TSDDD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TSDDD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlidsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wlidsvc","%SystemRoot%\system32\wlidsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CredentialEnrollmentManagerUserSvc_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvcrash","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvcrash",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmmouse","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmmouse",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SystemEventsBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SystemEventsBroker","%SystemRoot%\System32\SystemEventsBrokerServer.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\shpamsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\shpamsvc","%systemroot%\system32\Windows.SharedPC.AccountManager.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ProfSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ProfSvc","%systemroot%\system32\profsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\qeois","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\qeois",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NtFrs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NtFrs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService","%SystemRoot%\System32\CaptureService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ExecutionContext","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ExecutionContext",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsRPC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsRPC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Data Provider for SqlServer","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Data Provider for SqlServer",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smphost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smphost","%Systemroot%\System32\smphost.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vpci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vpci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsLldp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsLldp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidumdf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidumdf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TokenBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TokenBroker","%SystemRoot%\System32\TokenBroker.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4vbd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4vbd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReFS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAV",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPCLOCK","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSPCLOCK",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NETFramework","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NETFramework",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisTapi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NdisTapi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas3i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\percsas3i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\clr_optimization_v4.0.30319_64","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\clr_optimization_v4.0.30319_64",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winsock","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Winsock",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bfadi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bfadi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Msfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Msfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder","%SystemRoot%\System32\AudioEndpointBuilder.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmickvpexchange","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmickvpexchange","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\COMSysApp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\COMSysApp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RSoPProv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RSoPProv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HyperVideo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HyperVideo",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmrawdsk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmrawdsk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbhost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbhost",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHUSB","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHUSB",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UEFI","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UEFI",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpdUpFltr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpdUpFltr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MTConfig","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MTConfig",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidkmdf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mshidkmdf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cnghwassist","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cnghwassist",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fastfat","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\fastfat",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bxois","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bxois",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netman","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netman","%SystemRoot%\System32\netman.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbuhci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbuhci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DXGKrnl","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DXGKrnl",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pciide","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pciide",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvraid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvraid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Npfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Npfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiPmi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AcpiPmi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\crypt32","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\crypt32",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4iscsi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cht4iscsi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidserv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hidserv","%SystemRoot%\system32\hidserv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\w3logsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\w3logsvc","%windir%\system32\inetsrv\w3logsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc","%SystemRoot%\System32\WerSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\elxstor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\elxstor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Windows Workflow Foundation 4.0.0.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Windows Workflow Foundation 4.0.0.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Data Provider for Oracle","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET Data Provider for Oracle",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdK8","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdK8",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\seclogon","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\seclogon","%windir%\system32\seclogon.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storqosflt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storqosflt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pla","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pla","%systemroot%\system32\pla.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc","%SystemRoot%\System32\lltdsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCPolicySvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SCPolicySvc","%SystemRoot%\System32\certprop.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\udfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\udfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dam","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dam",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAgileVpn","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAgileVpn",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ksthunk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ksthunk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAuto","%SystemRoot%\System32\rasauto.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSTEE","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSTEE",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Usb4DeviceRouter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Usb4DeviceRouter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc","%SystemRoot%\System32\certprop.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mlx4_bus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mlx4_bus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sdbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wof","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wof",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FDResPub","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FDResPub","%SystemRoot%\system32\fdrespub.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiAcpiClient","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiAcpiClient",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wdf01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wdf01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WUDFRd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WUDFRd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService","%SystemRoot%\System32\termsrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdio","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdio",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar","%SystemRoot%\system32\coremessaging.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wcmsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wcmsvc","%SystemRoot%\System32\wcmsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc","%SystemRoot%\System32\ConsentUxClient.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwifibus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vwifibus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmwefifw","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmwefifw",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\monitor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\monitor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcifs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcifs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvmsession","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvmsession","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serenum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Serenum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LSM","%SystemRoot%\System32\lsm.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfProc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfProc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecDD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KSecDD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetbiosSmb","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetbiosSmb",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc","%SystemRoot%\System32\deviceaccess.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UASPStor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UASPStor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker","%SystemRoot%\System32\moshost.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HwNClx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HwNClx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UdkUserSvc_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIPTUNNEL","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIPTUNNEL",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmgid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmgid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache","%SystemRoot%\system32\FntCache.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volume","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volume",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc","%SystemRoot%\system32\wecsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StorSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\StorSvc","%SystemRoot%\system32\storsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpipagr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpipagr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorClass","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorClass",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\qebdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\qebdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rspndr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rspndr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcSs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcSs","%SystemRoot%\system32\rpcss.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DFSR","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DFSR",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdrom","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdrom",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileCrypt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FileCrypt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KdsSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\KdsSvc","%SystemRoot%\system32\KdsSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinNat","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinNat",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spaceport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPDR","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPDR",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EntAppSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EntAppSvc","%SystemRoot%\system32\EnterpriseAppMgmtSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Acx01000","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Acx01000",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\defragsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\defragsvc","%Systemroot%\System32\defragsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VGAuthService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VGAuthService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmhgfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmhgfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAVC","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iaStorAVC",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvdimm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvdimm",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp-stats","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vm3dmp-stats",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bfadfcoei","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bfadfcoei",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks","%SystemRoot%\System32\trkwks.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndfltr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ndfltr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FrameServer","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FrameServer","%SystemRoot%\system32\FrameServer.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Schedule","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Schedule","%systemroot%\system32\schedsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsChipidea","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UrsChipidea",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvservice","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\hvservice",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\e1i68x64","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\e1i68x64",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp","%SystemRoot%\system32\dhcpcore.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas2i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas2i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADOVMPPackage","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ADOVMPPackage",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ALG","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ALG",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\umbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\umbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicrdv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicrdv","%SystemRoot%\System32\icsvcext.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volsnap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volsnap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpsdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpsdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppMgmt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppMgmt","%SystemRoot%\System32\appmgmts.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ql2300i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ql2300i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode","%SystemRoot%\System32\embeddedmodesvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scfilter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scfilter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinMad","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinMad",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent","%SystemRoot%\System32\ipsecsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthLEEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BthLEEnum",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VirtualRender","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VirtualRender",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bthserv","%SystemRoot%\system32\bthserv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS","%systemroot%\system32\ntdsa.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicshutdown","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicshutdown","%SystemRoot%\System32\icsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\McpManagementService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\McpManagementService","%SystemRoot%\System32\McpManagementService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netprofm","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netprofm","%SystemRoot%\System32\netprofmsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HDAudBus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HDAudBus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsata","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdsata",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SMSvcHost 4.0.0.0","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SMSvcHost 4.0.0.0",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swprv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swprv","%Systemroot%\System32\swprv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas35i","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\megasas35i",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReFSv1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ReFSv1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfNet","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PerfNet",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDFRd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SDFRd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BITS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BITS","%SystemRoot%\System32\qmgr.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbaudio2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ErrDev","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ErrDev",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsmraid","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vsmraid",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbccgp","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbccgp",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DfsDriver","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DfsDriver",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netvsc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\netvsc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\afunix","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\afunix",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vds","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vds",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcLocator","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcLocator",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Fs_Rec","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Fs_Rec",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upnphost","%SystemRoot%\System32\upnphost.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tsusbhub","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tsusbhub",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmvss","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmvss",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\disk","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\disk",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvumis","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mvumis",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WarpJITSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WarpJITSvc","%SystemRoot%\System32\Windows.WARP.JITService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer","%SystemRoot%\system32\srvsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc","%SystemRoot%\System32\PrintWorkflowService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CscService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CscService","%SystemRoot%\System32\cscsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack","%SystemRoot%\system32\diagtrack.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdpbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdpbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorDataService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorDataService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpssvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mpssvc","%SystemRoot%\system32\mpssvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WPDBusEnum","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WPDBusEnum","%SystemRoot%\system32\wpdbusenum.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wisvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wisvc","%systemroot%\system32\flightsettings.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MMCSS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MMCSS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HpSAMD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HpSAMD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbhub","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbhub",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog","%SystemRoot%\System32\wevtsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bttflt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bttflt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiCx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmUcsiCx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DfsrRo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DfsrRo",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wercplsupport","%SystemRoot%\System32\wercplsupport.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc","%SystemRoot%\System32\CDPUserSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc","%SystemRoot%\system32\kdcsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stexstor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stexstor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Audiosrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Audiosrv","%SystemRoot%\System32\Audiosrv.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\applockerfltr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\applockerfltr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasGre","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasGre",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpitime","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\acpitime",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTRAP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTRAP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WudfPf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WudfPf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc","%SystemRoot%\System32\wbiosrvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SerCx2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc","%SystemRoot%\System32\nlasvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Mup","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Mup",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AxInstSV","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AxInstSV","%SystemRoot%\System32\AxInstSV.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ahcache","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ahcache",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nsi","%systemroot%\system32\nsisvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\atapi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\atapi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PEAUTH","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PEAUTH",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearchIdxPi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WSearchIdxPi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc","%SystemRoot%\System32\PimIndexMaintenance.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorTcgDrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EhStorTcgDrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc","%SystemRoot%\System32\DevicesFlowBroker.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Parport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Parport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RdpVideoMiniport","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RdpVideoMiniport",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SEMgrSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SEMgrSvc","%SystemRoot%\system32\SEMgrSvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Themes","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Themes","%SystemRoot%\system32\themeservice.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CompositeBus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CompositeBus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\workerdd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\workerdd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SiSRaid2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SensorService","%SystemRoot%\system32\SensorService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ESENT","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ESENT",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TieringEngineService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TieringEngineService",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevQueryBroker","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevQueryBroker","%SystemRoot%\system32\DevQueryBroker.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVemgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppvVemgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WalletService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WalletService","%SystemRoot%\system32\WalletService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Appinfo","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Appinfo","%SystemRoot%\System32\appinfo.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinSock2",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CmBatt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CmBatt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbprint","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbprint",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\svsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\svsvc","%SystemRoot%\system32\svsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhf","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vhf",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NgcSvc","%SystemRoot%\system32\ngcsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WIMMount","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WIMMount",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbohci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbohci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgr","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\volmgr",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msiserver","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msiserver",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smbdirect","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\smbdirect",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc_1170b1","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc_1170b1",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ldap","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ldap",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Networking","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\.NET CLR Networking",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdatem",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation","%SystemRoot%\System32\wkssvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmCx0101","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UcmCx0101",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tunnel","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tunnel",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRTProxy","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WindowsTrustedRTProxy",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinVerbs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinVerbs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAcd","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasAcd",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storufs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\storufs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Usb4HostRouter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Usb4HostRouter",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppHostSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppHostSvc","%windir%\system32\inetsrv\apphostsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbehci","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\usbehci",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scmbus","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\scmbus",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc","%systemroot%\system32\usosvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UfxChipidea","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UfxChipidea",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InstallService","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InstallService","%SystemRoot%\system32\InstallService.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DispBrokerDesktopSvc","%SystemRoot%\System32\DispBroker.Desktop.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\3ware","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\3ware",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\terminpt","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\terminpt",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lmhosts","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lmhosts","%SystemRoot%\System32\lmhsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvss","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmicvss","%SystemRoot%\System32\icsvcvss.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPUDD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPUDD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv","%systemroot%\system32\wuaueng.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppID","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppID",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidUsb","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HidUsb",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPNP","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDPNP",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdate","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\edgeupdate",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc","%SystemRoot%\System32\userdataservice.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdbss","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\rdbss",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDMANDK","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RDMANDK",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbip","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mausbip",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msgpiowin32","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\msgpiowin32",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\b06bdrv","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\b06bdrv",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WINUSB","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WINUSB",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dfs","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dfs",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventSystem","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventSystem","%systemroot%\system32\es.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmartSAMD","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SmartSAMD",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvstor","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvstor",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iphlpsvc","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\iphlpsvc","%SystemRoot%\System32\iphlpsvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS","%SystemRoot%\system32\dps.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdPPM","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AmdPPM",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsBridge","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsBridge",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EFS","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EFS","%SystemRoot%\system32\efssvc.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time","%systemroot%\system32\w32time.dll"
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\adsi","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\adsi",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\qlfcoei","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\qlfcoei",
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AJRouter","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AJRouter","%SystemRoot%\System32\AJRouter.dll"
  "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrustedInstaller","HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrustedInstaller",'
  
  function Get-UsersRunAndRunOnce
  {
    Write-Verbose -Message "Getting users' Run properties..."
    $hkeyUsers = Get-ChildItem -Path Registry::HKEY_USERS
    foreach($sidHive in $hkeyUsers)
    {
      $currentUser = "Registry::$sidHive"
      $runProps = Get-ItemProperty -Path "$currentUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
      if($runProps)
      {
        Write-Verbose -Message "[!] Found properties under $sidHive user's Run key which deserve investigation!"
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $runProps))
        {
          if($psProperties.Contains($prop.Name)) 
          {
            continue
          } # skip the property if it's powershell built-in property
          $propPath = Convert-Path -Path $runProps.PSPath
          $propPath += '\' + $prop.Name
          $PersistenceObject = New-PersistenceObject -Technique 'Registry Run Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runProps.($prop.Name) -AccessGained 'User' -Note 'Executables in properties of the key HKEY_USERS\<User_SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the user logs in.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
    }
    
    Write-Verbose -Message ''
    Write-Verbose -Message "Getting users' RunOnce properties..."
    foreach($sidHive in $hkeyUsers)
    {
      $currentUser = "Registry::$sidHive"
      $runOnceProps = Get-ItemProperty -Path "$currentUser\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
      if($runOnceProps)
      {
        Write-Verbose -Message "[!] Found properties under $sidHive user's RunOnce key which deserve investigation!"
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $runOnceProps))
        {
          if($psProperties.Contains($prop.Name)) 
          {
            continue
          } # skip the property if it's powershell built-in property
          $propPath = Convert-Path -Path $runOnceProps.PSPath
          $propPath += '\' + $prop.Name
          $PersistenceObject = New-PersistenceObject -Technique 'Registry RunOnce Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runOnceProps.($prop.Name) -AccessGained 'User' -Note 'Executables in properties of the key HKEY_USERS\<User_SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the user logs in and then deleted.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-SystemRunAndRunOnce
  {
    Write-Verbose -Message "Getting system's Run properties..."
    $runProps = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    if($runProps)
    {
      Write-Verbose -Message "[!] Found properties under system's Run key which deserve investigation!"
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $runProps))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $runProps.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'Registry Run Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runProps.($prop.Name) -AccessGained 'System' -Note 'Executables in properties of the key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the system boots.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
    }
    
    Write-Verbose -Message ''
    Write-Verbose -Message "Getting system's RunOnce properties..."
    $runOnceProps = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue
    if($runOnceProps)
    {
      Write-Verbose -Message "[!] Found properties under system's RunOnce key which deserve investigation!"
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $runOnceProps))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $runOnceProps.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'Registry RunOnce Key' -Classification 'MITRE ATT&CK T1547.001' -Path $propPath -Value $runOnceProps.($prop.Name) -AccessGained 'System' -Note 'Executables in properties of the key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the system boots and then deleted.' -Reference 'https://attack.mitre.org/techniques/T1547/001/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-ImageFileExecutionOptions
  {
    $IFEOptsDebuggers = New-Object -TypeName System.Collections.ArrayList
    $foundDangerousIFEOpts = $false
    Write-Verbose -Message 'Getting Image File Execution Options...'
    $ifeOpts = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue
    if($ifeOpts)
    {
      foreach($key in $ifeOpts)
      {
        $debugger = Get-ItemProperty -Path Registry::$key -Name Debugger -ErrorAction SilentlyContinue
        if($debugger) 
        {
          $foundDangerousIFEOpts = $true
          $null = $IFEOptsDebuggers.Add($key)
        }
      }
      
      if($foundDangerousIFEOpts)
      {
        Write-Verbose -Message '[!] Found subkeys under the Image File Execution Options key which deserve investigation!'
        foreach($key in $IFEOptsDebuggers)
        {
          $ifeProps = Get-ItemProperty -Path Registry::$key -Name Debugger
          foreach ($prop in (Get-Member -Type NoteProperty -InputObject $ifeProps))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $ifeProps.PSPath
            $propPath += '\' + $prop.Name
            $PersistenceObject = New-PersistenceObject -Technique 'Image File Execution Options' -Classification 'MITRE ATT&CK T1546.012' -Path $propPath -Value $ifeProps.($prop.Name) -AccessGained 'System/User' -Note 'Executables in the Debugger property of a subkey of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ are run instead of the program corresponding to the subkey. Gained access depends on whose context the debugged process runs in.' -Reference 'https://attack.mitre.org/techniques/T1546/012/'
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-NLDPDllOverridePath
  {
    $KeysWithDllOverridePath = New-Object -TypeName System.Collections.ArrayList
    $foundDllOverridePath = $false
    Write-Verbose -Message 'Getting Natural Language Development Platform DLL path override properties...'
    $NLDPLanguages = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language' -ErrorAction SilentlyContinue
    if($NLDPLanguages)
    {
      foreach($key in $NLDPLanguages)
      {
        $DllOverridePath = Get-ItemProperty -Path Registry::$key -Name *DLLPathOverride -ErrorAction SilentlyContinue
        if($DllOverridePath) 
        {
          $foundDllOverridePath = $true
          $null = $KeysWithDllOverridePath.Add($key)
        }
      }
      
      if($foundDllOverridePath)
      {
        Write-Verbose -Message '[!] Found subkeys under HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language which deserve investigation!'
        foreach($key in $KeysWithDllOverridePath)
        {
          $properties = Get-ItemProperty -Path Registry::$key | Select-Object -Property *DLLPathOverride, PS*
          foreach ($prop in (Get-Member -Type NoteProperty -InputObject $properties))
          {
            if($psProperties.Contains($prop.Name)) 
            {
              continue
            } # skip the property if it's powershell built-in property
            $propPath = Convert-Path -Path $properties.PSPath
            $propPath += '\' + $prop.Name
            $PersistenceObject = New-PersistenceObject -Technique 'Natural Language Development Platform 6 DLL Override Path' -Classification 'Hexacorn Technique N.98' -Path $propPath -Value $properties.($prop.Name) -AccessGained 'System' -Note 'DLLs listed in properties of subkeys of HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language are loaded via LoadLibrary executed by SearchIndexer.exe' -Reference 'https://www.hexacorn.com/blog/2018/12/30/beyond-good-ol-run-key-part-98/'
            Write-Verbose -Message $PersistenceObject
            $null = $persistenceObjectArray.Add($PersistenceObject)
          }
        }
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-AeDebug
  {
    Write-Verbose -Message 'Getting AeDebug properties...'
    $aeDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug' -Name Debugger -ErrorAction SilentlyContinue
    if($aeDebugger)
    {
      Write-Verbose -Message '[!] Found properties under the AeDebug key which deserve investigation!'
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $aeDebugger))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $aeDebugger.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'AEDebug Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $aeDebugger.($prop.Name) -AccessGained 'System/User' -Note "The executable in the Debugger property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a process crashes. Gained access depends on whose context the debugged process runs in; if the Auto property of the same registry key is set to 1, the debugger starts without user interaction. A value of 'C:\Windows\system32\vsjitdebugger.exe' might be a false positive if you have Visual Studio Community installed." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
    }
    
    $aeDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug' -Name Debugger -ErrorAction SilentlyContinue
    if($aeDebugger)
    {
      Write-Verbose -Message '[!] Found properties under the Wow6432Node AeDebug key which deserve investigation!'
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $aeDebugger))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $aeDebugger.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'Wow6432Node AEDebug Custom Debugger' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value $aeDebugger.($prop.Name) -AccessGained 'System/User' -Note "The executable in the Debugger property of HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a 32 bit process on a 64 bit system crashes. Gained access depends on whose context the debugged process runs in; if the Auto property of the same registry key is set to 1, the debugger starts without user interaction. A value of 'C:\Windows\system32\vsjitdebugger.exe' might be a false positive if you have Visual Studio Community installed." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
    }
    Write-Verbose -Message '' 
  }
  
  function Get-WerFaultHangs
  {
    Write-Verbose -Message 'Getting WerFault Hangs registry key Debug property...'
    $werfaultDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs' -Name Debugger -ErrorAction SilentlyContinue
    if($werfaultDebugger)
    {
      Write-Verbose -Message '[!] Found a Debugger property under the WerFault Hangs key which deserve investigation!'
      $werfaultDebugger | Select-Object -Property Debugger, PS*
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $werfaultDebugger))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $werfaultDebugger.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'Windows Error Reporting Debugger' -Classification 'Hexacorn Technique N.116' -Path $propPath -Value $werfaultDebugger.($prop.Name) -AccessGained 'System' -Note 'The executable in the Debugger property of HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when a process crashes.' -Reference 'https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
    }
    
    Write-Verbose -Message ''
    Write-Verbose -Message 'Getting WerFault Hangs registry key ReflectDebug property...'
    $werfaultReflectDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs' -Name ReflectDebugger -ErrorAction SilentlyContinue
    if($werfaultReflectDebugger)
    {
      Write-Verbose -Message '[!] Found a ReflectDebugger property under the WerFault Hangs key which deserve investigation!'
      $werfaultReflectDebugger | Select-Object -Property ReflectDebugger, PS*
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $werfaultReflectDebugger))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $werfaultReflectDebugger.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'Windows Error Reporting ReflectDebugger' -Classification 'Hexacorn Technique N.85' -Path $propPath -Value $werfaultReflectDebugger.($prop.Name) -AccessGained 'System' -Note 'The executable in the ReflectDebugger property of HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when called with the -pr argument.' -Reference 'https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
    }
    
    Write-Verbose -Message ''
  }

  function Get-UsersCmdAutoRun
  {
    Write-Verbose -Message "Getting users' cmd.exe's AutoRun property..."
    $hkeyUsers = Get-ChildItem -Path Registry::HKEY_USERS
    foreach($sidHive in $hkeyUsers)
    {
      $currentUser = "Registry::$sidHive"
      $autorun = Get-ItemProperty -Path "$currentUser\Software\Microsoft\Command Processor" -Name AutoRun -ErrorAction SilentlyContinue
      if($autorun)
      {
        Write-Verbose -Message "[!] $sidHive user's cmd.exe's AutoRun property is set and deserves investigation!"
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $autorun))
        {
          if($psProperties.Contains($prop.Name)) 
          {
            continue
          } # skip the property if it's powershell built-in property
          $propPath = Convert-Path -Path $autorun.PSPath
          $propPath += '\' + $prop.Name
          $PersistenceObject = New-PersistenceObject -Technique "Users' cmd.exe AutoRun key" -Classification 'Uncatalogued Technique N.1' -Path $propPath -Value $autorun.($prop.Name) -AccessGained 'User' -Note 'The executable in the AutoRun property of HKEY_USERS\<User_SID>\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument.' -Reference 'https://persistence-info.github.io/Data/cmdautorun.html'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
    }
    Write-Verbose -Message ''   
  }
  
  function Get-SystemCmdAutoRun
  {
    Write-Verbose -Message "Getting system's cmd.exe's AutoRun property..."
    $autorun = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Command Processor' -Name AutoRun -ErrorAction SilentlyContinue
    if($autorun)
    {
      Write-Verbose -Message "[!] System's cmd.exe's AutoRun property is set and deserves investigation!"
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $autorun))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $autorun.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique "System's cmd.exe AutoRun key" -Classification 'Uncatalogued Technique N.1' -Path $propPath -Value $autorun.($prop.Name) -AccessGained 'User' -Note 'The executable in the AutoRun property of HKEY_LOCAL_MACHINE\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument.' -Reference 'https://persistence-info.github.io/Data/cmdautorun.html'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
    }
    
    Write-Verbose -Message ''
  }
  
  function Get-ExplorerLoad
  {
    Write-Verbose -Message "Getting current user's Explorer's Load property..."
    $loadKey = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -Name Load -ErrorAction SilentlyContinue
    if($loadKey)
    {
      Write-Verbose -Message "[!] Current user's Load property is set and deserves investigation!"
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $loadKey))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $loadKey.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'Explorer Load Property' -Classification 'Uncatalogued Technique N.2' -Path $propPath -Value $loadKey.($prop.Name) -AccessGained 'User' -Note 'The executable in the Load property of HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows is run by explorer.exe at login time.' -Reference 'https://persistence-info.github.io/Data/windowsload.html'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-SystemWinlogonUserinit
  {
    Write-Verbose -Message "Getting system's Winlogon's Userinit property..."
    $userinit = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Userinit -ErrorAction SilentlyContinue
    if($userinit)
    {
      if($userinit.Userinit -ne 'C:\Windows\system32\userinit.exe,')
      {
        Write-Verbose -Message "[!] Winlogon's Userinit property is set to a non-standard value and deserves investigation!"
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $userinit))
        {
          if($psProperties.Contains($prop.Name)) 
          {
            continue
          } # skip the property if it's powershell built-in property
          $propPath = Convert-Path -Path $userinit.PSPath
          $propPath += '\' + $prop.Name
          $PersistenceObject = New-PersistenceObject -Technique 'Winlogon Userinit Property' -Classification 'MITRE ATT&CK T1547.004' -Path $propPath -Value $userinit.($prop.Name) -AccessGained 'User' -Note "The executables in the Userinit property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon are run at login time by any user. Normally this property should be set to 'C:\Windows\system32\userinit.exe,' without any further executables appended." -Reference 'https://attack.mitre.org/techniques/T1547/004/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-SystemWinlogonShell
  {
    Write-Verbose -Message "Getting Winlogon's Shell property..."
    $shell = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -ErrorAction SilentlyContinue
    if(!$shell)
    {
      Write-Verbose -Message '[!] No Shell property found, it may be an error...'
    }
    else 
    {
      if($shell.Shell -ne 'explorer.exe')
      {
        Write-Verbose -Message "[!] Winlogon's Shell property is set to a non-standard value and deserves investigation!"
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $shell))
        {
          if($psProperties.Contains($prop.Name)) 
          {
            continue
          } # skip the property if it's a powershell built-in property
          $propPath = Convert-Path -Path $shell.PSPath
          $propPath += '\' + $prop.Name
          $PersistenceObject = New-PersistenceObject -Technique 'Winlogon Shell Property' -Classification 'MITRE ATT&CK T1547.004' -Path $propPath -Value $shell.($prop.Name) -AccessGained 'User' -Note "The executables in the Shell property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon are run as the default shells for any users. Normally this property should be set to 'explorer.exe' without any further executables appended." -Reference 'https://attack.mitre.org/techniques/T1547/004/'
          $null = $persistenceObjectArray.Add($PersistenceObject)
        }
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-TerminalProfileStartOnUserLogin
  {
    Write-Verbose -Message "Checking if users' Windows Terminal Profile's settings.json contains a startOnUserLogin value..."
    $userDirectories = Get-ChildItem -Path 'C:\Users\'
    foreach($directory in $userDirectories)
    {
      $terminalDirectories = Get-ChildItem -Path "$($directory.FullName)\Appdata\Local\Packages\Microsoft.WindowsTerminal_*" -ErrorAction SilentlyContinue
      foreach($terminalDirectory in $terminalDirectories)
      {
        $settingsFile = Get-Content -Raw -Path "$($terminalDirectory.FullName)\LocalState\settings.json" | ConvertFrom-Json
        if($settingsFile.startOnUserLogin -ne 'true')
        {
          return 
        } # return if startOnUserLogin is not present
        $defaultProfileGuid = $settingsFile.defaultProfile
        $found = $false 
        foreach($profileList in $settingsFile.profiles)
        {
          foreach($profile in $profileList.list)
          {
            if($profile.guid -eq $defaultProfileGuid)
            {
              Write-Verbose -Message "[!] The file $($terminalDirectory.FullName)\LocalState\settings.json has the startOnUserLogin key set, the default profile has GUID $($profile.guid)!"
              if($profile.commandline)
              {
                $executable = $profile.commandline 
              }
              else 
              {
                $executable = $profile.name 
              }
              
              $PersistenceObject = New-PersistenceObject -Technique 'Windows Terminal startOnUserLogin' -Classification 'Uncatalogued Technique N.3' -Path "$($terminalDirectory.FullName)\LocalState\settings.json" -Value "$executable" -AccessGained 'User' -Note "The executable specified as value of the key `"commandline`" of a profile which has the `"startOnUserLogin`" key set to `"true`" in the Windows Terminal's settings.json of a user is run every time that user logs in." -Reference 'https://twitter.com/nas_bench/status/1550836225652686848'
              $null = $persistenceObjectArray.Add($PersistenceObject)
              $found = $true
              break
            }
          }
          if ($found) 
          {
            break 
          } 
        }
      }
    }    
    Write-Verbose -Message ''
  }
  
  function Get-AppCertDlls
  {
    Write-Verbose -Message 'Getting AppCertDlls properties...'
    $appCertDllsProps = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' -ErrorAction SilentlyContinue
    if($appCertDllsProps)
    {
      Write-Verbose -Message "[!] Found properties under system's AppCertDlls key which deserve investigation!"
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $appCertDllsProps))
      {
        if($psProperties.Contains($prop.Name)) 
        {
          continue
        } # skip the property if it's powershell built-in property
        $propPath = Convert-Path -Path $appCertDllsProps.PSPath
        $propPath += '\' + $prop.Name
        $PersistenceObject = New-PersistenceObject -Technique 'AppCertDlls' -Classification 'MITRE ATT&CK T1546.009' -Path $propPath -Value $appCertDllsProps.($prop.Name) -AccessGained 'System' -Note 'DLLs in properties of the key HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls are loaded by every process that loads the Win32 API at process creation.' -Reference 'https://attack.mitre.org/techniques/T1546/009/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      }
    }
    Write-Verbose -Message ''
  }
  
  function Get-AppPaths
  {
    Write-Verbose -Message 'Getting App Paths inside the registry...'
    $appPathsKeys = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths' -ErrorAction SilentlyContinue
    foreach($key in $appPathsKeys)
    {
      $appPath = Get-ItemProperty -Path Registry::$key -Name '(Default)' -ErrorAction SilentlyContinue
      if($appPath) 
      { 
        Write-Verbose -Message '[!] Found subkeys under the App Paths key which deserve investigation!'
        $propPath = Convert-Path -Path $key.PSPath
        $propPath += '\' + $appPath.Name
        $PersistenceObject = New-PersistenceObject -Technique 'App Paths' -Classification 'Hexacorn Technique N.3' -Path "$propPath(Default)" -Value $appPath.'(Default)' -AccessGained 'System/User' -Note 'Executables in the (Default) property of a subkey of HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ are run instead of the program corresponding to the subkey. Gained access depends on whose context the process runs in. Be aware this might be a false positive.' -Reference 'https://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      } 
    }
    Write-Verbose -Message ''
  }  
  function Get-ServiceDlls
  {
    Write-Verbose -Message 'Getting Service DLLs inside the registry...'
    $winVer = (Get-WmiObject -class Win32_OperatingSystem).Caption
    switch -Wildcard ($winVer)
    {
      "Microsoft Windows 10*"
      {
        Write-Verbose -Message 'Detected Windows 10...'
        $serviceTable = $W10ServiceDllTable | ConvertFrom-Csv
      }
      
      "Microsoft Windows 11*"
      {
        Write-Verbose -Message 'Detected Windows 11...'
        $serviceTable = $W11ServiceDllTable | ConvertFrom-Csv
      }
      
      "Microsoft Windows Server 2022*"
      {
        Write-Verbose -Message 'Detected Windows 2022...'
        $serviceTable = $W2022ServiceDllTable | ConvertFrom-Csv
      }
      
      default
      {
        Write-Verbose -Message 'Windows version not implemented, defaulting to Windows 10...'
        $serviceTable = $W10ServiceDllTable | ConvertFrom-Csv
      }
    }
    
    foreach($row in $serviceTable.GetEnumerator())
    {
      $serviceKey = Get-Item -Path Registry::$($row.Key)\Parameters -ErrorAction SilentlyContinue
      if($serviceKey)
      {
        $serviceDll = $serviceKey.GetValue('ServiceDll', $null, 'DoNotExpandEnvironmentNames') # .NET wizardry to prevent Powershell from expanding REG_EXPAND_SZ properties
      }
      else
      {
        $serviceDll = $null
      }

      if([string]::IsNullOrEmpty($row.Value))
      {
        $savedValue = $null
      }
      else
      {
        $savedValue = $row.Value
      }
      if(($serviceDll -ne $savedValue) -and ($serviceDll -ne $null)) 
      { 
        Write-Verbose -Message '[!] Found subkeys under the Services key which deserve investigation!'
        $propPath = "$($row.Key)\Parameters"
        $PersistenceObject = New-PersistenceObject -Technique 'ServiceDll Hijacking' -Classification 'Hexacorn Technique N.4' -Path $propPath -Value "$serviceDll" -AccessGained 'System' -Note "DLLs in the ServiceDll property of HKLM:\SYSTEM\CurrentControlSet\Services\<SERVICE_NAME>\Parameters are loaded in the corresponding service. If an attacker modifies said entry, the malicious DLL will be loaded in place of the legitimate one." -Reference 'https://www.hexacorn.com/blog/2013/09/19/beyond-good-ol-run-key-part-4/'
        $null = $persistenceObjectArray.Add($PersistenceObject)
      } 
    } 
    Write-Verbose -Message ''
  }
  
  Write-Verbose -Message 'Starting execution...'

  Get-UsersRunAndRunOnce
  Get-SystemRunAndRunOnce
  Get-ImageFileExecutionOptions
  Get-NLDPDllOverridePath
  Get-AeDebug
  Get-WerFaultHangs
  Get-UsersCmdAutoRun
  Get-SystemCmdAutoRun
  Get-ExplorerLoad
  Get-SystemWinlogonUserinit
  Get-SystemWinlogonShell
  Get-TerminalProfileStartOnUserLogin
  Get-AppCertDlls
  Get-ServiceDlls
  
  if($IncludeHighFalsePositivesChecks.IsPresent)
  {
    Write-Verbose -Message 'You have used the -IncludeHighFalsePositivesChecks switch, this may generate a lot of false positives since it includes checks with results which are difficult to filter programmatically...'
    Get-AppPaths
  }
  
  # Use Input CSV to make a diff of the results and only show us the persistences implanted on the local machine which are not in the CSV
  if($DiffCSV)
  {
    Write-Verbose -Message 'Diffing found persistences with the ones in the input CSV...'
    $importedPersistenceObjectArray = Import-Csv -Path $DiffCSV -ErrorAction Stop
    $newPersistenceObjectArray = New-Object -TypeName System.Collections.ArrayList
    foreach($localPersistence in $persistenceObjectArray)
    {
      $found = $false
      foreach($importedPersistence in $importedPersistenceObjectArray)
      {
        if(($importedPersistence.Technique -eq $localPersistence.Technique) -and ($importedPersistence.Path -eq $localPersistence.Path) -and ($importedPersistence.Value -eq $localPersistence.Value))
        {
          $found = $true
          break
        }
      }
      if($found -eq $false)
      {
        $null = $newPersistenceObjectArray.Add($localPersistence)
      }
    }
    $persistenceObjectArray = $newPersistenceObjectArray.Clone()
  }
  
  if($OutputCSV)
  {
    $persistenceObjectArray |
    ConvertTo-Csv |
    Out-File -FilePath $OutputCSV -ErrorAction Stop
  }
  
  Write-Verbose -Message 'Execution finished, outputting results...'  
  return $persistenceObjectArray
}

function Get-ServiceDllsFalsePositive
{
  Write-Verbose -Message "Outputting current Services' ServiceDll configuration to use as false positives..."
  $serviceDllsTable = @{}
  $services = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\'
  foreach($service in $services)
  {
    $serviceKey = Get-Item -Path Registry::$service\Parameters -ErrorAction SilentlyContinue
    if($serviceKey)
    {
      $serviceDll = $serviceKey.GetValue('ServiceDll', $null, 'DoNotExpandEnvironmentNames') # .NET wizardry to prevent Powershell from expanding REG_EXPAND_SZ properties
    }
    else
    {
      $serviceDll = $null
    }   
    $serviceDllsTable.Add($service, $serviceDll)
  }
    
  $serviceDllsTable.GetEnumerator()
}
