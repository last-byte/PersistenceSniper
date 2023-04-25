# Changelog

## 1.10.0
Features:
   - Detection for Office AI.exe hijacking
   - Detection for Service Control Manager Security Descriptor tampering
   - Detection for Explorer Context Menu hijacking
Fixes:
   - Fixed handling of system environment variables in the registry
   - Fixed the bug in which the script blocked if one of the remote computers was not reachable


## 1.9.3
Features:
   - Added the possibility of passing a Virustotal API key and check if the hash of the detected file is known.
   - Malicious Office Templates are now detected
   - New license has been implemented.

## 1.9.2
Fixes:
   - Fixed 3 lines of code dealing with minor bugs

## 1.9.1
Features:
   - Added the following persistence techniques:
	  - Screensaver
	  - BITS JOb NotifyCmdLine
	  - Power Automate

## 1.8.0
Features:
   - Added the following persistence techniques:
	  - AMSI Providers
	  - Powershell Profiles 
	  - Silent Exit Monitor
	  - Telemetry Controller Commands
	  - RDP WDS Startup Programs
	  - Scheduled Tasks
Fixes:
   - Fixed minor typos here and there
	
## 1.7.1
Fixes:
  - the PSM1 is now also signed (it was not in v1.7.0)

## 1.7.0
Features:
  - add support for accessibility tools backdoor detection

## 1.6.0
Features:
  - add support for RDP InitialProgram detection

## 1.5.0
Features:
  - added the `PersistenceMethod` parameter in order to selectively check for one persistence technique at a time
 
## 1.4.0
Features:
  - the module is now digitally signed with a valid code signing certificate  
  
## 1.3.1
Features:
  - a number of new persistence checks have been implemented

## 1.0
Features:
  - WMI event subscriptions persistence check has been implemented
## 0.9
Beta release
  
  
  
  
  
  
