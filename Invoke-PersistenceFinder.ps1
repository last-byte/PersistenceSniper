function Invoke-PersistenceFinder
{
  <#
      .SYNOPSIS

      This script tries to enumerate all the persistence methods implanted on a compromised machine.

      Function: Invoke-PersistenceFinder
      Author: Federico `last` Lagrasta, Twitter: @last0x00
      License: https://creativecommons.org/licenses/by/3.0/deed.en
      Required Dependencies: None
      Optional Dependencies: None

      .DESCRIPTION

      Enumerate all the persistence methods found on a machine and print them for the user to see.

      .PARAMETER PersistenceMethod

      Switch: Enumerate only given method. Default is: All
	    
      .EXAMPLE

      Enumerate all persistence techniques implanted on the local machine (implicit).
      Invoke-PersistenceFinder

      .EXAMPLE

      Enumerate all persistence techniques implanted on the local machine (explicit).
      Invoke-PersistenceFinder -PersistenceMethod All

      .EXAMPLE

      Enumerate only Run and RunOnce keys persistence techniques implanted on the local machine.
      Invoke-PersistenceFinder -PersistenceMethod RunAndRunOnce

      .NOTES

      This script tries to enumerate all persistence techniques that may have been deployed on a compromised machine. New techniques may take some time before they are implemented in this script, so don't assume that because the script doesn't find anything the machine is clean.
      Most persistence techniques this script searches for are explained here https://persistence-info.github.io/ and are based on research by @Hexacorn.
      On a sidenote, this scripts makes heavy use of the Write-Host cmdlet which should be avoided but allows for easy output coloring. 
      The downside to that is the fact that redirecting output to anything other than stdout will not redirect Write-Host output. In order to do so just import and run the script in another Powershell sessions: powershell.exe -ExecutionPolicy bypass -Command '. .\Invoke-PersistenceFinder.ps1; Invoke-PersistenceFinder -Verbose' > outputfile.txt

      .LINK

      https://github.com/last-byte/Invoke-PersistenceFinder
  #>
  
  [CmdletBinding(DefaultParameterSetName='PersistenceMethod')]
  
  Param(
    [Parameter(ParameterSetName = 'PersistenceMethod', Position = 0)]
    [Switch]
    $PersistenceMethod
  )
  
  function Get-UsersRunAndRunOnce
  {
    Write-Host
    Write-Verbose -Message "Getting users' Run properties..."
    Write-Verbose -Message "Executables in properties of the key HKEY_USERS\<User_SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the user logs in.`n"
    $hkeyUsers = Get-ChildItem -Path Registry::HKEY_USERS
    foreach($sidHive in $hkeyUsers)
    {
      Write-Verbose -Message "Checking $sidHive registry hive..."
      $currentUser = "Registry::$sidHive"
      $runProps = Get-ItemProperty -Path "$currentUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Select-Object -Property * -ExcludeProperty PS*
      if(!$runProps)
      {
        Write-Host "[+] No persistence found under $sidHive user's Run key`n" -ForegroundColor Green
      }
      else
      {
        Write-Host "[!] Found properties under $sidHive user's Run key which deserve investigation!" -ForegroundColor Red
        ($runProps| Format-List | Out-String).Trim()
        Write-Host
      }
    }
    
    Write-Verbose -Message "Getting users' RunOnce properties..."
    Write-Verbose -Message "Executables in properties of the key HKEY_USERS\<User_SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the user logs in and then deleted.`n"
    foreach($sidHive in $hkeyUsers)
    {
      Write-Verbose -Message "Checking $sidHive registry hive..."
      $currentUser = "Registry::$sidHive"
      $runOnceProps = Get-ItemProperty -Path "$currentUser\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue | Select-Object -Property * -ExcludeProperty PS*
      if(!$runOnceProps)
      {
        Write-Host "[+] No persistence found under $sidHive user's RunOnce key`n" -ForegroundColor Green 
      }
      else
      {
        Write-Host "[!] Found properties under $sidHive user's RunOnce key which deserve investigation!" -ForegroundColor Red -NoNewline
        ($runOnceProps | Format-List | Out-String).Trim()
        Write-Host 
      }
    }
  }
  
  function Get-HKLMRunAndRunOnce
  {
    Write-Verbose -Message "Getting system's Run properties..."
    Write-Verbose -Message "Executables in properties of the key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the system boots.`n"
    $runProps = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'  | Select-Object -Property * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider
    if(!$runProps)
    {
      Write-Host "[+] No persistence found under system's Run key" -ForegroundColor Green
    }
    else
    {
      Write-Host "[!] Found properties under system's Run key which deserve investigation!" -ForegroundColor Red
      ($runProps| Format-List | Out-String).Trim()
      Write-Host
    }
    Write-Verbose -Message "Getting system's RunOnce properties..."
    Write-Verbose -Message "Executables in properties of the key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the system boots and then deleted.`n"
    $runOnceProps = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    if(!$runOnceProps)
    {
      Write-Host "[+] No persistence found under system's RunOnce key`n" -ForegroundColor Green
    }
    else
    {
      Write-Host "[!] Found properties under system's RunOnce key which deserve investigation!" -ForegroundColor Red -NoNewline
      ($runOnceProps | Format-List | Out-String).Trim()
      Write-Host 
    }
  }
  
  function Get-ImageFileExecutionOptions
  {
    $IFEOptsDebuggers = New-Object -TypeName System.Collections.ArrayList
    $foundDangerousIFEOpts = $false
    Write-Verbose -Message 'Getting Image File Execution Options...'
    Write-Verbose -Message "Executables in the Debugger property of a subkey of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options are run when the process corresponding to the subkey crashes.`n"
    $ifeOpts = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue
    if(!$ifeOpts)
    {
      Write-Host "[!] No subkeys found under the Image File Execution Options key`n" -ForegroundColor Yellow
    }
    else
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
        Write-Host '[!] Found subkeys under the Image File Execution Options key which deserve investigation!' -ForegroundColor Red -NoNewline
        foreach($key in $IFEOptsDebuggers)
        {
          (Get-ItemProperty -Path Registry::$key -Name Debugger | Select-Object -Property @{Name='Program';Expression={$_.PSChildName}},Debugger | Out-String).TrimEnd()
          Write-Host
        }
      }
      else
      {
        Write-Host "[+] No persistence found under the Image File Execution Options key`n" -ForegroundColor Green | Out-Host
      }
    }
  }
  
  function Get-NLDPDllOverridePath
  {
    $KeysWithDllOverridePath = New-Object -TypeName System.Collections.ArrayList
    $foundDllOverridePath = $false
    Write-Verbose -Message 'Getting Natural Language Development Platform DLL path override properties...'
    Write-Verbose -Message "DLLs listed in properties of subkeys of HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language are loaded via LoadLibrary executed by SearchIndexer.exe`n"
    $NLDPLanguages = Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language' -ErrorAction SilentlyContinue
    if(!$NLDPLanguages)
    {
      Write-Host "[!] No subkeys found under the HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language`n" -ForegroundColor Yellow
    }
    else
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
        Write-Host '[!] Found subkeys under HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language which deserve investigation!' -ForegroundColor Red -NoNewline
        foreach($key in $KeysWithDllOverridePath)
        {
          (Get-ItemProperty -Path Registry::$key | Select-Object -Property @{Name='Language Key';Expression={$_.PSChildName}},WBDLLPathOverride,StemmerDLLPathOverride | Out-String).TrimEnd()
          Write-Host
        }
      }
      else
      {
        Write-Host '[+] No persistence found under the HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language' -ForegroundColor Green | Out-Host
      }
    }
  }
  
  function Get-AeDebug
  {
    Write-Host
    Write-Verbose -Message 'Getting AeDebug properties...'
    Write-Verbose -Message "The executable in the Debugger property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a process is debugged. If the Auto property (REG_SZ) is set to 1, no user interaction is required.`n"
    $aeDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug' -Name Debugger -ErrorAction SilentlyContinue
    if(!$aeDebugger)
    {
      Write-Host '[+] No persistence found under the AeDebug key' -ForegroundColor Green
    }
    else
    {
      Write-Host '[!] Found properties under the AeDebug key which deserve investigation!' -ForegroundColor Red
      ($aeDebugger | Select-Object -Property @{Name='Key';Expression={$_.PSChildName}},Debugger,Auto | Out-String).Trim()
    }
    
    return
  }
  
  function Get-WerFaultHangs
  {
    Write-Host
    Write-Verbose -Message 'Getting WerFault Hangs registry key Debug property...'
    Write-Verbose -Message "The executable in the Debugger property of HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when a process creashes.`n"
    $werfaultDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs' -Name Debugger -ErrorAction SilentlyContinue
    if(!$werfaultDebugger)
    {
      Write-Host "[+] No Debugger property persistence found under the WerFault Hangs key`n" -ForegroundColor Green
    }
    else
    {
      Write-Host "[!] Found a Debugger property under the WerFault Hangs key which deserve investigation!`n`n" -ForegroundColor Red -NoNewline
      ($werfaultDebugger | Select-Object -Property @{Name='Key';Expression={$_.PSChildName}},Debugger | Out-String).Trim()
      Write-Host
    }
    
    Write-Verbose -Message 'Getting WerFault Hangs registry key ReflectDebug property...'
    Write-Verbose -Message "The executable in the ReflectDebugger property of HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when called with the -pr argument.`n"
    $werfaultReflectDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs' -Name ReflectDebugger -ErrorAction SilentlyContinue
    if(!$werfaultReflectDebugger)
    {
      Write-Host '[+] No ReflectDebugger property persistence found under the WerFault Hangs key' -ForegroundColor Green
    }
    else
    {
      Write-Host "[!] Found a ReflectDebugger property under the WerFault Hangs key which deserve investigation!`n`n" -ForegroundColor Red -NoNewline
      ($werfaultReflectDebugger | Select-Object -Property @{Name='Key';Expression={$_.PSChildName}},ReflectDebugger | Out-String).Trim()
      Write-Host
    }
    
    return
  }

  function Get-HKCUCmdAutoRun
  {
    Write-Host
    Write-Verbose -Message "Getting current user's cmd.exe's AutoRun property..."
    Write-Verbose -Message "The executable in the AutoRun property of HKCU:\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument.`n"
    $autorun = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Command Processor' -Name AutoRun -ErrorAction SilentlyContinue
    if(!$autorun)
    {
      Write-Host "[+] No persistence found under current user's cmd.exe's AutoRun key" -ForegroundColor Green
    }
    else
    {
      Write-Host "[!] Current user's cmd.exe's AutoRun property is set and deserves investigation!" -ForegroundColor Red
      ($autorun | Select-Object -ExpandProperty AutoRun | Out-String).Trim()
    }
    
    return
  }
  
  function Get-HKLMCmdAutoRun
  {
    Write-Host
    Write-Verbose -Message "Getting system's cmd.exe's AutoRun property..."
    Write-Verbose -Message "The executable in the AutoRun property of HKLM:\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument.`n"
    $autorun = Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Command Processor' -Name AutoRun -ErrorAction SilentlyContinue
    if(!$autorun)
    {
      Write-Host "[+] No persistence found under system's cmd.exe's AutoRun key" -ForegroundColor Green
    }
    else
    {
      Write-Host "[!] System's cmd.exe's AutoRun property is set and deserves investigation!" -ForegroundColor Red
      ($autorun | Select-Object -ExpandProperty AutoRun | Out-String).Trim()
    }
    
    return
  }
  
  function Get-ExplorerLoad
  {
    Write-Host
    Write-Verbose -Message "Getting current user's Explorer's Load property..."
    Write-Verbose -Message "The executable in the Load property of HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows is run by explorer.exe at login time.`n"
    $loadKey = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -Name Load -ErrorAction SilentlyContinue
    if(!$loadKey)
    {
      Write-Host '[+] No Load property found which can be used to implement a persistence technique' -ForegroundColor Green
    }
    else
    {
      Write-Host "[!] Current user's Load property is set and deserves investigation!" -ForegroundColor Red
      ($loadKey | Select-Object -ExpandProperty Load | Out-String).Trim()
    }
    
    return
  }
  
  function Get-WinlogonUserInit
  {
    Write-Host
    Write-Verbose -Message "Getting Winlogon's Userinit property..."
    Write-Verbose -Message "The executables in the Userinit property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon are run at login time by any user. Normally this property should be set to 'C:\Windows\system32\userinit.exe,' without any further executables appended.`n"
    $userinit = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Userinit -ErrorAction SilentlyContinue
    if(!$userinit)
    {
      Write-Host '[!] No Userinit property found, it may be an error...' -ForegroundColor Yellow
    }
    else 
    {
      if($userinit.Userinit -ne 'C:\Windows\system32\userinit.exe,')
      {
        Write-Host "[!] Winlogon's Userinit property is set to a non-standard value and deserves investigation!" -ForegroundColor Red
        ($userinit | Select-Object -ExpandProperty Userinit | Out-String).Trim()
      }
      else
      {
        Write-Host "[+] Winlogon's Userinit property is set to a standard value, no persistence found." -ForegroundColor Green
      }
    }
    return
  }
  
  function Get-WinlogonShell
  {
    Write-Host
    Write-Verbose -Message "Getting Winlogon's Shell property..."
    Write-Verbose -Message "The executables in the Shell property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon are run as the default shells for any users. Normally this property should be set to 'explorer.exe' without any further executables appended.`n"
    $shell = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -ErrorAction SilentlyContinue
    if(!$shell)
    {
      Write-Host '[!] No Userinit property found, it may be an error...' -ForegroundColor Yellow
    }
    else 
    {
      if($shell.Shell -ne 'explorer.exe')
      {
        Write-Host "[!] Winlogon's Shell property is set to a non-standard value and deserves investigation!" -ForegroundColor Red
        ($shell | Select-Object -ExpandProperty Shell | Out-String).Trim()
      }
      else
      {
        Write-Host "[+] Winlogon's Shell property is set to a standard value, no persistence found." -ForegroundColor Green
      }
    }
    return
  }
  
  Write-Verbose -Message 'Starting execution...'
  Get-UsersRunAndRunOnce
  Get-HKLMRunAndRunOnce
  Get-ImageFileExecutionOptions
  Get-NLDPDllOverridePath
  Get-AeDebug
  Get-WerFaultHangs
  Get-HKCUCmdAutoRun
  Get-HKLMCmdAutoRun
  Get-ExplorerLoad
  Get-WinlogonUserInit
  Get-WinlogonShell
  Write-Verbose -Message 'Execution finished!'
}
# SIG # Begin signature block
# MIID7QYJKoZIhvcNAQcCoIID3jCCA9oCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUhSSYOS/aSUhOpsF9U075SenY
# zP2gggIHMIICAzCCAWygAwIBAgIQF+BNQBpcW6RBBEo1bSFRGzANBgkqhkiG9w0B
# AQUFADAcMRowGAYDVQQDDBFGZWRlcmljbyBMYWdyYXN0YTAeFw0yMjA3MTkxNDEz
# MDJaFw0yNjA3MTkwMDAwMDBaMBwxGjAYBgNVBAMMEUZlZGVyaWNvIExhZ3Jhc3Rh
# MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDjMbaODrvLdzZbpl4zEtqUXMXl
# taFuA8vnquV5373I4Tc8Obx7U18WvEfknFLQoGGzKV8M9d9kDX9NfTRydJmEksLB
# eFuMasI+U1N71Tn4dpN0LW6PKbE35XVZtZ10LggrozqSbk9giv1bJwTTz4ZeNpJ/
# ytHlV6zIwcmap1Dt4QIDAQABo0YwRDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNV
# HQ4EFgQUEvzrfw+6jTXcizBEwSWbnNZCGu4wDgYDVR0PAQH/BAQDAgeAMA0GCSqG
# SIb3DQEBBQUAA4GBAJNKf/cEn54Sh9H3iAy0+X3hlfLtRu0UamTNtgmi1Ul7qEth
# EfOGjDtjdYj8GD97blI3z3aGWeLQkoGzELJPG2gTfsORgIN4382YwzM7AhgN++Uv
# 2Bmwqlzi4CtqAIg+Owi15RlOVnNSj0hw9KqEVxw4M2D9sTiKpfYCIrhhPQ8cMYIB
# UDCCAUwCAQEwMDAcMRowGAYDVQQDDBFGZWRlcmljbyBMYWdyYXN0YQIQF+BNQBpc
# W6RBBEo1bSFRGzAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKA
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUU2EMc2saoT8SpDa1X9iQ3S1meccw
# DQYJKoZIhvcNAQEBBQAEgYASa22IFreW8kRZazxSsWwc/QgoE9IT7TKuoDye2Xd6
# bLxMD7hs0WszQu7tJIVyPMttd7H7BEX9LJ0CY3ehUN22TamFwLxD1wZUw/0iV3Gi
# wuUAqTofQ2d0YdzO1L/j3vMUvC+2cVdtjmLAV5Vf4Yz8ma8/CDMfiJ6Kh9O4LGAp
# 6A==
# SIG # End signature block
