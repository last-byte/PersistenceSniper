#Requires -RunAsAdministrator
function Find-AllPersistence
{ 
  <#
      .SYNOPSIS

      This script tries to enumerate all the persistence methods implanted on a compromised machine.

      Function: Find-AllPersistence
      Authors: Federico `last` Lagrasta, Twitter: @last0x00; Riccardo Ancarani, Twitter: @dottor_morte
      License: https://creativecommons.org/licenses/by/3.0/deed.en
      Required Dependencies: None
      Optional Dependencies: None

      .DESCRIPTION

      Enumerate all the persistence methods found on a machine and print them for the user to see.

      .PARAMETER PersistenceMethod

      Switch: Enumerate only given method. Default is: All
	    
      .EXAMPLE

      Enumerate all persistence techniques implanted on the local machine (implicit).
      Find-AllPersistence

      .EXAMPLE

      Enumerate all persistence techniques implanted on the local machine (explicit).
      Find-AllPersistence -PersistenceMethod All

      .EXAMPLE

      Enumerate only Run and RunOnce keys persistence techniques implanted on the local machine.
      Find-AllPersistence -PersistenceMethod RunAndRunOnce

      .NOTES

      This script tries to enumerate all persistence techniques that may have been deployed on a compromised machine. New techniques may take some time before they are implemented in this script, so don't assume that because the script doesn't find anything the machine is clean.
      Most persistence techniques this script searches for are explained here https://persistence-info.github.io/ and are based on research by @Hexacorn.
      On a sidenote, this scripts makes heavy use of the Write-Host cmdlet which should be avoided but allows for easy output coloring. 
      The downside to that is the fact that redirecting output to anything other than stdout will not redirect Write-Host output. In order to do so just import and run the script in another Powershell sessions: powershell.exe -ExecutionPolicy bypass -Command '. .\unPowersist.ps1; Find-AllPersistence -Verbose' > outputfile.txt

      .LINK

      https://github.com/last-byte/unPowersist
  #>
  
  [CmdletBinding(DefaultParameterSetName='PersistenceMethod')]
  
  Param(
    [Parameter(ParameterSetName = 'PersistenceMethod', Position = 0)]
    [Switch]
    $PersistenceMethod
  )  
  function New-PersistenceObject
  {
    param(
      $technique, 
      $classification, 
      $path, 
      $value, 
      $accessGained,
      $note,
      $reference
    )
    $persistenceObject = [PSCustomObject]@{
      "Technique" = $technique
      "Classification" = $classification
      "Path" = $path
      "Value" = $value
      "Access Gained" = $accessGained
      "Note" = $note
      "Reference" = $reference
    } 
    return $persistenceObject
  }
  
  $persistenceObjectArray = New-Object -TypeName System.Collections.ArrayList
  $psProperties = @("PSChildName","PSDrive","PSParentPath","PSPath","PSProvider")
  
  function Get-UsersRunAndRunOnce
  {
    Write-Host
    Write-Host "=== MITRE ATT&CK T1547.001 - USERS' RUN AND RUNONCE KEYS ===" -ForegroundColor DarkYellow
    Write-Verbose -Message "Getting users' Run properties..."
    Write-Verbose -Message "Executables in properties of the key HKEY_USERS\<User_SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the user logs in.`n"
    $hkeyUsers = Get-ChildItem -Path Registry::HKEY_USERS
    foreach($sidHive in $hkeyUsers)
    {
      Write-Verbose -Message "Checking $sidHive registry hive..."
      $currentUser = "Registry::$sidHive"
      $runProps = Get-ItemProperty -Path "$currentUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
      if(!$runProps)
      {
        Write-Host "[+] No persistence found under $sidHive user's Run key`n" -ForegroundColor Green
      }
      else
      {
        Write-Host "[!] Found properties under $sidHive user's Run key which deserve investigation!" -ForegroundColor Red
        #($runProps| Format-List | Out-String).Trim()
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $runProps))
        {
          if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
          $propPath = Convert-Path $runProps.PSPath
          $propPath += '\' + $prop.Name
          $persistenceObject = New-PersistenceObject "Registry Run Key" "MITRE ATT&CK T1547.001" $propPath $runProps.($prop.Name) "User" "Executables in properties of the key HKEY_USERS\<User_SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the user logs in." "https://attack.mitre.org/techniques/T1547/001/"
          Write-Verbose $persistenceObject
          $null = $persistenceObjectArray.Add($persistenceObject)
        }
        Write-Host
      }
    }
    
    Write-Verbose -Message "Getting users' RunOnce properties..."
    Write-Verbose -Message "Executables in properties of the key HKEY_USERS\<User_SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the user logs in and then deleted.`n"
    foreach($sidHive in $hkeyUsers)
    {
      Write-Verbose -Message "Checking $sidHive registry hive..."
      $currentUser = "Registry::$sidHive"
      $runOnceProps = Get-ItemProperty -Path "$currentUser\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ErrorAction SilentlyContinue
      if(!$runOnceProps)
      {
        Write-Host "[+] No persistence found under $sidHive user's RunOnce key`n" -ForegroundColor Green 
      }
      else
      {
        Write-Host "[!] Found properties under $sidHive user's RunOnce key which deserve investigation!" -ForegroundColor Red -NoNewline
        #($runOnceProps | Format-List | Out-String).Trim()
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $runOnceProps))
        {
          if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
          $propPath = Convert-Path $runOnceProps.PSPath
          $propPath += '\' + $prop.Name
          $persistenceObject = New-PersistenceObject "Registry RunOnce Key" "MITRE ATT&CK T1547.001" $propPath $runOnceProps.($prop.Name) "User" "Executables in properties of the key HKEY_USERS\<User_SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the user logs in and then deleted." "https://attack.mitre.org/techniques/T1547/001/"
          Write-Verbose $persistenceObject
          $null = $persistenceObjectArray.Add($persistenceObject)
        }
        Write-Host 
      }
    }
  }
  
  function Get-SystemRunAndRunOnce
  {
    Write-Host "=== MITRE ATT&CK T1547.001 - SYSTEM'S RUN AND RUNONCE KEYS ===" -ForegroundColor DarkYellow
    Write-Verbose -Message "Getting system's Run properties..."
    Write-Verbose -Message "Executables in properties of the key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the system boots.`n"
    $runProps = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
    if(!$runProps)
    {
      Write-Host "[+] No persistence found under system's Run key" -ForegroundColor Green
    }
    else
    {
      Write-Host "[!] Found properties under system's Run key which deserve investigation!" -ForegroundColor Red
      #($runProps| Format-List | Out-String).Trim()
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $runProps))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $runProps.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "Registry Run Key" "MITRE ATT&CK T1547.001" $propPath $runProps.($prop.Name) "System" "Executables in properties of the key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run are run when the system boots." "https://attack.mitre.org/techniques/T1547/001/"
        Write-Verbose $persistenceObject
        $null = $persistenceObjectArray.Add($persistenceObject)
      }
      Write-Host
    }
    Write-Verbose -Message "Getting system's RunOnce properties..."
    Write-Verbose -Message "Executables in properties of the key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the system boots and then deleted.`n"
    $runOnceProps = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction SilentlyContinue
    if(!$runOnceProps)
    {
      Write-Host "[+] No persistence found under system's RunOnce key`n" -ForegroundColor Green
    }
    else
    {
      Write-Host "[!] Found properties under system's RunOnce key which deserve investigation!" -ForegroundColor Red -NoNewline
      #($runOnceProps | Format-List | Out-String).Trim()
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $runOnceProps))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $runOnceProps.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "Registry RunOnce Key" "MITRE ATT&CK T1547.001" $propPath $runOnceProps.($prop.Name) "System" "Executables in properties of the key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce are run once when the system boots and then deleted." "https://attack.mitre.org/techniques/T1547/001/"
        Write-Verbose $persistenceObject
        $null = $persistenceObjectArray.Add($persistenceObject)
      }
      Write-Host 
    }
  }
  
  function Get-ImageFileExecutionOptions
  {
    $IFEOptsDebuggers = New-Object -TypeName System.Collections.ArrayList
    $foundDangerousIFEOpts = $false
    Write-Host "=== MITRE ATT&CK T1546.012 - IMAGE FILE EXECUTION OPTIONS ===" -ForegroundColor DarkYellow
    Write-Verbose -Message 'Getting Image File Execution Options...'
    Write-Verbose -Message "Executables in the Debugger property of a subkey of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options are run instead of the process corresponding to the subkey.`n"
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
          #(Get-ItemProperty -Path Registry::$key -Name Debugger | Select-Object -Property @{Name='Program';Expression={$_.PSChildName}},Debugger | Out-String).TrimEnd()
          $ifeProps =  Get-ItemProperty -Path Registry::$key -Name Debugger
          foreach ($prop in (Get-Member -Type NoteProperty -InputObject $ifeProps))
          {
            if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
            $propPath = Convert-Path $ifeProps.PSPath
            $propPath += '\' + $prop.Name
            $persistenceObject = New-PersistenceObject "Image File Execution Options" "MITRE ATT&CK T1546.012" $propPath $ifeProps.($prop.Name) "System/User" "Executables in the Debugger property of a subkey of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options are run instead of the process corresponding to the subkey. Gained access depends on whose context the debugged process runs in." "https://attack.mitre.org/techniques/T1546/012/"
            Write-Verbose $persistenceObject
            $null = $persistenceObjectArray.Add($persistenceObject)
          }
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
    Write-Host "=== HEXACORN TECHNIQUE N.98 - NATURAL LANGUAGE DEVELOPMENT PLATFORM 6 DLL OVERRIDE PATH ===" -ForegroundColor DarkYellow
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
          #(Get-ItemProperty -Path Registry::$key | Select-Object -Property @{Name='Language Key';Expression={$_.PSChildName}},WBDLLPathOverride,StemmerDLLPathOverride | Out-String).TrimEnd()
          $properties = Get-ItemProperty -Path Registry::$key | Select-Object *DLLPathOverride,PS*
          foreach ($prop in (Get-Member -Type NoteProperty -InputObject $properties))
          {
            if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
            $propPath = Convert-Path $properties.PSPath
            $propPath += '\' + $prop.Name
            $persistenceObject = New-PersistenceObject "Natural Language Development Platform 6 DLL Override Path" "Hexacorn Technique N.98" $propPath $properties.($prop.Name) "System" "DLLs listed in properties of subkeys of HKLM:\SYSTEM\CurrentControlSet\Control\ContentIndex\Language are loaded via LoadLibrary executed by SearchIndexer.exe" "https://www.hexacorn.com/blog/2018/12/30/beyond-good-ol-run-key-part-98/"
            Write-Verbose $persistenceObject
            $null = $persistenceObjectArray.Add($persistenceObject)
          }
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
    Write-Host "=== UNCATALOGUE TECHNIQUE N.1 - AEDEBUG CUSTOM DEBUGGER ===" -ForegroundColor DarkYellow
    Write-Verbose -Message 'Getting AeDebug properties...'
    Write-Verbose -Message "The executable in the Debugger property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a process crashes. If the Auto property (REG_SZ) is set to 1, no user interaction is required.`n"
    $aeDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug' -Name Debugger -ErrorAction SilentlyContinue
    if(!$aeDebugger)
    {
      Write-Host '[+] No persistence found under the AeDebug key' -ForegroundColor Green
    }
    else
    {
      Write-Host '[!] Found properties under the AeDebug key which deserve investigation!' -ForegroundColor Red
      #($aeDebugger | Select-Object -Property @{Name='Key';Expression={$_.PSChildName}},Debugger,Auto | Out-String).Trim()
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $aeDebugger))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $aeDebugger.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "AEDebug Custom Debugger" "Uncatalogued Technique N.1" $propPath $aeDebugger.($prop.Name) "System/User" "The executable in the Debugger property of HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug is run when a process crashes. Gained access depends on whose context the debugged process runs in; if the Auto property of the same registry key is set to 1, the debugger starts without user interaction." "https://persistence-info.github.io/Data/aedebug.html"
        Write-Verbose $persistenceObject
        $null = $persistenceObjectArray.Add($persistenceObject)
      }
    }
    
    return
  }
  
  function Get-WerFaultHangs
  {
    Write-Host
    Write-Host "=== HEXACORN TECHNIQUE N.116 - WINDOWS ERROR REPORTING DEBUGGER ===" -ForegroundColor DarkYellow
    Write-Verbose -Message 'Getting WerFault Hangs registry key Debug property...'
    Write-Verbose -Message "The executable in the Debugger property of HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when a process crashes.`n"
    $werfaultDebugger = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs' -Name Debugger -ErrorAction SilentlyContinue
    if(!$werfaultDebugger)
    {
      Write-Host "[+] No Debugger property persistence found under the WerFault Hangs key`n" -ForegroundColor Green
    }
    else
    {
      Write-Host "[!] Found a Debugger property under the WerFault Hangs key which deserve investigation!`n`n" -ForegroundColor Red -NoNewline
      #($werfaultDebugger | Select-Object -Property @{Name='Key';Expression={$_.PSChildName}},Debugger | Out-String).Trim()
      $werfaultDebugger | Select-Object -Property Debugger,PS*
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $werfaultDebugger))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $werfaultDebugger.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "Windows Error Reporting Debugger" "Hexacorn Technique N.116" $propPath $werfaultDebugger.($prop.Name) "System" "The executable in the Debugger property of HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when a process crashes." "https://www.hexacorn.com/blog/2019/09/20/beyond-good-ol-run-key-part-116/"
        Write-Verbose $persistenceObject
        $null = $persistenceObjectArray.Add($persistenceObject)
      }
      Write-Host
    }
    
    Write-Host "=== UNCATALOGUED TECHNIQUE N.2 - WINDOWS ERROR REPORTING REFLECTDEBUGGER ===" -ForegroundColor DarkYellow
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
      #($werfaultReflectDebugger | Select-Object -Property @{Name='Key';Expression={$_.PSChildName}},ReflectDebugger | Out-String).Trim()
      $werfaultReflectDebugger | Select-Object -Property ReflectDebugger,PS*
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $werfaultReflectDebugger))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $werfaultReflectDebugger.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "Windows Error Reporting ReflectDebugger" "Hexacorn Technique N.85" $propPath $werfaultReflectDebugger.($prop.Name) "System" "The executable in the ReflectDebugger property of HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs is spawned by WerFault.exe when called with the -pr argument." "https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/"
        Write-Verbose $persistenceObject
        $null = $persistenceObjectArray.Add($persistenceObject)
      }
      Write-Host
    }
    
    return
  }

  function Get-UsersCmdAutoRun
  {
    Write-Host
    Write-Host "=== UNCATALOGUED TECHNIQUE N.3 - USERS' CMD.EXE AUTORUN ===" -ForegroundColor DarkYellow
    Write-Verbose -Message "Getting users' cmd.exe's AutoRun property..."
    Write-Verbose -Message "The executable in the AutoRun property of HKEY_USERS\<User_SID>\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument.`n"
    $hkeyUsers = Get-ChildItem -Path Registry::HKEY_USERS
    foreach($sidHive in $hkeyUsers)
    {
      Write-Verbose -Message "Checking $sidHive registry hive..."
      $currentUser = "Registry::$sidHive"
      $autorun = Get-ItemProperty -Path "$currentUser\Software\Microsoft\Command Processor" -Name AutoRun -ErrorAction SilentlyContinue
      if(!$autorun)
      {
        Write-Host "[+] $sidHive user's cmd.exe's AutoRun key is not set so it's not being used as persistence!`n" -ForegroundColor Green
      }
      else
      {
        Write-Host "[!] $sidHive user's cmd.exe's AutoRun property is set and deserves investigation!" -ForegroundColor Red
        #($autorun | Select-Object -ExpandProperty AutoRun | Out-String).Trim()
        foreach ($prop in (Get-Member -Type NoteProperty -InputObject $autorun))
        {
          if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
          $propPath = Convert-Path $autorun.PSPath
          $propPath += '\' + $prop.Name
          $persistenceObject = New-PersistenceObject "Users' cmd.exe AutoRun key" "Uncatalogued Technique N.3" $propPath $autorun.($prop.Name) "User" "The executable in the AutoRun property of HKEY_USERS\<User_SID>\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument." "https://persistence-info.github.io/Data/cmdautorun.html"
          Write-Verbose $persistenceObject
          $null = $persistenceObjectArray.Add($persistenceObject)
        }
        Write-Host
      }
    }   
    return
  }
  
  function Get-SystemCmdAutoRun
  {
    Write-Host "=== UNCATALOGUED TECHNIQUE N.3 - SYSTEM'S CMD.EXE AUTORUN ===" -ForegroundColor DarkYellow
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
      #($autorun | Select-Object -ExpandProperty AutoRun | Out-String).Trim()
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $autorun))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $autorun.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "System's cmd.exe AutoRun key" "Uncatalogued Technique N.3" $propPath $autorun.($prop.Name) "User" "The executable in the AutoRun property of HKEY_LOCAL_MACHINE\Software\Microsoft\Command Processor\AutoRun is run when cmd.exe is spawned without the /D argument." "https://persistence-info.github.io/Data/cmdautorun.html"
        Write-Verbose $persistenceObject
        $null = $persistenceObjectArray.Add($persistenceObject)
      }
    }
    
    return
  }
  
  function Get-ExplorerLoad
  {
    Write-Host
    Write-Host "=== UNCATALOGUED TECHNIQUE N.4 - EXPLORER LOAD PROPERTY ===" -ForegroundColor DarkYellow
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
      #($loadKey | Select-Object -ExpandProperty Load | Out-String).Trim()
      foreach ($prop in (Get-Member -Type NoteProperty -InputObject $loadKey))
      {
        if($psProperties.Contains($prop.Name)) {continue} # skip the property if it's powershell built-in property
        $propPath = Convert-Path $loadKey.PSPath
        $propPath += '\' + $prop.Name
        $persistenceObject = New-PersistenceObject "Explorer Load Property" "Uncatalogued Technique N.4" $propPath $loadKey.($prop.Name) "User" "The executable in the Load property of HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows is run by explorer.exe at login time." "https://persistence-info.github.io/Data/windowsload.html"
        Write-Verbose $persistenceObject
        $null = $persistenceObjectArray.Add($persistenceObject)
      }
    }
    
    return
  }
  
  function Get-SystemWinlogonUserinit
  {
    Write-Host
    Write-Host "=== MITRE ATT&CK T1547.004 - SYSTEM'S WINLOGON USERINIT PROPERTY TAMPERING ===" -ForegroundColor DarkYellow
    Write-Verbose -Message "Getting system's Winlogon's Userinit property..."
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
  
  function Get-SystemWinlogonShell
  {
    Write-Host
    Write-Host "=== MITRE ATT&CK T1547.004 - SYSTEM'S WINLOGON SHELL PROPERTY TAMPERING ===" -ForegroundColor DarkYellow
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
  Get-SystemRunAndRunOnce
  Get-ImageFileExecutionOptions
  Get-NLDPDllOverridePath
  Get-AeDebug
  Get-WerFaultHangs
  Get-UsersCmdAutoRun
  Get-SystemCmdAutoRun
  Get-ExplorerLoad
  #Get-SystemWinlogonUserinit
  #Get-SystemWinlogonShell
    
  Write-Verbose -Message 'Execution finished!'  
  return $persistenceObjectArray
}