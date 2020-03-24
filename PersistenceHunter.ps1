<#
.Synopsis
  Queries scheduled task names, executables, and arguments
.DESCRIPTION
  This function gathers Security Support Provider (SSP) DLLs loaded by LSA upon startup to assist in the identification of T1101 - Security Support Providers.
#>
function Get-SSPs {

    Write-Output "[*] Gathering Security Support Providers (SSPs).."
    Write-Output ""
 
    $dllList = Get-ItemProperty -Path "Registry::hklm\System\CurrentControlSet\Control\Lsa\" | select -expandproperty "Security Packages"

    if ($dllList.count -ge 1) 
    {
    
        foreach ($dll in $dllList) 
        {

            if ($dll -ne '""')
            {
                if ($dll -eq "mimilib.dll")
                {
                    Write-Output "  $dll <-- Almost certainly bad"
                }

                else 
                {
                    Write-Output "  $dll"
                }
            }
        }

        Write-Output ""
    }

    else
    {
        Write-Output "[*] No DLLs were found."
        Write-Output ""
    }

    Write-Output "[*] End of SSP check"

}

<#
.Synopsis
 Queries registry locations associated with IFEO persistence
.DESCRIPTION
 This function gathers registry values and checks for the existence of keys that are typically not present and that are requirements of the T1183 - Image File Execution Options.
#>
function Get-IFEO
{
  if (Test-Path -path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\")
  {
    Write-Output "[*] Checking Image Execution File Option keys.."
    Write-Output ""
    
    $IFEOList = Get-ChildItem -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" |
      where-object { $_.Property -like "*GlobalFlag*" } 
    
    foreach ($k in $IFEOList) {
        $item = $k | Get-ItemProperty | Where-Object { $_.GlobalFlag -eq 512 } | Select -ExpandProperty PSPath | % {$_.split("::")[2] }
        Write-Output "Match found at $item"
      }
  }
  
  else
  {
    Write-Output ""
    Write-Output "[*] HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ not found"
    Write-Output ""
  }
  
  #SilentProcessExit Begin
  if (Test-Path -path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\")
  {
    Write-Output "[*] Non-standard key HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\ found. Enumerating.."
    Write-Output ""
    
    $SPEList = Get-ChildItem -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\" |
      where-object { $_.Property -like "*MonitorProcess*" } 
      
    foreach ($k in $SPEList)
    {
      $props = $k | Get-ItemProperty | select @{l="Path";e={$_ | select -expandproperty PSPath | % {$_.split("::")[2] }}}, @{l="BinaryLaunched";e={$_.MonitorProcess }}
      $path = $props.path
      $binary = $props.binaryLaunched
      Write-Output "Match found at $path"
      Write-Output "  Application launched: $binary"
      Write-Output ""
    }
    
    Write-Output "[*] End of SilentProcessExit check"
    Write-Output ""    
  } 
 
    Write-Output "[*] End of Image File Execution Options check"
}


<#
.Synopsis
 This function is used to find Shim Databases (SDBs) associated with custom application shims.
.DESCRIPTION
 The Get-AppShims function queries the registry for entires in the HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom.
 It then uses the GUIDs associated with each entry to search the InstalledSDB registry location to find the location of .sdb files that are loaded with an appliction.
 The .sdb files uncovered can be further examined with tools such as python-sdb to identify any DLLs or other executables that may be loaded with an application to employ T1138 - Application Shimming.
 #>
function Get-AppShims {

    Write-Output "[*] Checking App Shim keys.."
    Write-Output ""
  
    if (Test-Path -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\")
    {   
    
        $customList = Get-ChildItem -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\"
    
        if (($customList).count -ge 1) {
          foreach ($appMatch in $customList) {
            $customPath = $appMatch.PSPath | Out-String | % { $_.split("::")[2] }
            $guid = $appMatch.Property | Out-String | % { $_.split(".sdb")[0] }
   
            Write-Output "Match found at $customPath"
            Write-Output "  Checking for associated SDBs.."
    
            if (Test-Path -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\$guid")
            {
              $item = Get-ItemProperty -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\$guid"
              $dbPath = $item.DatabasePath
              Write-Output "    Shim database found at $dbPath - Recommend parsing file"
            }
            
            Write-Output ""
           }
        } 
   
        else {
                Write-Output "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\ not found. That's good."
                Write-Output ""
            }
    }
    
    Write-Output "[*] End of App Shim Check"
   
}

<#
.Synopsis
 Queries Get-BitsTransfer and bitsadmin binaries to identify command line arguments
.DESCRIPTION
 This function gathers data from Get-BitsTransfers for all users and matches the jobs based on GUID against output of the bitsadmin binary to match command line arguments to a GUID that could be evident of T1197.
#>
function Get-BitsPersistence {
    
    Write-Output "[*]  Checking for BITS persistence.."
  
    $bitsJobs = Get-BitsTransfer -AllUsers | Select -ExpandProperty JobID
    $bitsAdmin = bitsadmin /rawreturn /list /verbose /allusers
    $notficationCmdLine = $bitsAdmin | select-string "NOTIFICATION COMMAND LINE:"
  
    foreach ($j in $bitsJobs) {
    $guid = $bitsAdmin | select-string $j
    $cmdline = $notificationCmdLine[$bitsJobs.IndexOf($j)]
    
        if ($cmdLine -notmatch "none$") {
            Write-Output "Match found with $guid"
            Write-Output "  $cmdline"
        }
    }

    Write-Output ""
    Write-Output "[*] End of BITS persistence"
}

<#
.Synopsis
 Queries the registry for modifications to AppInit and AppCert DLL keys
.DESCRIPTION
 This function queries the registry to identify if the operating system has been modified to enable AppInit and AppCert DLLs to be loaded as well as lists the DLLs associated to assist in the detection of T1108 - AppInit DLLs and T1182 - AppCert DLLs.
#>
function Get-AppInitDLLs {
    
    Write-Output "[*] Checking for AppInit DLLs.."
    if (((Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" | select -expandproperty LoadAppInit_DLLs) -eq "1") -or (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" | select -ExpandProperty LoadAppInit_DLLs) -eq "1")
    { 
        Write-Output ""
        Write-Output "[*] AppInit DLLs are configured to load. Checking AppInit DLL keys.."
    }

    else {
        Write-Output ""
        Write-Output "[*] AppInit DLLs aren't configured to load. That's good. Checking AppInit DLL keys anyway.."
    }
    
    $dllList = New-Object -TypeName "System.Collections.Arraylist" 
    $firstCheck = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" | select -expandproperty AppInit_DLLs
    $secondCheck = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" | select -expandproperty AppInit_DLLs
    $thirdCheck = Get-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" | select -ExpandProperty AppCertDLLs -ErrorAction SilentlyContinue

    if ($firstCheck -ne "") {
        [void]$dllList.add($firstCheck)
    }
    if ($secondCheck -ne "") {
        [void]$dllList.Add($secondCheck)
    }
    if ($thirdCheck -ne $null) {
        [void]$dllList.Add($thirdCheck)
    }
    
    if ($dllList.Count -ge 1) 
    {
        Write-Output "  DLLs loaded:"
        foreach ($dll in $dllList) {
            Write-Output "    $dll"
        } 

        Write-Output ""
    }

    else
    {
        Write-Output "[*] No DLLs were found."
        Write-Output ""
    }

    Write-Output "[*] End of AppInit DLL check"
}

<#
.Synopsis
 Queries the registry for modifications to LSA Authenication Packages
.DESCRIPTION
 This function gathers data from the registry to identify any changes to the Authenication Packages value in the HKLM\System\CurrentControlSet\Control\LSA key that would enable the employment of T1131 - Authentication Packages.
#>
function Get-AuthenticationPackages {
    
    $Path = "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Lsa"

    Write-Output "[*] Checking for LSA Authentication Packages.."
    if ((Get-ItemProperty -Path $Path | select -expandproperty "Authentication Packages") -eq "msv1_0")
    { 
        Write-Output ""
        Write-Output "[*] No modifications detected in LSA Authentication Packages"
    }

    else {
        
        $value = Get-ItemProperty -Path $Path | select -ExpandProperty "Authentication Packages"
        
        Write-Output ""
        Write-Output "[*] Non-standard value found: $value"
    }

    Write-Output ""
    Write-Output "[*] End of LSA Authentication Packages check"
}

<#
.Synopsis
 Queries registry for Chrome Extensions
.DESCRIPTION
 This function gathers data from several registry locations and the filesystem to identify any .xpi files that could be used to employ T1176 - Browser Extensions. NOTE: The detection of any extension does not indicate malicious code. This function simply provides situational awareness.
#>
function Get-ChromeExtensions {
#This bad boy isn't done yet..
    Write-Output "[*] Checking for Chrome Extensions.."
    Write-Output ""

    if (Test-Path -Path "Registry::HKLM\Software\Google\Chrome\Extensions\")
    {
        $extensionList = Get-ChildItem -Path "Registry::HKLM\Software\Google\Chrome\Extensions\"

        foreach ($e in $extensionList)
        {
            $e | Get-ItemProperty | select @{l="RegistryPath"; e={ $_.PSPath | Out-String | % { $_.split("::")[2] } } },Path,Version
        }
    }

    if (Test-Path -Path "Registry::HKLM\Software\Wow6432Node\Google\Chrome\Extensions\")
    {
        $extensionList = Get-ChildItem -Path "Registry::HKLM\Software\Wow6432Node\Google\Chrome\Extensions\"

        foreach ($e in $extensionList)
        {
            $e | Get-ItemProperty | select @{l="RegistryPath"; e={ $_.PSPath | Out-String | % { $_.split("::")[2] } } },Path,Version
        }
    }

    Write-Output ""
    Write-Output "[*] End of Chrome extensions check"
    Write-Output ""
}

<#
.Synopsis
 Queries registry and file system for Firefox Extensions
.DESCRIPTION
 This function gathers data from several registry locations and the filesystem to identify any .xpi files that could be used to employ T1176 - Browser Extensions. NOTE: The detection of an .xpi file does not indicate malicious code. This function simply provides situational awareness.
#>
function Get-FirefoxExtensions {

    Write-Output "[*] Checking for Firefox extensions in the registry.."
    Write-Output ""

    if (Test-Path -Path "Registry::HKLM\Software\WOW6432Node\Mozilla\Firefox\Extensions")
    {
        $extension = Get-Item -Path "Registry::HKLM\Software\WOW6432Node\Mozilla\Firefox\Extensions"
        if ($extension | Get-ItemProperty)
        {
            $value = $extension | Get-ItemProperty | select "{*" | fl | out-string
            foreach ($v in $value.Trim())
            {
                $prop = $v -split ' : '
                $guid = $prop[0]
                $path = $prop[1]
                Write-Output "GUID: $guid"
                Write-Output "  Path: $path"
                Write-Output ""
            }
        }
    }

    Write-Output "[*] End of Firefox extension registry check"
    Write-Output ""
    Write-Output "[*] Checking for Firefox extensions in AppData.."
    Write-Output ""

    $user = Get-ChildItem -Path "C:\Users" | select -ExpandProperty Name
    foreach ($u in $user)
    {
        if (Test-Path -Path "C:\Users\$u\AppData\Roaming\Mozilla\")
        {
            $xpi = Get-ChildItem -Recurse -Force -Path "C:\Users\$u\AppData\Roaming\Mozilla\" | where { $_.Extension -eq ".xpi" }
            foreach ($x in $xpi) 
            {
                $path = $x | Select -ExpandProperty FullName
                Write-Output "Extension found: $path"
            }
            
            Write-Output ""
        }
    }

    Write-Output "[*] End of Firefox extensions in AppData"
    Write-Output ""
}

<#
.Synopsis
  Queries scheduled task names, executables, and arguments
.DESCRIPTION
  This function gathers scheduled tasks along with the binaries and command line arguments assocaited with them to assist in the identification of T1053 - Scheduled Tasks.
#>
function Get-PersistenceTasks
{
  Write-Output "[*] Gathering scheduled tasks.."
  Write-Output ""
  Get-ScheduledTask | % { [pscustomobject]@{
    Name = $_.TaskName
    Binary = $_.Actions.Execute
    Arguments = $_.Actions.Arguments
    }
  }
  Write-Output ""
  Write-Output "[*] End of scheduled tasks"
}
