<#
.Synopsis
 This function is used to find Shim Databases (SDBs) associated with custom application shims.
.DESCRIPTION
 The Get-AppShims function queries the registry for entires in the HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom.
 It then uses the GUIDs associated with each entry to search the InstalledSDB registry location to find the lcoation of .sdb files that are loaded with an appliction.
 The .sdb files uncovered can be further examined with tools such as python-sdb to identify any DLLs or other executables that may be loaded with an application.
 #>
function Get-AppShims {
  if (Test-Path -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\")
  {
    Write-Output ""
    Write-Output "[*] Checking App Shim keys.."
    Write-Output ""
    
    $customList = Get-ChildItem -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\"
    
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
        Write-Output "[*] End of App Shim Check"
      }
    }
   
    else {
        Write-Output ""
        Write-Output "[*]  HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\ not found"
        Write-Output ""
   }
  }
}

#Not Done
function Get-ChromeExtensions {

    Write-Output ""
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

#Not Done
function Get-FirefoxExtensions {

    Write-Output ""
    Write-Output "[*] Checking for Firefox extensions in the registry.."
    Write-Output ""

    if (Test-Path -Path "Registry::HKLM\Software\WOW6432Node\Mozilla\Firefox\Extensions")
    {
        $extension = Get-Item -Path "Registry::HKLM\Software\WOW6432Node\Mozilla\Firefox\Extensions"
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
    Write-Output "[*] End of Firefox extensions check"
    Write-Output ""
}

<#
.Synopsis
  Queries scheduled task names, executables, and arguments
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

<#
.Synopsis
 Queries registry locations associated with Technique 1183 - Image File Execution Options
#>
function Get-IFEO
{
  if (Test-Path -path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\")
  {
    Write-Output "[*] Checking Image Execution File Option keys.."
    Write-Output ""
    
    $IFEOList = Get-ChildItem -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" |
      where-object { $_.Property -like "*GlobalFlag*" } 
    
    foreach ($k in $keyList) {
        $item = $k | Get-ItemProperty | Where-Object { $_.GlobalFlag -eq 512 } | Select -ExpandProperty PSPath | % {$_.split("::")[2] }
        Write-Output "Match found at $item"
      }
    Write-Output ""
    Write-Output "[*] End of Image File Execution Options check"
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
    Write-Output ""
    Write-Output "[*] Checking SilentProcessExit keys.."
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
  
  else
  {
    Write-Output ""
    Write-Output "[*] HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\ not found"
    Write-Output ""
  }
}

function Get-BitsPersistence {
  Write-Output "[*]  Checking for BITS persistence.."
  Write-Output ""
  
  $bitsJobs = Get-BitsTransfer -AllUsers | Select -ExpandProperty JobID
  $bitsAdmin = bitsadmin /rawreturn /list /verbose /allusers
  $notficationCmdLine = $bitsAdmin | select-string "NOTIFICATION COMMAND LINE:"
  
  foreach ($j in $bitsJobs) {
    $guid = $bitsAdmin | select-string $j
    $cmdline = $notificatoinCmdLine[$bitsJobs.IndexOf($j)]
    
    if ($cmdLine -notmatch "none$") {
      Write-Output "Match found with $guid"
      Write-Output "  $cmdline"
    }
  }
  Write-Output ""
  Write-Output "[*] End of BITS persistence"
}
