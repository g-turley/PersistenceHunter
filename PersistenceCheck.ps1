<#
.Synopsis
  Queries scheduled task names, executables, and arguments
#>
function Get-PersistenceTasks
{
  Get-ScheduledTask | % { [pscustomobject]@{
    Name = $_.TaskName
    Binary = $_.Actions.Execute
    Arguments = $_.Actions.Arguments
    }
  }
}

<#
.Synopsis
 Queries registry locations associated with Technique 1183 - Image File Execution Options
#>
function Get-IFEO
{
  if (Test-Path -path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\")
  {
    Write-Host "[*] Checking Image Execution File Option keys.."
    Write-Host ""
    
    keyList = Get-ChildItem -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" |
      where-object { $_.Property -like "*GlobalFlag*" } | Get-ItemProperty | Where-Object { $_.GlobalFlag -eq 512 } | 
      Select -ExpandProperty PSPath | % {$_.split("::")[2] }
    
    foreach ($k in $keyList) {
        Write-Host "Match found at $k"
      }
    Write-Host ""
    Write-Host "[*] End of Image File Execution Options check"
  }
  
  else
  {
    Write-Host ""
    Write-Host "[*] HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ not found"
    Write-Host ""
  }
  
  #SilentProcessExit Begin
  if (Test-Path -path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\")
  {
    Write-Host ""
    Write-Host "[*] Checking SilentProcessExit keys.."
    Write-Host ""
    
    $keyList = Get-ChildItem -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\" |
      where-object { $_.Property -like "*MonitorProcess*" } | Get-ItemProperty | select @{l="Path";e={$_ | select -expandproperty PSPath |
      % {$_.split("::")[2] }}}, @{l="BinaryLaunched";e={$_.MonitorProcess }}
    
    foreach ($k in $keyList)
    {
      $path = $k.path
      $binary = $k.binaryLaunched
      Write-Host "Match found at $path"
      Write-Host "  Application launched: $binary"
      Write-Host ""
    }
    
    Write-Host "[*] End of SilentProcessExit check"
    Write-Host ""    
  } 
  
  else
  {
    Write-Host ""
    Write-Host "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\ not found."
    Write-Host ""
  }
}
