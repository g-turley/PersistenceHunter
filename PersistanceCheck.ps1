<#
.Synopsis
  Queries scheduled task names, executables, and arguments
#>
function Get-PersistanceTasks
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
    Get-ChildItem -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" |
      where-object { $_.Property -like "*GlobalFlag*" }
  }
  
  else
  {
    Write-Host ""
    Write-Host "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ not found."
  }
  
  if (Test-Path -path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\")
  {
    Get-ChildItem -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\" |
      where-object { $_.Property -like "*MonitorProcess*" }
    Get-ChildItem -Path "Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\" |
      where-object { $_.Property -like "*ReportingMode*" }
  }
  
  else
  {
    Write-Host ""
    Write-Host "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\ not found."
  }
}
