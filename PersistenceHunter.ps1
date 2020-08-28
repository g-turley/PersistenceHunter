<#
.Synopsis
 Queries registry locations associated with IFEO persistence
.DESCRIPTION
 This function gathers registry values and checks for the existence of keys that are typically not present and that are requirements of the T1183 - Image File Execution Options.
#>
function Get-IFEO {
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
#Currently buggy depending on PowerShell version
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
                Write-Output "  GUID: $guid"
                Write-Output "    Path: $path"
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
                Write-Output "  Extension found: $path"
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
function Get-PersistenceTasks {
  Write-Output "[*] Gathering scheduled tasks.."
  Write-Output ""
  $schTasks = Get-ScheduledTask | % { [pscustomobject]@{
    Name = $_.TaskName | Out-String
    Binary = $_.Actions.Execute | Out-String
    Arguments = $_.Actions.Arguments | Out-String
    }
  }
  
  $schTasks | Where {$_.binary -ne ""} | Select name, binary, arguments | ft -autosize -wrap
  Write-Output "[*] End of scheduled tasks"
}

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
                if ($dll -eq "mimilib")
                {
                    Write-Output "  $dll <-- Almost certainly bad"
                }

                else 
                {
                    if (Test-Path -Path C:\windows\system32\$dll.dll) {
                        $signer = Get-AuthenticodeSignature -FilePath "C:\windows\system32\$dll.dll" | select -expandproperty signercertificate | select -expandproperty DnsNameList
                        Write-Output "  $dll - Signed by $signer"
                    }

                    else {
                        Write-Output "    $dll is present in SSPs but not found in C:\Wiindows\System32\"
                    }
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
  Queries scheduled task names, executables, and arguments
.DESCRIPTION
  This function gathers Authentication Package DLLs and the associated signatures loaded by LSA upon startup to assist in the identification of T1131 - Authentication Package.
#>
function Get-AuthenticationPackages {

    Write-Output "[*] Gathering LSA Authentication Packages.."
    Write-Output ""
 
    $dllList = Get-ItemProperty -Path "Registry::hklm\System\CurrentControlSet\Control\Lsa\" | select -expandproperty "Authentication Packages"

    if ($dllList.count -ge 1) 
    {
    
        foreach ($dll in $dllList) 
        {
            if (Test-Path -Path C:\windows\system32\$dll.dll) 
            {
                $signer = Get-AuthenticodeSignature -FilePath "C:\windows\system32\$dll.dll" | select -expandproperty signercertificate | select -expandproperty DnsNameList
                Write-Output "  $dll - Signed by $signer"
            }

            else 
            {
                Write-Output "    $dll is present in Authentication Packages but not found in C:\Wiindows\System32\"
            }                        
        }

        Write-Output ""
    }

    else
    {
        Write-Output "[*] No DLLs were found."
        Write-Output ""
    }

    Write-Output "[*] End of Authentication Package check"

}

<#
.Synopsis
  Queries all HKCUs for Logon Scripts
.DESCRIPTION
  This function gathers UserInitMprLogonScript values across all HKCUs to assist in the identification of T1037 - Logon Scripts.
#>
function Get-LogonScripts {

    Write-Output "[*] Gathering Logon Scripts for all users.."
    Write-Output ""
 
    $HKCUList = Get-ChildItem -recurse -depth 0 "Registry::HKU" | select -expandproperty Name

    foreach ($h in $HKCUList) 
    {
        if (Test-Path -Path "Registry::$h\Environment")
        {
            $logonScript = Get-ItemProperty -Path "Registry::$h\Environment" | select -expandproperty UserInitMprLogonScript -ErrorAction SilentlyContinue
            if ($logonScript -ne $null)
            {
                $user = $h
                Write-Output "  User $h is set to run $logonscript at login"
                Write-Output "    Path to key: $h\Environment\UserInitMprLogonScript"
            }
        }           
    }

    Write-Output ""

    Write-Output "[*] End of Logon Scripts check"

}

<#
.Synopsis
  Queries all user directories for hidden files
.DESCRIPTION
  This function identifies all hidden files of specific file types, namely file types that can be executed, as well as file types that are common in phishing, to assist in the identification of T1158 - Hidden Files and Directories.
#>
function Get-HiddenFiles {

    Write-Output "[*] Checking for hidden files in user directories.."
    Write-Output ""
   
    $hidables = @(".APPLICATION", ".BAT", ".BIN", ".CAB", ".CMD", ".COM", ".CPL", ".DLL", ".DOC", ".DOCM", ".DOT", ".DOTM", ".DOCX", ".EXE", ".GADGET", 
                    ".HTA", ".HTM", ".HTML", ".INF1", ".INS", ".INX", ".ISU", ".JAR", ".JOB", ".JS", ".JSE", ".LNK", ".MSC", ".MSH", ".MSH1", ".MSH2", 
                    ".MSHXML", ".MSH1XML", ".MSH2XML", ".MSI", ".MSP", ".MST", ".ODT", ".PAF", ".PDF", ".PIF", ".PPTM", ".POTM", ".PPAM", ".PPSM", ".PPTX", 
                    ".PS1", ".PS1M", ".PS1XML", ".PS2", ".PS2XML", ".PSC1", ".PSC2", ".REG", ".RGS", ".SCR", ".SCT", ".SHB", ".SHS", ".SLDM", ".U3P", ".VB", 
                    ".VBE", ".VBS", ".VBSCRIPT", ".WS", ".WSF", ".WSH", ".XLS", ".XLSM", ".XLTM", ".XLAM", ".ZIP")
    $user = Get-ChildItem -Path "C:\Users" | select -ExpandProperty Name 
    foreach ($u in $user)
    {
        $file = Get-ChildItem -File -Hidden -Recurse -Path "C:\users\$u" -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in $hidables } | Select -ExpandProperty FullName

        foreach ($f in $file)
        {
            Write-Output "  $f"
        }
    }

    Write-Output ""
    Write-Output "[*] End of hidden files check"

}

<#
.Synopsis
  Queries all user directories for hidden folders
.DESCRIPTION
  This function identifies all hidden folders to assist in identification of T1158 - Hidden Files and Directories.
#>
function Get-HiddenDirectories {

    Write-Output "[*] Checking for hidden directories in user directories.."
    Write-Output ""
   
    $file = Get-ChildItem -Directory -Hidden -Recurse -Path "C:\users" -ErrorAction SilentlyContinue | Select -ExpandProperty FullName

    foreach ($f in $file)
    {
        Write-Output "  $f"
    }

    Write-Output ""
    Write-Output "[*] End of hidden directory check ($($file.Length) Found)"

}


function Get-OfficePersistence {
#Todo: Scan for macro files

    Write-Output "[*] Checking for Microsoft Office based persistence.."
    Write-Output ""
 
    $HKCUList = Get-ChildItem -recurse -depth 0 "Registry::HKU" | select -expandproperty Name

    foreach ($h in $HKCUList) 
    {
        if (Test-Path -Path "Registry::$h\Software\Microsoft\Office test\Special\Perf") #APT28
        {
            Write-Output "    Found non-standard key at: $h\Software\Microsoft\Office test\Special\Perf"
        }
    }

    Write-Output ""
    Write-Output "[*] End of Microsoft Office persistence check"
}

<#
.Synopsis
  Checks for unsigned DLLs and descriptionless services
.DESCRIPTION
  Persistence via Services can launch DLLs in place of executables. This function goes through services and identifies those that launch unsigned DLLs (code derived from: https://github.com/gtworek/PSBits/blob/master/Services/Get-ServiceDlls.ps1). Additionally, it searches for descriptionless services as most legitimate services provide a description.
#>
function Get-ServicePersistence { 

    Write-Output "[*] Checking for unsigned service DLLs.."
    Write-Output ""

    $keys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\"

    foreach ($key in $keys)
    {
        if (Test-Path ($key.pspath+"\Parameters"))
        {
            $ServiceDll = (Get-ItemProperty ($key.pspath+"\Parameters")).ServiceDll
            if ($ServiceDll -ne $null)
            {
                if ((Get-AuthenticodeSignature $ServiceDll).Status.value__ -ne 0) 
                {
                    Write-Output "    Unsigned DLL found at $ServiceDll"
                    $hash = (Get-FileHash -Algorithm md5 -Path $ServiceDll).Hash
                    Write-Output  "        MD5: $hash"
                }
            }

        }
    }

    Write-Output ""
    Write-Output "[*] End of unsigned service DLL check"
    Write-Output ""

    Write-Output "[*] Checking for description-less services.."
    Write-Output ""

    $nondescriptService = Get-WmiObject win32_service | where-object {$_.description -eq $null}

    foreach ($s in $nondescriptService)
    {
        $pathname = $s.PathName
        $pathname = $pathname -replace '"',''
        Write-Output "    $pathname"
        $hash = (Get-Filehash -Algorithm MD5 -LiteralPath $pathname -ErrorAction SilentlyContinue).Hash 
        Write-Output "        MD5: $hash"
    }

    Write-Output ""
    Write-Output "[*] End of unsigned service DLL check"
}

function Get-Exes {

    Write-Output "[*] Getting a list of all the EXEs, the path, and the MD5. Take 5, this will take a minute.."
    Write-Output ""
    
    $exes = Get-ChildItem -Recurse -File -Path C:\ -Force -Include "*.exe" -ErrorAction SilentlyContinue | Select FullName,Name
    foreach ($e in $exes)
    {
        $name = $e.Name
        $fullpath = $e.FullName
        $hash = (Get-FileHash -Algorithm MD5 -Path $fullpath).Hash

        Write-Output "    File Name: $name"
        Write-Output "        File Path: $fullpath"
        Write-Output "        MD5: $hash"
    }

    Write-Output ""
    Write-Output "[*] End of EXE check"
}

<#
.Synopsis
  Provides sorted LastWriteTime of specific registry keys to help identify SIP and Trust Provider Hijacking
.DESCRIPTION
  SIP and Trust Providers offer an interface between APIs and files. This detects direct registry changes by adversaries to mislead the OS into whitelisting malicious tools (T1198 - SIP and Trust Provider Hijacking).
  If certain registry values are changed recently it may indicate hijacking. Items which have been written in order of suspicion.
#>
function Get-TrustProviderHijacking { 

    Write-Output "[*] Checking for SIP and Trust Provider Hijacking.."
    Write-Output ""

    foreach ($potentiallocation in @("HKLM:\SOFTWARE\Microsoft\Cryptography\OID\", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID", "HKLM:\SOFTWARE\Microsoft\Cryptography\Providers\Trust", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers\Trust"))
    {
        $encodingtype = Get-ChildItem $potentiallocation -Recurse
        $out = foreach ($type in $encodingtype)
        {
            if($type.GetType().Name -eq "RegistryKey"){
                if($type.Property -ne ""){
                    # $path = "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{603BCC1F-4B59-4E08-B724-D2C6297EF351}"
                    [Microsoft.Win32.RegistryKey]$RegistryKey = Get-Item $type.PSPath

                    # This chunk extracts the LastWriteTime of a registry key.

                    #region Create Win32 API Object
                    Try {
                        [void][advapi32]
                    } Catch {
                        #region Module Builder
                        $Domain = [AppDomain]::CurrentDomain
                        $DynAssembly = New-Object System.Reflection.AssemblyName('RegAssembly')
                        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run) # Only run in memory
                        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('RegistryTimeStampModule', $False)
                        #endregion Module Builder
 
                        #region DllImport
                        $TypeBuilder = $ModuleBuilder.DefineType('advapi32', 'Public, Class')
 
                        #region RegQueryInfoKey Method
                        $PInvokeMethod = $TypeBuilder.DefineMethod(
                            'RegQueryInfoKey', #Method Name
                            [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
                            [IntPtr], #Method Return Type
                            [Type[]] @(
                                [Microsoft.Win32.SafeHandles.SafeRegistryHandle], #Registry Handle
                                [System.Text.StringBuilder], #Class Name
                                [UInt32 ].MakeByRefType(),  #Class Length
                                [UInt32], #Reserved
                                [UInt32 ].MakeByRefType(), #Subkey Count
                                [UInt32 ].MakeByRefType(), #Max Subkey Name Length
                                [UInt32 ].MakeByRefType(), #Max Class Length
                                [UInt32 ].MakeByRefType(), #Value Count
                                [UInt32 ].MakeByRefType(), #Max Value Name Length
                                [UInt32 ].MakeByRefType(), #Max Value Name Length
                                [UInt32 ].MakeByRefType(), #Security Descriptor Size           
                                [long].MakeByRefType() #LastWriteTime
                            ) #Method Parameters
                        )
 
                        $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
                        $FieldArray = [Reflection.FieldInfo[]] @(       
                            [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
                            [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
                        )
 
                        $FieldValueArray = [Object[]] @(
                            'RegQueryInfoKey', #CASE SENSITIVE!!
                            $True
                        )
 
                        $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
                            $DllImportConstructor,
                            @('advapi32.dll'),
                            $FieldArray,
                            $FieldValueArray
                        )
 
                        $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
                        #endregion RegQueryInfoKey Method
 
                        [void]$TypeBuilder.CreateType()
                        #endregion DllImport
                    }
                    #endregion Create Win32 API object
                                #region Constant Variables
                $ClassLength = 255
                [long]$TimeStamp = $null
                #endregion Constant Variables
 
                    $ClassName = New-Object System.Text.StringBuilder $RegistryKey.Name
                    $RegistryHandle = $RegistryKey.Handle
                    #endregion Registry Key Data

                    #region Retrieve timestamp
                    $Return = [advapi32]::RegQueryInfoKey(
                    $RegistryHandle,
                    $ClassName,
                    [ref]$ClassLength,
                    $Null,
                    [ref]$Null,
                    [ref]$Null,
                    [ref]$Null,
                    [ref]$Null,
                    [ref]$Null,
                    [ref]$Null,
                    [ref]$Null,
                    [ref]$TimeStamp
                    )
                    Switch ($Return) {
                        0 {
                            #Convert High/Low date to DateTime Object
                            $LastWriteTime = [datetime]::FromFileTime($TimeStamp)
 
                            #Return object
                            $Object = [pscustomobject]@{
                                FullName = $RegistryKey.Name
                                Name = $RegistryKey.Name -replace '.*\\(.*)','$1'
                                LastWriteTime = $LastWriteTime
                            }
                            $Object.pstypenames.insert(0,'Microsoft.Registry.Timestamp')
                            $Object
                        }
                        122 {
                            Throw "ERROR_INSUFFICIENT_BUFFER (0x7a)"
                        }
                        Default {
                            Throw "Error $(Return) occurred"
                        }
                    }
                }
           }
       }
        $out | Sort-Object -Property 'LastWriteTime' -Descending
    # END FUNC
    }
    Write-Output "[*] End of SIP and Trust Provider Hijacking Check"
}
