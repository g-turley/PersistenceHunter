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
                        Write-Output "    $dll is present in SSPs but not found in C:\Windows\System32\"
                    }
                }
            }
        }

        Write-Output ""
    }
