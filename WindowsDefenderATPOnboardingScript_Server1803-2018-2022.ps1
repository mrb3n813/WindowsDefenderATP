function Disable-MachineAccount
{
    
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount  
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    if(!$directory_entry.InvokeGet("AccountDisabled"))
    {

        try 
        {
            $directory_entry.InvokeSet("AccountDisabled","True")
            $directory_entry.SetInfo()
            Write-Output "[+] Machine account $MachineAccount disabled"
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
        }

    }
    else
    {
        Write-Output "[-] Machine account $MachineAccount is already disabled"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }
    
}

function Enable-MachineAccount
{
    
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount  
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    if($directory_entry.InvokeGet("AccountDisabled"))
    {

        try 
        {
            $directory_entry.InvokeSet("AccountDisabled","False")
            $directory_entry.SetInfo()
            Write-Output "[+] Machine account $MachineAccount enabled"
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
        }

    }
    else
    {
        Write-Output "[-] Machine account $MachineAccount is already enabled"   
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }
    
}

function Get-MachineAccountAttribute
{
    

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$true)][String]$Attribute,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $output = $directory_entry.InvokeGet($Attribute)
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

function Get-MachineAccountCreator
{
    

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    try
    {

        if($Credential)
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
        }
        
        $machine_account_searcher = New-Object DirectoryServices.DirectorySearcher 
        $machine_account_searcher.SearchRoot = $directory_entry  
        $machine_account_searcher.PageSize = 1000
        $machine_account_searcher.Filter = '(&(ms-ds-creatorsid=*))'
        $machine_account_searcher.SearchScope = 'Subtree'
        $machine_accounts = $machine_account_searcher.FindAll()
        $creator_object_list = @()
            
        ForEach($account in $machine_accounts)
        {
            $creator_SID_object = $account.properties."ms-ds-creatorsid"

            if($creator_SID_object)
            {
                $creator_SID = (New-Object System.Security.Principal.SecurityIdentifier($creator_SID_object[0],0)).Value
                $creator_object = New-Object PSObject

                try
                {

                    if($Credential)
                    {
                        $creator_account = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/<SID=$creator_SID>",$Credential.UserName,$credential.GetNetworkCredential().Password)
                        $creator_account_array = $($creator_account.distinguishedName).Split(",")
                        $creator_username = $creator_account_array[($creator_account_array.Length - 2)].SubString(3).ToUpper() + "\" + $creator_account_array[0].SubString(3)    
                    }
                    else
                    {
                        $creator_username = (New-Object System.Security.Principal.SecurityIdentifier($creator_SID)).Translate([System.Security.Principal.NTAccount]).Value                        
                    }

                    Add-Member -InputObject $creator_object -MemberType NoteProperty -Name Creator $creator_username
                }
                catch
                {
                    Add-Member -InputObject $creator_object -MemberType NoteProperty -Name Creator $creator_SID
                }
                
                Add-Member -InputObject $creator_object -MemberType NoteProperty -Name "Machine Account" $account.properties.name[0]
                $creator_object_list += $creator_object
                $creator_SID_object = $null
            }

        }

    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
        throw
    }

    Write-Output $creator_object_list | Sort-Object -property @{Expression = {$_.Creator}; Ascending = $false}, "Machine Account" | Format-Table -AutoSize

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Invoke-AgentSmith
{
    
    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$NetBIOSDomain,
        [parameter(Mandatory=$false)][String]$MachineAccountPrefix = "AgentSmith",
        [parameter(Mandatory=$false)][Int]$MachineAccountQuota = 10,
        [parameter(Mandatory=$false)][Int]$Sleep = 0,
        [parameter(Mandatory=$false)][System.Security.SecureString]$Password,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(Mandatory=$false)][Switch]$NoWarning,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    $i = 0
    $j = 1
    $k = 1
    $MachineAccountQuota--

    if(!$NoWarning)
    {
        $confirm_invoke = Read-Host -Prompt "Are you sure you want to do this? (Y/N)"
    }

    if(!$Password)
    {
        $password = Read-Host -Prompt "Enter a password for the new machine accounts" -AsSecureString
    }

    if(!$NetBIOSDomain)
    {

        try
        {
            $NetBIOSDomain = (Get-ChildItem -path env:userdomain).Value
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if($confirm_invoke -eq 'Y' -or $NoWarning)
    {

        :main_loop while($i -le $MachineAccountQuota)
        {
            $MachineAccount = $MachineAccountPrefix + $j
            
            try
            {
                $output = New-MachineAccount -MachineAccount $MachineAccount -Credential $Credential -Password $Password -Domain $Domain -DomainController $DomainController -DistinguishedName $DistinguishedName

                if($output -like "*The server cannot handle directory requests*")
                {
                    Write-Output "[-] Limit reached with $account"
                    $switch_account = $true
                    $j--
                }
                else
                {   
                    Write-Output $output  
                    $success = $j
                }

            }
            catch
            {

                if($_.Exception.Message -like "*The supplied credential is invalid*")
                {
                    
                    if($j -gt $success)
                    {
                        Write-Output "[-] Machine account $account was not added"
                        Write-Output "[-] No remaining machine accounts to try"
                        Write-Output "[+] Total machine accounts added = $($j - 1)"         
                        break main_loop
                    }

                    $switch_account = $true
                    $j--
                }
                else
                {
                    Write-Output "[-] $($_.Exception.Message)"    
                }

            }

            if($i -eq 0)
            {
                $account =  "$NetBIOSDomain\$MachineAccountPrefix" + $k + "$"
            }

            if($i -eq $MachineAccountQuota -or $switch_account)
            {
                Write-Output "[*] Trying machine account $account"
                $credential = New-Object System.Management.Automation.PSCredential ($account, $password)
                $i = 0
                $k++
                $switch_account = $false
            }
            else
            {
                $i++
            }

            $j++

            Start-Sleep -Milliseconds $Sleep
        }

    }
    else
    {
        Write-Output "[-] Function exited without adding machine accounts"
    }

}

function New-MachineAccount
{
    

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$false)][System.Security.SecureString]$Password,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    $null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")

    if(!$Password)
    {
        $password = Read-Host -Prompt "Enter a password for the new machine account" -AsSecureString
    }

    $password_BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $password_cleartext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($password_BSTR)

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }
    
    $Domain = $Domain.ToLower()
    $machine_account = $MachineAccount

    if($MachineAccount.EndsWith('$'))
    {
        $sam_account = $machine_account
        $machine_account = $machine_account.SubString(0,$machine_account.Length - 1)
    }
    else 
    {
        $sam_account = $machine_account + "$"
    }

    Write-Verbose "[+] SAMAccountName = $sam_account" 

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    $password_cleartext = [System.Text.Encoding]::Unicode.GetBytes('"' + $password_cleartext + '"')
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DomainController,389)

    if($Credential)
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier,$Credential.GetNetworkCredential())
    }
    else
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
    }
    
    $connection.SessionOptions.Sealing = $true
    $connection.SessionOptions.Signing = $true
    $connection.Bind()
    $request = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest
    $request.DistinguishedName = $distinguished_name
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass","Computer")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "SamAccountName",$sam_account)) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "userAccountControl","4096")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "DnsHostName","$machine_account.$Domain")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "ServicePrincipalName","HOST/$machine_account.$Domain",
        "RestrictedKrbHost/$machine_account.$Domain","HOST/$machine_account","RestrictedKrbHost/$machine_account")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "unicodePwd",$password_cleartext)) > $null
    Remove-Variable password_cleartext

    try
    {
        $connection.SendRequest($request) > $null
        Write-Output "[+] Machine account $MachineAccount added"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"

        if($error_message -like '*Exception calling "SendRequest" with "1" argument(s): "The server cannot handle directory requests."*')
        {
            Write-Output "[!] User may have reached ms-DS-MachineAccountQuota limit"
        }

    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Remove-MachineAccount
{
   

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount  
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $directory_entry.psbase.DeleteTree()
        Write-Output "[+] Machine account $MachineAccount removed"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Set-MachineAccountAttribute
{
   
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$true)][String]$Attribute,
        [parameter(Mandatory=$true)]$Value,
        [parameter(Mandatory=$false)][Switch]$Append,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount  
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {

        if($Append)
        {
            $directory_entry.$Attribute.Add($Value) > $null
            $directory_entry.SetInfo()
            Write-Output "[+] Machine account $machine_account attribute $Attribute appended"
        }
        else
        {
            $directory_entry.InvokeSet($Attribute,$Value)
            $directory_entry.SetInfo()
            Write-Output "[+] Machine account $machine_account attribute $Attribute updated"
        }
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

#endregion

#region begin DNS Functions

function Disable-ADIDNSNode
{
   

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    try
    {
        $SOASerialNumberArray = New-SOASerialNumberArray -DomainController $DomainController -Zone $Zone -SOASerialNumber $SOASerialNumber
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
        throw
    }

    if(!$DistinguishedName)
    {

        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }
        
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    $timestamp = [int64](([datetime]::UtcNow.Ticks)-(Get-Date "1/1/1601").Ticks)
    $timestamp = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($timestamp))
    $timestamp = $timestamp.Split("-") | ForEach-Object{[System.Convert]::ToInt16($_,16)}

    [Byte[]]$DNS_record = 0x08,0x00,0x00,0x00,0x05,0x00,0x00,0x00 +
        $SOASerialNumberArray[0..3] +
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
        $timestamp

    Write-Verbose "[+] DNSRecord = $([System.Bitconverter]::ToString($DNS_record))"

    try
    {
        $directory_entry.InvokeSet('dnsRecord',$DNS_record)
        $directory_entry.InvokeSet('dnsTombstoned',$true)
        $directory_entry.SetInfo()
        Write-Output "[+] ADIDNS node $Node tombstoned"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Enable-ADIDNSNode
{
   

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$Data,    
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]$Type = "A",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][Byte[]]$DNSRecord,
        [parameter(Mandatory=$false)][Int]$Preference,
        [parameter(Mandatory=$false)][Int]$Priority,
        [parameter(Mandatory=$false)][Int]$Weight,
        [parameter(Mandatory=$false)][Int]$Port,
        [parameter(Mandatory=$false)][Int]$TTL = 600,
        [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
        [parameter(Mandatory=$false)][Switch]$Static,
        [parameter(Mandatory=$false)][Switch]$Tombstone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if(!$DNSRecord)
    {

        try 
        {

            if($Static)
            {
                $DNSRecord = New-DNSRecordArray -Data $Data -DomainController $DomainController -Port $Port -Preference $Preference -Priority $Priority -SOASerialNumber $SOASerialNumber -TTL $TTL -Type $Type -Weight $Weight -Zone $Zone -Static
            }
            else
            {
                $DNSRecord = New-DNSRecordArray -Data $Data -DomainController $DomainController -Port $Port -Preference $Preference -Priority $Priority -SOASerialNumber $SOASerialNumber -TTL $TTL -Type $Type -Weight $Weight -Zone $Zone 
            }

            Write-Verbose "[+] DNSRecord = $([System.Bitconverter]::ToString($DNSRecord))"
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw    
        }

    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $directory_entry.InvokeSet('dnsRecord',$DNSRecord)
        $directory_entry.SetInfo()
        Write-Output "[+] ADIDNS node $Node enabled"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Get-ADIDNSNodeAttribute
{
    

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Attribute,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $output = $directory_entry.InvokeGet($Attribute)
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

function Get-ADIDNSNodeOwner
{
   

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $output = $directory_entry.PsBase.ObjectSecurity.Owner
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

function Get-ADIDNSNodeTombstoned
{
  
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $dnsTombstoned = $directory_entry.InvokeGet('dnsTombstoned')
        $dnsRecord = $directory_entry.InvokeGet('dnsRecord')
    }
    catch
    {

        if($_.Exception.Message -notlike '*Exception calling "InvokeGet" with "1" argument(s): "The specified directory service attribute or value does not exist.*' -and
        $_.Exception.Message -notlike '*The following exception occurred while retrieving member "InvokeGet": "The specified directory service attribute or value does not exist.*')
        {
            Write-Output "[-] $($_.Exception.Message)"
            $directory_entry.Close()
            throw
        }

    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    $node_tombstoned = $false

    if($dnsTombstoned -and $dnsRecord)
    {

        if($dnsRecord[0].GetType().name -eq [Byte])
        {

            if($dnsRecord.Count -ge 32 -and $dnsRecord[2] -eq 0)
            {
                $node_tombstoned = $true
            }

        }

    }

    return $node_tombstoned
}

function Get-ADIDNSPermission
{
   

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {

        if($Node)
        {

            if($Partition -eq 'System')
            {
                $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
            }
            else
            {
                $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
            }

        }
        else
        {

            if($Partition -eq 'System')
            {
                $distinguished_name = "DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
            }
            else
            {
                $distinguished_name = "DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
            }

        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $directory_entry_security = $directory_entry.psbase.ObjectSecurity
        $directory_entry_DACL = $directory_entry_security.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])
        $output=@()
        
        ForEach($ACE in $directory_entry_DACL)
        {
            $principal = ""
            $principal_distingushed_name = ""

            try
            {
                $principal = $ACE.IdentityReference.Translate([System.Security.Principal.NTAccount])
            }
            catch
            {
             
                if($ACE.IdentityReference.AccountDomainSid)
                {

                    if($Credential)
                    {
                        $directory_entry_principal = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/<SID=$($ACE.IdentityReference.Value)>",$Credential.UserName,$credential.GetNetworkCredential().Password)
                    }
                    else
                    {
                        $directory_entry_principal = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/<SID=$($ACE.IdentityReference.Value)>"
                    }

                    if($directory_entry_principal.Properties.userPrincipalname)
                    {
                        $principal = $directory_entry_principal.Properties.userPrincipalname.Value
                    }
                    else
                    {
                        $principal = $directory_entry_principal.Properties.sAMAccountName.Value
                        $principal_distingushed_name = $directory_entry_principal.distinguishedName.Value
                    }

                    if($directory_entry_principal.Path)
                    {
                        $directory_entry_principal.Close()
                    }

                }

            }
            
            $PS_object = New-Object PSObject
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "Principal" $principal

            if($principal_distingushed_name)
            {
                Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "DistinguishedName" $principal_distingushed_name
            }

            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "IdentityReference" $ACE.IdentityReference
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "ActiveDirectoryRights" $ACE.ActiveDirectoryRights
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "InheritanceType" $ACE.InheritanceType
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "ObjectType" $ACE.ObjectType
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "InheritedObjectType" $ACE.InheritedObjectType
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "ObjectFlags" $ACE.ObjectFlags
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "AccessControlType" $ACE.AccessControlType 
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "IsInherited" $ACE.IsInherited
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "InheritanceFlags" $ACE.InheritanceFlags
            Add-Member -InputObject $PS_object -MemberType NoteProperty -Name "PropagationFlags" $ACE.PropagationFlags
            $output += $PS_object
        }

    }
    catch
    {

        if($_.Exception.Message -notlike "*Some or all identity references could not be translated.*")
        {
            Write-Output "[-] $($_.Exception.Message)"
        }

    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

function Get-ADIDNSZone
{
   

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "",
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Partition)
    {

        if(!$DistinguishedName)
        {
            $partition_list = @("DomainDNSZones","ForestDNSZones","System")
        }
        else
        {
            $partition_array = $DistinguishedName.Split(",")
            $partition_list = @($partition_array[0].Substring(3))
        }

    }
    else
    {
        $partition_list = @($Partition)
    }

    ForEach($partition_entry in $partition_list)
    {
        Write-Verbose "[+] Partition = $partition_entry"

        if(!$DistinguishedName)
        {

            if($partition_entry -eq 'System')
            {
                $distinguished_name = "CN=$partition_entry"
            }
            else
            {
                $distinguished_name = "DC=$partition_entry"
            }

            $DC_array = $Domain.Split(".")

            ForEach($DC in $DC_array)
            {
                $distinguished_name += ",DC=$DC"
            }

            Write-Verbose "[+] Distinguished Name = $distinguished_name"
        }
        else
        {
            $distinguished_name = $DistinguishedName
        }

        if($Credential)
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
        }
        else
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
        }

        try
        {
            $directory_searcher = New-Object System.DirectoryServices.DirectorySearcher($directory_entry)
            
            if($Zone)
            {
                $directory_searcher.filter = "(&(objectClass=dnszone)(name=$Zone))"
            }
            else
            {
                $directory_searcher.filter = "(objectClass=dnszone)"
            }

            $search_results = $directory_searcher.FindAll()

            for($i=0; $i -lt $search_results.Count; $i++)
            {
                $output += $search_results.Item($i).Properties.distinguishedname
            }

        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
        }

        if($directory_entry.Path)
        {
            $directory_entry.Close()
        }

    }

    return $output
}

function Grant-ADIDNSPermission
{
   

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][ValidateSet("AccessSystemSecurity","CreateChild","Delete","DeleteChild",
        "DeleteTree","ExtendedRight","GenericAll","GenericExecute","GenericRead","GenericWrite","ListChildren",
        "ListObject","ReadControl","ReadProperty","Self","Synchronize","WriteDacl","WriteOwner","WriteProperty")][Array]$Access = "GenericAll",
        [parameter(Mandatory=$false)][ValidateSet("Allow","Deny")][String]$Type = "Allow",    
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Principal,
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {

        if($Node)
        {

            if($Partition -eq 'System')
            {
                $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
            }
            else
            {
                $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
            }

        }
        else
        {

            if($Partition -eq 'System')
            {
                $distinguished_name = "DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
            }
            else
            {
                $distinguished_name = "DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
            }

        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $NT_account = New-Object System.Security.Principal.NTAccount($Principal)
        $principal_SID = $NT_account.Translate([System.Security.Principal.SecurityIdentifier])
        $principal_identity = [System.Security.Principal.IdentityReference]$principal_SID
        $AD_rights = [System.DirectoryServices.ActiveDirectoryRights]$Access
        $access_control_type = [System.Security.AccessControl.AccessControlType]$Type
        $AD_security_inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($principal_identity,$AD_rights,$access_control_type,$AD_security_inheritance)
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
        throw
    }

    try
    {
        $directory_entry.psbase.ObjectSecurity.AddAccessRule($ACE)
        $directory_entry.psbase.CommitChanges()

        if($Node)
        {
            Write-Output "[+] ACE added for $Principal to $Node DACL"
        }
        else
        {
            Write-Output "[+] ACE added for $Principal to $Zone DACL"
        }

    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

function New-ADIDNSNode
{
   

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$Data,
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Forest,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]$Type = "A",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][Byte[]]$DNSRecord,
        [parameter(Mandatory=$false)][Int]$Preference,
        [parameter(Mandatory=$false)][Int]$Priority,
        [parameter(Mandatory=$false)][Int]$Weight,
        [parameter(Mandatory=$false)][Int]$Port,
        [parameter(Mandatory=$false)][Int]$TTL = 600,
        [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
        [parameter(Mandatory=$false)][Switch]$Static,
        [parameter(Mandatory=$false)][Switch]$Tombstone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    $null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")

    if(!$DomainController -or !$Domain -or !$Zone -or !$Forest)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Forest)
    {
        $Forest = $current_domain.Forest
        Write-Verbose "[+] Forest = $Forest"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if(!$DNSRecord)
    {

        try 
        {

            if($Static)
            {
                $DNSRecord = New-DNSRecordArray -Data $Data -DomainController $DomainController -Port $Port -Preference $Preference -Priority $Priority -SOASerialNumber $SOASerialNumber -TTL $TTL -Type $Type -Weight $Weight -Zone $Zone -Static
            }
            else
            {
                $DNSRecord = New-DNSRecordArray -Data $Data -DomainController $DomainController -Port $Port -Preference $Preference -Priority $Priority -SOASerialNumber $SOASerialNumber -TTL $TTL -Type $Type -Weight $Weight -Zone $Zone 
            }
            
            Write-Verbose "[+] DNSRecord = $([System.Bitconverter]::ToString($DNSRecord))"
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw    
        }

    }

    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DomainController,389)

    if($Credential)
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier,$Credential.GetNetworkCredential())
    }
    else
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
    }

    $object_category = "CN=Dns-Node,CN=Schema,CN=Configuration"
    $forest_array = $Forest.Split(".")

    ForEach($DC in $forest_array)
    {
        $object_category += ",DC=$DC"
    }
    
    try
    {
        $connection.SessionOptions.Sealing = $true
        $connection.SessionOptions.Signing = $true
        $connection.Bind()
        $request = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest
        $request.DistinguishedName = $distinguished_name
        $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass",@("top","dnsNode"))) > $null
        $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectCategory",$object_category)) > $null
        $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "dnsRecord",$DNSRecord)) > $null

        if($Tombstone)
        {
            $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "dNSTombstoned","TRUE")) > $null
        }
        
        $connection.SendRequest($request) > $null
        Write-Output "[+] ADIDNS node $Node added"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

}

function New-SOASerialNumberArray
{
    

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][Int]$Increment = 1,
        [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$SOASerialNumber)
    {

        if(!$DomainController -or !$Zone)
        {

            try
            {
                $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch
            {
                Write-Output "[-] $($_.Exception.Message)"
                throw
            }

        }

        if(!$DomainController)
        {
            $DomainController = $current_domain.PdcRoleOwner.Name
            Write-Verbose "[+] Domain Controller = $DomainController"
        }

        if(!$Domain)
        {
            $Domain = $current_domain.Name
            Write-Verbose "[+] Domain = $Domain"
        }

        if(!$Zone)
        {
            $Zone = $current_domain.Name
            Write-Verbose "[+] ADIDNS Zone = $Zone"
        }

        $Zone = $Zone.ToLower()

        function Convert-DataToUInt16($Field)
        {
            [Array]::Reverse($Field)
            return [System.BitConverter]::ToUInt16($Field,0)
        }

        function ConvertFrom-PacketOrderedDictionary($OrderedDictionary)
        {

            ForEach($field in $OrderedDictionary.Values)
            {
                $byte_array += $field
            }

            return $byte_array
        }

        function New-RandomByteArray
        {
            param([Int]$Length,[Int]$Minimum=1,[Int]$Maximum=255)

            [String]$random = [String](1..$Length | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum $Minimum -Maximum $Maximum)})
            [Byte[]]$random = $random.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

            return $random
        }

        function New-DNSNameArray
        {
            param([String]$Name)

            $character_array = $Name.ToCharArray()
            [Array]$index_array = 0..($character_array.Count - 1) | Where-Object {$character_array[$_] -eq '.'}

            if($index_array.Count -gt 0)
            {

                $name_start = 0

                ForEach ($index in $index_array)
                {
                    $name_end = $index - $name_start
                    [Byte[]]$name_array += $name_end
                    [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start,$name_end))
                    $name_start = $index + 1
                }

                [Byte[]]$name_array += ($Name.Length - $name_start)
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }
            else
            {
                [Byte[]]$name_array = $Name.Length
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
            }

            return $name_array
        }

        function New-PacketDNSSOAQuery
        {
            param([String]$Name)

            [Byte[]]$type = 0x00,0x06
            [Byte[]]$name = (New-DNSNameArray $Name) + 0x00
            [Byte[]]$length = [System.BitConverter]::GetBytes($Name.Count + 16)[1,0]
            [Byte[]]$transaction_ID = New-RandomByteArray 2
            $DNSQuery = New-Object System.Collections.Specialized.OrderedDictionary
            $DNSQuery.Add("Length",$length)
            $DNSQuery.Add("TransactionID",$transaction_ID)
            $DNSQuery.Add("Flags",[Byte[]](0x01,0x00))
            $DNSQuery.Add("Questions",[Byte[]](0x00,0x01))
            $DNSQuery.Add("AnswerRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("AuthorityRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("AdditionalRRs",[Byte[]](0x00,0x00))
            $DNSQuery.Add("Queries_Name",$name)
            $DNSQuery.Add("Queries_Type",$type)
            $DNSQuery.Add("Queries_Class",[Byte[]](0x00,0x01))

            return $DNSQuery
        }

        $DNS_client = New-Object System.Net.Sockets.TCPClient
        $DNS_client.Client.ReceiveTimeout = 3000

        try
        {
            $DNS_client.Connect($DomainController,"53")
            $DNS_client_stream = $DNS_client.GetStream()
            $DNS_client_receive = New-Object System.Byte[] 2048
            $packet_DNSQuery = New-PacketDNSSOAQuery $Zone
            [Byte[]]$DNS_client_send = ConvertFrom-PacketOrderedDictionary $packet_DNSQuery
            $DNS_client_stream.Write($DNS_client_send,0,$DNS_client_send.Length) > $null
            $DNS_client_stream.Flush()   
            $DNS_client_stream.Read($DNS_client_receive,0,$DNS_client_receive.Length) > $null
            $DNS_client.Close()
            $DNS_client_stream.Close()

            if($DNS_client_receive[9] -eq 0)
            {
                Write-Output "[-] $Zone SOA record not found"
            }
            else
            {
                $DNS_reply_converted = [System.BitConverter]::ToString($DNS_client_receive)
                $DNS_reply_converted = $DNS_reply_converted -replace "-",""
                $SOA_answer_index = $DNS_reply_converted.IndexOf("C00C00060001")
                $SOA_answer_index = $SOA_answer_index / 2
                $SOA_length = $DNS_client_receive[($SOA_answer_index + 10)..($SOA_answer_index + 11)]
                $SOA_length = Convert-DataToUInt16 $SOA_length
                [Byte[]]$SOA_serial_current_array = $DNS_client_receive[($SOA_answer_index + $SOA_length - 8)..($SOA_answer_index + $SOA_length - 5)]
                $SOA_serial_current = [System.BitConverter]::ToUInt32($SOA_serial_current_array[3..0],0) + $Increment
                [Byte[]]$SOA_serial_number_array = [System.BitConverter]::GetBytes($SOA_serial_current)[0..3]
            }

        }
        catch
        {
            Write-Output "[-] $DomainController did not respond on TCP port 53"
        }

    }
    else
    {
        [Byte[]]$SOA_serial_number_array = [System.BitConverter]::GetBytes($SOASerialNumber + $Increment)[0..3]
    }

    return ,$SOA_serial_number_array
}

function New-DNSRecordArray
{
    
    [CmdletBinding()]
    [OutputType([Byte[]])]
    param
    (
        [parameter(Mandatory=$false)][String]$Data,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]$Type = "A",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][Int]$Preference,
        [parameter(Mandatory=$false)][Int]$Priority,
        [parameter(Mandatory=$false)][Int]$Weight,
        [parameter(Mandatory=$false)][Int]$Port,
        [parameter(Mandatory=$false)][Int]$TTL = 600,
        [parameter(Mandatory=$false)][Int32]$SOASerialNumber,
        [parameter(Mandatory=$false)][Switch]$Static,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$Data -and $Type -eq 'A')
    {

        try
        {
            $Data = (Test-Connection 127.0.0.1 -count 1 | Select-Object -ExpandProperty Ipv4Address)
            Write-Verbose "[+] Data = $Data"
        }
        catch
        {
            Write-Output "[-] Error finding local IP, specify manually with -Data"
            throw
        }

    }
    elseif(!$Data)
    {
        Write-Output "[-] -Data required with record type $Type"
        throw
    }

    try
    {
        $SOASerialNumberArray = New-SOASerialNumberArray -DomainController $DomainController -Zone $Zone -SOASerialNumber $SOASerialNumber
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
        throw
    }

    function New-DNSNameArray
    {
        param([String]$Name)

        $character_array = $Name.ToCharArray()
        [Array]$index_array = 0..($character_array.Count - 1) | Where-Object {$character_array[$_] -eq '.'}

        if($index_array.Count -gt 0)
        {

            $name_start = 0

            ForEach ($index in $index_array)
            {
                $name_end = $index - $name_start
                [Byte[]]$name_array += $name_end
                [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start,$name_end))
                $name_start = $index + 1
            }

            [Byte[]]$name_array += ($Name.Length - $name_start)
            [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
        }
        else
        {
            [Byte[]]$name_array = $Name.Length
            [Byte[]]$name_array += [System.Text.Encoding]::UTF8.GetBytes($Name.Substring($name_start))
        }

        return $name_array
    }

    switch ($Type)
    {

        'A'
        {
            [Byte[]]$DNS_type = 0x01,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes(($Data.Split(".")).Count))[0..1]
            [Byte[]]$DNS_data += ([System.Net.IPAddress][String]([System.Net.IPAddress]$Data)).GetAddressBytes()
        }

        'AAAA'
        {
            [Byte[]]$DNS_type = 0x1c,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes(($Data -replace ":","").Length / 2))[0..1]
            [Byte[]]$DNS_data += ([System.Net.IPAddress][String]([System.Net.IPAddress]$Data)).GetAddressBytes()
        }
        
        'CNAME'
        {
            [Byte[]]$DNS_type = 0x05,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 4))[0..1]
            [Byte[]]$DNS_data = $Data.Length + 2
            $DNS_data += ($Data.Split(".")).Count
            $DNS_data += New-DNSNameArray $Data
            $DNS_data += 0x00
        }

        'DNAME'
        {
            [Byte[]]$DNS_type = 0x27,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 4))[0..1]
            [Byte[]]$DNS_data = $Data.Length + 2
            $DNS_data += ($Data.Split(".")).Count
            $DNS_data += New-DNSNameArray $Data
            $DNS_data += 0x00
        }
        
        'MX'
        {
            [Byte[]]$DNS_type = 0x0f,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 6))[0..1]
            [Byte[]]$DNS_data = [System.Bitconverter]::GetBytes($Preference)[1,0]
            $DNS_data += $Data.Length + 2
            $DNS_data += ($Data.Split(".")).Count
            $DNS_data += New-DNSNameArray $Data
            $DNS_data += 0x00
        }

        'NS'
        {
            [Byte[]]$DNS_type = 0x02,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 4))[0..1]
            [Byte[]]$DNS_data = $Data.Length + 2
            $DNS_data += ($Data.Split(".")).Count
            $DNS_data += New-DNSNameArray $Data
            $DNS_data += 0x00
        }

        'PTR'
        {
            [Byte[]]$DNS_type = 0x0c,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 4))[0..1]
            [Byte[]]$DNS_data = $Data.Length + 2
            $DNS_data += ($Data.Split(".")).Count
            $DNS_data += New-DNSNameArray $Data
            $DNS_data += 0x00
        }

        'SRV'
        {
            [Byte[]]$DNS_type = 0x21,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 10))[0..1]
            [Byte[]]$DNS_data = [System.Bitconverter]::GetBytes($Priority)[1,0]
            $DNS_data += [System.Bitconverter]::GetBytes($Weight)[1,0]
            $DNS_data += [System.Bitconverter]::GetBytes($Port)[1,0]
            $DNS_data += $Data.Length + 2
            $DNS_data += ($Data.Split(".")).Count
            $DNS_data += New-DNSNameArray $Data
            $DNS_data += 0x00
        }

        'TXT'
        {
            [Byte[]]$DNS_type = 0x10,0x00
            [Byte[]]$DNS_length = ([System.BitConverter]::GetBytes($Data.Length + 1))[0..1]
            [Byte[]]$DNS_data = $Data.Length
            $DNS_data += [System.Text.Encoding]::UTF8.GetBytes($Data)
        }

    }
    
    [Byte[]]$DNS_TTL = [System.BitConverter]::GetBytes($TTL)
    [Byte[]]$DNS_record = $DNS_length +
        $DNS_type +
        0x05,0xF0,0x00,0x00 +
        $SOASerialNumberArray[0..3] +
        $DNS_TTL[3..0] +
        0x00,0x00,0x00,0x00

    if($Static)
    {
        $DNS_record += 0x00,0x00,0x00,0x00
    }
    else
    {
        $timestamp = [Int64](([Datetime]::UtcNow)-(Get-Date "1/1/1601")).TotalHours
        $timestamp = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($timestamp))
        $timestamp = $timestamp.Split("-") | ForEach-Object{[System.Convert]::ToInt16($_,16)}
        $timestamp = $timestamp[0..3]
        $DNS_record += $timestamp
    }
    
    $DNS_record += $DNS_data

    return ,$DNS_record
}

function Rename-ADIDNSNode
{
   
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][String]$NodeNew = "*",
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName 
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $directory_entry.Rename("DC=$NodeNew")
        Write-Output "[+] ADIDNS node $Node renamed to $NodeNew"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Remove-ADIDNSNode
{
   

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName 
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $directory_entry.psbase.DeleteTree()
        Write-Output "[+] ADIDNS node $Node removed"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Revoke-ADIDNSPermission
{
   
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][ValidateSet("AccessSystemSecurity","CreateChild","Delete","DeleteChild",
        "DeleteTree","ExtendedRight","GenericAll","GenericExecute","GenericRead","GenericWrite","ListChildren",
        "ListObject","ReadControl","ReadProperty","Self","Synchronize","WriteDacl","WriteOwner","WriteProperty")][Array]$Access = "GenericAll",
        [parameter(Mandatory=$false)][ValidateSet("Allow","Deny")][String]$Type = "Allow",    
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$false)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Principal,
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {

        if($Node)
        {

            if($Partition -eq 'System')
            {
                $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
            }
            else
            {
                $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
            }

        }
        else
        {

            if($Partition -eq 'System')
            {
                $distinguished_name = "DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
            }
            else
            {
                $distinguished_name = "DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
            }

        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = $DistinguishedName 
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $NT_account = New-Object System.Security.Principal.NTAccount($Principal)
        $principal_SID = $NT_account.Translate([System.Security.Principal.SecurityIdentifier])
        $principal_identity = [System.Security.Principal.IdentityReference]$principal_SID
        $AD_rights = [System.DirectoryServices.ActiveDirectoryRights]$Access
        $access_control_type = [System.Security.AccessControl.AccessControlType]$Type
        $AD_security_inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($principal_identity,$AD_rights,$access_control_type,$AD_security_inheritance)
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
        throw
    }

    try
    {
        $directory_entry.psbase.ObjectSecurity.RemoveAccessRule($ACE) > $null
        $directory_entry.psbase.CommitChanges()
        Write-Output "[+] ACE removed for $Principal"
    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

function Set-ADIDNSNodeAttribute
{
   

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Attribute,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$true)]$Value,
        [parameter(Mandatory=$false)][Switch]$Append,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
        
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {

        if($Append)
        {
            $directory_entry.$Attribute.Add($Value) > $null
            $directory_entry.SetInfo()
            Write-Output "[+] ADIDNS node $Node $attribute attribute appended"
        }
        else
        {
            $directory_entry.InvokeSet($Attribute,$Value)
            $directory_entry.SetInfo()
            Write-Output "[+] ADIDNS node $Node $attribute attribute updated"
        }

    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

}

function Set-ADIDNSNodeOwner
{
   
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$Node,
        [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$Partition = "DomainDNSZones",
        [parameter(Mandatory=$true)][String]$Principal,
        [parameter(Mandatory=$false)][String]$Zone,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Output "[-] $($invalid_parameter) is not a valid parameter"
        throw
    }

    if(!$DomainController -or !$Domain -or !$Zone)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            Write-Output "[-] $($_.Exception.Message)"
            throw
        }

    }

    if(!$DomainController)
    {
        $DomainController = $current_domain.PdcRoleOwner.Name
        Write-Verbose "[+] Domain Controller = $DomainController"
    }

    if(!$Domain)
    {
        $Domain = $current_domain.Name
        Write-Verbose "[+] Domain = $Domain"
    }

    if(!$Zone)
    {
        $Zone = $current_domain.Name
        Write-Verbose "[+] ADIDNS Zone = $Zone"
    }

    if(!$DistinguishedName)
    {
       
        if($Partition -eq 'System')
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,CN=$Partition"
        }
        else
        {
            $distinguished_name = "DC=$Node,DC=$Zone,CN=MicrosoftDNS,DC=$Partition"
        }

        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

        Write-Verbose "[+] Distinguished Name = $distinguished_name"
    }
    else 
    {
        $distinguished_name = "DC=$Node," + $DistinguishedName
    }

    if($Credential)
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$Credential.GetNetworkCredential().Password)
    }
    else
    {
        $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $account = New-Object System.Security.Principal.NTAccount($Principal)
        $directory_entry.PsBase.ObjectSecurity.setowner($account)
        $directory_entry.PsBase.CommitChanges()

    }
    catch
    {
        Write-Output "[-] $($_.Exception.Message)"
    }

    if($directory_entry.Path)
    {
        $directory_entry.Close()
    }

    return $output
}

#endregion

#region begin Miscellaneous Functions

function Get-KerberosAESKey
{
   

    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$true)][String]$Salt,
        [parameter(Mandatory=$false)][System.Security.SecureString]$Password,
        [parameter(Mandatory=$false)][ValidateSet("AES","AES128","AES256","AES128ByteArray","AES256ByteArray")][String]$OutputType = "AES",
        [parameter(Mandatory=$false)][Int]$Iteration=4096
    )
    
    if(!$Password)
    {
        $password = Read-Host -Prompt "Enter password" -AsSecureString
    }

    $password_BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $password_cleartext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($password_BSTR)
    
    [Byte[]]$password_bytes = [System.Text.Encoding]::UTF8.GetBytes($password_cleartext)
    [Byte[]]$salt_bytes = [System.Text.Encoding]::UTF8.GetBytes($Salt)
    $AES256_constant = 0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4
    $AES128_constant = 0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93
    $IV = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 
    $PBKDF2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($password_bytes,$salt_bytes,$iteration)
    $PBKDF2_AES256_key = $PBKDF2.GetBytes(32)
    $PBKDF2_AES128_key = $PBKDF2_AES256_key[0..15]
    $PBKDF2_AES256_key_string = ([System.BitConverter]::ToString($PBKDF2_AES256_key)) -replace "-",""
    $PBKDF2_AES128_key_string = ([System.BitConverter]::ToString($PBKDF2_AES128_key)) -replace "-",""
    Write-Verbose "PBKDF2 AES128 Key: $PBKDF2_AES128_key_string"
    Write-Verbose "PBKDF2 AES256 Key: $PBKDF2_AES256_key_string"
    $AES = New-Object "System.Security.Cryptography.AesManaged"
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AES.Padding = [System.Security.Cryptography.PaddingMode]::None
    $AES.IV = $IV
    # AES 256
    $AES.KeySize = 256
    $AES.Key = $PBKDF2_AES256_key
    $AES_encryptor = $AES.CreateEncryptor()
    $AES256_key_part_1 = $AES_encryptor.TransformFinalBlock($AES256_constant,0,$AES256_constant.Length)
    $AES256_key_part_2 = $AES_encryptor.TransformFinalBlock($AES256_key_part_1,0,$AES256_key_part_1.Length)
    $AES256_key = $AES256_key_part_1[0..15] + $AES256_key_part_2[0..15]
    $AES256_key_string = ([System.BitConverter]::ToString($AES256_key)) -replace "-",""    
    # AES 128
    $AES.KeySize = 128
    $AES.Key = $PBKDF2_AES128_key
    $AES_encryptor = $AES.CreateEncryptor()
    $AES128_key = $AES_encryptor.TransformFinalBlock($AES128_constant,0,$AES128_constant.Length)
    $AES128_key_string = ([System.BitConverter]::ToString($AES128_key)) -replace "-",""
    Remove-Variable password_cleartext
    
    switch($OutputType)
    {
    
        'AES'
        {
            Write-Output "AES128 Key: $AES128_key_string"
            Write-Output "AES256 Key: $AES256_key_string"
        }
        
        'AES128'
        {
            Write-Output "$AES128_key_string"
        }
        
        'AES256'
        {
            Write-Output "$AES256_key_string"
        }
        
        'AES128ByteArray'
        {
            Write-Output $AES128_key
        }
        
        'AES256ByteArray'
        {
            Write-Output $AES256_key
        }
        
    }
    
}

#endregion
