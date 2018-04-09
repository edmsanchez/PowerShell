function Get-ESXiAccount {
    <#
     .SYNOPSIS
       Get ESXi 6.x local account
     .DESCRIPTION
       List all local ESXi 6.x account(s) and their role
     .NOTES
       Author: Edgar Sanchez - @edmsanchez13
     .Link
       https://github.com/edmsanchez/PowerShell
       https://virtualcornerstone.com/
     .INPUTS
       No inputs required
     .OUTPUTS
       To Screen
     .PARAMETER VMhost
       The name(s) of the vSphere ESXi Host(s)
     .EXAMPLE
       Get-ESXiAccount -VMhost devvm001.lab.local
     .PARAMETER Cluster
       The name(s) of the vSphere Cluster(s)
     .EXAMPLE
       Get-ESXiAccount -Cluster production-cluster
     .PARAMETER Datacenter
       The name(s) of the vSphere Virtual Datacenter(s).
     .EXAMPLE
       Get-ESXiAccount -Datacenter vDC001
    #> 
    
    <#
     ----------------------------------------------------------[Declarations]----------------------------------------------------------
    #>
  
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]$VMhost,
        [Parameter(Mandatory = $false)]$Cluster,
        [Parameter(Mandatory = $false)]$Datacenter
    )
    
    $skipCollection = @()
    $outputCollection = @()
    $vHostList = @()
    $date = Get-Date -format s
    $date = $date -replace ":", "-"
    
    <#
     ----------------------------------------------------------[Execution]----------------------------------------------------------
    #>
  
    <#
      Query PowerCLI version if
      running Verbose
    #>
    if ($VerbosePreference -eq "continue") {
        Write-Verbose -Message ((Get-Date -Format G) + "`tPowerCLI Version:")
        Get-Module -Name VMware.* | Select-Object -Property Name, Version | Format-Table -AutoSize
    } #END if
    
    <#
      Validate if a parameter was specified (-VMhost, -Cluster, or -Datacenter)
      Although all 3 can be specified, only the first one is used
      Example: -VMhost "host001" -Cluster "test-cluster". -VMhost is the first parameter
      and what will be used.
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tValidate parameters used")
    if ([string]::IsNullOrWhiteSpace($VMhost) -and [string]::IsNullOrWhiteSpace($Cluster) -and [string]::IsNullOrWhiteSpace($Datacenter)) {
        Write-Error -Message "You must specify a parameter (-VMhost, -Cluster, or -Datacenter)."
        break
    } #END if

    <#
      Check for an active connection to a VIServer
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tValidate connection to a vSphere server")
    if ($Global:DefaultViServers.Count -gt 0) {
        Write-Host "`tConnected to $Global:DefaultViServers" -ForegroundColor Green
    }
    else {
        Write-Error -Message "You must be connected to a vSphere server before running this Cmdlet."
        break
    } #END if/else
    
    <#
      Gather host list based on parameter used
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tGather host list")
    if ([string]::IsNullOrWhiteSpace($VMhost)) {      
        Write-Verbose -Message ((Get-Date -Format G) + "`t-VMhost parameter is Null or Empty")
        if ([string]::IsNullOrWhiteSpace($Cluster)) {
            Write-Verbose -Message ((Get-Date -Format G) + "`t-Cluster parameter is Null or Empty")
            if ([string]::IsNullOrWhiteSpace($Datacenter)) {
                Write-Verbose -Message ((Get-Date -Format G) + "`t-Datacenter parameter is Null or Empty")
            }
            else {
                Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using Datacenter parameter")
                Write-Host "`tGathering host list from the following DataCenter(s): " (@($Datacenter) -join ',')
                foreach ($vDCname in $Datacenter) {
                    $tempList = Get-Datacenter -Name $vDCname.Trim() -ErrorAction SilentlyContinue | Get-VMHost 
                    if ($tempList) {
                        $vHostList += $tempList | Sort-Object -Property Name
                    }
                    else {
                        Write-Warning -Message "`tDatacenter with name $vDCname was not found in $Global:DefaultViServers"
                    } #END if/else
                } #END foreach
            } #END if/else
        }
        else {
            Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using cluster parameter")
            Write-Host "`tGathering host list from the following Cluster(s): " (@($cluster) -join ',')
            foreach ($vClusterName in $Cluster) {
                $tempList = Get-Cluster -Name $vClusterName.Trim() -ErrorAction SilentlyContinue | Get-VMHost 
                if ($tempList) {
                    $vHostList += $tempList | Sort-Object -Property Name
                }
                else {
                    Write-Warning -Message "`tCluster with name $vClusterName was not found in $Global:DefaultViServers"
                } #END if/else
            } #END foreach
        } #END if/else
    }
    else { 
        Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using VMhost parameter")
        Write-Host "`tGathering host list..."
        foreach ($invidualHost in $VMhost) {
            $tempList = Get-VMHost -Name $invidualHost.Trim() -ErrorAction SilentlyContinue
            if ($tempList) {
                $vHostList += $tempList | Sort-Object -Property Name
            }
            else {
                Write-Warning -Message "`tESXi host $invidualHost was not found in $Global:DefaultViServers"
            } #END if/else
        } #END foreach
    } #END if/else
    $tempList = $null

    <#
      Main code execution
    #>
    foreach ($vmhost in $vHostList) {
    
        <#
          Skip if ESXi host is not in a Connected
          or Maintenance ConnectionState
        #>
        Write-Verbose -Message ((Get-Date -Format G) + "`t$vmhost Connection State: " + $vmhost.ConnectionState)
        if ($vmhost.ConnectionState -eq "Connected" -or $vmhost.ConnectionState -eq "Maintenance") {
            <#
              Do nothing - ESXi host is reachable
            #>
        }
        else {
            <#
              Use a custom object to keep track of skipped
              hosts and continue to the next foreach loop
            #>
            $skipCollection += [pscustomobject]@{
                'Hostname'         = $vmhost.Name
                'Connection State' = $vmhost.ConnectionState
            } #END [PSCustomObject]
            continue
        } #END if/else
    
        <#
         Validate ESXi Version
         Will run only of 6.x
        #>
        if ($vmhost.ApiVersion -notmatch '6.') {
            Write-Warning -Message ("`t$vmhost is ESXi v" + $vmhost.ApiVersion + ". Skipping host.")
            continue
        }

        <#
          Get list of local accounts
        #>
        Write-Host "`tGathering local accounts from $vmhost ..."
        $esxcli = Get-EsxCli -VMHost $vmhost -V2
        $localAccounts = $esxcli.system.account.list.Invoke()
        $systemPermission = $esxcli.system.permission.list.Invoke()
        foreach ($account in $localAccounts) {
            $accountRole = $systemPermission | Where-Object {$_.Principal -eq $account.UserID} | Select-Object -ExpandProperty Role

            <#
              Use a custom object to store
              collected data
            #>
            $outputCollection += [PSCustomObject]@{
                'Hostname'    = $vmhost.Name
                'UserID'      = $account.UserID
                'Role'        = $accountRole
                'Description' = $account.Description
            } #END [PSCustomObject]
        } #END foreach
    } #END foreach
    
    <#
      Display skipped hosts and their connection status
    #>
    If ($skipCollection) {
        Write-Warning -Message "`tCheck Connection State or Host name"
        Write-Warning -Message "`tSkipped hosts:"
        $skipCollection | Format-Table -AutoSize
    } #END if
    
    <#
      Validate output arrays
    #>
    if ($outputCollection) {
        Write-Verbose -Message ((Get-Date -Format G) + "`tInformation gathered")
        Write-Host "`nESXi Local Accounts:" -ForegroundColor Green
        $outputCollection | Format-Table -Wrap
    }
    else {
        Write-Verbose -Message ((Get-Date -Format G) + "`tNo information gathered")
    } #END if/else
} #END function

function Add-ESXiAccount {
    <#
     .SYNOPSIS
       Add ESXi 6.x local account
     .DESCRIPTION
       Create local ESXi 6.x account
     .NOTES
       Author: Edgar Sanchez - @edmsanchez13
     .Link
       https://github.com/edmsanchez/PowerShell
       https://virtualcornerstone.com/
     .INPUTS
       No inputs required
     .OUTPUTS
       To Screen
     .PARAMETER Name
      User ID to add
     .Example
       Add-ESXiAccount -Name "testuser"
     .PARAMETER Description
       User ID Description to add
     .EXAMPLE
       Add-ESXiAccount -Name "testuser" -Description "Local test User"
     .PARAMETER Permission
       Permission to assign the new User ID (Admin,ReadOnly,NoAccess)
     .Example
       Add-ESXiAccount -Name "testuser" -Description "Local test User" -Permission "Admin"
     .PARAMETER VMhost
       The name(s) of the vSphere ESXi Host(s)
     .EXAMPLE
       Add-ESXiAccount -Name "testuser" -Description "Local test User" -Permission "Admin" -VMhost devvm001.lab.local
     .PARAMETER Cluster
       The name(s) of the vSphere Cluster(s)
     .EXAMPLE
       Add-ESXiAccount -Name "testuser" -Description "Local test User" -Permission "Admin" -Cluster production-cluster
     .PARAMETER Datacenter
       The name(s) of the vSphere Virtual Datacenter(s).
     .EXAMPLE
       Add-ESXiAccount -Name "testuser" -Description "Local test User" -Permission "Admin" -Datacenter vDC001
    #> 
    
    <#
     ----------------------------------------------------------[Declarations]----------------------------------------------------------
    #>
  
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][String]$Name,
        [Parameter(Mandatory = $false)][String]$Description,
        [Parameter(Mandatory = $false)][ValidateSet("Admin", "ReadOnly", "NoAccess")]$Permission,
        [Parameter(Mandatory = $false)]$VMhost,
        [Parameter(Mandatory = $false)]$Cluster,
        [Parameter(Mandatory = $false)]$Datacenter
    )
    
    $skipCollection = @()
    $outputCollection = @()
    $vHostList = @()
    $date = Get-Date -format s
    $date = $date -replace ":", "-"
    
    <#
     ----------------------------------------------------------[Execution]----------------------------------------------------------
    #>
  
    <#
      Query PowerCLI version if
      running Verbose
    #>
    if ($VerbosePreference -eq "continue") {
        Write-Verbose -Message ((Get-Date -Format G) + "`tPowerCLI Version:")
        Get-Module -Name VMware.* | Select-Object -Property Name, Version | Format-Table -AutoSize
    } #END if
    
    <#
      Validate if a parameter was specified (-VMhost, -Cluster, or -Datacenter)
      Although all 3 can be specified, only the first one is used
      Example: -VMhost "host001" -Cluster "test-cluster". -VMhost is the first parameter
      and what will be used.
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tValidate parameters used")
    if ([string]::IsNullOrWhiteSpace($VMhost) -and [string]::IsNullOrWhiteSpace($Cluster) -and [string]::IsNullOrWhiteSpace($Datacenter)) {
        Write-Error -Message "You must specify a parameter (-VMhost, -Cluster, or -Datacenter)."
        break
    } #END if

    <#
      Check for an active connection to a VIServer
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tValidate connection to a vSphere server")
    if ($Global:DefaultViServers.Count -gt 0) {
        Write-Host "`tConnected to $Global:DefaultViServers" -ForegroundColor Green
    }
    else {
        Write-Error -Message "You must be connected to a vSphere server before running this Cmdlet."
        break
    } #END if/else
    
    <#
      Gather host list based on parameter used
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tGather host list")
    if ([string]::IsNullOrWhiteSpace($VMhost)) {      
        Write-Verbose -Message ((Get-Date -Format G) + "`t-VMhost parameter is Null or Empty")
        if ([string]::IsNullOrWhiteSpace($Cluster)) {
            Write-Verbose -Message ((Get-Date -Format G) + "`t-Cluster parameter is Null or Empty")
            if ([string]::IsNullOrWhiteSpace($Datacenter)) {
                Write-Verbose -Message ((Get-Date -Format G) + "`t-Datacenter parameter is Null or Empty")
            }
            else {
                Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using Datacenter parameter")
                Write-Host "`tGathering host list from the following DataCenter(s): " (@($Datacenter) -join ',')
                foreach ($vDCname in $Datacenter) {
                    $tempList = Get-Datacenter -Name $vDCname.Trim() -ErrorAction SilentlyContinue | Get-VMHost 
                    if ($tempList) {
                        $vHostList += $tempList | Sort-Object -Property Name
                    }
                    else {
                        Write-Warning -Message "`tDatacenter with name $vDCname was not found in $Global:DefaultViServers"
                    } #END if/else
                } #END foreach
            } #END if/else
        }
        else {
            Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using cluster parameter")
            Write-Host "`tGathering host list from the following Cluster(s): " (@($cluster) -join ',')
            foreach ($vClusterName in $Cluster) {
                $tempList = Get-Cluster -Name $vClusterName.Trim() -ErrorAction SilentlyContinue | Get-VMHost 
                if ($tempList) {
                    $vHostList += $tempList | Sort-Object -Property Name
                }
                else {
                    Write-Warning -Message "`tCluster with name $vClusterName was not found in $Global:DefaultViServers"
                } #END if/else
            } #END foreach
        } #END if/else
    }
    else { 
        Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using VMhost parameter")
        Write-Host "`tGathering host list..."
        foreach ($invidualHost in $VMhost) {
            $tempList = Get-VMHost -Name $invidualHost.Trim() -ErrorAction SilentlyContinue
            if ($tempList) {
                $vHostList += $tempList | Sort-Object -Property Name
            }
            else {
                Write-Warning -Message "`tESXi host $invidualHost was not found in $Global:DefaultViServers"
            } #END if/else
        } #END foreach
    } #END if/else
    $tempList = $null

    <#
      Main code execution
    #>
    $credentials = $null
    foreach ($vmhost in $vHostList) {
    
        <#
          Skip if ESXi host is not in a Connected
          or Maintenance ConnectionState
        #>
        Write-Verbose -Message ((Get-Date -Format G) + "`t$vmhost Connection State: " + $vmhost.ConnectionState)
        if ($vmhost.ConnectionState -eq "Connected" -or $vmhost.ConnectionState -eq "Maintenance") {
            <#
              Do nothing - ESXi host is reachable
            #>
        }
        else {
            <#
              Use a custom object to keep track of skipped
              hosts and continue to the next foreach loop
            #>
            $skipCollection += [pscustomobject]@{
                'Hostname'         = $vmhost.Name
                'Connection State' = $vmhost.ConnectionState
            } #END [PSCustomObject]
            continue
        } #END if/else
    
        <#
         Validate ESXi Version
         Will run only of 6.x
        #>
        if ($vmhost.ApiVersion -notmatch '6.') {
            Write-Warning -Message ("`t$vmhost is ESXi v" + $vmhost.ApiVersion + ". Skipping host.")
            continue
        }

        <#
          Validate that Account to add does not exist
        #>
        $esxcli = Get-EsxCli -VMHost $vmhost -V2
        Write-Verbose -Message ((Get-Date -Format G) + "`tValidating if $Name User ID exists on $vmhost...")
        if ($esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq $Name}) {
            Write-Warning -Message "`t$Name User ID already exists on $vmhost. Skipping host."
            continue
        } #END if

        <#
          Add ESXi Local Account
        #>
        if ($credentials) {
            <#
              Do nothing - Credentials already Gathered
            #>
        }
        else {
            Write-Verbose -Message ((Get-Date -Format G) + "`tPrompt for $Name password...")
            $credentials = Get-Credential -UserName $Name -Message "Enter Password for UserID: $Name"    
        } #END if/else
        $accountArgs = $esxcli.system.account.add.CreateArgs()
        $accountArgs.id = $credentials.UserName
        $accountArgs.description = $Description
        $accountArgs.password = $credentials.GetNetworkCredential().Password
        $accountArgs.passwordconfirmation = $credentials.GetNetworkCredential().Password
        Write-Host "`tAdding UserID: "$credentials.UserName" on $vmhost..."
        try {
            $esxcli.system.account.add.Invoke($accountArgs)
        }
        catch {
            $vmhostAdvancedView = Get-View $vmhost.ExtensionData.ConfigManager.AdvancedOption
            $pwdQualityControl = $vmhostAdvancedView.Setting | Where-Object {$_.Key -eq "Security.PasswordQualityControl"} | Select-Object -ExpandProperty Value
            $retry = ($pwdQualityControl.Split('')[0])
            $pwd = ($pwdQualityControl.Split('')[1]).Split('=')[1]
            Write-Host "`nError: Failed to add User ID: $Name" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            Write-Host "`nPassword Quality Control: " $pwdQualityControl -ForegroundColor Green
            Write-Host $retry ": is the number of times a user is prompted for a new password if the password candidate is not sufficiently strong."
            Write-Host "N0 =" $pwd.Split(',')[0] ": is the number of characters required for a password that uses characters from only one character class. For example, the password contains only lowercase letters."
            Write-Host "N1 =" $pwd.Split(',')[1] ": is the number of characters required for a password that uses characters from two character classes."
            Write-Host "N2 =" $pwd.Split(',')[2] ": is used for passphrases. ESXi requires three words for a passphrase. Each word in the passphrase must be 8-40 characters long."
            Write-Host "N3 =" $pwd.Split(',')[3] ": is the number of characters required for a password that uses characters from three character classes."
            Write-Host "N4 =" $pwd.Split(',')[4] ": is the number of characters required for a password that uses characters from all four character classes."
            break
        } #END try

        <#
          Assign Permission if parameter was specified
        #>
        if ($Permission) {
            Write-Verbose -Message ((Get-Date -Format G) + "`tAssigning Permission for UserID: $Name on $vmhost...")
            $permissionArgs = $esxcli.system.permission.set.CreateArgs()
            $permissionArgs.id = $Name.Trim()
            $permissionArgs.group = $false
            $permissionArgs.role = $Permission.Trim()
            $esxcli.system.permission.set.Invoke($permissionArgs)
        } #END if

        <#
          List account added
        #>
        $accountAdded = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq $Name.Trim()}
        $accountRole = $esxcli.system.permission.list.Invoke() | Where-Object {$_.Principal -eq $Name.Trim()} | Select-Object -ExpandProperty Role

        <#
          Use a custom object to store
          collected data
        #>
        $outputCollection += [PSCustomObject]@{
            'Hostname'    = $vmhost.Name
            'UserID'      = $accountAdded.UserID
            'Role'        = $accountRole
            'Description' = $accountAdded.Description
        } #END [PSCustomObject]
    } #END foreach
    
    <#
      Display skipped hosts and their connection status
    #>
    If ($skipCollection) {
        Write-Warning -Message "`tCheck Connection State or Host name"
        Write-Warning -Message "`tSkipped hosts:"
        $skipCollection | Format-Table -AutoSize
    } #END if    

    <#
      Validate output arrays
    #>
    if ($outputCollection) {
        Write-Verbose -Message ((Get-Date -Format G) + "`tAccount Added")
        Write-Host "`nESXi Local Account Added:" -ForegroundColor Green
        $outputCollection | Format-Table -Wrap
    }
    else {
        Write-Verbose -Message ((Get-Date -Format G) + "`tNo Account Added")
    } #END if/else
} #END function

function Set-ESXiAccount {
    <#
     .SYNOPSIS
       Set ESXi 6.x account security settings
     .DESCRIPTION
       Updates ESXi local account Description, Password or Permission
     .NOTES
       Author: Edgar Sanchez - @edmsanchez13
     .Link
       https://github.com/edmsanchez/PowerShell
       https://virtualcornerstone.com/
     .INPUTS
       No inputs required
     .OUTPUTS
       To Screen
     .PARAMETER Name
      User name (UserID) to update
     .Example
       Set-ESXiAccount -Name "testuser"
     .PARAMETER Description
       User ID Description to update
     .EXAMPLE
       Set-ESXiAccount -Name "testuser" -Description "Local test User"
     .PARAMETER Permission
       Permission to assign the User ID (Admin,ReadOnly,NoAccess)
     .Example
      Set-ESXiAccount -Name "testuser" -Permission "Admin" -VMhost devvm001.lab.local
     .PARAMETER  ResetPassword
       Switch to reset the User ID's Password. This is a switch ONLY, You will be prompted for the Password during the script execution
     .EXAMPLE  
       Set-ESXiAccount -Name "testuser" -ResetPassword -VMhost devvm001.lab.local
     .PARAMETER VMhost
       The name(s) of the vSphere ESXi Host(s)
     .EXAMPLE
       Set-ESXiAccount -Name "testuser" -ResetPassword -VMhost devvm001.lab.local
     .PARAMETER Cluster
       The name(s) of the vSphere Cluster(s)
     .EXAMPLE
       Set-ESXiAccount -Name "testuser" -Permission "Admin" -Cluster production-cluster
     .PARAMETER Datacenter
       The name(s) of the vSphere Virtual Datacenter(s).
     .EXAMPLE
       Set-ESXiAccount -Name "testuser" -Description "Local test User" -Permission "Admin" -Datacenter vDC001
    #> 
    
    <#
     ----------------------------------------------------------[Declarations]----------------------------------------------------------
    #>
  
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][String]$Name,
        [Parameter(Mandatory = $false)][String]$Description,
        [Parameter(Mandatory = $false)][ValidateSet("Admin", "ReadOnly", "NoAccess")]$Permission,
        [switch]$ResetPassword,
        [Parameter(Mandatory = $false)]$VMhost,
        [Parameter(Mandatory = $false)]$Cluster,
        [Parameter(Mandatory = $false)]$Datacenter
    )
    
    $skipCollection = @()
    $outputCollection = @()
    $vHostList = @()
    $date = Get-Date -format s
    $date = $date -replace ":", "-"
    
    <#
     ----------------------------------------------------------[Execution]----------------------------------------------------------
    #>
  
    <#
      Query PowerCLI version if
      running Verbose
    #>
    if ($VerbosePreference -eq "continue") {
        Write-Verbose -Message ((Get-Date -Format G) + "`tPowerCLI Version:")
        Get-Module -Name VMware.* | Select-Object -Property Name, Version | Format-Table -AutoSize
    } #END if
    
    <#
      Validate if a parameter was specified (-VMhost, -Cluster, or -Datacenter)
      Although all 3 can be specified, only the first one is used
      Example: -VMhost "host001" -Cluster "test-cluster". -VMhost is the first parameter
      and what will be used.
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tValidate parameters used")
    if ([string]::IsNullOrWhiteSpace($VMhost) -and [string]::IsNullOrWhiteSpace($Cluster) -and [string]::IsNullOrWhiteSpace($Datacenter)) {
        Write-Error -Message "You must specify a parameter (-VMhost, -Cluster, or -Datacenter)."
        break
    } #END if
    if ($Description -or $Permission -or $ResetPassword) {
        Write-Verbose -Message ((Get-Date -Format G) + "`tA Cmdlet Paramter was used")
    }
    else {
        Write-Error -Message "You must specify a Cmdlet parameter to update (-Description, -Permission, or -ResetPassword)."
        break        
    } #END if/else

    <#
      Check for an active connection to a ViServer
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tValidate connection to a vSphere server")
    if ($Global:DefaultViServers.Count -gt 0) {
        Write-Host "`tConnected to $Global:DefaultViServers" -ForegroundColor Green
    }
    else {
        Write-Error -Message "You must be connected to a vSphere server before running this Cmdlet."
        break
    } #END if/else
    
    <#
      Gather host list based on parameter used
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tGather host list")
    if ([string]::IsNullOrWhiteSpace($VMhost)) {      
        Write-Verbose -Message ((Get-Date -Format G) + "`t-VMhost parameter is Null or Empty")
        if ([string]::IsNullOrWhiteSpace($Cluster)) {
            Write-Verbose -Message ((Get-Date -Format G) + "`t-Cluster parameter is Null or Empty")
            if ([string]::IsNullOrWhiteSpace($Datacenter)) {
                Write-Verbose -Message ((Get-Date -Format G) + "`t-Datacenter parameter is Null or Empty")
            }
            else {
                Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using Datacenter parameter")
                Write-Host "`tGathering host list from the following DataCenter(s): " (@($Datacenter) -join ',')
                foreach ($vDCname in $Datacenter) {
                    $tempList = Get-Datacenter -Name $vDCname.Trim() -ErrorAction SilentlyContinue | Get-VMHost 
                    if ($tempList) {
                        $vHostList += $tempList | Sort-Object -Property Name
                    }
                    else {
                        Write-Warning -Message "`tDatacenter with name $vDCname was not found in $Global:DefaultViServers"
                    } #END if/else
                } #END foreach
            } #END if/else
        }
        else {
            Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using cluster parameter")
            Write-Host "`tGathering host list from the following Cluster(s): " (@($Cluster) -join ',')
            foreach ($vClusterName in $Cluster) {
                $tempList = Get-Cluster -Name $vClusterName.Trim() -ErrorAction SilentlyContinue | Get-VMHost 
                if ($tempList) {
                    $vHostList += $tempList | Sort-Object -Property Name
                }
                else {
                    Write-Warning -Message "`tCluster with name $vClusterName was not found in $Global:DefaultViServers"
                } #END if/else
            } #END foreach
        } #END if/else
    }
    else { 
        Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using VMhost parameter")
        Write-Host "`tGathering host list..."
        foreach ($invidualHost in $VMhost) {
            $tempList = Get-VMHost -Name $invidualHost.Trim() -ErrorAction SilentlyContinue
            if ($tempList) {
                $vHostList += $tempList | Sort-Object -Property Name
            }
            else {
                Write-Warning -Message "`tESXi host $invidualHost was not found in $Global:DefaultViServers"
            } #END if/else
        } #END foreach
    } #END if/else
    $tempList = $null

    <#
      Main code execution
    #>
    $credentials = $null
    foreach ($vmhost in $vHostList) {
    
        <#
          Skip if ESXi host is not in a Connected
          or Maintenance ConnectionState
        #>
        Write-Verbose -Message ((Get-Date -Format G) + "`t$vmhost Connection State: " + $vmhost.ConnectionState)
        if ($vmhost.ConnectionState -eq "Connected" -or $vmhost.ConnectionState -eq "Maintenance") {
            <#
              Do nothing - ESXi host is reachable
            #>
        }
        else {
            <#
              Use a custom object to keep track of skipped
              hosts and continue to the next foreach loop
            #>
            $skipCollection += [pscustomobject]@{
                'Hostname'         = $vmhost.Name
                'Connection State' = $vmhost.ConnectionState
            } #END [PSCustomObject]
            continue
        } #END if/else
    
        <#
         Validate ESXi Version
         Will run only of 6.x
        #>
        if ($vmhost.ApiVersion -notmatch '6.') {
            Write-Warning -Message ("`t$vmhost is ESXi v" + $vmhost.ApiVersion + ". Skipping host.")
            continue
        }

        <#
          Validate that Account to update exists
        #>
        $esxcli = Get-EsxCli -VMHost $vmhost -V2
        Write-Verbose -Message ((Get-Date -Format G) + "`tValidating $Name User ID exists on $vmhost...")
        if ($esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq $Name.Trim()}) {
            $accountArgs = $esxcli.system.account.set.CreateArgs()
            $updateAccount = $false
            $updatePermission = $false

            <#
              Update ESXi Local Account
              Query for Pasword if -ResetPassword switch is used
            #>
            if ($Description) {
                $updateAccount = $true
                $accountArgs.id = $Name.Trim()
                $accountArgs.description = $Description.Trim()
            } #END if            
            if ($ResetPassword) {
                if ($credentials) {
                    <#
                      Do nothing - Credentials already Gathered
                    #>
                }
                else {
                    Write-Verbose -Message ((Get-Date -Format G) + "`tPrompt for $Name password...")
                    $credentials = Get-Credential -UserName $Name -Message "Enter new password for UserID: $Name"
                } #END if/else
                $updateAccount = $true
                $accountArgs.id = $Name.Trim()
                $accountArgs.password = $credentials.GetNetworkCredential().Password
                $accountArgs.passwordconfirmation = $credentials.GetNetworkCredential().Password
            } #END if
            if ($updateAccount) {
                Write-Host "`tUpdating UserID: $Name on $vmhost..."
                try {
                    $esxcli.system.account.set.Invoke($accountArgs)
                }
                catch {
                    $vmhostAdvancedView = Get-View $vmhost.ExtensionData.ConfigManager.AdvancedOption
                    $pwdQualityControl = $vmhostAdvancedView.Setting | Where-Object {$_.Key -eq "Security.PasswordQualityControl"} | Select-Object -ExpandProperty Value
                    $retry = ($pwdQualityControl.Split('')[0])
                    $pwd = ($pwdQualityControl.Split('')[1]).Split('=')[1]
                    Write-Host "`nError: Failed to update User ID: $Name" -ForegroundColor Red
                    Write-Host $_.Exception.Message -ForegroundColor Red
                    Write-Host "`nPassword Quality Control: " $pwdQualityControl -ForegroundColor Green
                    Write-Host $retry ": is the number of times a user is prompted for a new password if the password candidate is not sufficiently strong."
                    Write-Host "N0 =" $pwd.Split(',')[0] ": is the number of characters required for a password that uses characters from only one character class. For example, the password contains only lowercase letters."
                    Write-Host "N1 =" $pwd.Split(',')[1] ": is the number of characters required for a password that uses characters from two character classes."
                    Write-Host "N2 =" $pwd.Split(',')[2] ": is used for passphrases. ESXi requires three words for a passphrase. Each word in the passphrase must be 8-40 characters long."
                    Write-Host "N3 =" $pwd.Split(',')[3] ": is the number of characters required for a password that uses characters from three character classes."
                    Write-Host "N4 =" $pwd.Split(',')[4] ": is the number of characters required for a password that uses characters from all four character classes."
                    break
                } #END try
            } #END if

            <#
              Update Permission if parameter was specified
            #>
            if ($Permission) {
                Write-Host "`tUpdating Permission for UserID: $Name on $vmhost..."
                $updatePermission = $true
                $permissionArgs = $esxcli.system.permission.set.CreateArgs()
                $permissionArgs.id = $Name.Trim()
                $permissionArgs.group = $false
                $permissionArgs.role = $Permission.Trim()
                $esxcli.system.permission.set.Invoke($permissionArgs)
            } #END if

            <#
              List account added
            #>
            $accountUpdated = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq $Name.Trim()}
            $accountRole = $esxcli.system.permission.list.Invoke() | Where-Object {$_.Principal -eq $Name.Trim()} | Select-Object -ExpandProperty Role

            <#
          Use a custom object to store
          collected data
        #>
            $outputCollection += [PSCustomObject]@{
                'Hostname'    = $vmhost.Name
                'UserID'      = $accountUpdated.UserID
                'Role'        = $accountRole
                'Description' = $accountUpdated.Description
            } #END [PSCustomObject]
        }
        else {
            Write-Warning -Message "`t$Name User ID does not exist $vmhost. Skipping host."
            continue   
        } #END if/else
    } #END foreach
    
    <#
      Display skipped hosts and their connection status
    #>
    If ($skipCollection) {
        Write-Warning -Message "`tCheck Connection State or Host name"
        Write-Warning -Message "`tSkipped hosts:"
        $skipCollection | Format-Table -AutoSize
    } #END if    
    
    <#
      Validate output arrays
    #>
    if ($outputCollection) {
        Write-Verbose -Message ((Get-Date -Format G) + "`tAccount Updated")
        Write-Host "`nESXi Local Account Updated:" -ForegroundColor Green
        $outputCollection | Format-Table -Wrap
    }
    else {
        Write-Verbose -Message ((Get-Date -Format G) + "`tNo Account Updated")
    } #END if/else
} #END function

function Remove-ESXiAccount {
    <#
     .SYNOPSIS
       Removes ESXi 6.x loca account
     .DESCRIPTION
       Checks and removes ESXi 6.x local account
     .NOTES
       Author: Edgar Sanchez - @edmsanchez13
     .Link
       https://github.com/edmsanchez/PowerShell
       https://virtualcornerstone.com/
     .INPUTS
       No inputs required
     .OUTPUTS
       To Screen
     .PARAMETER Name
       The name (UserID) of the local account to remove
     .EXAMPLE
       Remove-ESXiAccount -Name "testuser" -VMhost devvm001.lab.local
     .PARAMETER VMhost
       The name(s) of the vSphere ESXi Host(s)
     .EXAMPLE
       Remove-ESXiAccount -VMhost devvm001.lab.local
     .PARAMETER Cluster
       The name(s) of the vSphere Cluster(s)
     .EXAMPLE
       Remove-ESXiAccount -Cluster production-cluster
     .PARAMETER Datacenter
       The name(s) of the vSphere Virtual Datacenter(s).
     .EXAMPLE
       Remove-ESXiAccount -Datacenter vDC001
    #> 
    
    <#
     ----------------------------------------------------------[Declarations]----------------------------------------------------------
    #>
  
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][String]$Name,
        [Parameter(Mandatory = $false)]$VMhost,
        [Parameter(Mandatory = $false)]$Cluster,
        [Parameter(Mandatory = $false)]$Datacenter
    )
    
    $skipCollection = @()
    $outputCollection = @()
    $vHostList = @()
    $date = Get-Date -format s
    $date = $date -replace ":", "-"
    
    <#
     ----------------------------------------------------------[Execution]----------------------------------------------------------
    #>
  
    <#
      Query PowerCLI version if
      running Verbose
    #>
    if ($VerbosePreference -eq "continue") {
        Write-Verbose -Message ((Get-Date -Format G) + "`tPowerCLI Version:")
        Get-Module -Name VMware.* | Select-Object -Property Name, Version | Format-Table -AutoSize
    } #END if
    
    <#
      Validate if a parameter was specified (-VMhost, -Cluster, or -Datacenter)
      Although all 3 can be specified, only the first one is used
      Example: -VMhost "host001" -Cluster "test-cluster". -VMhost is the first parameter
      and what will be used.
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tValidate parameters used")
    if ([string]::IsNullOrWhiteSpace($VMhost) -and [string]::IsNullOrWhiteSpace($Cluster) -and [string]::IsNullOrWhiteSpace($Datacenter)) {
        Write-Error -Message "You must specify a parameter (-VMhost, -Cluster, or -Datacenter)."
        break
    } #END if

    <#
      Check for an active connection to a VIServer
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tValidate connection to a vSphere server")
    if ($Global:DefaultViServers.Count -gt 0) {
        Write-Host "`tConnected to $Global:DefaultViServers" -ForegroundColor Green
    }
    else {
        Write-Error -Message "You must be connected to a vSphere server before running this Cmdlet."
        break
    } #END if/else
    
    <#
      Gather host list based on parameter used
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tGather host list")
    if ([string]::IsNullOrWhiteSpace($VMhost)) {      
        Write-Verbose -Message ((Get-Date -Format G) + "`t-VMhost parameter is Null or Empty")
        if ([string]::IsNullOrWhiteSpace($Cluster)) {
            Write-Verbose -Message ((Get-Date -Format G) + "`t-Cluster parameter is Null or Empty")
            if ([string]::IsNullOrWhiteSpace($Datacenter)) {
                Write-Verbose -Message ((Get-Date -Format G) + "`t-Datacenter parameter is Null or Empty")
            }
            else {
                Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using Datacenter parameter")
                Write-Host "`tGathering host list from the following DataCenter(s): " (@($Datacenter) -join ',')
                foreach ($vDCname in $Datacenter) {
                    $tempList = Get-Datacenter -Name $vDCname.Trim() -ErrorAction SilentlyContinue | Get-VMHost 
                    if ($tempList) {
                        $vHostList += $tempList | Sort-Object -Property Name
                    }
                    else {
                        Write-Warning -Message "`tDatacenter with name $vDCname was not found in $Global:DefaultViServers"
                    } #END if/else
                } #END foreach
            } #END if/else
        }
        else {
            Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using cluster parameter")
            Write-Host "`tGathering host list from the following Cluster(s): " (@($Cluster) -join ',')
            foreach ($vClusterName in $Cluster) {
                $tempList = Get-Cluster -Name $vClusterName.Trim() -ErrorAction SilentlyContinue | Get-VMHost 
                if ($tempList) {
                    $vHostList += $tempList | Sort-Object -Property Name
                }
                else {
                    Write-Warning -Message "`tCluster with name $vClusterName was not found in $Global:DefaultViServers"
                } #END if/else
            } #END foreach
        } #END if/else
    }
    else { 
        Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using VMhost parameter")
        Write-Host "`tGathering host list..."
        foreach ($invidualHost in $VMhost) {
            $tempList = Get-VMHost -Name $invidualHost.Trim() -ErrorAction SilentlyContinue
            if ($tempList) {
                $vHostList += $tempList | Sort-Object -Property Name
            }
            else {
                Write-Warning -Message "`tESXi host $invidualHost was not found in $Global:DefaultViServers"
            } #END if/else
        } #END foreach
    } #END if/else
    $tempList = $null

    <#
      Main code execution
    #>
    foreach ($vmhost in $vHostList) {
    
        <#
          Skip if ESXi host is not in a Connected
          or Maintenance ConnectionState
        #>
        Write-Verbose -Message ((Get-Date -Format G) + "`t$vmhost Connection State: " + $vmhost.ConnectionState)
        if ($vmhost.ConnectionState -eq "Connected" -or $vmhost.ConnectionState -eq "Maintenance") {
            <#
              Do nothing - ESXi host is reachable
            #>
        }
        else {
            <#
              Use a custom object to keep track of skipped
              hosts and continue to the next foreach loop
            #>
            $skipCollection += [pscustomobject]@{
                'Hostname'         = $vmhost.Name
                'Connection State' = $vmhost.ConnectionState
            } #END [PSCustomObject]
            continue
        } #END if/else
    
        <#
         Validate ESXi Version
         Will run only of 6.x
        #>
        if ($vmhost.ApiVersion -notmatch '6.') {
            Write-Warning -Message ("`t$vmhost is ESXi v" + $vmhost.ApiVersion + ". Skipping host.")
            continue
        }

        <#
          Validate that Account to remove exists
        #>
        $esxcli = Get-EsxCli -VMHost $vmhost -V2
        Write-Verbose -Message ((Get-Date -Format G) + "`tValidating $Name User ID exists on $vmhost...")
        if ($esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq $Name.Trim()}) {
            $accountArgs = $esxcli.system.account.remove.CreateArgs()
            $accountArgs.id = $Name.Trim()
            Write-Host "`tRemoving UserID: $Name on $vmhost..."
            try {
                $esxcli.system.account.remove.Invoke($accountArgs)
            }
            catch {
                Write-Host "`nError: Failed to remove User ID: $Name" -ForegroundColor Red
                Write-Host $_.Exception.Message -ForegroundColor Red
                break
            } #END try   
        }
        else {
            Write-Warning -Message "`t$Name User ID does not exist $vmhost. Skipping host."
            continue               
        } #END if

        <#
          Report on local accounts
          after removal event
        #>
        $localAccounts = $esxcli.system.account.list.Invoke()
        $systemPermission = $esxcli.system.permission.list.Invoke()
        foreach ($account in $localAccounts) {
            $accountRole = $systemPermission | Where-Object {$_.Principal -eq $account.UserID} | Select-Object -ExpandProperty Role

            <#
              Use a custom object to store
              collected data
            #>
            $outputCollection += [PSCustomObject]@{
                'Hostname'    = $vmhost.Name
                'UserID'      = $account.UserID
                'Role'        = $accountRole
                'Description' = $account.Description
            } #END [PSCustomObject]
        } #END foreach        
    } #END foreach

    <#
      Display skipped hosts and their connection status
    #>
    If ($skipCollection) {
        Write-Warning -Message "`tCheck Connection State or Host name"
        Write-Warning -Message "`tSkipped hosts:"
        $skipCollection | Format-Table -AutoSize
    } #END if
    
    <#
      Validate output arrays
    #>
    if ($outputCollection) {
        Write-Verbose -Message ((Get-Date -Format G) + "`tInformation gathered")
        Write-Host "`nESXi Local Accounts:" -ForegroundColor Green
        $outputCollection | Format-Table -Wrap
    }
    else {
        Write-Verbose -Message ((Get-Date -Format G) + "`tNo information gathered")
    } #END if/else
} #END function

function Get-ESXiAccountSecurity {
    <#
     .SYNOPSIS
       Get ESXi 6.x local account security settings
     .DESCRIPTION
       Get local account security settings and password quality control for ESXi 6.x
     .NOTES
       Author: Edgar Sanchez - @edmsanchez13
     .Link
       https://github.com/edmsanchez/PowerShell
       https://virtualcornerstone.com/
     .INPUTS
       No inputs required
     .OUTPUTS
       To Screen
     .PARAMETER EventsPastHrs
      Switch to gather account locked and bad logon events for past 1,2 or 24 hr(s)
     .EXAMPLE
       Get-ESXiAccountSecurity -EventsPastHrs 1 -VMhost devvm001.lab.local       
     .PARAMETER VMhost
       The name(s) of the vSphere ESXi Host(s)
     .EXAMPLE
       Get-ESXiAccountSecurity -VMhost devvm001.lab.local
     .PARAMETER Cluster
       The name(s) of the vSphere Cluster(s)
     .EXAMPLE
       Get-ESXiAccountSecurity -Cluster production-cluster
     .PARAMETER Datacenter
       The name(s) of the vSphere Virtual Datacenter(s).
     .EXAMPLE
       Get-ESXiAccountSecurity -Datacenter vDC001
    #> 
    
    <#
     ----------------------------------------------------------[Declarations]----------------------------------------------------------
    #>
  
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)][ValidateSet(1, 2, 24)][Int]$EventsPastHrs,
        [Parameter(Mandatory = $false)]$VMhost,
        [Parameter(Mandatory = $false)]$Cluster,
        [Parameter(Mandatory = $false)]$Datacenter
    )
    
    $outputCollection = @()
    $accountLockedCollection = @()
    $badLogonCollection = @()
    $skipCollection = @()
    $vHostList = @()
    $date = Get-Date -format s
    $date = $date -replace ":", "-"
    
    <#
     ----------------------------------------------------------[Execution]----------------------------------------------------------
    #>
  
    <#
      Query PowerCLI version if
      running Verbose
    #>
    if ($VerbosePreference -eq "continue") {
        Write-Verbose -Message ((Get-Date -Format G) + "`tPowerCLI Version:")
        Get-Module -Name VMware.* | Select-Object -Property Name, Version | Format-Table -AutoSize
    } #END if
    
    <#
      Validate if a parameter was specified (-VMhost, -Cluster, or -Datacenter)
      Although all 3 can be specified, only the first one is used
      Example: -VMhost "host001" -Cluster "test-cluster". -VMhost is the first parameter
      and what will be used.
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tValidate parameters used")
    if ([string]::IsNullOrWhiteSpace($VMhost) -and [string]::IsNullOrWhiteSpace($Cluster) -and [string]::IsNullOrWhiteSpace($Datacenter)) {
        Write-Error -Message "You must specify a parameter (-VMhost, -Cluster, or -Datacenter)."
        break
    } #END if

    <#
      Check for an active connection to a VIServer
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tValidate connection to a vSphere server")
    if ($Global:DefaultViServers.Count -gt 0) {
        Write-Host "`tConnected to $Global:DefaultViServers" -ForegroundColor Green
    }
    else {
        Write-Error -Message "You must be connected to a vSphere server before running this Cmdlet."
        break
    } #END if/else
    
    <#
      Gather host list based on parameter used
    #>
    Write-Verbose -Message ((Get-Date -Format G) + "`tGather host list")
    if ([string]::IsNullOrWhiteSpace($VMhost)) {      
        Write-Verbose -Message ((Get-Date -Format G) + "`t-VMhost parameter is Null or Empty")
        if ([string]::IsNullOrWhiteSpace($Cluster)) {
            Write-Verbose -Message ((Get-Date -Format G) + "`t-Cluster parameter is Null or Empty")
            if ([string]::IsNullOrWhiteSpace($Datacenter)) {
                Write-Verbose -Message ((Get-Date -Format G) + "`t-Datacenter parameter is Null or Empty")
            }
            else {
                Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using Datacenter parameter")
                Write-Host "`tGathering host list from the following DataCenter(s): " (@($Datacenter) -join ',')
                foreach ($vDCname in $Datacenter) {
                    $tempList = Get-Datacenter -Name $vDCname.Trim() -ErrorAction SilentlyContinue | Get-VMHost 
                    if ($tempList) {
                        $vHostList += $tempList | Sort-Object -Property Name
                    }
                    else {
                        Write-Warning -Message "`tDatacenter with name $vDCname was not found in $Global:DefaultViServers"
                    } #END if/else
                } #END foreach
            } #END if/else
        }
        else {
            Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using cluster parameter")
            Write-Host "`tGathering host list from the following Cluster(s): " (@($Cluster) -join ',')
            foreach ($vClusterName in $Cluster) {
                $tempList = Get-Cluster -Name $vClusterName.Trim() -ErrorAction SilentlyContinue | Get-VMHost 
                if ($tempList) {
                    $vHostList += $tempList | Sort-Object -Property Name
                }
                else {
                    Write-Warning -Message "`tCluster with name $vClusterName was not found in $Global:DefaultViServers"
                } #END if/else
            } #END foreach
        } #END if/else
    }
    else { 
        Write-Verbose -Message ((Get-Date -Format G) + "`tExecuting Cmdlet using VMhost parameter")
        Write-Host "`tGathering host list..."
        foreach ($invidualHost in $VMhost) {
            $tempList = Get-VMHost -Name $invidualHost.Trim() -ErrorAction SilentlyContinue
            if ($tempList) {
                $vHostList += $tempList | Sort-Object -Property Name
            }
            else {
                Write-Warning -Message "`tESXi host $invidualHost was not found in $Global:DefaultViServers"
            } #END if/else
        } #END foreach
    } #END if/else
    $tempList = $null

    <#
      Main code execution
    #>
    foreach ($vmhost in $vHostList) {
    
        <#
          Skip if ESXi host is not in a Connected
          or Maintenance ConnectionState
        #>
        Write-Verbose -Message ((Get-Date -Format G) + "`t$vmhost Connection State: " + $vmhost.ConnectionState)
        if ($vmhost.ConnectionState -eq "Connected" -or $vmhost.ConnectionState -eq "Maintenance") {
            <#
              Do nothing - ESXi host is reachable
            #>
        }
        else {
            <#
              Use a custom object to keep track of skipped
              hosts and continue to the next foreach loop
            #>
            $skipCollection += [pscustomobject]@{
                'Hostname'         = $vmhost.Name
                'Connection State' = $vmhost.ConnectionState
            } #END [PSCustomObject]
            continue
        } #END if/else
    
        <#
          Get vSphere 6 Account Management Settings
        #>
        Write-Host "`tGathering Account Management Settings from $vmhost ..."
        if ($vmhost.ApiVersion -notmatch '6.') {
            Write-Warning -Message ("`t$vmhost is ESXi v" + $vmhost.ApiVersion + ". Skipping host.")
            continue
        }
        $vmhostAdvancedView = Get-View $VMhost.ExtensionData.ConfigManager.AdvancedOption
        $vmhostSecurity = $vmhostAdvancedView.Setting

        <#
         Gather Account Events
        #>
        if ($EventsPastHrs) {
            $accountLockedEvents = $null
            $badLogonEvents = $null
            Write-Verbose -Message ((Get-Date -Format G) + "`tGathering Bad logon/locked out events for the past $EventsPastHrs Hr(s) on $vmhost...")
            $accountLockedEvents = $vmhost | Get-VIEvent -Start (Get-Date).AddHours( - $EventsPastHrs) | Where-Object {$_.EventTypeId -eq "esx.audit.account.locked"}
            $badLogonEvents = $vmhost | Get-VIEvent -Start (Get-Date).AddHours( - $EventsPastHrs) | Where-Object {$_ -is [VMware.Vim.BadUsernameSessionEvent]}
            if ($accountLockedEvents) {
                foreach ($accountLockEvent in $accountLockedEvents) {

                    <#
                      Use a custom object to store
                      collected data
                    #>
                    $accountLockedCollection += [PSCustomObject]@{
                        'Hostname'    = $vmhost.Name
                        'CreatedTime' = $accountLockEvent.CreatedTime
                        'Event'       = $accountLockEvent.FullFormattedMessage
                    } #END [PSCustomObject]
                } #END foreach
            } #END if
            if ($badLogonEvents) {
                foreach ($badLogonEvent in $badLogonEvents) {

                    <#
                      Use a custom object to store
                      collected data
                    #>
                    $badLogonCollection += [PSCustomObject]@{
                        'Hostname'    = $vmhost.Name
                        'IpAddress'   = $badLogonEvent.IpAddress
                        'CreatedTime' = $accountLockEvent.CreatedTime
                        'UserName'    = $badLogonEvent.UserName
                        'Event'       = $badLogonEvent.FullFormattedMessage
                    } #END [PSCustomObject]
                } #END foreach
            } #END if
        } #End if
                    
        <#
          Use a custom object to store
          collected data
        #>
        $outputCollection += [PSCustomObject]@{
            'Hostname'               = $vmhost.Name
            'LockFailures'           = $vmhostSecurity | Where-Object { $_.Key -eq "Security.AccountLockFailures"} | Select-Object -ExpandProperty Value
            'UnlockTime Seconds'     = $vmhostSecurity | Where-Object { $_.Key -eq "Security.AccountUnlockTime"} | Select-Object -ExpandProperty Value
            'PasswordQualityControl' = $vmhostSecurity | Where-Object { $_.Key -eq "Security.PasswordQualityControl"} | Select-Object -ExpandProperty Value
        } #END [PSCustomObject]
    } #END foreach
    
    <#
      Display skipped hosts and their connection status
    #>
    If ($skipCollection) {
        Write-Warning -Message "`tCheck Connection State or Host name"
        Write-Warning -Message "`tSkipped hosts:"
        $skipCollection | Format-Table -AutoSize
    } #END if
    
    <#
      Validate output arrays
    #>
    if ($outputCollection -or $accountLockedCollection -or $badLogonCollection) {
        Write-Verbose -Message ((Get-Date -Format G) + "`tInformation gathered")
    }
    else {
        Write-Verbose -Message ((Get-Date -Format G) + "`tNo information gathered")
    } #END if/else
    if ($outputCollection) {
        Write-Host "`nESXi Account Management Settings:" -ForegroundColor Green    
        $outputCollection | Format-Table -Wrap
    } #END if
    if ($accountLockedCollection) {
        Write-Host "`nESXi locked account events past $EventsPastHrs Hr(s):" -ForegroundColor Green    
        $accountLockedCollection | Format-Table -Wrap
    } #END if
    if ($badLogonCollection) {
        Write-Host "`nESXi bad logon events past $EventsPastHrs Hr(s):" -ForegroundColor Green    
        $badLogonCollection | Format-Table -Wrap
    } #END if
} #END function