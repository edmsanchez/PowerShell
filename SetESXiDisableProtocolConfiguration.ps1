<#
.SYNOPSIS
    Disables TLS protocols for Hostd, Authd, sfcbd & VSANVP/IOFilter
.DESCRIPTION
    This scritp will disable SSLV3, TLS 1.0 and TLS 1.1 protocols
    for a vSphere Cluster, DataCenter or individual ESXi host. 
    Works with 6.0 U3 and 6.5
.NOTES
    File Name     : SetESXiDisableProtocolConfiguration.ps1
    Author        : Edgar Sanchez - @edmsanchez13
    Version       : 1.2
    Last Modified : 6/9/2017
        Wrote script breaking Functions based on @lamw original script
    
    Script based on ESXiDisableProtocolConfiguration.ps1 from William Lam - @lamw
    Link:  William Lam - https://github.com/lamw/vghetto-scripts/blob/master/powershell/ESXiDisableProtocolConfiguration.ps1
.INPUTS
   No inputs required
.OUTPUTS
   CSV file
.PARAMETER esxi
   The name(s) of the vSphere ESXi Host(s)
.EXAMPLE
    GetESXiDisabledProtocolConfiguration.ps1 -esxi devvm001.lab.local
.PARAMETER cluster
   The name(s) of the vSphere Cluster(s)
.EXAMPLE
    GetESXiDisabledProtocolConfiguration.ps1 -cluster production-cluster
.PARAMETER datacenter
   The name(s) of the vSphere Virtual DataCenter(s)
.EXAMPLE
    GetESXiDisabledProtocolConfiguration.ps1 -datacenter vDC001
#>

#----------------------------------------------------------[Declarations]----------------------------------------------------------

param(
    $esxi,
    $cluster,
    $datacenter
)

$vHostList = @()
$date = Get-Date -format s
$date = $date -replace ":","-"
[Boolean]$TLS1 = $true
[Boolean]$TLS1_1 = $true
[Boolean]$TLS1_2 = $false
[Boolean]$SSLV3 = $true
$sslCipherList = "ECDHE+AES"
[Boolean]$sfcbTLS1 = $false
[Boolean]$sfcbTLS1_1 = $false
[Boolean]$sfcbTLS1_2 = $True

# Path to save a backup of sfcb.cfg file
$configurationBackup = "c:\getpowercli\"

# Check to see if there are any currently connected servers
if($Global:DefaultViServers.Count -gt 0) {
    Clear-Host
    Write-Host -ForegroundColor Green "`tConnected to " $Global:DefaultViServers
} else {
    Write-Host -ForegroundColor Red "`tError: You must be connected to a vCenter or a vSphere Host before running this script."
    break
}

# Check to make sure at least 1 parameter was used
if([string]::IsNullOrWhiteSpace($esxi) -and [string]::IsNullOrWhiteSpace($cluster) -and [string]::IsNullOrWhiteSpace($datacenter)) {
    Write-Host -ForegroundColor Red "`tError: You must at least use one parameter, run Get-Help " $MyInvocation.MyCommand.Name " for more information"
    break
}

# Gather host list
if([string]::IsNullOrWhiteSpace($esxi)) {
    # $Vmhost Parameter Empty

    if([string]::IsNullOrWhiteSpace($cluster)) {
        # $Cluster Parameter Empty

        if([string]::IsNullOrWhiteSpace($datacenter)) {
            # $Datacenter Parameter Empty

        } else {                
            # Processing by Datacenter
            Write-Host "`tGathering host list from the following DataCenter(s): " (@($datacenter) -join ',')
            foreach ($vDCname in $datacenter) {
                $tempList = Get-DataCenter $vDCname.Trim() | Get-VMHost 
                $vHostList += $tempList | Sort-Object -Property name
            }
        }
    } else {
        # Processing by Cluster
        Write-Host "`tGatehring host list from the following Cluster(s): " (@($cluster) -join ',')
        foreach ($vClusterName in $cluster) {
            $tempList = Get-Cluster $vClusterName.Trim() | Get-VMHost 
            $vHostList += $tempList | Sort-Object -Property name
        }
    }
} else {
    # Processing by ESXi Host
    Write-Host "`tGathering host list..."
    foreach($invidualHost in $esxi) {
        $tempList = $invidualHost.Trim()
        $vHostList += $tempList | Sort-Object -Property name
    }
}

# Build TLS string based on user input for setting ESXi Advanced Settings
if($TLS1 -and $TLS1_1 -and $TLS1_2 -and $SSLV3) {
    Write-Host -ForegroundColor Red "Error: You must at least enable one of the TLS protocols"
    break
}

$tlsString = @()
if($SSLV3) { $tlsString += "sslv3" }
if($TLS1) { $tlsString += "tlsv1" }
if($TLS1_1) { $tlsString += "tlsv1.1" }
if($TLS1_2) { $tlsString += "tlsv1.2" }
$tlsString = $tlsString -join ","

# Main code execution
Write-Host "`nDisabling the following TLS protocols: $tlsString on ESXi hosts ...`n"
foreach ($esxihost in $vHostList) {
        $vmhost = Get-VMHost $esxihost
        if( ($vmhost.ApiVersion -eq "6.0" -and (Get-AdvancedSetting -Entity $vmhost -Name "Misc.HostAgentUpdateLevel").value -eq "3") -or ($vmhost.ApiVersion -eq "6.5") ) {
            Write-Host -ForegroundColor Green "Updating $vmhost ..."

            #Update sfcb.cfg
            Write-Host "`tUpdating sfcb.cfg ..."
            $url = "https://$vmhost/host/sfcb.cfg"

            $sessionManager = Get-View ($global:DefaultVIServer.ExtensionData.Content.sessionManager)

            $spec = New-Object VMware.Vim.SessionManagerHttpServiceRequestSpec
            $spec.Method = "httpGet"
            $spec.Url = $url
            $ticket = $sessionManager.AcquireGenericServiceTicket($spec)

            $websession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $cookie = New-Object System.Net.Cookie
            $cookie.Name = "vmware_cgi_ticket"
            $cookie.Value = $ticket.id
            $cookie.Domain = $vmhost.name
            $websession.Cookies.Add($cookie)
            $result = Invoke-WebRequest -Uri $url -WebSession $websession
            $sfcbConf = $result.content

            # Create backup of sfcb.cfg, update $configurationBackup under declarations if you want to use this
            #$sfcbBak = ($configurationBackup + $vmhost + $date + "_sfcvb_TLS.conf")
            #$sfcbConf | Out-File $sfcbBak
            #if(Test-Path $sfcbBak) {
            #    Write-Host "`tSuccessfully backed up sfcb.cfg file"
            #} else {
            #    Write-Host "Failed to backup sfcb.cfg file"
            #    break
            #}
        
            #Download the current sfcb.cfg and ignore existing TLS configuration
            $sfcbResults = ""
            foreach ($line in $sfcbConf.Split("`n")) {
                if($line -notmatch "enableTLSv1:" -and $line -notmatch "enableTLSv1_1:" -and $line -notmatch "enableTLSv1_2:" -and $line -notmatch "sslCipherList:" -and $line -ne "") {
                    $sfcbResults+="$line`n"
                }
            }

            #Append the TLS and SSL Cipher List Configuration
            $sfcbResults+="enableTLSv1: " + $sfcbTLS1.ToString().ToLower() + "`n"
            $sfcbResults+="enableTLSv1_1: " + $sfcbTLS1_1.ToString().ToLower() + "`n"
            $sfcbResults+="enableTLSv1_2: " + $sfcbTLS1_2.ToString().ToLower() +"`n"
            $sfcbResults+="sslCipherList: " + $sslCipherList +"`n"

            #Create HTTP PUT spec
            $spec.Method = "httpPut"
            $spec.Url = $url
            $ticket = $sessionManager.AcquireGenericServiceTicket($spec)
            
            #Upload sfcb.cfg back to ESXi host
            $websession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $cookie.Name = "vmware_cgi_ticket"
            $cookie.Value = $ticket.id
            $cookie.Domain = $vmhost.name
            $websession.Cookies.Add($cookie)
            $result = Invoke-WebRequest -Uri $url -WebSession $websession -Body $sfcbResults -Method Put -ContentType "plain/text"
            if($result.StatusCode -eq 200) {
                Write-Host "`tSuccessfully updated sfcb.cfg file"
            } else {
                Write-Host "Failed to upload sfcb.cfg file"
                break
            }

            if($vmhost.ApiVersion -eq "6.0") {
                Write-Host "`tUpdating UserVars.ESXiRhttpproxyDisabledProtocols ..."
                Get-AdvancedSetting -Entity $vmhost -Name "UserVars.ESXiRhttpproxyDisabledProtocols" | Set-AdvancedSetting -Value $tlsString -Confirm:$false | Out-Null

                Write-Host "`tUpdating UserVars.VMAuthdDisabledProtocols ..."
                Get-AdvancedSetting -Entity $vmhost -Name "UserVars.VMAuthdDisabledProtocols" | Set-AdvancedSetting -Value $tlsString -Confirm:$false | Out-Null
            }
            Write-Host "`tUpdating UserVars.ESXiVPsDisabledProtocols ..."
            Get-AdvancedSetting -Entity $vmhost -Name "UserVars.ESXiVPsDisabledProtocols" | Set-AdvancedSetting -Value $tlsString -Confirm:$false | Out-Null
        }
}
