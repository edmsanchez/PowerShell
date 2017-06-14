<#
.SYNOPSIS
    Returns current disabled TLS protocols for Hostd, Authd, sfcbd & VSANVP/IOFilter
.DESCRIPTION
    Retreives the current disabled TLS protocols for a vSphere Cluster, 
    DataCenter or individual ESXi host. Works with 6.0 U3 and 6.5
.NOTES
    File Name     : GetESXiDisabledProtocolConfiguration.ps1
    Author        : Edgar Sanchez - @edmsanchez13
    Version       : 1.2
    Last Modified : 6/8/2017
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

$outputCollection = @()
$outputService = @()
$vHostList = @()
$services = "VMware HTTP Reverse Proxy and Host Daemon","VMware vSAN VASA Vendor Provider","VMware Fault Domain Manager","VMware vSphere API for IO Filters","VMware Authorization Daemon"
$serviceName = "Hostd","vSANVP","FDM","ioFilterVPServer","vmware-authd"
$port = "443","8080","8182","9080","902"
$i = 0
$outputFile = "DisabledProtocols.csv"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

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

# Main code execution
foreach ($esxihost in $vHostList) {
        $vmhost = Get-VMHost $esxihost

        # Validate ESXi Version
        if( ($vmhost.ApiVersion -eq "6.0" -and (Get-AdvancedSetting -Entity $vmhost -Name "Misc.HostAgentUpdateLevel").value -eq "3") -or ($vmhost.ApiVersion -eq "6.5") ) {
            Write-Host "`tGathering information from $vmhost ..."
            $esxiVersion = ($vmhost.ApiVersion) + " Update " + (Get-AdvancedSetting -Entity $vmhost -Name "Misc.HostAgentUpdateLevel").value
            $vps = (Get-AdvancedSetting -Entity $vmhost -Name "UserVars.ESXiVPsDisabledProtocols" -ErrorAction SilentlyContinue).value
            
            # ESXi 6.5 - UserVars.ESXiVPsDisabledProtocols covers both VPs+rHTTP
            if($vmhost.ApiVersion -eq "6.5") {
                $rhttpProxy = $vps
                # Only TLS 1.2 is enabled 
                $vmauth = "tlsv1,tlsv1.1,sslv3"
            } else {
                $rhttpProxy = (Get-AdvancedSetting -Entity $vmhost -Name "UserVars.ESXiRhttpproxyDisabledProtocols" -ErrorAction SilentlyContinue).value
                $vmauth = (Get-AdvancedSetting -Entity $vmhost -Name "UserVars.VMAuthdDisabledProtocols" -ErrorAction SilentlyContinue).value
            }

            # Get sfcb.cfg Configuration
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
            
            # Extract the TLS fields if they exists
            $sfcbResults = @()
            $usingDefault = $true
            $sslCipherList = "Default"
            foreach ($line in $sfcbConf.Split("`n")) {
                if($line -match "enableTLSv1:") {
                    ($key,$value) = $line.Split(":")
                    if($value -match "false") {
                        $sfcbResults+="tlsv1"
                    }
                    $usingDefault = $false
                }
                if($line -match "enableTLSv1_1:") {
                    ($key,$value) = $line.Split(":")
                    if($value -match "false") {
                        $sfcbResults+="tlsv1.1"
                    }
                    $usingDefault = $false
                }
                if($line -match "enableTLSv1_2:") {
                    ($key,$value) = $line.Split(":")
                    if($value -match "false") {
                        $sfcbResults+="tlsv1.2"
                    }
                    $usingDefault = $false
                }

                #Get sfcb sslCipherList
                if($line -match "sslCipherList:") {
                    $sslCipherList = $line.Split(":")[1]
                }
            }
            if($usingDefault -or ($sfcbResults.Length -eq 0)) {
                $sfcbResults = "tlsv1,tlsv1.1,sslv3"
            } else {
                $sfcbResults+="sslv3"
            }
            
            #Make a combined object
            $hostTLSSettings = [pscustomobject] @{
                'Hostname' = $vmhost.name;
                'Version' = $esxiVersion;
                'hostd' = $rhttpProxy;
                'authd' = $vmauth;
                'sfcbd' = $sfcbResults -join ","
                'sfcbd sslCipherList' = $sslCipherList.Trim()
                'ioFilterVSANVP' = $vps
            }
            $outputCollection+=$hostTLSSettings
        }
}

#Make a combined object
foreach ($service in $services) {  
    $serviceInfo = New-Object -Type PSObject -Prop ([ordered]@{
        'Service' = $service
        'Service Name' = $serviceName[$i]
        'Port' = $port[$i]
    })
    #Add the object to the collection
    $i = $i + 1
    $outputService += $serviceInfo
}

# Display output on screen
Write-Host -ForegroundColor Green "`n" "Disabled TLS Protocols for ESXi Services (https://kb.vmware.com/kb/2148819, https://kb.vmware.com/kb/2147469):"
$outputCollection | Format-Table -AutoSize
$outputService | Format-Table -AutoSize

# Export combined object
Write-Host -ForegroundColor Green "`tData was saved to" $outputFile "CSV file"
$outputCollection | Export-Csv $outputFile -NoTypeInformation