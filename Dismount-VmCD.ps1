function Dismount-VMCD {
    <#
      .SYNOPSIS
      Unmounts any CD/DVD ISO image, and sets drive selection to "Client Device".

      .DESCRIPTION
      Unmounts any CD/DVD ISO image including VMware tools installer, and sets drive selection to "Client Device".
      Will also detect stale CDROM ISO path Based on https://kb.vmware.com/s/article/66581 and can
      implement v1 or v2 fix on a potentially affected VM
      
      Dismount-VMCD has been tested on ESXi 6.0 and above and VCSA 6.5 an above.
    
      "Get-Help Dismount-VMCD -Examples" for some common usage tips.
    
      .NOTES
      Thanks to lucdekens for doing the hard work long ago on the ScriptBlock
      http://www.lucd.info/2015/10/02/answer-the-question/
      please vote for https://powercli.ideas.aha.io/ideas/PCLI-I-177 if you find 
      this script helpful
    
      .EXAMPLE
      Dismount-VMCD
      By default, will unmount any ISO images on all VMs gathered from $global:DefaultVIServers (all open Connect-VIServer sessions).

      .EXAMPLE
      Dismount-VMCD -VM "vm00*" -Whatif
      For any VM with name vm00* it will identify and notify you of the intended action(s), but will not carry them out

      .EXAMPLE
      Dismount-VMCD -VMhost "esxi01" -verbose
      For all VMs in VMhost 'esxi01', it will  unmounts any CD/DVD ISO image including VMware tools installer
      Verbose output tracks current progress, and helps when troubleshooting results.
      
      .EXAMPLE
      Dismount-VMCD -Cluster "Cluster01"  -StaleCdRomIsoPath ReconfigureV2
      For all VMs in Cluster 'Cluster01', it will unmount any ISO images, and will apply workaround from v2 Script to any VMs potentially affected by KB66581.
      ReconfigureV2 will update the CD/DVD device filename to "auto detect" or "emptyBackingString" for an affected VM. Example of VMX file update: ide1:0.fileName = "auto detect"
      You can also use -StaleCdRomIsoPath ReportOnly, -StaleCdRomIsoPath ReconfigureV1 and add -Whatif to get a preview of what would happen
    
      .EXAMPLE
      Dismount-VMCD -Datacenter "Datacenter01"  -StaleCdRomIsoPath ReconfigureV1 -verbose
      For all VMs in Datacenter 'Datacenter01', it will unmount any ISO images, and will apply workaround from v1 Script to any VMs potentially affected by KB66581.
      ReconfigureV1 will reconfigure the CDROM with useAutoDetect to true. The VMX file will als be updated, Example of VMX file update: ide1:0.autoDetect = "TRUE"
      You can also use -StaleCdRomIsoPath ReportOnly, -StaleCdRomIsoPath ReconfigureV2 and add -Whatif to get a preview of what would happen
      Verbose output tracks current progress, and helps when troubleshooting results.
    
      .INPUTS
      Parameters name(s) of: VM / VMhost / Cluster / DataCenter
      StaleCdRomIsoPath Parameter, with valid options: "ReportOnly", "ReconfigureV1", "ReconfigureV2"

      .OUTPUTS
      [System.Collections.ArrayList]
      [System.Management.Automation.PSCustomObject]

      .LINK
      https://github.com/edmsanchez/PowerShell/Dismount-VMCD.ps1
    #>

    [CmdletBinding(DefaultParameterSetName = 'VM')]
    param (
        [Parameter(Mandatory = $false,
            ParameterSetName = "VM")]
        [ValidateNotNullOrEmpty()]
        [String[]]$VM = "*",    
        [Parameter(Mandatory = $false,
            ParameterSetName = "VMhost")]
        [ValidateNotNullOrEmpty()]
        [String[]]$VMhost,
        [Parameter(Mandatory = $false,
            ParameterSetName = "Cluster")]
        [ValidateNotNullOrEmpty()]
        [String[]]$Cluster,
        [Parameter(Mandatory = $false,
            ParameterSetName = "DataCenter")]
        [ValidateNotNullOrEmpty()]
        [String[]]$DataCenter,
        [Parameter(Mandatory = $false)]
        [ValidateSet("ReportOnly", "ReconfigureV1", "ReconfigureV2")]$StaleCdRomIsoPath,
        [switch]$WhatIf
    ) #END param

    BEGIN {
        $stopWatch = [system.diagnostics.stopwatch]::startNew()
        $outputCollection = [System.Collections.ArrayList]@()

        <#
          Check for an active connection to a VIServer
        #>
        Write-Verbose -Message "$(Get-Date -Format G) `tValidate connection to a vSphere server"
        if ($Global:DefaultViServers.Count -gt 0) {
            Write-Host -Object "`tConnected to $Global:DefaultViServers" -ForegroundColor Green
        }
        else {
            throw "You must be connected to a vSphere server before running this Cmdlet."
        } #END if/else

        <#
          Gather vm list based on parameter set used
        #>
        if ($VMhost -or $Cluster -or $DataCenter) {
            [String[]]$VM = $null
        } #END if

        Write-Verbose -Message "$(Get-Date -Format G) `tGather vm list"
        if ($VM) {
            Write-Verbose -Message "$(Get-Date -Format G) `tExecuting Cmdlet using VM parameter set"
            Write-Output -InputObject "`tGathering vm list..."
            foreach ($oneVm in $VM) {
                $tempList = Get-VM -Name $oneVm.Trim() -ErrorAction SilentlyContinue
                if ($tempList) {
                    $vmList += $tempList
                }
                else {
                    Write-Warning -Message "`tVM: $oneVm was not found in $Global:DefaultViServers"
                } #END if/else
            } #END foreach    
        } #END if

        if ($VMhost) {
            Write-Verbose -Message "$(Get-Date -Format G) `tExecuting Cmdlet using VMhost parameter set"
            Write-Output -InputObject "`tGathering vm list from the following VMhost(s): $(@($VMhost) -join ',')"
            foreach ($oneHost in $VMhost) {
                $tempList = Get-VMHost -Name $oneHost.Trim() -ErrorAction SilentlyContinue | Get-VM
                if ($tempList) {
                    $vmList += $tempList
                }
                else {
                    Write-Warning -Message "`tVMhost: $oneHost was not found in $Global:DefaultViServers"
                } #END if/else
            } #END foreach    
        } #END if

        if ($Cluster) {
            Write-Verbose -Message "$(Get-Date -Format G) `tExecuting Cmdlet using Cluster parameter set"
            Write-Output -InputObject "`tGathering vm list from the following Cluster(s): $(@($Cluster) -join ',')"
            foreach ($oneCluster in $Cluster) {
                $tempList = Get-Cluster -Name $oneCluster.Trim() -ErrorAction SilentlyContinue | Get-VM 
                if ($tempList) {
                    $vmList += $tempList
                }
                else {
                    Write-Warning -Message "`tCluster: $oneCluster was not found in $Global:DefaultViServers"
                } #END if/else
            } #END foreach
        } #END if

        if ($DataCenter) {
            Write-Verbose -Message "$(Get-Date -Format G) `tExecuting Cmdlet using Datacenter parameter set"
            Write-Output -InputObject "`tGathering vm list from the following DataCenter(s): $(@($DataCenter) -join ',')"
            foreach ($oneDataCenter in $DataCenter) {
                $tempList = Get-Datacenter -Name $oneDataCenter.Trim() -ErrorAction SilentlyContinue | Get-VM
                if ($tempList) {
                    $vmList += $tempList
                }
                else {
                    Write-Warning -Message "`tDatacenter: $oneDataCenter was not found in $Global:DefaultViServers"
                } #END if/else
            } #END foreach
        } #END if

        $vmList = $vmList | Where-Object { $_.PowerState -eq 'PoweredOn' } | Sort-Object -Property Name

        <#
          This ScriptBlock looks for an outstanding “locked CD rom door” question for the specific VM. 
          If such a question is found, the function will reply with “Yes”.
          Code taken from Set-CDDriveAndAnswer function, written by Luc Dekens
          http://www.lucd.info/2015/10/02/answer-the-question/
        #>
        $answerVmCdQuestion = {  
            param($vmName, $viServer)
            $maxPass = 5
            $pass = 0
            
            Connect-VIServer -Server $viServer.Name  -Session $viServer.SessionSecret | Out-Null
            while ($pass -lt $maxPass) {
                $question = Get-VM -Name $vmName | Get-VMQuestion -QuestionText "*locked the CD-ROM*"
                if ($question) {
                    if ($question.Options.Label.Contains("button.yes")) {
                        Set-VMQuestion -VMQuestion $question -Option button.yes -Confirm:$false
                    }
                    else {
                        Set-VMQuestion -VMQuestion $question -Option yes -Confirm:$false
                    } #END if/else
                    $pass = $maxPass + 1
                } #END if
                $pass++
            } #END while
            Start-Sleep -Seconds 1
        } #END ScriptBlock
    } #END BEGIN

    PROCESS {
        foreach ($oneVm in $vmList) {
            Write-Output -InputObject "`n`tGathering configuration details from $($oneVm.Name) ..."

            <# 
              Unmount VMware tools installer
              and set CD/DVD Drive selection to "Client Device"
            #>
            $dismountAction = $false
            $cdConnected = $false
            $vmView = Get-View $oneVm
            $vCdRoms = $oneVm.ExtensionData.Config.Hardware.Device | Where-Object { $_ -is [VMware.Vim.VirtualCdrom] }
            foreach ($vOneCdRom in $vCdRoms) {
                if ($vOneCdRom.Connectable.Connected -or $vOneCdRom.DeviceInfo.Summary -match "iso") {
                    Write-Output -InputObject "`tDevice: $($vOneCdRom.DeviceInfo.Label) | Path: $($vOneCdRom.DeviceInfo.Summary) | Connected: $($vOneCdRom.Connectable.Connected)"
                } #END if

                if ($vOneCdRom.Connectable.Connected) {
                    $dismountAction = $true
                    $cdConnected = $true
                } #END if
            } #END foreach

            if ($vmView.Runtime.ToolsInstallerMounted) {
                if ($WhatIf) {
                    Write-Host -ForegroundColor Yellow "`tWhatIf: Would be unmounting VMware tools installer by executing this command: ""Dismount-Tools -VM $oneVm"""
                }
                else {
                    Write-Output -InputObject "`tUnmounting VMware Tools Installer ..."
                    Dismount-Tools -VM $oneVm
                    $dismountAction = $true
                } #END if/else
            } #END if

            if ($null -ne $vCdRoms.Backing.Filename -or $dismountAction) {
                $cd = Get-CDDrive -VM $oneVm
                if ($cdConnected) {
                    if ($WhatIf) {
                        Write-Host -ForegroundColor Yellow "`tWhatIf: Would be disconnecting CD/DVD drive(s) by executing this command: ""Set-CDDrive -CD $cd -NoMedia -Confirm:$false -ErrorAction Stop | Out-Null"""
                    }
                    else {
                        Write-Output -InputObject "`tDisconnecting and changing CD/DVD drive(s) to ""Client Device"" ..."
                        $server = $global:DefaultVIServer
                        $job = Start-Job -Name Check-CDQuestion -ScriptBlock $answerVmCdQuestion -ArgumentList $oneVm.Name, $server
                        Write-Verbose -Message "$(Get-Date -Format G) `tScriptBlock: $($job.Name) started, SateInfo: $($job.JobStateInfo), Id: $($job.Id)"
                        Set-CDDrive -CD $cd -NoMedia -Confirm:$false -ErrorAction Stop | Out-Null
                    } #END if/else
                }
                else {
                    if ($WhatIf) {
                        Write-Host -ForegroundColor Yellow "`tWhatIf: Would be disconnecting CD/DVD drive(s) by executing this command: ""Set-CDDrive -CD $cd -NoMedia -Confirm:$false | Out-Null"""
                    }
                    else {
                        Write-Output -InputObject "`tDisconnecting and changing CD/DVD drive(s) to ""Client Device"" ..."
                        Set-CDDrive -CD $cd -NoMedia -Confirm:$false | Out-Null
                    } #END if/else
                } #END if/else
            } #END if

            if ($dismountAction) {
                $oneVm = Get-VM -Name $($oneVm.Name)
                $vmView = Get-View $oneVm
                $vCdRoms = $vmView.Config.Hardware.Device | Where-Object { $_ -is [VMware.Vim.VirtualCdrom] }
            } #END if
            
            $vCdRomList = @()
            foreach ($vOneCdRom in $vCdRoms) {
                if ($vOneCdRom.Backing.GetType().Name -ne 'VirtualCdromIsoBackingInfo') { 
                    if ($vOneCdRom.Backing.DeviceName.Length -eq 0) {
                        $devName = "emptyBackingString"
                    }
                    else {
                        $devName = $vOneCdRom.Backing.DeviceName
                    } #END if/else
                    
                    Write-Verbose -Message "$(Get-Date -Format G) `tDevice: $($vOneCdRom.DeviceInfo.Label) | Backing: $($vOneCdRom.Backing.GetType().Name) | DeviceName: $devName | UseAutoDetect: $($vOneCdRom.Backing.UseAutoDetect)"
                    if (-not $devName -or ($devName -match '.iso$')) {
                        if ($StaleCdRomIsoPath -eq "ReportOnly") {

                            <#
                              Use a ArrayList object to store
                              collected data
                            #>
                            $output = [PSCustomObject]@{
                                'VM'            = $oneVm.Name
                                'Device'        = $vOneCdRom.DeviceInfo.Label
                                'Path'          = $vOneCdRom.DeviceInfo.Summary
                                'Connected'     = $vOneCdRom.Connectable.Connected
                                'UseAutoDetect' = $vOneCdRom.Backing.UseAutoDetect
                            } #END [PSCustomObject]
                            [void]$outputCollection.Add($output)
                        } #END if

                        if ($StaleCdRomIsoPath -match "Reconfigure") {
                            $vCdRomList += $vOneCdRom
                        } #END if
                    } #END if
                } #END if
            } #END foreach

            if ($vCdRomList.Length -eq 0) {
                continue
            } #END if

            <#
              Add device(s) to spec. Reconfigure the CDROM
              KB: https://kb.vmware.com/s/article/66581
            #>
            $runReconfigVM_Task = $false
            $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
            $spec.DeviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec[] ($vCdRomList.Length)
            $i = 0
            if ($StaleCdRomIsoPath -eq "ReconfigureV1") {
                if ($WhatIf) {
                    Write-Host -ForegroundColor Yellow "`tWhatIf: Would change the path to the CDROMs for $($oneVm.Name), using logic from cdromV1 script, setting useAutoDetect to true"
                }
                else {
                    $runReconfigVM_Task = $true
                    Write-Output -InputObject "`tConfiguring Device: change useAutoDetect to true (v1 Script) ..."
                    foreach ($vOneCdRom in $vCdRomList) {
                        $spec.DeviceChange[$i] = New-Object VMware.Vim.VirtualDeviceConfigSpec
                        $spec.DeviceChange[$i].Operation = "edit"
                        $spec.DeviceChange[$i].Device = $vOneCdRom
                        $spec.DeviceChange[$i].Device.Backing.UseAutoDetect = $true
                        $i += 1
                    } #END foreach        
                } #END if/else
            } #END if

            if ($StaleCdRomIsoPath -eq "ReconfigureV2") {
                if ($WhatIf) {
                    Write-Host -ForegroundColor Yellow "`tWhatIf: Would change the path to the CDROMs for $($oneVm.Name), using logic from cdromV2 script, setting the device name directly in the VMX file"
                }
                else {
                    $runReconfigVM_Task = $true
                    Write-Output -InputObject "`tConfiguring Device: set the device name directly in the VMX file (v2 Script) ..."
                    foreach ($vOneCdRom in $vCdRomList) {
                        $spec.DeviceChange[$i] = New-Object VMware.Vim.VirtualDeviceConfigSpec
                        $spec.DeviceChange[$i].Operation = "edit"
                        if ($vOneCdRom.Backing.UseAutoDetect -eq $true) {
                            $vOneCdRom.Backing.DeviceName = "auto detect"
                        }
                        else {
                            $vOneCdRom.Backing.DeviceName = "emptyBackingString"
                        } #END if/else

                        $spec.deviceChange[$i].Device = $vOneCdRom
                        $i += 1
                    } #END foreach        
                } #END if/else
            } #END if

            if ($runReconfigVM_Task) {
                $taskRef = $vmView.ReconfigVM_Task($spec)
                $taskState = Get-Task -Id $taskRef
                while ($taskState.PercentComplete -ne 100) {
                    Start-Sleep -Seconds 2
                    $taskState = Get-Task -Id $taskRef
                } #END while
    
                $vmPath = $vmView.Summary.Config.VmPathName
                if ($taskState.State -eq 'success') {
                    Write-Output -InputObject "`tReconfigVM_Task on '$vmPath' succeeded ($i device(s) modified)"
                }
                else {
                    $taskView = Get-View $taskRef
                    Write-Output -InputObject "`tReconfigVM_Task on '$vmPath' failed with $($taskView.Info.Error.Fault)"
                } #END if/else      
            } #END if
        } #END foreach
    } #END PROCESS

    END {
        $stopWatch.Stop()
        Write-Verbose -Message "$(Get-Date -Format G) `tMain code execution completed"
        Write-Verbose -Message "$(Get-Date -Format G) `tScript Duration: $($stopWatch.Elapsed.Duration())"

        <#
          Validate output arrays
          and output to screen
        #>
        if ($outputCollection) {
            Write-Verbose -Message "$(Get-Date -Format G) `tInformation gathered"
            Write-Host -Object "`nVM potentially affected by KB66581:" -ForegroundColor Green
            $outputCollection
        } #END if
    } #END END
} #END function