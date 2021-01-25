#region Help
# ----------

<#
	.SYNOPSIS
		nri-hyperv-report.ps1 - HyperV reporting for New Relic Infrastructure
    Collects inventory and resource usage of Hyper-V Cluster or Standalone environments.

	.PARAMETER Cluster
		A single Hyper-V Cluster name.

	.PARAMETER VMHost
		A single standalone Hyper-V Host name or an array of standalone Hyper-V Host names

	.PARAMETER LogFilePath
		Log file path. Default: Script working directory

  .PARAMETER LogLevel
    Log Level. Default: INFO. Available levels: [NONE, ERROR, WARNING, INFO, DEBUG]

  .PARAMETER WriteToNRI
    Write to New Relic Infrastructure. Sends logs to stderr and only NRI JSON output to stdout. Default: $true

	.NOTES
		Adapted from Hyper-V Capacity Report:
    http://wiki.webperfect.ch/index.php?title=Hyper-V:_Capacity_Report
#>

#endregion Help

#region Script Parameters
# -----------------------

[CmdletBinding(SupportsShouldProcess=$True)]

Param (
    [parameter(
                Mandatory=$false,
                HelpMessage='Hyper-V Cluster name (i.e. HvCluster1 or hvcluster1.domain.corp')]
                [string]$Cluster,

    [parameter(
                Mandatory=$false,
                HelpMessage='Standalone Hyper-V Host name(s) (i.e. Host1, Host2, Host3)')]
                [array]$VMHost,

    [parameter(
                Mandatory=$false,
                HelpMessage='Disk path for log file. Only used if not reporting to New Relic. Default: (Get-Location).path aka "pwd"')]
                [string]$LogFilePath = (Get-Location).path,

    [parameter(
                Mandatory=$false,
                HelpMessage='Write to New Relic Infrastructure ($true/$false). Default: $true')]
                [bool]$WriteToNRI = $true,

    [parameter(
                Mandatory=$false,
                HelpMessage='Log Level (NONE|ERROR|WARNING|INFO|DEBUG). Default: INFO')]
                [string]$LogLevel = "INFO",

    [parameter(
                Mandatory=$False,
                HelpMessage='Check for and install prerequisites. Default: $false')]
                [bool]$FirstRun = $false
	)

#endregion Script Parameters

#region Functions
#----------------

  # Get WMI data
  function sGet-Wmi {

      param (
          [Parameter(Mandatory = $true)]
          [string]$CompName,
          [Parameter(Mandatory = $true)]
          [string]$Namespace,
          [Parameter(Mandatory = $true)]
          [string]$Class,
          [Parameter(Mandatory = $false)]
          $Property,
          [Parameter(Mandatory = $false)]
          $Filter,
          [Parameter(Mandatory = $false)]
          [switch]$AI
      )

      # Base string
      $wmiCommand = "gwmi -ComputerName $CompName -Namespace $Namespace -Class $Class -ErrorAction Stop"

      # If available, add Filter parameter
      if ($Filter) {
          # $Filter = ($Filter -join ',').ToString()
          $Filter = [char]34 + $Filter + [char]34
          $wmiCommand += " -Filter $Filter"
      }

      # If available, add Property parameter
      if ($Property) {
          $Property = ($Property -join ',').ToString()
          $wmiCommand += " -Property $Property"
      }

      # If available, Authentication and Impersonation
      if ($AI) {
          $wmiCommand += " -Authentication PacketPrivacy -Impersonation Impersonate"
      }

      # Try to connect
      $ResultCode = "1"
      Try {
          # $wmiCommand
          $wmiResult = iex $wmiCommand
      } Catch {
          $wmiResult = $_.Exception.Message
          $ResultCode = "0"
      }

      # If wmiResult is null
      if ($wmiResult -eq $null) {
          $wmiResult = "Result is null"
          $ResultCode = "2"
      }

      Return $wmiResult, $ResultCode
  }

  # Write Log
  Function sPrint {

      param(
          [string]$MsgLevel = "INFO",
          [string]$Message
      )

      $hostOut = $true
      $logOut = $true
      $msgTitle = $null
      $msgColor = $DefaultFGColor
      $logLevelNum = $LogLevels.($LogLevel.ToUpper())
      $msgLevelNum = $LogLevels.($MsgLevel.ToUpper())
      if($logLevelNum -ge $msgLevelNum) {
        switch($msgLevelNum) {
          -1 {$logOut = $false}
          1 {$Message = ""}
          2 {$msgColor = 'Red'}
          3 {$msgColor = 'Yellow'}
          4 {$msgColor = 'Green'}
          5 {$hostOut = $false}
          default {}
        }

        # All messages except "SPACE" and "NEWRELIC" get labeled
        if($msgLevelNum -gt 1) {
		$TimeStamp = Get-Date -Format "dd.MMM.yyyy HH:mm:ss"
          $TimeStamp = Get-Date -Format "dd.MMM.yyyy HH:mm:ss"
          $Message = ("[" + $MsgLevel + "]").PadRight(10,' ') + " - $TimeStamp - $Message"
        }

        if($hostOut -And !$WriteToNRI) {
          Write-Host $Message -ForegroundColor $msgColor
        } elseif (($msgLevelNum -eq -1) -And $WriteToNRI) {
		Write-Output $Message
	  }

	  if(($msgLevelNum -ne -1) -And $WriteToNRI) {
          Write-StdErr $Message
        }

        if($WriteToLog -And ($logOut -Or ($logLevelNum -eq 5))) {
          Add-Content -Path $LogFile -Value $Message
        }
      }
  }

	Function Write-StdErr {
		param ([PSObject] $InputObject)

		$outFunc = if ($Host.Name -eq 'ConsoleHost') {
			[Console]::Error.WriteLine
		} else {
			$host.ui.WriteErrorLine
		}

		if ($InputObject) {
			[void] $outFunc.Invoke($InputObject.ToString())
		} else {
			[string[]] $lines = @()
			$Input | % { $lines += $_.ToString() }
			[void] $outFunc.Invoke($lines -join "`r`n")
		}
	}

  # Convert BusType Value to BusType Name
  Function sConvert-BusTypeName {

    Param ([Byte] $BusTypeValue)

    switch($BusTypeValue) {
      1 {Return "SCSI"}
      2 { Return "ATAPI" }
      3 { Return "ATA" }
      4 { Return "IEEE 1394" }
      5 { Return "SSA" }
      6 { Return "FC" }
      7 { Return "USB" }
      8 { Return "RAID" }
      9 { Return "iSCSI" }
      10 { Return "SAS" }
      11 { Return "SATA" }
      12 { Return "SD" }
      13 { Return "SAS" }
      14 { Return "Virtual" }
      15 { Return "FB Virtual" }
      16 { Return "Storage Spaces" }
      17 { Return "NVMe" }
      default { Return "Unknown" }
    }
  }

  # Convert Cluster Disk State Value to Name
  Function sConvert-ClusterDiskState {

      Param ([Byte] $StateValue)

      switch($StateValue) {
        0 { Return "Inherited" }
        1 { Return "Initializing" }
        2 { Return "Online" }
        3 { Return "Offline" }
        4 { Return "Failed" }
        127 { Return "Offline" }
        128 { Return "Pending" }
        129 { Return "Online Pending" }
        130 { Return "Offline Pending" }
        default { Return "Unknown" }
      }
  }

  # Convert BusType Value to BusType Name
  Function sConvert-DiskPartitionStyle {

      Param ([Byte] $PartitionStyleValue)

      switch($PartitionStyleValue) {
        0 { Return "MBR" }
        1 { Return "GPT" }
        2 { Return "Unknown" }
      }
  }

  # Add Event to data to be output for New Relic Infrastructure
  Function sAddToNRIData {

    param(
        [string]$entityName=$null,
        [string]$entityType=$DefaultEntityType,
        [PSObject]$metrics
    )

    if(!$WriteToNRI) {
      Return
    }

    # Empty unless declared below
    $entity = @{}
    $inventory = @{}

    if($entityName) {
      $entity.add("type", $entityType)
      $entity.add("name", $entityName)
      $entity.add("id_attributes", $EmptyArray)

      $invValue = @{
        value = $entityName
      }
      $inventory.add("name", $invValue)
    }

    $thisData = @{
      entity = $entity
      inventory = $inventory
      metrics = @($metrics)
      events = $EmptyArray
    }

    $global:NRIData += $thisData
  }

  Function sWriteToNRI {

    if(!$WriteToNRI) {
      Return
    }

    sPrint -MsgLevel "DEBUG" -Message "Writing to NR:"
    $inputObj = @{
      name = "com.newrelic.hyperv.report"
      integration_version = "0.1.0"
      protocol_version = 3
      data = $global:NRIData
    }

    $payload = ConvertTo-Json -InputObject $inputObj -Depth 100 -Compress
    sPrint -MsgLevel "NEWRELIC" -Message $payload

  }

#endregion Functions

#region Variables
#----------------

  $LogLevels = @{
      NEWRELIC = -1
      NONE = 0
      SPACE = 1
      ERROR = 2
      WARNING = 3
      INFO = 4
      DEBUG = 5
  }

  # Logging enabled by default
  [bool]$WriteToLog = $true
  if($LogLevel -eq "NONE" -Or $WriteToNRI -eq $true) {
    $WriteToLog = $false
  }

  $LogFile = $LogFilePath + "\" + "ScriptLog" + ".txt"

  $DefaultFGColor = (get-host).ui.rawui.ForegroundColor

  $progressPreference = "Continue"

  $global:NRIData = @()
  $DefaultEntityType = "hyperv"
  $EmptyArray = @()

  # Print MSG
  sPrint -MsgLevel "SPACE"
  sPrint -MsgLevel "INFO" -Message "Started! Hyper-V Reporting Script (Version 1.9)"

  if ($WriteToNRI -eq $true) {
    sPrint -MsgLevel "INFO" -Message "Will report JSON version of report to stdout for New Relic Infrastructure."
    $progressPreference = "SilentlyContinue"
  }

#endregion Variables

#region Initialization

  if($WriteToLog -eq $true) {
    # Log file check and write subject line
    if (!(Test-Path -Path $LogFile)) {
        New-Item -Path $LogFile -ItemType file -Force -ErrorAction SilentlyContinue | Out-Null
        if (Test-Path -Path $LogFile) {
            sPrint -MsgLevel "DEBUG" -Message "----- Start -----"
            sPrint -MsgLevel "INFO" -Message "Logging started: $LogFile"
        } else {
            $WriteToLog = $false
            sPrint -MsgLevel "WARNING" -Message "Unable to create the log file. Script will continue without logging..."
        }
    } else {
        sPrint -MsgLevel "DEBUG" -Message "----- Start -----"
        sPrint -MsgLevel "INFO" -Message "Logging started: $LogFile"
    }
  }

  # Requires VMHost or Cluster, but not both.
  if ((!$VMHost) -and (!$Cluster)) {
      sPrint -MsgLevel "ERROR" -Message "Hyper-V target parameter is missing. Use -Cluster or -VMHost parameter to define target."
      sPrint -MsgLevel "WARNING" -Message "For technical information, type: Get-Help .\Get-HyperVReport.ps1 -examples"
      sPrint -MsgLevel "ERROR" -Message "Script terminated!"
      Break
  }
  if (($VMHost) -and ($Cluster)) {
      sPrint -MsgLevel "ERROR" -Message "-Cluster and -VMHost parameters can not be used together."
      sPrint -MsgLevel "WARNING" -Message "For technical information, type: Get-Help .\Get-HyperVReport.ps1 -examples"
      sPrint -MsgLevel "ERROR" -Message "Script terminated!"
      Break
  }

  # Import Hyper-V Module 1.1 (Windows 10 or Server 2016 higher to Server 2012 R2 or older)
  $hyperVModuleVersion = 1.1
  if (Get-Module Hyper-V -ListAvailable | ? {$_.Version -eq "$hyperVModuleVersion"}) {
      sPrint -MsgLevel "INFO" -Message "Using Hyper-V $hyperVModuleVersion Module."
      Remove-Module Hyper-V -ErrorAction SilentlyContinue
      Import-Module Hyper-V -RequiredVersion $hyperVModuleVersion
  }

#endregion Initialization

#region Gathering Hyper-V Host Information
#-----------------------------------------

    $Computers = $null
    $ClusterName = $null
    [array]$VMHosts = $null

    if ($Cluster) {

        if (($Cluster -eq "localhost") -or ($Cluster -eq "127.0.0.1")) {
            $ClusterName = $env:COMPUTERNAME
        }
        else {
            $ClusterName = $Cluster
        }

        $ClusterNodes = $null

        $getClusterErr = $Null
        $getCluster = Get-Cluster -Name $ClusterName -ErrorVariable getClusterErr -ErrorAction SilentlyContinue

        if (!$getClusterErr) {
            $ClusterName = $getCluster.Name

            $hostTableCaption = "Cluster Nodes"
            $volumeTableCaption = "Clustered Disks/Volumes"

            sPrint -MsgLevel "INFO" -Message "$($ClusterName) is accessible. Gathering Node information..."

            sPrint -MsgLevel "INFO" -Message "Checking prerequisites for Hyper-V Cluster reporting..."

            $clusterNodesData = Get-ClusterNode -Cluster $ClusterName -ErrorAction SilentlyContinue | select Name,State
            $ClusterNodes = ($clusterNodesData | where{$_.State -ne "Down"}).Name
            $downClusterNodes = ($clusterNodesData | where{$_.State -eq "Down"}).Name
            $ovTotalNode = ($clusterNodesData).Count

            if ($downClusterNodes) {
                sPrint -MsgLevel "ERROR" "Unavailable or down Hyper-V Cluster Node(s): $downClusterNodes"
            }

            if ($ClusterNodes) {
                # Checking Cluster Owner Node OS version and Hyper-V role
                $clusterOwnerHostName = sGet-Wmi -CompName $ClusterName -Namespace root\Cimv2 -Class  Win32_ComputerSystem -Property Name
                if ($clusterOwnerHostName[1] -eq 1) {
                    $clusterOwnerHostName = $clusterOwnerHostName[0].Name
                }
                else {
                    sPrint -MsgLevel "ERROR" -Message "$ClusterName`: $($clusterOwnerHostName[0])"
                    sPrint -MsgLevel "ERROR" -Message "Script terminated!"
                    Break
                }

                $getClusterOwnerNode = Get-ClusterNode -Cluster $ClusterName -Name $clusterOwnerHostName
                $clusterOsVersion = ($getClusterOwnerNode.MajorVersion).ToString() + "." + ($getClusterOwnerNode.MinorVersion).ToString()

                if (($clusterOsVersion -like "6.2") -or ($clusterOsVersion -like "6.3") -or ($clusterOsVersion -like "10.0*")) {
                    if ((Get-WindowsFeature -ComputerName $clusterOwnerHostName -Name "Hyper-V").Installed) {
                        sPrint -MsgLevel "DEBUG" -Message "Operating system version and Hyper-V role on the cluster owner node is OK."
                        $VMHosts = $ClusterNodes

                        # Clear
                        $offlineVmConfigData = $null
                        $ovTotalVm, $ovOfflineVmConfig = 0

                        # Get ClusterResource Data
                        $clusterResourceData = Get-ClusterResource -Cluster $ClusterName

                        # Detect offline Virtual Machine Configuration resources
                        $offlineVmConfigData = $clusterResourceData | where{($_.ResourceType -eq "Virtual Machine Configuration") -and ($_.State -ne "Online")}

                        # For Cluster Overview
                        $ovTotalVm = ($clusterResourceData | where{$_.ResourceType -eq "Virtual Machine"}).Count
                    }
                    else {
                        sPrint -MsgLevel "WARNING" -Message "Hyper-V role is not installed on $clusterOwnerHostName."
                        sPrint -MsgLevel "ERROR" -Message "Script terminated!"
                        Break
                    }
                }
                else {
                    sPrint -MsgLevel "WARNING" -Message "$($ClusterName): Incompatible operating system version detected. Supported operating systems are Windows Server 2012 and Windows Server 2012 R2."
                    sPrint -MsgLevel "ERROR" -Message "Script terminated!"
                    Break
                }
            }
            else {
                sPrint -MsgLevel "ERROR" -Message "$ClusterName`: $($error[0].Exception.Message)"
                sPrint -MsgLevel "ERROR" -Message "Script terminated!"
                Break
            }
        }
        else {
            sPrint -MsgLevel "ERROR" -Message "$($ClusterName): $($error[0].Exception.Message)"
            sPrint -MsgLevel "ERROR" -Message "Script terminated!"
            Break
        }
    }

    if ($VMHost) {

        if (($VMHost -eq "localhost") -or ($VMHost -eq "127.0.0.1")) {
            $Computers = $env:COMPUTERNAME
        }
        else {
            $Computers = $VMHost | Sort-Object -Unique
        }

        [array]$invalidVmHost = $null
        [array]$invalidVmHostMsg = $null
        $hostTableCaption = "Standalone Host(s)"
        $volumeTableCaption = "Local Disks/Volumes"

        sPrint -MsgLevel "INFO" -Message "Checking prerequisites for standalone Hyper-V host(s) reporting..."

        foreach ($computerName in $Computers) {
            $hvOs = sGet-Wmi -CompName $computerName -Namespace root\Cimv2 -Class Win32_OperatingSystem -Property Version
            $hvOsVersion = $null
            if ($hvOs[1] -eq 1) {
                $hvOsVersion = $hvOsVersion[0].Version
            } else {
                sPrint -MsgLevel "ERROR" -Message "$($computerName): $($hvOsVersion[0])"
                $invalidVmHost += $computerName
                $invalidVmHostMsg += $hvOsVersion[0]
                Continue
            }

            if ($hvOsVersion) {
                if (($hvOsVersion -like "6.2*") -or ($hvOsVersion -like "6.3*") -or ($hvOsVersion -like "10.0*")) {
                    if ((Get-WindowsFeature -ComputerName $computerName -Name "Hyper-V").Installed) {
                        $checkClusterMember = sGet-Wmi -CompName $computerName -Namespace root\MSCluster -Class MSCluster_Cluster -Property Name
                        if ($checkClusterMember[1] -eq 1)
                        {
                            sPrint -MsgLevel "ERROR" -Message "$($computerName) is a member of a Hyper-V Cluster and didn't included in the VMHost list. Please use -Cluster parameter to report this node."
                            $invalidVmHost += $computerName
                            $invalidVmHostMsg += "This Node is a member of a cluster. Please use -Cluster parameter to report this node."
                        }
                        else
                        {
                            sPrint -MsgLevel "DEBUG" -Message "$($computerName): Operating system version and Hyper-V role is OK."
                            $VMHosts += $computerName
                        }
                    }
                    else
                    {
                        sPrint -MsgLevel "ERROR" -Message "$($computerName): Could not be added to the VMHost list because Hyper-V role is not installed."
                        $invalidVmHost += $computerName
                        $invalidVmHostMsg += "Could not be added to the VMHost list because Hyper-V role is not installed"
                    }
                }
                else
                {
                    sPrint -MsgLevel "ERROR" -Message "$($computerName): Could not be added to the VMHost list because incompatible operating system version detected."
                    $invalidVmHost += $computerName
                    $invalidVmHostMsg += "Could not be added to the VMHost list because incompatible operating system version detected"
                }
            }
            else
            {
                sPrint -MsgLevel "ERROR" -Message "$($computerName): Could not be added to the VMHost list because operating system version could not be detected."
                $invalidVmHost += $computerName
                $invalidVmHostMsg += "Could not be added to the VMHost list because operating system version could not be detected"
            }
        }
    }

    if (!$VMHosts) {
        sPrint -MsgLevel "WARNING" "No valid Hyper-V hosts for reporting."
        sPrint -MsgLevel "ERROR" -Message "Script terminated!"
        Break
    }

    if ($Cluster) {
        sPrint -MsgLevel "INFO" "Available Hyper-V Cluster Node(s) for reporting: $VMHosts"
    }
    else {
        sPrint -MsgLevel "INFO" "Available Hyper-V Hypervisor(s) for reporting: $VMHosts"
    }

    # Print MSG
    sPrint -MsgLevel "INFO" "Gathering Hyper-V Host information..."

    $ovUpNode, $ovTotalLP, $ovTotalMemory, $ovUsedMemory = 0
    $ovTotalVProc, $ovTotalVmMemory, $ovUsedVmMemory, $ovUsedVmVHD, $ovTotalVmVHD = 0

    $VMHostsDomains = @{};
    $VMHostsOSVersions = @{};

    foreach ($vmHostItem in $VMHosts) {

        $chargerVMHostTable = $null
        $vmHostData = $null
        $vmHostTotalVProc = 0
        $vmHostVpLpRatio = 0
        $vmHostRunningClusVmCount= 0
        $vmHostGet = Get-VMHost -ComputerName $vmHostItem
        $vmHostVMs = Hyper-V\Get-VM -ComputerName $vmHostItem
        $vmHostVmCount = $vmHostVMs.Count + ($offlineVmConfigData | where{$_.OwnerNode -eq "$vmHostItem"}).Count
        $vmHostRunningVmCount = ($vmHostVMs | where{$_.State -eq "Running"}).Count
        $vmHostRunningClusVmCount = ($vmHostVMs | where{($_.IsClustered -eq $true) -and ($_.State -eq "Running")}).Count
        $vmHostRunningNonClusVmCount = $vmHostRunningVmCount - $vmHostRunningClusVmCount
        $vmHostTotalVProc = (($vmHostVMs | where{(($_.State -eq "Running") -or ($_.State -eq "Paused"))}).ProcessorCount | Measure-Object -Sum).Sum
        $vmHostClusVProc = (($vmHostVMs | where{(($_.State -eq "Running") -and ($_.IsClustered -eq $true)) -or (($_.State -eq "Paused") -and ($_.IsClustered -eq $true))}).ProcessorCount | Measure-Object -Sum).Sum
        $vmHostWmiData = Get-WmiObject -ComputerName $vmHostItem -Class Win32_OperatingSystem
        $VMHostsOSVersions.add($vmHostItem, $vmHostWmiData.Version)

        # For Cluster Overview
        $ovTotalVProc = $ovTotalVProc + $vmHostClusVProc

        # State
        if ($Cluster) {
            $vmHostState = (Get-ClusterNode -Cluster $ClusterName -Name $vmHostItem).State
        } else {
            $vmHostState = "Up"
        }

        # Clear
        $TotalUsedMemory = $null
        $TotalFreeMemory = $null
        $TotalVisibleMemory = $null
        $vmHostUptime = $null
        $TotalFreeMemoryPercentage = $null

        # Memory Capacty
        # 'Raw' memory capacity vars for use with New Relic
        $TotalUsedMemory = $vmHostWmiData.TotalVisibleMemorySize - $vmHostWmiData.FreePhysicalMemory
        $TotalFreeMemory = $vmHostWmiData.FreePhysicalMemory
        $TotalVisibleMemory = $vmHostWmiData.TotalVisibleMemorySize
        $TotalFreeMemoryPercentage = [math]::round(($vmHostWmiData.FreePhysicalMemory/$vmHostWmiData.TotalVisibleMemorySize)*100)

        # Uptime
        $vmHostUptime = ([Management.ManagementDateTimeConverter]::ToDateTime($vmHostWmiData.LocalDateTime)) - ([Management.ManagementDateTimeConverter]::ToDateTime($vmHostWmiData.LastBootUpTime))

        # Processor socket and HT state
        $processorData = sGet-Wmi -CompName $vmHostItem -Namespace root\CIMv2 -Class Win32_Processor -Property DeviceID,NumberOfCores,NumberOfLogicalProcessors
        if ($processorData[1] -eq 1) {
            $socketCount = ($processorData[0] | ForEach-Object {$_.DeviceID} | select-object -unique).Count
            $coreCount = ($processorData[0].NumberOfCores | Measure-Object -Sum).Sum
            $logicalProcCount = ($processorData[0].NumberOfLogicalProcessors | Measure-Object -Sum).Sum

            if ($logicalProcCount -gt $coreCount) {
              $htState = "Active"
            } else {
                $htState = "Inactive"
            }
        } else {
            $socketCount = "-"
            $htState = "Unknown"
        }

        $vmHostLpCount = $vmHostGet.LogicalProcessorCount
        if (!$vmHostLpCount)
        {
            $vmHostLpCount = $logicalProcCount
        }

        # For Cluster Overview
        if(($Cluster) -and ($vmHostState -eq "Up"))
        {
            $ovUpNode = $ovUpNode + 1
            $ovTotalLP = $ovTotalLP + $vmHostLpCount
            $ovUsedMemory = $ovUsedMemory + ($vmHostWmiData.TotalVisibleMemorySize - $vmHostWmiData.FreePhysicalMemory)
            $ovTotalMemory = $ovTotalMemory + $vmHostWmiData.TotalVisibleMemorySize
        }

        # LP:VP Ratio
        $vmHostVpLpRatioRaw = $vmHostTotalVProc / $vmHostLpCount
        $vmHostVpLpRatio = ("{0:N2}" -f $vmHostVpLpRatioRaw).Replace(".00","")

        # Computer and Processor Manufacturer/Model Info
        $outVmHostComputerInfo = gwmi -ComputerName $vmHostItem -Class Win32_ComputerSystem -Property BootupState,Domain,Manufacturer,Model,NumberOfLogicalProcessors,NumberOfProcessors,Status,TotalPhysicalMemory
        $VMhostsDomains.add($vmHostItem, $outVmHostComputerInfo.Domain)
        $outVmHostProcModel = (gwmi -ComputerName $vmHostItem -Class Win32_Processor).Name
        if($outVmHostProcModel.count -gt 1)
        {
            $outVmHostProcModel = $outVmHostProcModel[0]
        }
        $outVmHostProcModel = $outVmHostProcModel.Replace("           "," ")

        # New Relic Infrastructure output - Host
        $vmHostMetrics = @{
          bootupState = $outVmHostComputerInfo.BootupState
          clusterName = $ClusterName
          domain = $vmHostGet.FullyQualifiedDomainName
          event_type = "HypervHostSample"
          hyperthreading = $htState
          hypervisorHostname = $vmHostGet.ComputerName
          logicalProcessors = $vmHostLpCount
          manufacturer = $outVmHostComputerInfo.Manufacturer
          migrationEnabled = $vmHostGet.VirtualMachineMigrationEnabled
          model = $outVmHostComputerInfo.Model
          name = $vmHostGet.ComputerName
          osVersion = $VMHostsOSVersions.($vmHostGet.ComputerName)
          processorModel = $outVmHostProcModel
          processorSocketCount = $socketCount
          state = $vmHostState
          status = $outVmHostComputerInfo.Status
          uptime = $vmHostUptime.TotalMilliseconds
          virtualProcessors = $vmHostTotalVProc
          vpLpRatio = ([math]::Round($vmHostVpLpRatioRaw,3))
          "mem.free_percent" = $TotalFreeMemoryPercentage
          "mem.free" = $TotalFreeMemory
          "mem.total" = $TotalVisibleMemory
          "mem.used" = $TotalUsedMemory
          "vm.running.clustered" = $vmHostRunningClusVmCount
          "vm.running.nonClustered" = $vmHostRunningNonClusVmCount
          "vm.running.total" = $vmHostRunningVmCount
          "vm.total" = $vmHostVmCount
        }
        $vmHostEntityName = "hypervisor:" + $ClusterName + ":" + $vmHostGet.ComputerName
        sAddToNRIData -entityName $vmHostEntityName -metrics $vmHostMetrics
    }

    # Add offline or unsupported standalone hosts
    if ($invalidVmHost)
    {
        $outVmHostState = "Inaccessible"

        [bytle]$numb = 0
        ForEach ($VMhostIN in $invalidVmHost)
        {

          # New Relic Infrastructure output - Host (inaccessible)
          $vmHostMetrics = @{
            event_type = "HypervHostSample"
            clusterName = $ClusterName
            domain = $VMhostsDomains.$VMhostIN
            hypervisorHostname = $VMhostIN
            name = $VMhostIN
            state = $outVmHostState
            vmHostErrMsg = $invalidVmHostMsg[$numb]
          }
          $vmHostEntityName = "hypervisor:" + $ClusterName + ":" + $VMhostIN
          sAddToNRIData -entityName $vmHostEntityName -metrics $vmHostMetrics

          $numb = $numb + 1
        }
    }

    # Add down cluster nodes
    if ($downClusterNodes)
    {
        $outErrMsg = "Hyper-V Cluster node is down or unavailable."
        ForEach ($downClusterNode in $downClusterNodes)
        {

          # New Relic Infrastructure output - Host (down node)
          $vmHostMetrics = @{
            event_type = "HypervHostSample"
            clusterName = $ClusterName
            domain = $VMhostsDomains.$downClusterNode
            hypervisorHostname = $downClusterNode
            name = $downClusterNode
            state = "Down or Unavailable"
            vmHostErrMsg = $outErrMsg
          }
          $vmHostEntityName = "hypervisor:"  + $ClusterName + ":" + $downClusterNode
          sAddToNRIData -entityName $vmHostEntityName -metrics $vmHostMetrics
        }
    }

#endregion

#region Gathering VM Information
#-------------------------------

    # Print MSG
    sPrint -MsgLevel "INFO" "Gathering Virtual Machine information..."

    # Generate Data Lines
    $cntVM = 0
    $vmNoInTable = 0
    $ovRunningVm = 0
    $ovPausedVm = 0

    # Active VHD Array
    $activeVhds = @()

    ForEach ($VMHostItem in $VMHosts) {

        $getVMerr = $null
        $VMs = Hyper-V\Get-VM -ComputerName $VMHostItem -ErrorVariable getVMerr -ErrorAction SilentlyContinue
        $vNetworkAdapters = Hyper-V\Get-VM -ComputerName $VMHostItem | Get-VMNetworkAdapter -ErrorAction SilentlyContinue

        # Offline Virtual Machine Configuration resources on this node
        if ($Cluster)
        {
            $offlineVmConfigs = $offlineVmConfigData | where{$_.OwnerNode -eq "$VMHostItem"}
            if ($offlineVmConfigs)
            {
                ForEach ($offlineVmConfig in $offlineVmConfigs)
                {
                  # New Relic Infrastructure output - VM
                  $vmMetrics = @{
                    event_type = "HypervVmSample"
                    domain = $VMhostsDomains.($offlineVmConfig.OwnerNode)
                    state = $offlineVmConfig.State
                    ownerGroup = $offlineVmConfig.OwnerGroup
                    clusterName = $offlineVmConfig.Cluster.Trim()
                    hypervisorHostname = $VMHostItem
                    name = $offlineVmConfig.Name
                    id = $offlineVmConfig.Id
                  }
                  $vmEntityName = "vm:" + $VMHostItem + ":" + $offlineVmConfig.Name
                  sAddToNRIData -entityName $vmEntityName -metrics $vmMetrics
                }
            }
        }

        # If Hyper-V\Get-VM is success
        if ($VMs)
        {
            $cntVM = $cntVM + 1

            foreach ($VM in $VMs)
            {
                $highL = $false
                $chargerVmTable = $null
                $chargerVmMemoryTable = $null
                $outVmReplReplicaServer = $null
                $outVmReplFrequency = $null

                # Table TR Color
                if([bool]!($vmNoInTable%2))
                {
                   #Even or Zero
                   $vmTableTrBgColor = ""
                }
                else
                {
                   #Odd
                   $vmTableTrBgColor = "#F9F9F9"
                }

                # Name and Config Path
                $outVmName = $VM.VMName
                $outVmPath = $VM.ConfigurationLocation

                # VM State
                $outVmState = $VM.State

                # IsClustered Yes or No
                if ($VM.IsClustered -eq $True)
                {
                    switch($VM.State) {
                      "Running" { $ovRunningVm = $ovRunningVm + 1 }
                      "Paused" { $ovPausedVm = $ovPausedVm + 1 }
                       {$_ -eq "Running" -Or $_ -eq "Paused"} {
                         if(!$VM.DynamicMemoryEnabled) {
                             $ovTotalVmMemory = $ovTotalVmMemory + $VM.MemoryStartup
                         } else {
                             $ovTotalVmMemory = $ovTotalVmMemory + $VM.MemoryMaximum
                         }
                         $ovUsedVmMemory = $ovUsedVmMemory + $VM.MemoryAssigned
                       }
                       "default" {}
                    }

                    # Clustered VM State
                    $getClusVMerr = $null
                    $outVmIsClustered = "Yes"
                    $clusVmState = (Get-ClusterResource -Cluster $ClusterName -VMId $VM.VMId -ErrorAction SilentlyContinue -ErrorVariable getClusVMerr).State

                    if ($getClusVMerr)
                    {
                        $outVmState = "Unknown"
                    }
                    elseif ($clusVmState -eq "Online")
                    {
                        if ($VM.State -eq "Paused")
                        {
                            $outVmState = "Paused"
                        }
                        else
                        {
                            $outVmState = "Running"
                        }
                    }
                    elseif ($clusVmState -eq "Offline")
                    {
                        if ($VM.State -eq "Saved")
                        {
                            $outVmState = "Saved"
                        }
                        else
                        {
                            $outVmState = "Off"
                        }
                    }
                    else
                    {
                        $outVmState = $clusVmState
                    }
                }
                else
                {
                    $outVmIsClustered = "No"
                }

                # Owner Host
                $outVmHost = $VM.ComputerName

                # vCPU
                $outVmCPU = $VM.ProcessorCount

                # IS State, Version and Color
                if ($VM.IntegrationServicesState -eq "Up to date")
                {
                    $outVmIs = "UpToDate"
                    $outVmIsVer = $VM.IntegrationServicesVersion
                }
                elseif ($VM.IntegrationServicesState -eq "Update required")
                {
                    $outVmIs = "UpdateRequired"
                    $outVmIsVer = $VM.IntegrationServicesVersion
                }
                else
                {
                    if ($vm.State -eq "Running")
                    {
                        if ($VM.IntegrationServicesVersion -eq "6.2.9200.16433")
                        {
                            $outVmIs = "UpToDate"
                            $outVmIsVer = $VM.IntegrationServicesVersion
                        }
                        elseif ($VM.IntegrationServicesVersion -eq $null)
                        {
                            $outVmIs = "NotDetected"
                            $outVmIsVer = "NotDetected"
                        }
                        else
                        {
                            $outVmIs = "MayBeRequired"
                            $outVmIsVer = $VM.IntegrationServicesVersion
                        }
                    }
                    else
                    {
                        $outVmIs = "NotDetected"
                        $outVmIsVer = "NotDetected"
                    }
                }

                # Checkpoints
                if ($VM.ParentSnapshotId)
                {
                    $outVmCheckpoint = "Yes"
                    $vmCheckpointCount = (Get-VMSnapshot -ComputerName $VM.ComputerName -VMName $VM.Name).Count
                }
                else
                {
                    $outVmCheckpoint = "No"
                    $outVmCheckpointCount = $null
                }

                # Replication
                if ($VM.ReplicationState -ne "Disabled")
                {
                    $getVmReplication = Get-VMReplication -ComputerName $VM.ComputerName -VMName $VM.Name

                    foreach ($getVmReplItem in $getVmReplication)
                    {
                        if(!$getVmReplItem.FrequencySec -eq $null -And $VMHostsOSVersions.$VMHostItem -like "6.2*") {
                          $getVmReplItem.FrequencySec = 300
                        }

                        # New Relic Infrastructure output - VM Network Adapater
                        $vmReplicaMetrics = @{
                          domain = $VMhostsDomains.$VMHostItem
                          event_type = "HypervVmReplicaSample"
                          health = $getVmReplItem.Health
                          hypervisorHostname = $VMHostItem
                          lastReplicationTime = $getVmReplItem.LastReplicationTime
                          mode = $getVmReplItem.Mode
                          name = $getVmReplItem.Name
                          primaryServer = $getVmReplItem.PrimaryServer
                          relationshipType = $getVmReplItem.RelationshipType
                          replicaServer = $getVmReplItem.ReplicaServer
                          state = $getVmReplItem.State
                          vmName = $outVmName
                        }
                        sAddToNRIData -metrics $vmReplicaMetrics
                    }
                }

                # Network Adapters
                $vmNetAdapters = ($vNetworkAdapters | where{$_.VMId -eq $VM.VMId})
                if ($vmNetAdapters)
                {
                    foreach ($vmNetAdapter in $vmNetAdapters)
                    {
                        # Type
                        if (!$vmNetAdapter.IsLegacy)
                        {
                            $outVMNetAdapterType = "Synthetic"
                        }
                        else
                        {
                            $outVMNetAdapterType = "Legacy"
                        }

                        # IP
                        if ($vmNetAdapter.IPAddresses)
                        {
                            if ($vmNetAdapter.IPAddresses.Count -gt 1)
                            {
                                foreach ($ipAddress in $vmNetAdapter.IPAddresses) {
                                  if ($ipAddress -match '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}') {
                                    $outVmNetAdapterNR = $ipAddress
                                    break;
                                  }
                                }
                                $outVmNetAdapterIP = ($vmNetAdapter.IPAddresses -join ', ').ToString()
                            }
                            else
                            {
                                $outVmNetAdapterIP = $vmNetAdapter.IPAddresses
                                $outVmNetAdapterNR = $vmNetAdapter.IPAddresses
                            }
                        }
                        else
                        {
                            $outVmNetAdapterIP = "Unable to get ip address information"
                        }

                        if ($vmNetAdapter.ClusterMonitored)
                        {
                            $outVmNetAdapterClusterMonitored = "Protected Network: On"
                        }
                        else
                        {
                            if ($VMHostsOSVersions.$VMHostItem -like "6.2*")
                            {
                                $outVmNetAdapterClusterMonitored = "Protected Network: N/A"
                            }
                            else
                            {
                                $outVmNetAdapterClusterMonitored = "Protected Network: Off"
                            }
                        }

                        # New Relic Infrastructure output - VM Network Adapater
                        $vmNetworkAdapterMetrics = @{
                          clusterMonitored = $outVmNetAdapterClusterMonitored
                          dhcpGuard = $vmNetAdapter.DhcpGuard
                          domain = $VMhostsDomains.$outVmHost
                          event_type = "HypervVmNetworkAdapterSample"
                          hypervisorHostname = $vmNetAdapter.ComputerName
                          id = ($vmNetAdapter.Id -replace '[^\\]+\\', '').ToLower()
                          ipAddress = $outVmNetAdapterNR
                          ipAddresses = $outVmNetAdapterIP
                          isConnected = $vmNetAdapter.Connected
                          macAddress = $vmNetAdapter.MacAddress
                          macIsDynamic = $vmNetAdapter.DynamicMacAddressEnabled
                          name = $vmNetAdapter.Name
                          portMirroringMode = $vmNetAdapter.PortMirroringMode
                          routerGuard = $vmNetAdapter.RouterGuard
                          switchId = $vmNetAdapter.SwitchId
                          switchName = $vmNetAdapter.SwitchName
                          type = $outVMNetAdapterType
                          vlan = $vmNetAdapter.VlanSetting.AccessVlanId
                          vmId = $vmNetAdapter.VMId
                          vmName = $outVmName
                        }
                        sAddToNRIData -metrics $VMNetworkAdapterMetrics
                    }
                }

                # Disks
                $getVhdErr = $null
                $vmDisks = Get-VHD -ComputerName $VMHostItem -VMId $vm.VMId -ErrorAction SilentlyContinue -ErrorVariable getVhdErr
                $vmPTDisks = Get-VMHardDiskDrive -ComputerName $VMHostItem -VMname $vm.name | where{$_.Path -like "Disk*"}

                # Pass-through
                if ($vmPTDisks)
                {
                  $vmPTDiskNo = 0
                  foreach ($vmPTDisk in $vmPTDisks)
                    {
                        $vmPTDiskNo = $vmPTDiskNo + 1
                        $ptDiskName = "Pass-through-disk-" + $vmPTDiskNo

                        # New Relic Infrastructure output - VM Pass-Through Disk
                        $vmDiskMetrics = @{
                          domain = $VMhostsDomains.$VMHostItem
                          event_type = "HypervVmDiskSample"
                          fragmentationPercentage = $vmDisk.FragmentationPercentage
                          hypervisorHostname = $VMHostItem
                          name = $ptDiskName
                          path = $vmPTDisk.Path
                          type = $vmPTDisk.ControllerType
                          vmName = $outVmName
                        }
                        sAddToNRIData -metrics $vmDiskMetrics
                    }
                }

                # VHD
                if ($vmDisks)
                {
                    foreach($vmDisk in $vmDisks)
                    {
                        # Name, Path, Type, Size and File Size
                        $vmDiskName = $vmDisk.Path.Split('\')[-1]

                        # For Cluster Overview
                        if ($VM.IsClustered -eq $true -and $VM.State -eq "Running")
                        {
                            $ovUsedVmVHD = $ovUsedVmVHD + $vmDisk.FileSize
                            $ovTotalVmVHD = $ovTotalVmVHD + $vmDisk.Size
                        }

                        # For Active VHDs File Size
                        $activeVhdFileSize = $vmDisk.FileSize

                        # Get Controller Type
                        $vmDiskControllerType = (Get-VMHardDiskDrive -ComputerName $VMHostItem -VMName $vm.VMName | where{$_.Path -eq $vmDisk.Path}).ControllerType

                        # If differencing disks exist
                        if ($vmDisk.ParentPath)
                        {
                            # Checkpoint label
                            $cpNumber = $vmCheckpointCount

                            if ($vmDisk.Path.EndsWith(".avhdx",1))
                            {
                                if (($cpNumber -ne 0) -or ($cpNumber -ne $null))
                                {
                                    $vmDiskName = "Checkpoint $cpNumber"
                                    $cpNumber = $cpNumber - 1
                                }
                            }

                            # Differencing disk loop
                            Do
                            {
                                $vmDiffDisk = Get-VHD -ComputerName $VMHostItem -Path $parentPath
                                $vmDiffDiskName = $vmDiffDisk.Path.Split('\')[-1]

                                # Checkpoint label
                                if ($vmDiskDiff.Path.EndsWith(".avhdx",1))
                                {
                                    if (($cpNumber -ne 0) -or ($cpNumber -ne $null))
                                    {
                                        $vmDiskName = "Checkpoint $cpNumber"
                                        $cpNumber = $cpNumber - 1
                                    }
                                }

                                # For Active VHD file size
                                $activeVhdFileSize = $activeVhdFileSize + $vmDiffDisk.FileSize

                                # For Cluster Overview
                                if ($VM.IsClustered -eq $true -and $VM.State -eq "Running")
                                {
                                    $ovUsedVmVHD = $ovUsedVmVHD + $vmDiffDisk.FileSize
                                }

                                # New Relic Infrastructure output - VM VHD Diff Disk
                                $vmDiskMetrics = @{
                                  attached  = $vmDiffDisk.Attached
                                  checkpointNumber = $cpNumber
                                  domain = $VMhostsDomains.$VMHostItem
                                  event_type = "HypervVmDiskSample"
                                  format = $vmDiffDisk.VhdFormat
                                  fragmentationPercentage = $vmDiffDisk.FragmentationPercentage
                                  hypervisorHostname = $VMHostItem
                                  isDiffDisk = $true
                                  name = $vmDiffDiskName
                                  path = $vmDiffDisk.Path
                                  type = $vmDiffDisk.VhdType
                                  vmName = $VM.ComputerName
                                  "size.max" = $vmDiffDisk.Size
                                  "size.used" = $vmDiffDisk.FileSize
                                }
                                sAddToNRIData -metrics $vmDiskMetrics

                            }
                            Until (($parentPath -eq $null) -or ($parentPath -eq ""))
                        }

                        # Active VHD Array ($activeVhds)
                        if ($VM.State -eq "Running")
                        {
                            $vhdHash = @{
                                Path      = $vmDisk.Path
                                Size      = $vmDisk.Size
                                FileSize  = $activeVhdFileSize
                                Host      = $VM.ComputerName
                                VhdType   = $vmDisk.VhdType
                                VhdFormat = $vmDisk.VhdFormat
                                Attached  = $vmDisk.Attached
                                VMName    = $VM.VMName
                            }

                            # Create PSCustom object
                            $customObjVHD = New-Object PSObject -Property $vhdHash

                            # Add to Array
                            $activeVhds += $customObjVHD
                        }

                        # New Relic Infrastructure output - VM VHD Disk
                        $vmDiskMetrics = @{
                          attached  = $vmDisk.Attached
                          domain = $VMhostsDomains.$VMHostItem
                          event_type = "HypervVmDiskSample"
                          format = $vmDisk.VhdFormat
                          fragmentationPercentage = $vmDisk.FragmentationPercentage
                          hypervisorHostname = $VMHostItem
                          isDiffDisk = $true
                          name = $vmDiskName
                          path = $vmDisk.Path
                          type = $vmDisk.VhdType
                          vmName = $VM.ComputerName
                          "size.max" = $vmDisk.Size
                          "size.used" = $vmDisk.FileSize

                        }
                        sAddToNRIData -metrics $vmDiskMetrics
                    }
                }

                # New Relic Infrastructure output - VM
                $vmMetrics = @{
                  checkpointCount = $vmCheckpointCount
                  clusterName = $ClusterName
                  domain = $VMhostsDomains.$VMHostItem
                  event_type = "HypervVmSample"
                  generation = $VM.Generation
                  hasCheckpoint = $outVmCheckpoint
                  hypervisorHostname = $VMHostItem
                  integrationServicesState = $VM.IntegrationServicesState
                  integrationServicesVersion = [string]$VM.integrationServicesVersion
                  isClustered = $VM.IsClustered
                  name = $outVmName
                  path = $outVmPath
                  processorCount = $VM.ProcessorCount
                  state = [string]$outVmState
                  uptime = ($VM.Uptime).TotalMilliseconds
                  version = $VM.Version
                  "cpu.usage" = $VM.CPUUsage
                  "mem.assigned" = $VM.MemoryAssigned
                  "mem.demand" = $VM.MemoryDemand
                  "mem.startup" = $VM.MemoryStartup
                  "mem.max" = $VM.MemoryMaximum
                  "mem.min" = $VM.MemoryMinimum
                }
                $vmEntityName = "vm:" + $VMHostItem + ":" + $outVmName
                sAddToNRIData -entityName $vmEntityName -metrics $vmMetrics
            }
        }
        # Error
        elseif ($getVMerr)
        {
            sPrint -MsgLevel "ERROR" -Message "$($VMHostItem): $($getVMerr.exception.message)"
            sPrint -MsgLevel "WARNING" -Message "Gathering VM Information for '$($VMHostItem)' failed."
            Continue
        }
        else
        # Blank
        {
            sPrint -MsgLevel "WARNING" -Message "$($VMHostItem): Does not have any Virtual Machines."
        }
    }

#endregion

#region Gathering Disk/Volume Information
#----------------------------------------

    # Print MSG
    sPrint -MsgLevel "INFO" "Gathering Disk/Volume information..."

    # Cluster
    if ($Cluster) {

        $ovUsedStorage = 0
        $ovTotalStorage = 0

        # Check and get WMI Data
        $clusResourceDiskData = sGet-Wmi -CompName $clusterName -Namespace root\MSCluster -Class MSCluster_Resource -AI -Filter "Type='Physical Disk'"

        if ($clusResourceDiskData[1] -eq 1)
        {
            $clusResourceDiskData = $clusResourceDiskData[0] | Sort-Object
            $clusResourceToDiskData = gwmi -ComputerName $clusterName -Namespace root\MSCluster -Class MSCluster_ResourceToDisk -Authentication PacketPrivacy -Impersonation Impersonate
            $clusDiskToDiskPartitionData = gwmi -ComputerName $clusterName -Namespace root\MSCluster -Class MSCluster_DiskToDiskPartition -Authentication PacketPrivacy -Impersonation Impersonate
            $clusDiskPartitionData = gwmi -ComputerName $clusterName -Namespace root\MSCluster -Class MSCluster_DiskPartition -Authentication PacketPrivacy -Impersonation Impersonate
            $msftDiskData = gwmi -ComputerName $clusterName -Namespace root\Microsoft\Windows\Storage -Class MSFT_Disk | where{$_.IsClustered -eq $true}
            $msClusterData = gwmi -ComputerName $clusterName -Namespace root\MSCluster -Class MSCluster_Cluster -Authentication PacketPrivacy -Impersonation Impersonate

            # If Quorum disk exists, determine the drive letter
            if ($msClusterData.QuorumTypeValue -eq 3)
            {
                if ($msClusterData.QuorumPath)
                {
                    $quorumPathLetter = ($msClusterData.QuorumPath).Substring(0,2)
                }
                else
                {
                    $quorumPathLetter = $null
                }
            }
            else
            {
                $quorumPathLetter = $null
            }

            # Each Cluster Disk Resource
            foreach($clusterDisk in $clusResourceDiskData)
            {

                # Disk State
                if ($clusterDisk.StatusInformation -eq 1)
                {
                    # In maintenance mode
                    $outDiskState = "Maintenance"
                }
                else
                {
                    $outDiskState = (sConvert-ClusterDiskState -StateValue $clusterDisk.State)
                }

                # Cluster Disk State, If...
                if ($clusterDisk.State -eq 2) # Online
                {
                    # Get DiskID and CSV Paths
                    $clusResourceRELPATH = $clusterDisk.__RELPATH
                    $clusDiskID = ($clusResourceToDiskData | where{$_.GroupComponent -eq $clusResourceRELPATH}).PartComponent
                    $shortClusDiskID = $clusDiskID.TrimStart("MSCluster_Disk.Id=`"").TrimEnd("`"")

                    # Get physical cluster disk information form MSFT_Disk
                    $thisMsftDisk = $msftDiskData | where{(($_.Signature -eq $shortClusDiskID) -or ($_.Guid -eq $shortClusDiskID))}
                    $clusterDiskBusType = sConvert-BusTypeName -BusTypeValue $thisMsftDisk.BusType
                    $clusterDiskPartitionStyle = sConvert-DiskPartitionStyle -PartitionStyleValue $thisMsftDisk.PartitionStyle
                    $outVolumeUsage = "CSV"

                    # IsClusterSharedVolume True
                    if ($clusterDisk.IsClusterSharedVolume -eq $true)
                    {
                        # If maintenance mode enabled
                        if ($clusterDisk.StatusInformation -eq 1)
                        {
                            $clusDiskPartitionPaths = ((($clusDiskToDiskPartitionData | where{$_.GroupComponent -eq $clusDiskID}).PartComponent) -replace "MSCluster_DiskPartition.Path=`"","").TrimEnd("`"")
                            $clusDiskVolumeData = Get-ClusterSharedVolume -Cluster $ClusterName -Name $clusterDisk.Name

                            foreach($clusDiskPartitionPath in $clusDiskPartitionPaths)
                            {
                                $outVolumePath = ($clusDiskVolumeData.SharedVolumeInfo | where{$_.Partition.Name -eq $clusDiskPartitionPath}).FriendlyVolumeName
                                $outVolumeName = $outVolumePath.Split("\")[-1]
                                $outVolumeFS = (($clusDiskVolumeData.SharedVolumeInfo.Partition) | where{$_.Name -eq $clusDiskPartitionPath}).FileSystem
                                $outVolumeTotalSize = (($clusDiskVolumeData.SharedVolumeInfo.Partition) | where{$_.Name -eq $clusDiskPartitionPath}).Size
                                $outVolumeFreeSpace = (($clusDiskVolumeData.SharedVolumeInfo.Partition) | where{$_.Name -eq $clusDiskPartitionPath}).FreeSpace
                                $outVolumeUsedSpace = (($clusDiskVolumeData.SharedVolumeInfo.Partition) | where{$_.Name -eq $clusDiskPartitionPath}).UsedSpace
                                $outVolumeFreePercent = [math]::Round((($clusDiskVolumeData.SharedVolumeInfo.Partition) | where{$_.Name -eq $clusDiskPartitionPath}).PercentFree)

                                # New Relic Infrastructure output- Clustered Disk
                                $vmDiskMetrics = @{
                                  clusterName = $ClusterName
                                  diskBusType = $clusterDiskBusType
                                  diskPartitionStyle = $clusterDiskPartitionStyle
                                  diskState = $outDiskState
                                  domain = $getCluster.Domain
                                  event_type = "HypervClusteredDiskSample"
                                  hypervisorHostname = $clusterDisk.OwnerNode
                                  name = $clusterDisk.Name
                                  quarumPath = $msClusterData.QuorumPath
                                  quorumPathLetter = $quorumPathLetter
                                  volumeFS = $outVolumeFS
                                  volumeName = $outVolumeName
                                  volumePath = $outVolumePath
                                  volumeUsage = $outVolumeUsage
                                  "disk.size" = $thisMsftDisk.Size
                                  "disk.allocated" = $thisMsftDisk.AllocatedSize
                                  "volume.total" = $outVolumeTotalSize
                                  "volume.free" = $outVolumeFreeSpace
                                  "volume.used" = $outVolumeUsedSpace
                                  "volume.percentFree" = $outVolumeFreePercent
                                }
                                sAddToNRIData -metrics $vmDiskMetrics
                            }
                        }
                        else
                        {
                            $clusDiskPartitionPaths = (($clusDiskToDiskPartitionData | where{$_.GroupComponent -eq $clusDiskID}).PartComponent).TrimStart("MSCluster_DiskPartition.Path=`"\\\\?\\Volume").TrimEnd("\\`"")

                            foreach($clusDiskPartitionPath in $clusDiskPartitionPaths) {
                                $outVolumePath = ($clusDiskPartitionData | where{$_.Path -match $clusDiskPartitionPath}).MountPoints
                                $outVolumeName = (($clusDiskPartitionData | where{$_.Path -match $clusDiskPartitionPath}).MountPoints).Split("\")[-1]
                                $outVolumeLabel = ($clusDiskPartitionData | where{$_.Path -match $clusDiskPartitionPath}).VolumeLabel
                                $outVolumeFS = ($clusDiskPartitionData | where{$_.Path -match $clusDiskPartitionPath}).FileSystem

                                $outVolumeTotalSize = ($clusDiskPartitionData | where{$_.Path -match $clusDiskPartitionPath}).TotalSize
                                $outVolumeFreeSpace = ($clusDiskPartitionData | where{$_.Path -match $clusDiskPartitionPath}).FreeSpace
                                $outVolumeUsedSpace = $outVolumeTotalSize - $outVolumeFreeSpace
                                $outVolumeFreePercent = [math]::Round((((($clusDiskPartitionData | where{$_.Path -match $clusDiskPartitionPath}).FreeSpace) / (($clusDiskPartitionData | where{$_.Path -match $clusDiskPartitionPath}).TotalSize))) * 100)

                                # For Cluster Overview
                                $ovUsedStorage = $ovUsedStorage + (($clusDiskPartitionData | where{$_.Path -match $clusDiskPartitionPath}).TotalSize - ($clusDiskPartitionData | where{$_.Path -match $clusDiskPartitionPath}).FreeSpace)
                                $ovTotalStorage = $ovTotalStorage + ($clusDiskPartitionData | where{$_.Path -match $clusDiskPartitionPath}).TotalSize

                                # Active VHD
                                $thisActiveVhd = $activeVhds | where{$_.Path -like "$outVolumePath*"}
                                if ($thisVhd)
                                {
                                    $activeVhdCount = $thisVhd.Count
                                    $activeVhdTotalFileSize = ($thisVhd.FileSize | measure -Sum).Sum
                                    $activeVhdTotalDiskSize = ($thisVhd.Size | measure -Sum).Sum
                                } else {
                                    $activeVhdCount = 0
                                    $activeVhdTotalFileSize = 0
                                    $activeVhdTotalDiskSize = 0
                                }

                                # New Relic Infrastructure output- Clustered Disk
                                $vmDiskMetrics = @{
                                  activeVHDCount = $activeVhdCount
                                  activeVhdTotalDiskSize = $activeVhdTotalDiskSize
                                  activeVHDTotalFileSize = $activeVhdTotalFileSize
                                  clusterName = $ClusterName
                                  diskBusType = $clusterDiskBusType
                                  diskPartitionStyle = $clusterDiskPartitionStyle
                                  diskState = $outDiskState
                                  domain = $getCluster.Domain
                                  event_type = "HypervClusteredDiskSample"
                                  hypervisorHostname = $clusterDisk.OwnerNode
                                  name = $clusterDisk.Name
                                  quarumPath = $msClusterData.QuorumPath
                                  quorumPathLetter = $quorumPathLetter
                                  volumeFS = $outVolumeFS
                                  volumeLabel = $outVolumeLabel
                                  volumeName = $outVolumeName
                                  volumePath = $outVolumePath
                                  volumeUsage = $outVolumeUsage
                                  "disk.size" = $thisMsftDisk.Size
                                  "disk.allocated" = $thisMsftDisk.AllocatedSize
                                  "volume.total" = $outVolumeTotalSize
                                  "volume.free" = $outVolumeFreeSpace
                                  "volume.used" = $outVolumeUsedSpace
                                  "volume.percentFree" = $outVolumeFreePercent
                                }
                                sAddToNRIData -metrics $vmDiskMetrics
                            }
                        }
                    }
                    else # IsClusterSharedVolume False
                    {
                        # Get Partition Paths (drives)
                        $clusDiskPartitionPaths = ($clusDiskToDiskPartitionData | where{$_.GroupComponent -eq $clusDiskID}).PartComponent

                        # If partition(s) on physical disk exists
                        if ($clusDiskPartitionPaths)
                        {
                            # Get partition (volume) information
                            foreach ($clusDiskPartitionPath in $clusDiskPartitionPaths)
                            {
                                $clusPartitionVolume = $clusDiskPartitionData | where{$_.__RELPATH -eq $clusDiskPartitionPath}
                                $assignedPT = $false
                                $driveLetterExist = $true

                                $outDiskOwner = $clusterDisk.OwnerNode
                                $outBusType = $busTypeName
                                $outDiskPartStyle = $diskPartitionStyle
                                $outVolumeLabel = $clusPartitionVolume.VolumeLabel
                                $outVolumeFS = $clusPartitionVolume.FileSystem

                                # Volume Name
                                if ($clusDiskPartitionPath -match "Volume")
                                {
                                    # Missing Volume (drive) Letter
                                    $outVolumeName = "No Drive Letter"
                                    $driveLetterExist = $false
                                }
                                elseif ($clusDiskPartitionPath -match "GLOBALROOT")
                                {
                                    # PT
                                    $outVolumeName = "PT Disk"
                                    $outVolumeLabel = "Assigned to '$($clusterDisk.OwnerGroup)' as a pass-through disk"
                                    $outVolumeFS = "-"
                                    $assignedPT = $true
                                }
                                else
                                {
                                    $outVolumeName = ($clusDiskPartitionPath -replace "MSCluster_DiskPartition.Path=`"","").TrimEnd("`"")
                                }

                                # Volume Usage Type
                                if ($outVolumeName -eq $quorumPathLetter)
                                {
                                    $thisVolumeUsage = "Quorum"
                                }
                                elseif ($assignedPT -eq $True)
                                {
                                    $thisVolumeUsage = "Pass-through"
                                }
                                else
                                {
                                    $thisVolumeUsage = $outVolumeUsage
                                }

                                $vmDiskMetrics = @{
                                  clusterName = $ClusterName
                                  diskBusType = $clusterDiskBusType
                                  diskPartitionStyle = $clusterDiskPartitionStyle
                                  diskState = $outDiskState
                                  domain = $getCluster.Domain
                                  event_type = "HypervClusteredDiskSample"
                                  hypervisorHostname = $clusterDisk.OwnerNode
                                  name = $clusterDisk.Name
                                  quarumPath = $msClusterData.QuorumPath
                                  quorumPathLetter = $quorumPathLetter
                                  volumeFS = $outVolumeFS
                                  volumeLabel = $outVolumeLabel
                                  volumeName = $outVolumeName
                                  volumePath = $outVolumePath
                                  volumeUsage = $thisVolumeUsage
                                }

                                # Volume Info
                                if (!$assignedPT)
                                {
                                    $outVolumeTotalSize = $clusPartitionVolume.TotalSize
                                    $outVolumeFreeSpace = $clusPartitionVolume.FreeSpace
                                    $outVolumeUsedSpace = $clusPartitionVolume.TotalSize - $clusPartitionVolume.FreeSpace
                                    $outVolumeFreePercent = [math]::Round(((($clusPartitionVolume.FreeSpace) / ($clusPartitionVolume.TotalSize))) * 100)

                                    # For Cluster Overview
                                    if(($outVolumeUsage -eq "Volume") -and ($clusterDisk.StatusInformation -ne 1) -and ($driveLetterExist -eq $true))
                                    {
                                        $ovUsedStorage = $ovUsedStorage + $outVolumeUsedSpace
                                        $ovTotalStorage = $ovTotalStorage + $outVolumeTotalSize
                                    }

                                    $activeVhdCount = 0
                                    $activeVhdTotalFileSize = 0
                                    $activeVhdTotalDiskSize = 0
                                    $thisActiveVhd = $activeVhds | where{($_.Path -like "$outVolumeName*") -and ($_.Host -eq $clusterDisk.OwnerNode)}
                                    if ($thisVhd)
                                    {
                                        $activeVhdCount = $thisVhd.Count
                                        $activeVhdTotalFileSize = ($thisVhd.FileSize | measure -Sum).Sum
                                        $activeVhdTotalDiskSize = ($thisVhd.Size | measure -Sum).Sum
                                    }

                                    $vmDiskMetrics.add("activeVHDCount", $activeVhdCount)
                                    $vmDiskMetrics.add("activeVHDTotalFileSize", $activeVhdTotalFileSize)
                                    $vmDiskMetrics.add("activeVhdTotalDiskSize", $activeVhdTotalDiskSize)
                                    $vmDiskMetrics.add("disk.size", $thisMsftDisk.Size)
                                    $vmDiskMetrics.add("disk.allocated", $thisMsftDisk.AllocatedSize)
                                    $vmDiskMetrics.add("volume.total", $outVolumeTotalSize)
                                    $vmDiskMetrics.add("volume.free", $outVolumeFreeSpace)
                                    $vmDiskMetrics.add("volume.used", $outVolumeUsedSpace)
                                    $vmDiskMetrics.add("volume.percentFree", $outVolumeFreePercent)
                                }

                                # New Relic Infrastructure output - Clustered Disk
                                sAddToNRIData -metrics $vmDiskMetrics

                                if(assignedPT) {
                                  Break
                                }
                            }
                        }
                        else
                        {
                            # OwnerGroup
                            if ($clusterDisk.OwnerGroup -eq "Available Storage")
                            {
                                $outVolumeName = "Unassigned Disk"
                                $thisVolumeUsage = "Unassigned"
                                $outVolumeLabel = "This clustered disk has not assigned for any purpose"
                            }
                            else
                            {
                                $outVolumeName = "PT Disk"
                                $thisVolumeUsage = "Pass-through"
                                $outVolumeLabel = "Assigned to '$($clusterDisk.OwnerGroup)' as a pass-through disk"
                            }

                            # New Relic Infrastructure output- Clustered Disk
                            $vmDiskMetrics = @{
                              clusterName = $ClusterName
                              diskBusType = $clusterDiskBusType
                              diskPartitionStyle = $clusterDiskPartitionStyle
                              diskState = $outDiskState
                              domain = $getCluster.Domain
                              event_type = "HypervClusteredDiskSample"
                              hypervisorHostname = $clusterDisk.OwnerNode
                              name = $clusterDisk.Name
                              quarumPath = $msClusterData.QuorumPath
                              quorumPathLetter = $quorumPathLetter
                              volumeLabel = $outVolumeLabel
                              volumeName = $outVolumeName
                              volumeUsage = $thisVolumeUsage
                              "disk.size" = $thisMsftDisk.Size
                              "disk.allocated" = $thisMsftDisk.AllocatedSize
                              "volume.total" = $outVolumeTotalSize
                              "volume.free" = $outVolumeFreeSpace
                              "volume.used" = $outVolumeUsedSpace
                              "volume.percentFree" = $outVolumeFreePercent
                            }
                            sAddToNRIData -metrics $vmDiskMetrics
                        }
                    }
                }
                else {
                    # New Relic Infrastructure output- Clustered Disk
                    $vmDiskMetrics = @{
                      clusterName = $ClusterName
                      diskState = $outDiskState
                      domain = $getCluster.Domain
                      event_type = "HypervClusteredDiskSample"
                      hypervisorHostname = $clusterDisk.OwnerNode
                      name = $clusterDisk.Name
                      quarumPath = $msClusterData.QuorumPath
                      quorumPathLetter = $quorumPathLetter
                    }
                    sAddToNRIData -metrics $vmDiskMetrics
                }
            }
        }
        elseif ($clusResourceDiskData[1] -ne 2)
        {
            sPrint -MsgLevel "ERROR" -Message "$ClusterName`: Gathering Disk/Volume information failed. $($clusResourceDiskData[0])"
        }
    }

    # Standalone
    if ($VMHost)
    {
        foreach ($computerName in $VMHosts)
        {
            $outDomain = (Get-VMHost -ComputerName $vmHostItem).FullyQualifiedDomainName
            $logicalDisks = sGet-Wmi -CompName $computerName -Namespace root\CIMv2 -Class Win32_LogicalDisk -AI -Filter "DriveType='3'"

            if ($logicalDisks[1] -eq 1)
            {
                $logicalDisks = $logicalDisks[0]
                $SystemDrive = ((gwmi -ComputerName $computerName -Class Win32_OperatingSystem).SystemDirectory).Substring(0,2)

                # Get WMI Data
                $logicalToDiskPartitionData = gwmi -ComputerName $computerName Win32_LogicalDiskToPartition
                $physicalDiskPathData = gwmi -ComputerName $computerName Win32_DiskDriveToDiskPartition
                $physicalDiskNameData = gwmi -ComputerName $computerName Win32_DiskDrive
                $msftDiskIdData = gwmi -ComputerName $computerName -Namespace root\Microsoft\Windows\Storage -Class MSFT_Partition
                $msftDiskData = gwmi -ComputerName $computerName -Namespace root\Microsoft\Windows\Storage -Class MSFT_Disk

                # Each logical disk
                foreach ($logicalDisk in $logicalDisks)
                {
                    # Filter for physical disk name
                    $logicalToDiskPartition = ($logicalToDiskPartitionData | where{$_.Dependent -eq $logicalDisk.Path}).Antecedent
                    $physicalDiskPath = ($physicalDiskPathData | where{$_.Dependent -eq $logicalToDiskPartition}).Antecedent
                    $physicalDiskName = (($physicalDiskNameData | where{($_.Path).Path -eq $physicalDiskPath}).Name).Replace("\\.\PHYSICALDRIVE","Disk ").Replace("PHYSICALDRIVE","Disk")

                    # Filter for other physical disk information
                    $msftDiskId = ($msftDiskIdData | where{$_.DriveLetter -eq ($logicalDisk.DeviceID).TrimEnd(":")}).DiskId
                    $msftDisk = $msftDiskData | where{$_.ObjectId -eq $msftDiskId}

                    # Logical disk (volume) information
                    $logicalDiskFreePercent = [math]::Round((($logicalDisk.FreeSpace) / ($logicalDisk.Size)) * 100)

                    # Physical disk information
                    $outMsftDiskBusType = sConvert-BusTypeName -BusTypeValue $msftDisk.BusType
                    $outMsftDiskPartitionStyle = sConvert-DiskPartitionStyle -PartitionStyleValue $msftDisk.PartitionStyle
                    $msftDiskState = "Online"

                    # Volume usage type
                    if ($logicalDisk.Name -eq $SystemDrive)
                    {
                        $logicalDiskUsage = "System"
                    }
                    else
                    {
                        $logicalDiskUsage = "Volume"
                    }

                    $thisActiveVhd = $activeVhds | where{($_.Path -like "$outLogicalDiskName*") -and ($_.Host -eq $msftDiskOwner)}
                    if ($thisActiveVhd)
                    {
                        $activeVhdCount = $thisVhd.Count
                        $activeVhdTotalFileSize = ($thisVhd.FileSize | measure -Sum).Sum
                        $activeVhdTotalDiskSize = ($thisVhd.Size | measure -Sum).Sum
                    } else {
                        $activeVhdCount = 0
                        $activeVhdTotalFileSize = 0
                        $activeVhdTotalDiskSize = 0
                    }

                    # New Relic Infrastructure output- Clustered Disk
                    $vmDiskMetrics = @{
                      activeVhdCount = $activeVhdCount
                      activeVhdTotalDiskSize = $activeVhdTotalDiskSize
                      activeVhdTotalFileSize = $activeVhdTotalFileSize
                      clusterName = $ClusterName
                      domain = $outDomain
                      event_type = "HypervHostLogicalDiskSample"
                      fileSystem = $logicalDisk.FileSystem
                      hypervisorHostname = $computerName
                      logicalDiskUsage = $logicalDiskUsage
                      logicalToDiskPartition = $logicalToDiskPartition
                      msftDiskId = $msftDiskId
                      name = $logicalDisk.Name
                      physicalDiskBusType = $outMsftDiskBusType
                      physicalDiskName  = $physicalDiskName
                      physicalDiskPartitionStyle = $outMsftDiskPartitionStyle
                      physicalDiskPath = $physicalDiskPath
                      physicalDiskState = $msftDiskState
                      volumeName = $logicalDisk.VolumeName
                      "logical.free" = $logicalDisk.FreeSpace
                      "logical.freePercent" = $logicalDiskFreePercent
                      "logical.size" = $logicalDisk.Size
                      "physical.allocated" = $msftDisk.AllocatedSize
                      "physical.size" = $msftDisk.Size
                    }
                    sAddToNRIData -metrics $vmDiskMetrics
                }
            }
            elseif ($logicalDisks[1] -eq 2)
            {
                Continue
            }
            else
            {
                # Error
                sPrint -MsgLevel "ERROR" -Message "$($computerName): Gathering Disk/Volume information failed. $($logicalDisks[0])"
                Continue
            }
        }
    }

#endregion

#region Cluster Overview Information
#-----------------------------------

    if($ovTotalNode -eq $null) { $ovTotalNode = 0 }
    if($ovTotalVm -eq $null) { $ovTotalVm = 0 }
    if($ovRunningVm -eq $null) { $ovRunningVm = 0 }
    if($ovTotalLP -eq $null) { $ovTotalLP = 0 }

    # New Relic Infrastructure output - Cluster overview
    $clusterMetrics = @{
      backupInProgress = $getCluster.BackupInProgress
      domain = $getCluster.Domain
      event_type = "HypervClusterSample"
      functionalLevel = $getCluster.ClusterFunctionalLevel
      logicalProcessors = $ovTotalLP
      name = $ClusterName
      sharedVolumeRoot = $getCluster.SharedVolumesRoot
      sharedVolumesEnabled = [string]$getCluster.EnableSharedVolumes
      upgradeVersion = $getCluster.ClusterUpgradeVersion
      "mem.reserved" = $getCluster.RootMemoryReserved
      "mem.size" = $ovTotalMemory
      "mem.used" = $ovUsedMemory
      "nodes.total" = $ovTotalNode
      "nodes.up" = $ovUpNode
      "storage.size" = $ovTotalStorage
      "storage.used" = $ovUsedStorage
      "vm.mem.size" = $ovTotalVmMemory
      "vm.mem.used" = $ovUsedVmMemory
      "vm.running" = $ovRunningVm
      "vm.total" = $ovTotalVm
      "vm.vhd.size" = $ovTotalVmVHD
      "vm.vhd.used" = $ovUsedVmVHD
    }
    $clusterEntityName = "cluster:"  + $ClusterName
    sAddToNRIData -entityName $clusterEntityName -metrics $clusterMetrics

#endregion

#region Write to NRI and Peace Out
#---------------------------------

    sWriteToNRI
    sPrint -MsgLevel "INFO" "Completed!"
    sPrint -MsgLevel "DEBUG" -Message "----- End   -----"

#endregion
