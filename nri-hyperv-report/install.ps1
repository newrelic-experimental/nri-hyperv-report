
Param (
    [parameter(
                Mandatory=$false,
                HelpMessage='If using this installation to poll Cluster(s) (Default: $true)')]
                [bool]$UseForClusters = $true,
    [parameter(
                Mandatory=$false,
                HelpMessage='Generate config file of clusters discovered on a given domain (Default: $true)')]
                [bool]$GenerateConfig = $true,
    [parameter(
                Mandatory=$false,
                HelpMessage='Domain to search for Clusters (Default: Domain of this Computer.)')]
                [string]$ConfigDomain =	$(gwmi win32_ComputerSystem).Domain,
    [parameter(
                Mandatory=$false,
                HelpMessage='Path to New Relic Infrastructure (Default: C:\Program Files\New Relic\newrelic-infra)')]
                [string]$NRIPath = "C:\Program Files\New Relic\newrelic-infra"
)

$IntegrationName = "nri-hyperv-report"
$RunInterval = "3600s"
$timeOutTime = "600s"

Write-Host "## Installing $IntegrationName ##"

$BinDir = "$NRIPath\custom-integrations"
$ConfigDir = "$NRIPath\integrations.d"
$ConfigFile = "$IntegrationName-config.yml"
$GeneratedConfigFile = $ConfigFile + ".generated"
$TemplateConfigFile = $ConfigFile + ".template"
$NRIAgentSoftware = "New Relic Infrastructure Agent"
$NRIAgentService = "newrelic-infra"

$ScriptDir = Split-Path $script:MyInvocation.MyCommand.Path

Write-Host " Admin requirement check..."

### require admin rights
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
  Write-Warning "   This setup needs admin permissions. Please run this file as admin."
  Break
}

Write-Host " ...passed!"

# Controls for runtime environment operating system version, Hyper-V PowerShell and Clustering PowerShell modules
Write-Host " Checking and installing prerequisites to run $IntegrationName..."

# Import Hyper-V Module 1.1 (Windows 10 or Server 2016 higher to Server 2012 R2 or older)
$hyperVModuleVersion = 1.1
if (Get-Module Hyper-V -ListAvailable | ? {$_.Version -eq "$hyperVModuleVersion"}) {
    Write-Host "   Using Hyper-V $hyperVModuleVersion Module."
    Remove-Module Hyper-V -ErrorAction SilentlyContinue
    Import-Module Hyper-V -RequiredVersion $hyperVModuleVersion
}

$thisOs = gwmi -Class Win32_OperatingSystem -Property Caption,Version

if ($thisOs.Version) {
    if (($thisOs.Version -like "6.2*") -or ($thisOs.Version -like "6.3*") -or ($thisOs.Version -like "10.0*")) {
        Write-Host "   Operating system is supported as script runtime environment."
        if ($thisOs.Caption -like "Microsoft Windows 8*") {
            # Check Hyper-V PowerShell
            if ((Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-Management-PowerShell -Online).State -eq "Enabled") {
                Write-Host "   Hyper-V PowerShell Module is OK."
            }
            else {
                Write-Warning "   Hyper-V PowerShell Module is not found. Please enable manually and run this script again."
                Write-Warning "   You can use `"Turn Windows features on or off`" to enable `"Hyper-V Module for Windows PowerShell`"."
                Break
            }

            # Check Failover Cluster PowerShell
            if ($UseForClusters) {
                if (Get-Hotfix -ID KB2693643 -ErrorAction SilentlyContinue) {
                    if ((Get-WindowsOptionalFeature -FeatureName RemoteServerAdministrationTools-Features-Clustering -Online).State -eq "Enabled") {
                        Write-Host "   Failover Clustering PowerShell Module is already installed."
                    }
                    else {
                        Write-Warning "   Failover Clustering PowerShell Module is not found. Please enable manually and run this script again."
                        Write-Warning "   You can use `"Turn Windows features on or off`" to enable `"Failover Clustering Tools`"."
                        Break
                    }
                }
                else {
                    Write-Warning "   Remote Server Administration Tools (RSAT) is not found."
                    Write-Warning "   Please download (KB2693643) and install manually and run this script again."
                    Break
                }
            }
        } else {
            # Check Hyper-V PowerShell
            if ((Get-WindowsFeature -Name "Hyper-V-PowerShell").Installed) {
                Write-Host "   Hyper-V PowerShell Module is already installed."
            } else {
                Write-Host "   Hyper-V PowerShell Module is not found."
                Write-Host "   Installing Hyper-V PowerShell Module... "
                Add-WindowsFeature -Name "Hyper-V-PowerShell" -ErrorAction SilentlyContinue | Out-Null

                if (!(Get-WindowsFeature -Name "Hyper-V-PowerShell").Installed) {
                    Write-Warning "   Hyper-V PowerShell Module could not be installed. Please install it manually and run this script again."
                    Break
                }
            }

            # Check Failover Cluster PowerShell
            if ($UseForClusters) {
                if ((Get-WindowsFeature -Name "RSAT-Clustering-PowerShell").Installed) {
                    Write-Host "   Failover Clustering PowerShell Module is OK."
                } else {
                    Write-Host "   Failover Clustering PowerShell Module is not found."
                    Write-Host "   Installing Failover Clustering PowerShell Module..."
                    Add-WindowsFeature -Name "RSAT-Clustering-PowerShell" | Out-Null

                    if (!(Get-WindowsFeature -Name "RSAT-Clustering-PowerShell").Installed) {
                        Write-Warning "   Failover Clustering PowerShell Module could not be installed. Please install it manually and run this script again."
                        Break
                    }
                }
            }
        }
    }
    else {
        Write-Warning "   Incompatible operating system version detected. Supported operating systems are Windows Server 2012 and above."
        Break
    }
} else {
    Write-Warning "   Could not detect operating system version."
    Break
}

Write-Host " Checking for $NRIAgentSoftware and permissions..."

$nriInstalled = ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*).DisplayName -Match $NRIAgentSoftware).Length -gt 0

if(!$nriInstalled) {
	Write-Warning "   $NRIAgentSoftware is not installed. Please install and re-run this installer."
  Write-Warning "   Guided procedure: https://one.nr/04ERPKVDYwW"
  Break
}

Write-Host "   Please enter the user credentials to run $IntegrationName (requires a Domain administrator)"
$credentials = Get-Credential -Message "Please enter the user credentials to run $IntegrationName (requires a Domain administrator)"

$filter = 'Name=' + "'" + $NRIAgentService + "'" + ''
$service = Get-WMIObject -class Win32_Service -Filter $filter
$service.Change($null,$null,$null,$null,$null,$null,$credentials.UserName,$credentials.GetNetworkCredential().password) | Out-Null

Write-Host " ...finished."

if($ConfigDomain -and $UseForClusters) {
  Write-Host " Generating config file for Clusters found on $ConfigDomain"

  $allClusters = Get-Cluster -Domain $ConfigDomain
  if($allClusters) {
    Write-Host "   $($allClusters.length) Clusters discovered. Checking cluster reachability."

    Clear-Content $GeneratedConfigFile -ErrorAction SilentlyContinue | Out-Null
    Add-Content -Path $GeneratedConfigFile -Value "### Generated by nri-hyperv-report install.ps1"
    Add-Content -Path $GeneratedConfigFile -Value "integrations:"
    foreach($thisCluster in $allClusters) {
      $clusterErr = $null
      Get-Cluster -Name $thisCluster.Name -ErrorVariable clusterErr -ErrorAction SilentlyContinue | Out-Null
      if(!$clusterErr) {
        Write-Host "   $($thisCluster.Name) was found in domain and is reachable. Added to $GeneratedConfigFile."
        Add-Content -Path $GeneratedConfigFile -Value "  - name: nri-hyperv-report"
        Add-Content -Path $GeneratedConfigFile -Value "    interval: $RunInterval"
        Add-Content -Path $GeneratedConfigFile -Value "    inventory_source: metadata/system"
        Add-Content -Path $GeneratedConfigFile -Value "    timeout: $timeOutTime"
        Add-Content -Path $GeneratedConfigFile -Value "    env:"
        Add-Content -Path $GeneratedConfigFile -Value "      Cluster: $($thisCluster.Name)"
      } else {
        Write-Warning "   $($thisCluster.Name) was found in domain, but is unreachable. Error: $($error[0].Exception.Message)"
        Write-Warning "   Added but commented-out in $GeneratedConfigFile."
        Add-Content -Path $GeneratedConfigFile -Value "`#  - name: nri-hyperv-report"
        Add-Content -Path $GeneratedConfigFile -Value "`#    interval: $RunInterval"
        Add-Content -Path $GeneratedConfigFile -Value "`#    inventory_source: metadata/system"
        Add-Content -Path $GeneratedConfigFile -Value "`#    env:"
        Add-Content -Path $GeneratedConfigFile -Value "`#      Cluster: $($thisCluster.Name)"
      }
    }
  } else {
    Write-Warning "   No Clusters found on $ConfigDomain. Skipping config file generation."
  }
  Write-Host " ...finished."
}

Write-Host " Copying $IntegrationName files to $NRIAgentSoftware..."

Copy-Item -Force -Recurse "$ScriptDir\$IntegrationName.*" -Destination $BinDir

# Order of priority: (1) customer-generated, (2) script-generated, (3) template
if (Test-Path $ScriptDir\$ConfigFile -PathType Leaf) {
  Write-Host "   $ConfigFile exists, will copy to $ConfigDir"
  Copy-Item -Force $ScriptDir\$ConfigFile -Destination $ConfigDir
} elseif (Test-Path $ScriptDir\$GeneratedConfigFile -PathType Leaf) {
  Write-Host "   $GeneratedConfigFile exists, will copy to $ConfigDir as $ConfigFile"
  Copy-Item -Force $ScriptDir\$GeneratedConfigFile -Destination $ConfigDir\$ConfigFile
} elseif (Test-Path $ScriptDir\$TemplateConfigFile -PathType Leaf) {
  Write-Host "   $TemplateConfigFile exists, will copy to $ConfigDir as $ConfigFile"
  Copy-Item -Force $ScriptDir\$TemplateConfigFile -Destination $ConfigDir\$ConfigFile
} else {
  Write-Warning "   No suitable config file exists to copy to $ConfigDir."
  Write-Warning "   Please add one manually to $ConfigDir, then restart New Relic Infrastructure Agent in Windows Services."
  Break
}

Write-Host " ...finished."
Write-Host " Restarting New Relic Infrastructure agent..."

$nrServiceInfo = Get-Service -Name $NRIAgentService
if ($nrServiceInfo.Status -eq 'Running') {
  Stop-Service -Name $NRIAgentService
}

Start-Service -Name $NRIAgentService -ErrorVariable svcStartErr -ErrorAction SilentlyContinue

if($svcStartErr) {
  Write-Warning "   Error starting $($NRIAgentService): $($error[0].Exception.Message)"
  Write-Warning "   If you see this error, ensure that your user has the 'Log on as a service' right on this computer."
  Write-Warning "   Run 'secpol.msc' -> Local Policies -> User Rights Assignment -> Add user to 'Log on as a service'"
} else {
  Write-Host " ...finished."
}

Write-Host "## Finished installing $IntegrationName ##"
