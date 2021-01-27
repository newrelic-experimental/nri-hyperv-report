Param (
    [parameter(Mandatory=$False)]
    [bool]$RunDebug = $false,
	
    [parameter(Mandatory=$True)]
    [string]$Cluster
)

$intgname = "nri-hyperv-report"
$intgscript = "C:\Program Files\New Relic\newrelic-infra\custom-integrations\$intgname.ps1"
$intglogpath = "C:\Temp"
$intglog = "$intglogpath\$intgname.log"

if(Test-Path -Path $intglog -PathType leaf) {
	del $intglog
}

if($RunDebug -eq $true) {
	write-host "Running $intgname with PSDebug Tracing enabled"
	Set-PSDebug -Trace 1
} else {
	 "Running $intgname with PSDebug Tracing disabled"
	Set-PSDebug -Trace 0
}

& "$intgscript" -Cluster $Cluster -LogLevel DEBUG -LogFilePath $intglogpath