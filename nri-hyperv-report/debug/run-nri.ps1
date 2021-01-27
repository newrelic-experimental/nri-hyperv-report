Param (
    [parameter(Mandatory=$False)]
    [bool]$RunVerbose = $false
)
				
$svcname = "newrelic-infra"
$nrilogfile = "C:\Temp\$svcname.log"
$nriconffile = "C:\Program Files\New Relic\$svcname\$svcname.yml"
$verbon	= "verbose: 1"
$verboff = "verbose: 0"
$file = Get-Content -path "$nriconffile"

if($RunVerbose) {
	echo "Starting $svcname with Verbose Logging ON"
	if($file -match "verbose")
	{
		(($file) -replace "$verboff", "$verbon") | Set-Content -Path "$nriconffile"
	} else {
		Add-Content -Path "$nriconffile" -Value "$verbon"
	}
} else {
	echo "Starting $svcname with Verbose Logging OFF"
	if($file -match "verbose") {
		(($file) -replace "$verbon", "$verboff") | Set-Content -Path "$nriconffile"
	} else {
		Add-Content -Path "$nriconffile" -Value "$verboff"
	}
}

net stop $svcname
del $nrilogfile
net start $svcname
