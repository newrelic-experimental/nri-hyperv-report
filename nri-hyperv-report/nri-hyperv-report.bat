@ECHO OFF
set runStr=
if defined Cluster (
  set runStr=%runStr% -Cluster %Cluster%
)
if defined VMHost (
  set runStr=%runStr% -VMHost %VMHost%
)
if defined LogLevel (
  set runStr=%runStr% -LogLevel %LogLevel%
)
powershell.exe -NoLogo -file "%~dp0\nri-hyperv-report.ps1" %runStr%
