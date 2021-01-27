@ECHO OFF
if defined LogLevel (
  set runStr=-LogLevel %LogLevel%
) else (
  set runStr=
)

if defined Cluster (
  set runStr=%runStr% -Cluster %Cluster%
)
if defined VMHost (
  set runStr=%runStr% -VMHost %VMHost%
)

powershell.exe -NoLogo -file "%~dp0\nri-hyperv-report.ps1" %runStr%
