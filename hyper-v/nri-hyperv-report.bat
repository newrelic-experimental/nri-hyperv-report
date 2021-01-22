@ECHO OFF
powershell.exe -NoLogo -file "%~dp0\nri-hyperv-report.ps1" -Cluster %Cluster% -LogLevel %LogLevel% 
