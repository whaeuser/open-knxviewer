$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$desktop = [Environment]::GetFolderPath('Desktop')
$shell = New-Object -ComObject WScript.Shell

$shortcut = $shell.CreateShortcut("$desktop\KNX Viewer starten.lnk")
$shortcut.TargetPath = "wscript.exe"
$shortcut.Arguments = "`"$dir\start_server.vbs`""
$shortcut.WorkingDirectory = $dir
$shortcut.IconLocation = "C:\Windows\System32\shell32.dll,14"
$shortcut.Description = "KNX Viewer Server starten"
$shortcut.Save()

Write-Host "Desktop-Verknuepfung erstellt: KNX Viewer starten"
