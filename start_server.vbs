Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

strDir = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\") - 1)
WshShell.CurrentDirectory = strDir

' Start server (batch exits quickly, server runs in background)
WshShell.Run "openknxviewer.bat start", 0, True

' Read port from config.json (default 8002)
Dim port : port = 8002
Dim cfgPath : cfgPath = strDir & "\config.json"
If fso.FileExists(cfgPath) Then
    Dim content : content = fso.OpenTextFile(cfgPath, 1).ReadAll
    Set re = New RegExp
    re.Pattern = """server_port""\s*:\s*(\d+)"
    If re.Test(content) Then
        port = re.Execute(content)(0).SubMatches(0)
    End If
End If

' Wait for server to be ready, then open browser
WScript.Sleep 2000
WshShell.Run "http://localhost:" & port, 1, False
