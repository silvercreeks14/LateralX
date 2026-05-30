Set WShell = CreateObject("WScript.Shell")
Set FSO    = CreateObject("Scripting.FileSystemObject")
Dim AppDir : AppDir = FSO.GetParentFolderName(WScript.ScriptFullName)
WShell.CurrentDirectory = AppDir
WShell.Run "pythonw """ & AppDir & "\launcher.pyw""", 0, False
