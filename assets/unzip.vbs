Set ArgObj = WScript.Arguments
zipFile = ArgObj(0)

pwd = CreateObject("Scripting.FileSystemObject").GetAbsolutePathName(".")
input = pwd & "\" & zipFile
output = pwd & "\"

Set shell = CreateObject( "Shell.Application" )
Set source = shell.NameSpace(input).Items()
Set target = shell.NameSpace(output)
shell.NameSpace(target).CopyHere(source)
