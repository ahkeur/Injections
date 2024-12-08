import std/dynlib

#[

Basic code execution using DLL loading. 
Steps :
1. Get a malicious DLL on the disk.
2. Load the DLL using loadLib function from dynlib.
3. When the DLL is loaded, the DllMain function is executed with the DLL_PROCESS_ATTACH flag, which can be abused to execute code.

]#

proc main(): void = 

    # msfvenom -p windows/x64/exec CMD=calc.exe -f dll -o malicious.dll
    var mydll = loadLib("sample/malicious.dll")

    if mydll == nil:
        echo "Failed to load library"
        quit(1)

when isMainModule:
    main()