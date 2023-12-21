# NimLoader

A shellcode loader that injects into a process of your choice. It uses NTAPI for everything besides getting the PID of the process specified by the user, for which I used `CreateToolhelp32Snapshot`.

### Usage

Copy your payload into the shellcode array, change the size appropriately and compile it. Afterwards, 

`.\loader.exe notepad`
