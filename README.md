# NimLoader

A shellcode loader that injects into a process of your choice. It uses NTAPI for everything besides getting the PID of the process specified by the user. I decided `NtQuerySystemInformation` was too tedious to implement in Nim.

### Usage

`.\loader.exe notepad`
