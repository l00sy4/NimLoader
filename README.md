# NimLoader

A shellcode loader that injects into a process of your choice. It uses NTAPI for everything besides getting the PID of the process specified by the user. 

### Usage

Copy your payload into the shellcode array, change the size appropriately and compile it. Afterwards, 

`.\loader.exe notepad`

### To-do

- Use `NtQuerySystemInformation` for process enumeration. This is quite tedious, but I will implement it when I have more free time.
