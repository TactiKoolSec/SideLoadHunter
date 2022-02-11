# Sysmon-SideLoadHunter

Through continued research of executable files vulnerable to sideloading on
Windows systems, X-Force has identified a list of executables name and the
associated DLL which can be sideloaded.

To assist in the real-time detection of these sideload targets, X-Force has
migrated the known sideload list into a Sysmon configuration aimed to log module
loads for the associated executables and DLLS.
