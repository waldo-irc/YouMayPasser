# Summary
YouMayPasser is an x64 implementation of Gargoyle (https://github.com/JLospinoso/gargoyle)

BLOG POST HERE: https://www.arashparsa.com/bypassing-pesieve-and-moneta-the-easiest-way-i-could-find/

It contains several parts.

- Lockd: This is the main Gargoyle component
- sRDI-Master: This has been slightly re worked to provide a free mechanism.
- test.profile: This sample profile shows required options to work
- ShellcodeRDI.py: This is the altered python generator with the new sRDI assembly

## Stable PeSieve and Moneta Bypass and Clean Exits.
### This gif demonstrates full functionality and stability of the code on Windows 10.
![PESieve Bypassed](images/Stable.gif?raw=true "PE Sieve Bypass")

## Stable Moneta Bypass
![Moneta Bypassed](images/Moneta.gif?raw=true "Moneta Bypass")

### IOCs
Below are a list of current IOCs

- The new sRDI assembly can of course by statically detected in memory.
- The DLL loads are leveraged in order to obtain the required ropgadgets, these can all be monitored and alerted on
- VEH Handlers constantly getting created and deleted not originating from disk (These get removed on sleep so it cannot be detected on sleep)
- VEH Handlers getting created that aren't generated from disk
- The SetThreadContext injection leveraged to spoof the start address is in itself suspicious as these calls are often only used by debuggers

#### I will fix none of these issues.  This is nothing more than an x64 gargoyle POC to demonstrate how it can be leveraged to bypass PeSieve and Moneta.

#### shoutouts
1. Ret address spoofing - Namaszo (https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html)
2. Timer sleep - computerBeat (https://blat-blatnik.github.io/computerBear/making-accurate-sleep-function/)
3. VEH Hooks - CheatEngine Forums https://www.cheatengine.org/forum/viewtopic.php?t=610689&sid=c329059fbe5c36ef296bce5ef72decfc
