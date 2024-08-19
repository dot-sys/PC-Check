# PC-Check
Simple tool to safely dump system logs in PC Check.
This will be fully local, no data will be externally collected.
Running PC Checking Programs, including this script, outside of PC Checks may have impact on the outcome.
Tool is open for everybody to look into the code.

### Usage of other Software
The script invokes the following CLI tools:
- [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) by Nir Sofer (more infos at nirsoft.net)
- [strings2](https://github.com/glmcdona/strings2) by Geoff McDonald (more infos at split-code.com)
- [PECmd](https://github.com/EricZimmerman/PECmd), [EvtxCmd](https://github.com/EricZimmerman/evtx), [SBECmd](https://www.sans.org/tools/sbecmd/), [RECmd](https://github.com/EricZimmerman/RECmd), [SQLECmd](https://github.com/EricZimmerman/SQLECmd), [ACC Parser](https://github.com/EricZimmerman/AppCompatCacheParser) and [WxTCmd](https://github.com/EricZimmerman/WxTCmd) from Eric Zimmerman Tools (more infos at ericzimmerman.github.io)
I do not claim any rights to the programs and thank the developers.

### Invoke Script
To directly invoke the script in Powershell use:

New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null; Set-Location "C:\temp"; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dot-sys/PC-Check/master/PCCheck.ps1" -OutFile "PC-Check.ps1"; Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force; .\PC-Check.ps1
