## Detecting PowerShell Version Downgrade Usage
This repository consists of several scripts to assist in finding Powershell Downgrade versions being used (e.g. PSv2.0), to assess before removing it (if being used, for example, on servers), or as a Threat Hunt for Downgrade Attacks.<br><br>
Script 1:
## Find-PSDowngradeUsage.ps1 ###
Can help with assessing if PS v2.0 is in use, on servers etc. before removing it, or as a Hunt for downgrade attacks.<br>
Can run with SCCM (locally), WinRM (Remotely) or any other agent/tool.<br>
Results can be collected via WEC/WEF, or queried remotely from the event log, event id 555 is written with the details, if usage of legacy versions is found.<br>
#### NOTE: You can change the version number to hunt for (default is anything below 5.x as minimum).<br>
#### You can also change the event id being written, or where you want it to be written (or not to be written as all, just report to console, with minor editing of the code).<br>

Example:
```
.\Find-PSDowngradeUsage.ps1
```
Example of post-run results, reporting evidence of PS downgrade versions usage to the SYSTEM event log, with custom event id 555:<br><br>
![Sample results](/screenshots/findpsdowngradeusage_sshot1.png) <br><br>

Script 2:
## Get-ADServersPSDowngradeUse.ps1 ###
Finds powershell downgrade versions in use on all Servers in an Active Directory Domain.<br>
Can help with assessing if PS v2.0 is in use by querying all servers remotely, as a step before removing it, or as a Hunt for downgrade attacks.<br>
Uses RPC to query relevant events.<br>
Regarding Permissions - Remote Event Log access needed, e.g. 'Event Log Readers' or Local admin on Servers.<br>
#### NOTE: Use the switch -SaveResultsToCSV to save detailed run results to a CSV file (ComputerName, Availability in Port ping - True|False, Downgrade versions found - True|False, Number of events/processes launched)<br>
NOTE2: You can change the ldap filter to query another scope (default is servers only, active in the last 30 days).<br>
You can also change the event id being written, or where you want it to be written.<br>

Example:
```
.\Get-ADServersPSDowngradeUse.ps1 -SaveResultsToCSV
```
Example run of querying all active servers in the domain, with one server down, and another reporting legacy versions being used:<br><br>
![Sample results](/screenshots/getadserverspsdowngradeuse_sshot1.png) <br><br>

Example run where all servers are up and responding, yet only one has downgrade PS versions usage evidence:<br><br>
![Sample results](/screenshots/getadserverspsdowngradeuse_sshot2.png) 
