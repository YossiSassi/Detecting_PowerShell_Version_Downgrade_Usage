<# 
* Find powershell downgrade versions in use *
Can help with assessing if PS v2.0 is in use, on servers etc. before removing it, or as a Hunt for downgrade attacks. 
Can run with SCCM (locally), WinRM (Remotely) or any other agent/tool. 
Results can be collected via WEC/WEF, or queried remotely from the event log, eid 555

Comments to yossis@protonmail.com
Version 1.0
#>

# Set some variables (can change minimum version to alert on anything other than before PSv5.1)
$MinimumVersion = 5;
[int]$Counter = 0;

# Get relevant events
$Events = Get-WinEvent -FilterHashtable @{logname='Windows PowerShell';id=400}

if ($Events) {
$Events | ForEach-Object {
    $version = [Version] ($_.Message -replace '(?s).*EngineVersion=([\d\.]+)*.*','$1');
    if ($version -lt ([Version] "$($MinimumVersion).0")) {
        $Counter++
        }
    }
}

if ($Counter -ge 1)
    {
        # Write an event to System log (NOTE: Custom events cannot be created into security log)
        eventcreate /ID 555 /L SYSTEM /T INFORMATION /SO "PowerShell_Check" /D "PowerShell Downgrade Version(s) found to be in use.`nTotal of $Counter process(es) with versions less than $($MinimumVersion).0";   
        
        # Alternative: using Write-EventLog, but you need to register an event source FIRST, e.g. New-EventLog -LogName Security -Source "PowerShell_Check"
        # Write-EventLog -LogName Security -Source 'PowerShell (PowerShell)' -EventId 555 -EntryType Information -Message "PowerShell Downgrade Version(s) found to be in use.`nTotal of $Counter process(es) with versions less than $($MinimumVersion).0";
}