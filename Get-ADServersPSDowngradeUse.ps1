<# 
* Find powershell downgrade versions in use on Servers in an Active Directory Domain *
Can help with assessing if PS v2.0 is in use by querying all servers remotely, as a step before removing it, or as a Hunt for downgrade attacks.
Uses RPC. Event Log access needed, e.g. 'Event Log Readers' or Local admin on Servers.

Comments to yossis@protonmail.com
Version 1.0.1 - Added better error handling, especially when no events found
#>
[cmdletbinding()]
param(
    [switch]$SaveResultsToCSV
)

# Set some variables (can change minimum version to alert on anything other than before PSv5.1)
$MinimumVersion = 5;
[int]$MinVersionCounter = 0;
[int]$HostCounter = 0;

# Set date to get computer accounts that logged on in the last 30 days
$Date = (Get-Date).AddDays(-30);
$FileTimeUtc = $Date.ToFileTimeUtc();

# Get computer names from AD
$ds = new-object system.directoryservices.directorysearcher;
# Can remove the (operatingsystem=*server*) filter if you want to get all computer objects, including workstations/endpoints etc.
$ds.Filter = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingsystem=*server*)(lastlogontimestamp>=$FileTimeUtc))";
$ds.PageSize = 100000; $ds.SizeLimit = 100000;
$Computers = $ds.FindAll().Properties.name;

# Set function for quick port ping, short timeout
filter Invoke-PortPing {((New-Object System.Net.Sockets.TcpClient).ConnectAsync($_,135)).Wait(100)}

if (!$Computers)
    {
        "[!] No computer accounts found for the relevant query. quiting.";
        break
}

if ($SaveResultsToCSV)
    {
        $ReportName = "$(Get-Location)\PSDowngradeUse_$(get-date -Format ddMMyyyyHHmmss).csv";
        # open stream writer for the csv report
        $SW = New-Object System.IO.StreamWriter $ReportName;
        $SW.AutoFlush = $true;
        $SW.WriteLine('ComputerName,PingStatus,PSDowngradeDetected,NumberOfEventsDetected')
}

# set errors to silent
$CurrentEAP = $ErrorActionPreference;
$ErrorActionPreference = "silentlycontinue";

foreach ($ComputerName in $Computers) {
    $HostCounter++;

    Write-Host "Pinging computer $HostCounter of $($Computers.count)...";
    if (($ComputerName | Invoke-PortPing) -eq "True") {
        Write-Host "[x] Checking for PS Downgrade events on $ComputerName" -ForegroundColor Cyan;

        # Get relevant events
        $Events = Get-WinEvent -FilterHashtable @{logname='Windows PowerShell';id=400} -ComputerName $ComputerName;
        if (!$?)
            {
                Write-Host "$($Error[0].exception.Message)" -ForegroundColor DarkYellow
        }

        if ($Events) {
        $Events | ForEach-Object {
            $version = [Version] ($_.Message -replace '(?s).*EngineVersion=([\d\.]+)*.*','$1');
            if ($version -lt ([Version] "$($MinimumVersion).0")) {
                $MinVersionCounter++
                }
            }

        if ($MinVersionCounter -ge 1)
            {
                Write-Host "[!] PowerShell Downgrade Version(s) found to be in use on $ComputerName.`nTotal of $MinVersionCounter process(es) with versions less than $($MinimumVersion).0" -ForegroundColor Yellow;
                                
                if ($SaveResultsToCSV)
                    {
                        $SW.WriteLine("$ComputerName,TRUE,TRUE,$MinVersionCounter")
                }

                # reset minimum version counter for this computer in the loop
                $MinVersionCounter = 0;
        }
        elseif ($SaveResultsToCSV)
            {
                $SW.WriteLine("$ComputerName,TRUE,FALSE,")
        }
    }
        
        elseif ($SaveResultsToCSV)
            {
                $SW.WriteLine("$ComputerName,TRUE,FALSE,")
        }
    }
    else # RPC ping failed, so no access to event log (Firewall etc.)
        {
            Write-Host "[!] Ping to $ComputerName failed. skipping host." -ForegroundColor Red;
            if ($SaveResultsToCSV)
                {
                    $SW.WriteLine("$ComputerName,FALSE,,")
            }
    }
}

# wrap up
if ($SaveResultsToCSV) {
    # close streamWriter and handles
    $SW.Close();
    $SW.Dispose();
    Write-Host "`nReport saved to $ReportName." -ForegroundColor Green
}

# wrap up
[gc]::Collect();
$ErrorActionPreference = $CurrentEAP