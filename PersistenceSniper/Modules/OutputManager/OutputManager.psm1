function Write-Log {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("CSV", "JSON", "EVENT")]
        [string]$LogType,

        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $true)]
        [Collections.ArrayList]$Results
    ) 
    

    Begin {

    }

    Process {
        switch ($LogType) {
            "CSV" {
                $Results |
                Export-Csv $Destination -NoTypeInformation

            }
            "JSON" {
                $Results | 
                ConvertTo-Json | Out-File $Destination
            }
            "EVENT" {
                # Variables
                $LogName = "Application"            # The target event log (e.g., "Application", "System", "Security", or a custom log)
                $Source = $Destination     # A unique name for your event source
                $EventID = 1001                     # The Event ID you want to use (must be an integer)
                $EventType = "Warning"          # Event type (e.g., "Error", "Warning", "Information", "SuccessAudit", or "FailureAudit")
                #$Message = "My custom event message" # The event message
                
                foreach ($entry in $Results)
                {
                    
                }
                
            }

        }
    }
}

Export-ModuleMember -Function Write-Log