<#
    File: DirSync.psm1
    Version: 1.0
    Author: Simon Décosse (@simondotsh)
    License: MIT
    Repository: https://github.com/simondotsh/DirSync
#>

Add-Type -AssemblyName System.DirectoryServices.Protocols

function Sync-LAPS {
    <#
    .SYNOPSIS
        Synchronizes the LAPS password of computer accounts.

    .DESCRIPTION
        Uses the DirSync LDAP control to synchronize LAPS' attribute ms-Mcs-AdmPwd.
        Requires DS-Replication-Get-Changes and DS-Replication-Get-Changes-In-Filtered-Set.

    .EXAMPLE
        Sync-LAPS

    .EXAMPLE
        Sync-LAPS -LDAPFilter '(samaccountname=workstation01$)'

    .EXAMPLE
        Sync-LAPS -Server dc.contoso.com -Username Administrator -Password Password1$ -Domain contoso.com

    .EXAMPLE
        Sync-LAPS -UseLDAPS -IgnoreCert

    .LINK
        https://github.com/simondotsh/DirSync
    #>
    Param(
        # Target server to synchronize from.
        [string] $Server,
        # Domain username to request synchronization.
        [string] $Username,
        # Domain user password.
        [string] $Password,
        # Domain to authenticate to.
        [string] $Domain,
        # Use LDAPS to encrypt the request.
        [switch] $UseLDAPS,
        # Ignore certificate validation.
        [switch] $IgnoreCert,
        # LDAP filter of objects to synchronize.
        [string] $LDAPFilter
    )

    if (!$LDAPFilter) {
        $PSBoundParameters.LDAPFilter = "(objectClass=computer)"
    }

    Invoke-DirSync @PsBoundParameters -Attributes ("ms-Mcs-AdmPwd", "msLAPS-Password")
}

function Sync-Attributes {
    <#
    .SYNOPSIS
        Synchronizes the requested attribute(s).

    .DESCRIPTION
        Uses the DirSync LDAP control to synchronize any requested attribute(s), namely confidential and RODC filtered ones.
        Requires DS-Replication-Get-Changes-In-Filtered-Set and/or DS-Replication-Get-Changes depending on the attribute.

    .EXAMPLE
        Sync-Attributes -LDAPFilter '(samaccountname=unix_user)' -Attributes unixUserPassword

    .EXAMPLE
        Sync-Attributes -LDAPFilter '(samaccountname=unix_user)' -Attributes unixUserPassword,description

    .EXAMPLE
        Sync-Attributes -Server dc.contoso.com -Username Administrator -Password Password1$ -Domain contoso.com -LDAPFilter '(samaccountname=unix_user)' -Attributes unixUserPassword

    .EXAMPLE
        Sync-Attributes -UseLDAPS -IgnoreCert -LDAPFilter '(samaccountname=unix_user)' -Attributes unixUserPassword

    .LINK
        https://github.com/simondotsh/DirSync
    #>
    Param(
        # Target server to synchronize from.
        [string] $Server,
        # Domain username to request synchronization.
        [string] $Username,
        # Domain user password.
        [string] $Password,
        # Domain to authenticate to.
        [string] $Domain,
        # Use LDAPS to encrypt the request.
        [switch] $UseLDAPS,
        # Ignore certificate validation.
        [switch] $IgnoreCert,
        # LDAP filter of objects to synchronize.
        [Parameter(Mandatory)][string] $LDAPFilter,
        # Attribute(s) to synchronize.
        [Parameter(Mandatory)][string[]] $Attributes
    )
    
    Invoke-DirSync @PsBoundParameters
}

function Invoke-DirSync {
    Param(
        [string] $Server,
        [string] $Username,
        [string] $Password,
        [string] $Domain,
        [switch] $UseLDAPS,
        [switch] $IgnoreCert,
        [Parameter(Mandatory)][string] $LDAPFilter,
        [Parameter(Mandatory)][string[]] $Attributes
    )

    $Connection = Get-Connection @PsBoundParameters

    $SearchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest($Connection.defaultNamingContext, $LDAPFilter, "Subtree", $Attributes)
    $DirSyncRC = New-Object System.DirectoryServices.Protocols.DirSyncRequestControl
    $SearchRequest.Controls.Add($DirSyncRC) | Out-Null

    $Response = $Connection.SendRequest($SearchRequest)

    foreach ($Entry in $Response.Entries) {
        Write-Host "Object:" $Entry.distinguishedName

        foreach ($Attribute in $Attributes) {
            for ($i = 0; $i -lt $Entry.Attributes[$Attribute].Count; $i++) {
                $Value = $Entry.Attributes[$Attribute][$i]
                Write-Host "${Attribute}: $Value"
            }
        }
        
        Write-Host
    }
}

function Get-Connection {
    Param(
        [string] $Server,
        [string] $Username,
        [string] $Password,
        [string] $Domain,
        [switch] $UseLDAPS,
        [switch] $IgnoreCert
    )

    if (!$Server) {
        $PSBoundParameters.Server = $env:USERDNSDOMAIN
    }

    $DefaultNamingContext = Get-Default-Naming-Context @PSBoundParameters

    if ($UseLDAPS) {
        $Server += ":636"
    }

    $LDAPId = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server)
    $Connection = New-Object System.DirectoryServices.Protocols.LDAPConnection($LDAPId)
    $Connection | Add-Member -MemberType NoteProperty -Name "defaultNamingContext" -Value $DefaultNamingContext;

    if ($Username -and $Password -and $Domain) {
        $Connection.Credential = New-Object System.Net.NetworkCredential($Username, $Password, $Domain) 
    }

    if ($UseLDAPS) {
        $Connection.SessionOptions.SecureSocketLayer = $true

        if ($IgnoreCert) {
            $Connection.SessionOptions.VerifyServerCertificate = { return $true }
        }
    }

    return $Connection
}

function Get-Default-Naming-Context {
    Param(
        [string] $Server,
        [string] $Username,
        [string] $Password,
        [switch] $UseLDAPS,
        [switch] $IgnoreCert
    )

    <#
      I haven't found a clean way to get the default naming context with the possibility of not validating the certificate.
      For this reason, with -IgnoreCert, this LDAP traffic to get the context can be seen over the wire, but SendRequest will be encrypted.
    #>
    if ($UseLDAPS -and -not $IgnoreCert) {
        $RootDir = New-Object System.DirectoryServices.DirectoryEntry("LDAP://${Server}/RootDSE", $Username, $Password, "SecureSocketsLayer")
    }
    else {
        $RootDir = New-Object System.DirectoryServices.DirectoryEntry("LDAP://${Server}/RootDSE", $Username, $Password)
    }

    if (-not (Get-Member -InputObject $RootDir -Name "defaultNamingContext" -MemberType Properties)) {
        Write-Error "Failed to connect to the LDAP server. Are your credentials valid, and if using LDAPS, is the certificate valid?"
        Break
    }

    return $RootDir.Properties["defaultNamingContext"].Value
}

Export-ModuleMember -Function Sync-LAPS, Sync-Attributes