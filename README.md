# DirSync
DirSync is a simple proof of concept PowerShell module to demonstrate the impact of delegating `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-In-Filtered-Set`.

* `DS-Replication-Get-Changes` allows to read the value of [confidential attributes](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential#summary).
* `DS-Replication-Get-Changes-In-Filtered-Set`, coupled with `DS-Replication-Get-Changes`, allows to read the value of confidential and [Read-Only Domain Controller (RODC) filtered](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema#rodc-filtered-attribute-set) attributes, such as [Local Administrator Password Solution](https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-laps)'s (LAPS) `ms-Mcs-AdmPwd`.

See technical details at https://simondotsh.com/infosec/2022/07/11/dirsync.html.

## Usage
`Import-Module .\DirSync.psm1`

## Sync-LAPS
Uses the DirSync LDAP control to synchronize LAPS' attribute `ms-Mcs-AdmPwd`. Requires `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-In-Filtered-Set`.

### Synchronize the LAPS password of all computer accounts using the current domain context
`Sync-LAPS`

### Synchronize the LAPS password of all computer accounts from a WORKGROUP host
`Sync-LAPS -Server dc.contoso.com -Username Administrator -Password Password1$ -Domain contoso.com`

### Synchronize the LAPS password of the provided LDAP filter
`Sync-LAPS -LDAPFilter '(samaccountname=workstation01$)'`

### Synchronize the LAPS password of all computer accounts over LDAPS, and ignore certificate validation.
`Sync-LAPS -UseLDAPS -IgnoreCert`

## Sync-Attributes
Uses the DirSync LDAP control to synchronize any requested attribute(s), namely confidential and RODC filtered ones. Requires `DS-Replication-Get-Changes-In-Filtered-Set` and/or `DS-Replication-Get-Changes` depending on the attribute.

The usage is identical to `Sync-LAPS`, except it requires`-LDAPFilter` and `-Attributes`.

### Synchronize the unixUserPassword attribute using the current domain context
`Sync-Attributes -LDAPFilter '(samaccountname=unix_user)' -Attributes unixUserPassword`

### Synchronize multiple attributes
`Sync-Attributes -LDAPFilter '(samaccountname=unix_user)' -Attributes unixUserPassword,description`

## Acknowledgements
Thank you to [@marcan2020](https://twitter.com/marcan2020) for his usual code reviews.

## License
See the `LICENSE` file for legal wording. Essentially it is MIT, meaning that I cannot be held responsible for whatever results from using this code, and do not offer any warranty. By agreeing to this, you are free to use and do anything you like with the code.