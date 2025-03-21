# FidoMds
Downloads and parses FIDO alliance MDS.  Intended as a tool to help organizations keep their relying parties configured with the correct AAGUIDs for a specific set vendors. 

# Requirements

Requires the JWT module from https://www.powershellgallery.com/packages/JWT/1.9.1

```powershell
Install-Module JWT -Scope CurrentUser
```

# Usage

Run `Get-FidoMdsEntries.ps1` to get a list of entries from the FIDO MDS.

# Example

See `example.ps1` for an example of the process to use a manufacturer's root attestation certificates to filter the MDS down to a specific manufacturer. 