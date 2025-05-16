# Get an individual metadata statement from the MDS and save it locally as a JSON document.
[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $AAGUID
)

$authenticator = .\Get-FidoMdsEntries.ps1 -ProtocolFamily fido2 | Where-Object {$_.aaguid -eq $AAGUID}
if (-not $authenticator) {
    Write-Error "AAGUID $AAGUID not found in the MDS. Check the AAGUID and try again."
}  
$authenticator.metadatastatement | ConvertTo-Json -Depth 10 | Out-File "$AAGUID.metadata.json"