#requires -modules jwt

<#
.SYNOPSIS
    Retrieves, validates and parses the FIDO metadata.
.DESCRIPTION
    Retrieves, validates and parses the FIDO metadata.  
    Includes an option to flatten metadata into an easier to sort and filter format.
    Automatically removes legalheader and icon from each entry for easier viewing.
.EXAMPLE
    .\Get-FidoMdsEntries.ps1 -ProtocolFamily fido2 -IncludeStatus FIDO_CERTIFIED -Flatten 
    Gets the list of all FIDO2 authenticators that are FIDO_CERTIFIED (includes all L1 and L2 authenticators), and flattens the output. 
#>
[CmdletBinding()]
param (
    # Filter on the protocol family.  FIDO2 is the default as most relying parties that do AAGUID filtering only process FIDO2 attestations.  
    [Parameter()]
    [ValidateSet('uaf','u2f','fido2')]
    [string[]]
    $ProtocolFamily = 'fido2',
    # If present, only show entries that have one the selected status.
    [Parameter()]
    [ValidateSet('NOT_FIDO_CERTIFIED','FIDO_CERTIFIED_L1', 'FIDO_CERTIFIED', 'FIDO_CERTIFIED_L2', 'REVOKED')]
    [Alias('Status')]
    [string]
    $IncludeStatus,
    # If present, filter out entries that have any of the selected statuses.
    [Parameter()]
    [ValidateSet('NOT_FIDO_CERTIFIED','FIDO_CERTIFIED_L1', 'FIDO_CERTIFIED', 'FIDO_CERTIFIED_L2', 'REVOKED')]
    [string]
    $ExcludeStatus,
    # Flatten entries for easier sorting and filtering
    [switch]
    $Flatten
)
function Flatten-Entry {
    param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        $aaguid, 
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]
        $aaid, 
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [object[]]
        $metadataStatement,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [object[]] 
        $statusReports,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string] 
        $timeOfLastStatusChange
    )
    begin {}

    process {
        if ($statusReports) {
            $status = $statusReports.status
        }
    
    
        $entry = @{
            aaid = $aaid
            timeOfLastStatusChange = $timeOfLastStatusChange
            status = $status
        }
    
        $excludemetadataStatementproperties = @(
            'icon', 'legalheader','authenticatorGetInfo', 'aaid'
        )
        $excludeAuthenticatorGetInfoProperties = @(
            'aaguid' #duplicate
        )
    
        if ($metadataStatement) {
            $properties = $metadataStatement | get-member -MemberType NoteProperty | Where-Object {$_.Name -notin $excludemetadataStatementproperties}
            foreach ($propertyname in $properties.Name) {
                $entry.Add($propertyname, $metadataStatement.$propertyname)
            }
    
            if ($metadataStatement.authenticatorGetInfo) {
                $properties = $metadataStatement.authenticatorGetInfo | get-member -MemberType NoteProperty | Where-Object {$_.Name -notin $excludeAuthenticatorGetInfoProperties}
                foreach ($propertyname in $properties.Name) {
    
                    $entry.Add("getinfo_$propertyname", $metadataStatement.authenticatorGetInfo.$propertyname)
                }
            }
    
            if ($metadataStatement.attestationRootCertificates) {
                $CertificateObjects = $metadataStatement.attestationRootCertificates | ConvertFrom-Base64Certificate
                $entry.Add('attestationRootCertificateObjects', $CertificateObjects)
            }
        }
    
        [PSCustomObject]$entry
    }

    end {

    }
}

<#
.SYNOPSIS
    Converts a base64 encoded certificate to an X509Certificates
.DESCRIPTION
    Converts a base64 encoded certificate to an X509Certificates
    Removes  -----BEGIN CERTIFICATE----- and -----END CERTIFICATE----- if required.  
    Trims leading and trailing whitespace.
#>
function ConvertFrom-Base64Certificate {
    [CmdletBinding()]
    param (
        # Parameter help description
        [Parameter(ValueFromPipeline)]
        [String]
        $Base64Certificate
    )
    
    begin {}
    
    process {
        $Base64 = $Base64Certificate.replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','').Trim()
        [System.Security.Cryptography.X509Certificates.X509Certificate2]::new( [Convert]::FromBase64String($base64))
    }
    
    end {}
}

function Get-CertsFromURL {
    [CmdletBinding()]
    param (
        [string]
        $URL
    )
    
    try {
        $RootsDocument = (Invoke-WebRequest -Uri $URL).Content 
    }
    catch {
        throw "Unable to get certificate(s) from $URL"
    }

    $pattern = "-----BEGIN CERTIFICATE-----\s[A-Za-z0-9=\s\+\/]*\s-----END CERTIFICATE-----"
    $certificates = [regex]::Matches($RootsDocument, $pattern)
    
    foreach ($certificate in $certificates.value) {
        $base64 = $certificate.replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','').Trim()
        [System.Security.Cryptography.X509Certificates.X509Certificate2]::new( [Convert]::FromBase64String($base64))
    }
        
}


#Get Globalsign Root for validating MDS
$GlobalSignRootURI = 'https://valid.r3.roots.globalsign.com/'
$MDSRoot = Get-CertsFromURL $GlobalSignRootURI

# Get MDS Document
$MDSURI = 'https://mds3.fidoalliance.org/'
try {
    Invoke-WebRequest -Uri $MDSURI -OutFile 'latest.blob.jwt' 
}
catch {
    throw "Unable to retrieve MDS from $MDSURI.  Check network connection and try again."
}

$jwt = Get-Content 'latest.blob.jwt' -Raw


$header = Get-JwtHeader -jwt $jwt | ConvertFrom-Json

$certs = @()
$x5c = $header.X5c
foreach ($x5c_cert in $header.x5c) {
    $Bytes = $x5c_cert | ConvertFrom-Base64UrlString -AsByteArray
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$bytes)
    $certs += $cert
} 

$signingcert = $certs | Where-Object {$_.subject -match 'CN=mds.fidoalliance.org'}

# Test that the JWT is not using NULL as the Signature Alg

if ($header.alg -eq 'NONE') {
    throw "MDS JWT signature algorithm is NONE.  JWT cannot be verified."
}

# Test that the JWT signature is valid
try {
    $SignatureResult = Test-Jwt -jwt $jwt -Cert $certs[0]
}
catch {
    throw "Error while attempting to validate MDS JWT signature"
}

if (-not $SignatureResult){
    throw "Unable to validate MDS JWT signature"
}
else 
{
    Write-Host -ForegroundColor Green "MDS Signature Verified"
}    


try {

    $CertChain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain -ArgumentList $false
    $CertChain.ChainPolicy.TrustMode = 'CustomRootTrust'
    #$Root = get-item Cert:\LocalMachine\My\5ACE31E2AED3FA8F09CEA0F8134BFD88DF5BF701 
    $CertChain.ChainPolicy.CustomTrustStore.Add($MDSRoot) | Out-Null
    
    $ChainResult = $certChain.Build($signingcert) 
}
catch {
    throw "Error while attempting to validate MDS certificate chain"
}

if (-not $ChainResult) {
    throw "Unable to validate MDS Signing Certificate Chain"
}
else
{
    Write-Host -ForegroundColor Green "MDS Signing Certificate Chain Verified"
}

# If all of the checks are OK
if ($ChainResult -and $SignatureResult -and ($header.alg -ne 'none')) {
    $payload = Get-JwtPayload -jwt $jwt | ConvertFrom-Json
    $MDSVersion = $payload.no
    $date = get-date -Format 'yyyy-MM-dd'
    $MDSFileName = "mds-$MDSVersion-$date.jwt"
    $JSONFileName = "mds-$MDSVersion-$date.json"

    Move-Item 'latest.blob.jwt' $MDSFileName -Force
    $payload | ConvertTo-Json -Depth 100 | Out-File $JSONFileName -Force
}

$entries = $payload.entries

Write-Verbose "$($entries.count) entries total."

#Filter on Protocol Family
if ($ProtocolFamily) {
    $entries = $entries | Where-Object {$_.metadataStatement.ProtocolFamily -in $ProtocolFamily}
    Write-Verbose "$($entries.count) entries after filtering for protocol family: $($ProtocolFamily -join ', ')"
}

if ($IncludeStatus) {
    $entries = $entries | Where-Object {$_.statusreports.status -contains $IncludeStatus}
}

if ($ExcludeStatus) {
    $entries = $entries | Where-Object {$_.statusreports.status -notcontains $ExcludeStatus}

}

if ($flatten) {
    $entries | Flatten-Entry
}
else {
    $entries
}

