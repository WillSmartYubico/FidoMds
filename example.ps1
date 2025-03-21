<#
.SYNOPSIS
    Generates X509Certificate2 objects from a string containing one or more PEM encoded certificates.
#>
function Split-PEMCertificates{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        [string]
        $PEMContents
    )
    
    $pattern = "-----BEGIN CERTIFICATE-----\s[A-Za-z0-9=\s\+\/]*\s-----END CERTIFICATE-----"
    $certificates = [regex]::Matches($PEMContents, $pattern)
    
    foreach ($certificate in $certificates.value) {
        #For each certificate, remove the BEGIN and END blocks, then trim any whitespace from the beginning or end.
        $base64 = $certificate.replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','').Trim()
        [System.Security.Cryptography.X509Certificates.X509Certificate2]::new( [Convert]::FromBase64String($base64))
    }
        
}

# Get Root and Intermediate Certificates from the web
# Ideally these lists of certificates should be pre-downloaded and independently validated, but that is out of scope for this example.
Invoke-WebRequest 'https://developers.yubico.com/PKI/yubico-ca-certs.txt' -OutFile Manufacturer_roots.txt
Invoke-WebRequest 'https://developers.yubico.com/PKI/yubico-intermediate.pem' -OutFile Manufacturer_intermediates.pem

# Load the manufacturer's root and intermediate certificates
$Manufacturer_Roots =  Get-Content .\Manufacturer_roots.txt -Raw | Split-PEMCertificates
$Manufacturer_Intermediates = Get-Content .\Manufacturer_intermediates.pem -Raw | Split-PEMCertificates

# Retrieve, validate and parse the MDS
# Flatten the file for easier searching and sorting
# generate .Net X509Certificate2 objects for each of the certificates in attestationRootCertificate
# filter the MDS entries to only FIDO2 authenticators 
# filter the MDS entries to only FIDO_CERTIFIED authenticators
$MDSEntries = .\Get-FidoMdsEntries.ps1 -ProtocolFamily fido2 -IncludeStatus FIDO_CERTIFIED -Flatten 

# For each MDS entry, test the attestationRootCertificates
$ManufacturerMDSEntries = $MDSEntries | Where-Object {$_.attestationRootCertificateObjects | ./Test-AttestationCertificateChain.ps1 -AttestationRoots $Manufacturer_Roots -AttestationIntermediates $Manufacturer_Intermediates}

# Display a table of authenticator AAGUIDS, descriptions and versions
$ManufacturerMDSEntries | Select-Object aaguid, description, authenticatorversion | Sort-Object authenticatorVersion | Format-Table -AutoSize
# Display the total number of AAGUIDs in the list.
$ManufacturerMDSEntries.Count

#Export a CSV with the list of Entries
$ManufacturerMDSEntries | Select-Object aaguid, description, authenticatorversion | Export-Csv -Path "AAGUIDs.csv" -Force
