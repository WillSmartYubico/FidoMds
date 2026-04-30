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

function ConvertTo-YubicoFirmwareVersion {
    [CmdletBinding()]
    param ( 
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        $authenticatorversion
    )
    
    begin {

    }
    
    process {
        if ($authenticatorversion -gt 50200 ) {
            $major = ($authenticatorversion -shr 16 ) % 256
            $minor = ($authenticatorversion -shr 8 ) % 256
            $patch = ($authenticatorversion ) % 256   
        }
        else {
            $major = [math]::Floor(($authenticatorversion / 10000))
            $minor = [math]::Floor(($authenticatorversion / 100)) % 100
            $patch = [math]::Floor(($authenticatorversion )) % 100
        }
        "$major.$minor.$patch"

    }
    
    end {
        
    }
}

function ConvertFrom-YubicoFirmwareVersion {
    [CmdletBinding()]
    param ( 
        [string] $firmwareversion
    )
    
    begin {

    }
    
    process {
        $firmwareversion -split '\.'
        ($major -shl 16) + ($minor -shl 8) + ($patch)
    }
    
    end {
        
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
