<#
.SYNOPSIS
    Validates that every certificate in AttestationCertificates chains back to a root certificate in AttestationRoots.
.DESCRIPTION
    Validates that every certificate in AttestationCertificates chains back to a root certificate in AttestationRoots.   
    AttestationIntermediates is optional.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [object[]]
    $AttestationRoots,
    [Parameter()]
    [object[]]
    $AttestationIntermediates,
    [Parameter(ValueFromPipeline=$true)]
    [object[]]
    $AttestationCertificates
)

begin {
    # Ensure that at least one certificate validates
    $any = $false
    # Ensure that all certificates validate
    $every = $true 
}

process {
    foreach ($Cert in $AttestationCertificates) {
        $CertChain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain -ArgumentList $false
        $CertChain.ChainPolicy.TrustMode = 'CustomRootTrust'
        $CertChain.ChainPolicy.RevocationMode = 'NoCheck'
        $AttestationRoots | foreach-object {
            $CertChain.ChainPolicy.CustomTrustStore.Add($_) | Out-Null
        }
    
        if ($AttestationIntermediates){
            $AttestationIntermediates | foreach-object {
                if ($_.thumbprint -ne $cert.Thumbprint) {
                    $CertChain.ChainPolicy.ExtraStore.Add($_) | Out-Null
                }
            }
        }
    
        $result =  $certChain.Build($Cert)
        $any = $any -or $result
        $every = $every -and $result        
    }
       
}

end {
    $any -and $every
}

