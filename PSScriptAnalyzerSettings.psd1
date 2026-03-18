@{
    ExcludeRules = @(
        # Write-Host is intentional — these are interactive installer scripts
        # that report progress to the console.
        'PSAvoidUsingWriteHost'

        # BOM encoding is not needed — files are UTF-8 without BOM, which is
        # standard for cross-platform repos.
        'PSUseBOMForUnicodeEncodedFile'

        # Our Remove-* functions are internal helpers always called intentionally.
        # ShouldProcess support would add noise with no benefit.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
