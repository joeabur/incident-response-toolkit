@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Colourless Write-Output is intentional in scripts/ (output is consumed by users and tests).
        'PSAvoidUsingWriteHost',
        # Internal helpers mutate in-memory objects only; they never change system state.
        'PSUseShouldProcessForStateChangingFunctions',
        # Data-source wrappers intentionally keep plural nouns (Get-IRRawProcess etc.).
        'PSUseSingularNouns',
        # Parameters that are consumed inside script blocks/closures (and Config kept for a uniform collector
        # signature) are reported as unused; the rule does not follow script-block scope.
        'PSReviewUnusedParameter'
    )
    Rules        = @{
        PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1', '7.0') }
    }
}
