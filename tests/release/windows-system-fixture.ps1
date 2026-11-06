# The real NRPT fixture is disabled until a test-created rule can be identified
# without adopting or deleting a rule another installation owns.

[CmdletBinding()]
param(
	[string]$Tld = 'testdrestore'
)

throw 'The Windows system fixture is blocked: NRPT ownership cannot yet be proven; no system state was changed.'
