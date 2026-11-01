# Make captured PowerShell output match what the release runner expects: UTF-8.
#
# `tests/release/run.py` drains stdout and stderr through pipes and decodes them
# as UTF-8, like the cargo, bun, and git output it also captures. PowerShell 5.1
# otherwise writes its own output, and decodes the output of native tools such as
# testd and curl, with the active code page. On a non-English system that is not
# UTF-8, so the report and the checks that read native output come out garbled.

$Utf8 = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = $Utf8
try {
	[Console]::OutputEncoding = $Utf8
} catch {
	# A detached host has no console code page to set; its own output is ASCII.
}
