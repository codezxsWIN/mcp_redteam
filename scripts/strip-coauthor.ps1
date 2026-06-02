$m = [Console]::In.ReadToEnd()
$clean = [regex]::Replace($m, '(?m)^Co-authored-by: Cursor <cursoragent@cursor.com>\r?\n?', '')
Write-Output $clean.TrimEnd()
