$processNames = $args

$id = $PID
while ($true) {
  $p = Get-CimInstance -Class Win32_Process -Filter "ProcessId = $id"
  if ($null -eq $p) {
    throw "Could not determine $processName process"
  }
  Write-Host "Found process: $p"
  # case-sensitive comparison
  if ($processNames -ccontains $p[0].Name) {
    Break
  }
  else {
    $id = $p[0].ParentProcessId
  }
}
Write-Host "Injecting into process: $p"
Start-Process -FilePath ".\tracer.exe" -Wait -NoNewWindow -ArgumentList "--inject=$id"
