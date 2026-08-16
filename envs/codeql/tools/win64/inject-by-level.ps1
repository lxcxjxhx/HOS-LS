$targetTraceProcessLevel = [int]$args[0]
$scriptProcessOffset = [int]$args[1]
$targetProcessLevel = $scriptProcessOffset + $targetTraceProcessLevel

Write-Host "Looking for process tree index ${targetProcessLevel} (trace process level ${targetTraceProcessLevel})"

$id = $PID
for ($i = 0; $i -le $targetProcessLevel; $i++) {
  $p = Get-CimInstance -Class Win32_Process -Filter "ProcessId = $id"
  $traceLevel = $i - $scriptProcessOffset
  Write-Host "Process tree index ${i} (trace process level ${traceLevel}): $p"
  if ($null -eq $p) {
    throw "Process tree ended before reaching required level"
  }
  # Special case just in case the runner is used on actions
  if ($p[0].Name -eq "Runner.Worker.exe") {
    Write-Host "Found Runner.Worker.exe process which means we are running on GitHub Actions"
    Write-Host "Aborting search early and using process: $p"
    Break
  } elseif ($p[0].Name -eq "Agent.Worker.exe") {
    Write-Host "Found Agent.Worker.exe process which means we are running on Azure Pipelines"
    Write-Host "Aborting search early and using process: $p"
    Break
  } elseif ($i -lt $targetProcessLevel) {
    # We haven't hit one of the special processes we prioritise injecting into, nor the user-supplied
    # level. So, we navigate to the parent process. The next loop iteration will check it really exists.
    $id = $p[0].ParentProcessId
  }
}
Write-Host "Injecting into process: $p"
Start-Process -FilePath ".\tracer.exe" -Wait -NoNewWindow -ArgumentList "--inject=$id"
