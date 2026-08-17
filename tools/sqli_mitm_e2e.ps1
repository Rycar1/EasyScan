$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $root "easyscan.sqli-e2e.yaml"
$featuresPath = Join-Path $root "features.sqli-e2e.yaml"
$dbPath = Join-Path $root "data/easyscan-sqli-e2e.db"
$reportPath = Join-Path $root "easyscan-sqli-e2e-report.html"
$stdoutPath = Join-Path $root "build/bin/sqli-e2e.stdout.log"
$stderrPath = Join-Path $root "build/bin/sqli-e2e.stderr.log"
$responsePath = Join-Path $root "build/bin/sqli-e2e-response.html"
$completed = $false

$config = Get-Content (Join-Path $root "easyscan.yaml") -Raw -Encoding UTF8
$config = $config.Replace('path: "data/easyscan.db"', 'path: "data/easyscan-sqli-e2e.db"')
$config = $config.Replace('html_path: "easyscan-scan-report.html"', 'html_path: "easyscan-sqli-e2e-report.html"')
$config = $config.Replace('path: "features.yaml"', 'path: "features.sqli-e2e.yaml"')
Set-Content -LiteralPath $configPath -Value $config -Encoding utf8

$features = Get-Content (Join-Path $root "features.yaml") -Raw -Encoding UTF8
$features = [regex]::Replace($features, '(?m)^passive_sqli_probe_qps:\s*\d+\s*$', 'passive_sqli_probe_qps: 10')
Set-Content -LiteralPath $featuresPath -Value $features -Encoding utf8

Remove-Item -LiteralPath $dbPath, $reportPath, $stdoutPath, $stderrPath, $responsePath -Force -ErrorAction SilentlyContinue

$exe = Join-Path $root "build/bin/easyscan-cli.exe"
$process = Start-Process -FilePath $exe `
    -ArgumentList @("serve", "-config", $configPath, "-listen", "127.0.0.1:17777", "-api-listen", "127.0.0.1:18787") `
    -WorkingDirectory $root `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath `
    -PassThru

try {
    $healthy = $false
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        Start-Sleep -Milliseconds 200
        try {
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:18787/healthz" -TimeoutSec 1
            if ($health.status -eq "ok") {
                $healthy = $true
                break
            }
        }
        catch {
        }
        if ($process.HasExited) {
            break
        }
    }
    if (-not $healthy) {
        $stderr = Get-Content $stderrPath -Raw -ErrorAction SilentlyContinue
        throw "EasyScan E2E service did not become healthy. stderr: $stderr"
    }

    $previousNoProxy = $env:NO_PROXY
    $previousLowerNoProxy = $env:no_proxy
    $env:NO_PROXY = $null
    $env:no_proxy = $null
    $statuses = @()
    try {
        for ($lesson = 1; $lesson -le 15; $lesson++) {
            $target = "http://127.0.0.1:8080/Less-$lesson/"
            if ($lesson -le 10) {
                $httpCode = & curl.exe -sS -o $responsePath -w "%{http_code}" -x "http://127.0.0.1:17777" "${target}?id=1"
            }
            else {
                $httpCode = & curl.exe -sS -o $responsePath -w "%{http_code}" -x "http://127.0.0.1:17777" -H "Content-Type: application/x-www-form-urlencoded" --data "uname=admin&passwd=admin&submit=Submit" $target
            }
            if ($LASTEXITCODE -ne 0) {
                throw "curl through proxy failed for Less-$lesson with exit code $LASTEXITCODE"
            }
            $statuses += "Less-$lesson=$httpCode"
        }
    }
    finally {
        $env:NO_PROXY = $previousNoProxy
        $env:no_proxy = $previousLowerNoProxy
    }

    $matches = @()
    for ($attempt = 0; $attempt -lt 200; $attempt++) {
        Start-Sleep -Milliseconds 200
        $findingsResponse = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:18787/api/v1/findings" -TimeoutSec 2
        $findings = $findingsResponse.Content | ConvertFrom-Json
        $matches = @($findings | Where-Object { $_.rule_id -like "passive.sqli-probe.*" })
        if ($matches.Count -ge 15) {
            break
        }
    }

    Write-Host ("proxied_http_statuses=" + ($statuses -join ","))
    if ($matches.Count -lt 15) {
        Write-Host "--- stdout ---"
        Get-Content $stdoutPath -ErrorAction SilentlyContinue
        Write-Host "--- stderr ---"
        Get-Content $stderrPath -ErrorAction SilentlyContinue
        throw "Full proxy/runtime/SQL worker E2E produced $($matches.Count) of 15 expected SQL findings."
    }

    Write-Host "sql_findings=$($matches.Count)"
    $matches | Sort-Object url | Select-Object rule_id, severity, confidence, url, method, evidence | ConvertTo-Json -Depth 5
    $completed = $true
}
finally {
    if ($null -ne $process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $process.WaitForExit()
    }
    if ($completed) {
        Remove-Item -LiteralPath `
            $configPath, `
            $featuresPath, `
            $dbPath, `
            "$dbPath-shm", `
            "$dbPath-wal", `
            $reportPath, `
            $stdoutPath, `
            $stderrPath, `
            $responsePath `
            -Force -ErrorAction SilentlyContinue
    }
}
