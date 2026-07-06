# build-all.ps1 — buduje SENSMOS firmware dla wielu rodzin ESP przez arduino-cli.
#
# Użycie (z katalogu firmware):
#   .\build-all.ps1                          # domyślnie: esp32, esp32s3, esp32c3
#   .\build-all.ps1 -Targets esp32,esp32s3   # wybrane
#   .\build-all.ps1 -Targets all             # wszystkie zdefiniowane
#
# Wynik: dist\<target>\SENSMOS_Firmware.merged.bin  (pełny obraz flash; offsety per-chip
# ustawia rdzeń esp32 — ESP32 bootloader @0x1000, S3/S2/C3/C6 @0x0). Flash:
#   esptool --chip <chip> write_flash 0x0 SENSMOS_Firmware.merged.bin
#   albo:  arduino-cli upload -p COMx --fqbn <fqbn> .

param([string[]]$Targets)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$cli = (Get-Command arduino-cli -ErrorAction SilentlyContinue).Source
if (-not $cli) { $cli = "$env:LOCALAPPDATA\Programs\Arduino IDE\resources\app\lib\backend\resources\arduino-cli.exe" }
if (-not (Test-Path $cli)) { throw "Nie znaleziono arduino-cli (Arduino IDE lub arduino-cli w PATH)" }

# FQBN per rodzina. FlashSize=4M + min_spiffs: 2 sloty OTA po 1.9MB (od v0.35; NimBLE zmiescil app).
# Wczesniej huge_app (potwierdzone na Heltec/DevKit S3 — 8M dawało
# boot-loop). Bez CDCOnBoot=cdc (domyślnie disabled — tak wstaje pewnie; Serial po UART/BLE).
# PSRAM=disabled (kod nie wymaga; włącz gdy moduł ma PSRAM).
$fqbns = [ordered]@{
  'esp32'   = 'esp32:esp32:esp32:PartitionScheme=min_spiffs,PSRAM=disabled,FlashSize=4M,CPUFreq=240,FlashMode=qio,FlashFreq=80'
  'esp32s3' = 'esp32:esp32:esp32s3:PartitionScheme=min_spiffs,PSRAM=disabled,FlashSize=4M,CPUFreq=240'
  'esp32c3' = 'esp32:esp32:esp32c3:PartitionScheme=min_spiffs,FlashSize=4M,CPUFreq=160'
  'esp32s2' = 'esp32:esp32:esp32s2:PartitionScheme=min_spiffs,PSRAM=disabled,FlashSize=4M,CPUFreq=240'
  'esp32c6' = 'esp32:esp32:esp32c6:PartitionScheme=min_spiffs,FlashSize=4M,CPUFreq=160'
}

if (-not $Targets) { $Targets = @('esp32','esp32s3','esp32c3') }
if ($Targets.Count -eq 1 -and $Targets[0] -eq 'all') { $Targets = @($fqbns.Keys) }

$results = @()
foreach ($t in $Targets) {
  if (-not $fqbns.Contains($t)) { Write-Host "pomijam nieznany: $t" -ForegroundColor Yellow; continue }
  Write-Host "== buduję $t ==" -ForegroundColor Cyan
  # --build-path per target: izolowany, deterministyczny (arduino-cli domyślnie buduje do
  # cache współdzielonego między FQBN → nadpisywanie; build/<t> to eliminuje). Hooki rdzenia
  # (merged.bin) działają, bo kompilacja odbywa się w tym katalogu.
  $bp = Join-Path $PSScriptRoot "build\$t"
  Remove-Item -Recurse -Force $bp -ErrorAction SilentlyContinue
  & $cli compile --fqbn $fqbns[$t] --build-path $bp $PSScriptRoot
  if ($LASTEXITCODE -ne 0) { Write-Host "FAIL $t (kompilacja)" -ForegroundColor Red; $results += [pscustomobject]@{target=$t;ok=$false}; continue }

  $merged = Join-Path $bp 'SENSMOS_Firmware.ino.merged.bin'
  if (-not (Test-Path $merged)) { Write-Host "FAIL $t (brak merged.bin)" -ForegroundColor Red; $results += [pscustomobject]@{target=$t;ok=$false}; continue }

  $outDir = Join-Path $PSScriptRoot "dist\$t"
  New-Item -ItemType Directory -Force $outDir | Out-Null
  Copy-Item $merged (Join-Path $outDir 'SENSMOS_Firmware.merged.bin') -Force
  Copy-Item (Join-Path $bp 'SENSMOS_Firmware.ino.bin') (Join-Path $outDir 'SENSMOS_Firmware.bin') -Force -ErrorAction SilentlyContinue
  $sz = '{0:N0}' -f (Get-Item $merged).Length
  Write-Host "OK  $t -> $outDir  [merged $sz B]" -ForegroundColor Green
  $results += [pscustomobject]@{ target=$t; ok=$true; merged_B=$sz }
}
"`n== podsumowanie =="
$results | Format-Table -AutoSize
