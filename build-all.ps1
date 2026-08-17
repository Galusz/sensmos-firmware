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
# Target = FQBN + opcjonalne definicje. Warianty radiowe to TEN SAM fqbn co flota,
# rozni je wylacznie -DLORA_ENABLED=1: przy 0 kod LoRa nie wchodzi do bina ani jedna
# instrukcja (patrz lora_config.h), wiec biny floty sa nietkniete.
$fqbns = [ordered]@{
  'esp32'   = 'esp32:esp32:esp32:PartitionScheme=min_spiffs,PSRAM=disabled,FlashSize=4M,CPUFreq=240,FlashMode=qio,FlashFreq=80'
  'esp32s3' = 'esp32:esp32:esp32s3:PartitionScheme=min_spiffs,PSRAM=disabled,FlashSize=4M,CPUFreq=240'
  # ESP32-S3-WROOM-1 N16R8 (16MB flash + 8MB OCTAL PSRAM). PSRAM=disabled na płytce z OPI PSRAM
  # rozwalało init/RF → WiFi RX martwe, CPU/BLE żyły (potwierdzone: N16R8 gościa, NerdMiner działał).
  # PSRAM=opi = poprawny build (flash-mode ustawia rdzeń S3; FlashMode/FlashFreq nieakceptowane w FQBN).
  # Partycja 4M — OTA-kompatybilna z resztą S3.
  'esp32s3-n16r8' = 'esp32:esp32:esp32s3:PartitionScheme=min_spiffs,PSRAM=opi,FlashSize=4M,CPUFreq=240'
  'esp32c3' = 'esp32:esp32:esp32c3:PartitionScheme=min_spiffs,FlashSize=4M,CPUFreq=160'
  # ── warianty radiowe (SX1262) ── ten sam chip S3, wlasny target OTA "esp32s3-lora"
  'esp32s3-lora'        = 'esp32:esp32:esp32s3:PartitionScheme=min_spiffs,PSRAM=disabled,FlashSize=4M,CPUFreq=240'
  'esp32s2' = 'esp32:esp32:esp32s2:PartitionScheme=min_spiffs,PSRAM=disabled,FlashSize=4M,CPUFreq=240'
  'esp32c6' = 'esp32:esp32:esp32c6:PartitionScheme=min_spiffs,FlashSize=4M,CPUFreq=160'
}

# Definicje per target. Puste = build flotowy.
# Jeden wariant radiowy na wszystkie plytki — piny wykrywa sonda przy starcie, wiec nie ma
# osobnego builda per plytka. Nowa plytka = wiersz w LORA_PINOUTS, nie nowy target.
$defines = @{
  'esp32s3-lora' = '-DLORA_ENABLED=1'
}

# Domyslnie TYLKO flota — warianty radiowe trzeba wybrac jawnie albo wziac 'all',
# zeby zwykle wydanie nie produkowalo binow, ktorych nikt nie zamawial.
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
  $args = @('compile', '--fqbn', $fqbns[$t], '--build-path', $bp)
  if ($defines[$t]) {
    $args += @('--build-property', "compiler.cpp.extra_flags=$($defines[$t])")
    Write-Host "   definicje: $($defines[$t])" -ForegroundColor DarkGray
  }
  & $cli @args $PSScriptRoot
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
