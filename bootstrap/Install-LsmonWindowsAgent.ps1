[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$ManifestPath,
  [string]$RegistrationCode,
  [ValidateRange(60, 900)][int]$DeliveryWaitSeconds = 600
)
$ErrorActionPreference = 'Stop'
function Fail([string]$Message) { throw "LSMON bootstrap stopped: $Message" }
function B64Url([byte[]]$Bytes) { ([Convert]::ToBase64String($Bytes)).TrimEnd('=').Replace('+','-').Replace('/','_') }
function FromB64Url([string]$Value) { $v=$Value.Replace('-','+').Replace('_','/'); $v += '=' * ((4-$v.Length%4)%4); [Convert]::FromBase64String($v) }
function FixedTimeEquals([byte[]]$Left,[byte[]]$Right) { if($Left.Length -ne $Right.Length){return $false};$different=0;for($i=0;$i -lt $Left.Length;$i++){$different=$different -bor ($Left[$i] -bxor $Right[$i])};return $different -eq 0 }
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Fail 'Run this bootstrap from an elevated PowerShell session.' }
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { Fail 'Manifest file not found.' }
if ([string]::IsNullOrWhiteSpace($RegistrationCode)) {
  $secureCode = Read-Host -Prompt 'Enter the one-time registration code' -AsSecureString
  $codePointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureCode)
  try { $RegistrationCode = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($codePointer) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($codePointer) }
}
Write-Output 'LSMON validating enrollment manifest.'
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
if ($manifest.kind -ne 'lsmon-agent-bootstrap-manifest' -or $manifest.operating_system -ne 'windows') { Fail 'This is not a Windows LSMON enrollment manifest.' }
if ([DateTimeOffset]$manifest.expires_at -le [DateTimeOffset]::UtcNow) { Fail 'This enrollment manifest has expired.' }
$package=$manifest.package
if (-not $package.source_url.StartsWith('https://') -or $package.sha256 -notmatch '^[A-Fa-f0-9]{64}$') { Fail 'Manifest package policy is invalid.' }
$work=Join-Path $env:TEMP ('lsmon-'+$manifest.enrollment_id); New-Item -ItemType Directory -Force -Path $work | Out-Null
$msi=Join-Path $work $package.filename
Write-Output 'LSMON downloading the approved agent package.'
Invoke-WebRequest -UseBasicParsing -Uri $package.source_url -OutFile $msi -TimeoutSec 300
Write-Output 'LSMON validating the downloaded agent package.'
if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ne $package.sha256.ToUpperInvariant()) { Fail 'Downloaded package checksum does not match the approved catalog record.' }
$signature=Get-AuthenticodeSignature -LiteralPath $msi
if ($signature.Status -ne 'Valid') { Fail 'Downloaded package signature is not valid.' }
if ($package.expected_publisher -and $signature.SignerCertificate.Subject -notmatch [regex]::Escape($package.expected_publisher)) { Fail 'Package publisher does not match the approved catalog record.' }
Write-Output 'LSMON package verified; registering this endpoint.'
$rsa=[Security.Cryptography.RSA]::Create(3072); $parameters=$rsa.ExportParameters($false)
$keyJson=@{modulus=(B64Url $parameters.Modulus); exponent=(B64Url $parameters.Exponent)} | ConvertTo-Json -Compress
$form=@{enrollment_id=$manifest.enrollment_id;registration_code=$RegistrationCode.Trim().ToUpperInvariant();endpoint_public_key=(B64Url ([Text.Encoding]::UTF8.GetBytes($keyJson)));endpoint_key_algorithm='rsa-csp-public-v1'}
$registration=Invoke-RestMethod -Method Post -Uri $manifest.validation_url -Body $form
if (-not $registration.valid -or -not $registration.delivery_token) { Fail 'Registration was rejected.' }
Write-Output "LSMON registration accepted for enrollment $($manifest.enrollment_id); waiting up to $DeliveryWaitSeconds seconds for encrypted tenant configuration."
for($attempt=0;$attempt -lt [Math]::Ceiling($DeliveryWaitSeconds / 2);$attempt++) { Start-Sleep -Seconds 2; try { $delivery=Invoke-RestMethod -Method Post -Uri $manifest.configuration_url -Body @{delivery_token=$registration.delivery_token} } catch { continue }; if($delivery.available){break} }
if (-not $delivery.available) { Fail 'Encrypted tenant configuration was not delivered before the timeout.' }
$envelope=$delivery.envelope
if ($envelope.algorithm -ne 'rsa-oaep-sha256+a256cbc-hs256') { Fail 'Unsupported configuration envelope.' }
$keys=$rsa.Decrypt((FromB64Url $envelope.encrypted_key),[Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
$aesKey=$keys[0..31];$macKey=$keys[32..63];$iv=FromB64Url $envelope.iv;$cipher=FromB64Url $envelope.ciphertext
$aad=[Text.Encoding]::UTF8.GetBytes('lsmon-agent-delivery-v1:'+$manifest.enrollment_id)
$hmac=New-Object Security.Cryptography.HMACSHA256(,[byte[]]$macKey);$actual=$hmac.ComputeHash($aad+$iv+$cipher);if(-not (FixedTimeEquals $actual (FromB64Url $envelope.tag))){Fail 'Configuration authentication failed.'}
$aes=[Security.Cryptography.Aes]::Create();$aes.Key=$aesKey;$aes.IV=$iv;$aes.Mode='CBC';$aes.Padding='PKCS7';$decryptor=$aes.CreateDecryptor();$plain=$decryptor.TransformFinalBlock($cipher,0,$cipher.Length);$config=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json
Write-Output 'LSMON encrypted tenant configuration received; installing the agent.'
$args=@('/i',('"'+$msi+'"'),'/qn',('SERVER='+$config.server),('TAG='+$config.tag),'TASKS=Inventory','RUNNOW=1','NO_HTTPD=1','NO_P2P=1','NO_SSL_CHECK=0',('OAUTH_CLIENT_ID='+$config.oauth_client_id),('OAUTH_CLIENT_SECRET='+$config.oauth_client_secret))
$process=Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru
[Array]::Clear($keys,0,$keys.Length);$rsa.Dispose()
if($process.ExitCode -ne 0){Fail "MSI installation failed with exit code $($process.ExitCode)."}
# The Windows MSI service reads its configuration from the registry, rather
# than a .cfg file below Program Files. Store only non-secret routing values.
$agentRegistryPath='HKLM:\SOFTWARE\GLPI-Agent'
New-Item -Path $agentRegistryPath -Force | Out-Null
@{
  server=[string]$config.server
  tag=[string]$config.tag
  'oauth-client-id'=[string]$config.oauth_client_id
  'oauth-client-secret'=[string]$config.oauth_client_secret
  tasks='inventory'
  'no-httpd'='1'
  'no-p2p'='1'
  force='1'
}.GetEnumerator() | ForEach-Object {
  New-ItemProperty -Path $agentRegistryPath -Name $_.Key -Value $_.Value -PropertyType String -Force | Out-Null
}
if([string]::IsNullOrWhiteSpace((Get-ItemPropertyValue -Path $agentRegistryPath -Name 'server' -ErrorAction Stop))){Fail 'GLPI Agent registry configuration was not written.'}
Restart-Service -Name 'glpi-agent' -ErrorAction Stop
$agentLauncher=Join-Path $env:ProgramFiles 'GLPI-Agent\glpi-agent.bat'
if(Test-Path -LiteralPath $agentLauncher -PathType Leaf){& $agentLauncher --set-forcerun}
Write-Output 'LSMON Windows agent bootstrap completed.'
