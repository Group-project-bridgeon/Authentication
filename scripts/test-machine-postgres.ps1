#Requires -Version 7.4
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$run='auth-machine-test-'+[guid]::NewGuid().ToString('N')
$containerID=$null
$attempted=$false
$names=@('POSTGRES_PASSWORD','PGPASSWORD','AUTH_MACHINE_TEST_DATABASE_URL','AUTH_MACHINE_TEST_RUN_ID','AUTH_MACHINE_TEST_PORT')
$previous=@{}
foreach($name in $names){$previous[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
function FixtureDocker([string[]]$Arguments){
 $output=& docker @Arguments 2>&1
 if($LASTEXITCODE -ne 0){throw "Machine fixture Docker operation failed ($($Arguments[0])); output suppressed"}
 return $output
}
function Ownership {
 if(!$containerID -or $containerID -notmatch '^[0-9a-f]{64}$'){throw 'Missing owned container ID'}
 $label=([string](FixtureDocker @('inspect','--format','{{index .Config.Labels "auth.machine.fixture"}}',$containerID))).Trim()
 if($label -ne $run){throw 'Refusing non-owned container operation'}
}
function SQL([string]$query){Ownership;$result=FixtureDocker @('exec',$containerID,'psql','-X','-q','-t','-A','-v','ON_ERROR_STOP=1','-U','auth_machine_fixture','-d','auth_machine_test','-c',$query);return ([string]::Join("`n",[string[]]@($result))).Trim()}
function AssertSQL([string]$query,[string]$expected,[string]$label){if((SQL $query) -ne $expected){throw "Fixture assertion failed: $label"};Write-Host "PASS: $label"}
function Migrate([string[]]$op){Ownership;$migrationPath=Join-Path $root 'db/migrations';FixtureDocker (@('run','--rm','--network',"container:$containerID",'-e','PGPASSWORD','-v',"${migrationPath}:/migrations:ro",'migrate/migrate:v4.18.3','-path=/migrations','-database=postgres://auth_machine_fixture@127.0.0.1:5432/auth_machine_test?sslmode=disable')+$op)|Out-Null}
try {
 $bytes=[byte[]]::new(32);[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
 $env:POSTGRES_PASSWORD=[Convert]::ToHexString($bytes).ToLowerInvariant();$env:PGPASSWORD=$env:POSTGRES_PASSWORD
 $attempted=$true
 $output=@(FixtureDocker @('run','--rm','-d','--name',$run,'--label',"auth.machine.fixture=$run",'--tmpfs','/var/lib/postgresql/data','-e','POSTGRES_USER=auth_machine_fixture','-e','POSTGRES_PASSWORD','-e','POSTGRES_DB=auth_machine_test','-p','127.0.0.1::5432','postgres:17-alpine'))
 $ids=@($output|ForEach-Object{([string]$_).Trim()}|Where-Object{$_ -match '^[0-9a-f]{64}$'})
 if($ids.Count -ne 1){throw 'Invalid fixture identity'};$containerID=$ids[0];Ownership
 $mapping=([string](FixtureDocker @('port',$containerID,'5432/tcp'))).Trim();if($mapping -notmatch '^127\.0\.0\.1:(\d+)$'){throw 'Invalid fixture binding'};$port=$Matches[1]
 $ready=$false
 for($i=0;$i -lt 60;$i++){try{if((SQL 'SELECT 1') -eq '1'){$ready=$true;break}}catch{};Start-Sleep -Seconds 1}
 if(!$ready){throw 'Fixture readiness failed'}
 SQL "ALTER DATABASE auth_machine_test SET auth.fixture_id='$run'"|Out-Null
 Migrate @('up','6')
 AssertSQL "SELECT version::text||':'||dirty::text FROM schema_migrations" '6:false' 'legacy schema baseline'
 SQL "INSERT INTO identity_users(id,email,full_name) VALUES ('01935f00-0000-7000-8000-000000000001','preserved-human@example.invalid','Preserved synthetic human')" | Out-Null
 $legacyCount=SQL 'SELECT count(*) FROM identity_users'
 Migrate @('up','1')
 AssertSQL 'SELECT (SELECT count(*) FROM machine_identities)+(SELECT count(*) FROM machine_credentials)+(SELECT count(*) FROM machine_grants)' '0' 'no automatic machines or grants'
 Migrate @('down','1');Migrate @('up','1')
 $env:AUTH_MACHINE_TEST_DATABASE_URL="postgres://auth_machine_fixture:$($env:POSTGRES_PASSWORD)@127.0.0.1:$port/auth_machine_test?sslmode=disable"
 $env:AUTH_MACHINE_TEST_RUN_ID=$run;$env:AUTH_MACHINE_TEST_PORT=$port
 & go -C $root test -count=1 -timeout=240s -v ./internal/integration -run '^TestMachine'
 if($LASTEXITCODE -ne 0){throw 'Machine integration tests failed'}
 Migrate @('down','1')
 AssertSQL "SELECT version::text||':'||dirty::text FROM schema_migrations" '6:false' 'populated rollback clean'
 AssertSQL 'SELECT count(*) FROM identity_users' $legacyCount 'human data preserved'
 AssertSQL "SELECT count(*) FROM identity_users WHERE id='01935f00-0000-7000-8000-000000000001' AND email='preserved-human@example.invalid' AND full_name='Preserved synthetic human'" '1' 'human sentinel unchanged'
 AssertSQL "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('machine_identities','machine_credentials','machine_grants')" '0' 'machine tables removed'
 Migrate @('up','1')
 AssertSQL "SELECT version::text||':'||dirty::text FROM schema_migrations" '7:false' 'reapply clean'
 AssertSQL 'SELECT count(*) FROM machine_identities' '0' 'reapply does not provision'
} finally {
 try {
  if($attempted -and !$containerID){$owned=@(FixtureDocker @('ps','-a','--no-trunc','--filter',"label=auth.machine.fixture=$run",'--format','{{.ID}}'));if($owned.Count -gt 1){throw 'Ambiguous owned cleanup'};if($owned.Count -eq 1){$containerID=([string]$owned[0]).Trim()}}
  if($containerID){Ownership;FixtureDocker @('rm','-f',$containerID)|Out-Null;Write-Host 'PASS: owned fixture removed; tmpfs discarded'}
 } finally {foreach($name in $names){[Environment]::SetEnvironmentVariable($name,$previous[$name],'Process')};Write-Host 'PASS: environment restored'}
}
