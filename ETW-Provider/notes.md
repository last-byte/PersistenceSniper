# Notes

## Extract supported techniques without repetition

```powershell
Get-Content '.\PersistenceSniper.psm1' | 
Select-String -Pattern "-Technique '([^']+)'", -AllMatches | 
ForEach-Object { $_.Matches.Groups[1].Value } | 
Sort-Object -Unique
```

## Extract supported techniques without repetition and apply snake_case. Remove alse **.** and **,**

```powershell
Get-Content '.\PersistenceSniper.psm1' |
Select-String -Pattern "-Technique '([^']+)'", -AllMatches |
ForEach-Object { $_.Matches.Groups[1].Value } |
Sort-Object -Unique |
ForEach-Object {
    (($_ -replace '[.,]', '') -replace ' ', '_').ToLower()}
```


### Cases

#### Generate events for manifest

```powershell
$lista=$(Get-Content '.\PersistenceSniper.psm1' |
Select-String -Pattern "-Technique '([^']+)'", -AllMatches |
ForEach-Object { $_.Matches.Groups[1].Value } |
Sort-Object -Unique |
ForEach-Object {
    (($_ -replace '[.,]', '') -replace ' ', '_').ToLower()})

$i=1001; $lista | ForEach-Object { $res='<event value="{0}" version="0" level="win:Warning" task="T_{1}" channel="Operational" template="EventArgs" message="$(string.event_{1})"/>' -f $i, $_ ;Write-Output $res; $i++ }
```