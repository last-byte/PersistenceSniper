![](resources/persistencesniper.png)
# Persistence Sniper
Persistence Sniper is a Powershell script that can be used by Blue Teams, Incident Responders and System Administrators to hunt persistences implanted in Windows machines.

## Usage
Using Persistence Sniper is as simple as:
```
PS C:\> git clone https://github.com/last-byte/PersistenceSniper
PS C:\> Import-Module .\PersistenceSniper\PersistenceSniper.ps1
PS C:\> Find-AllPersistence
```

Persistence Sniper's `Find-AllPersistence` returns an array of objects of type PSCustomObject with the following properties:
```
$PersistenceObject = [PSCustomObject]@{
      "Technique" = $Technique
      "Classification" = $Classification
      "Path" = $Path
      "Value" = $Value
      "Access Gained" = $AccessGained
      "Note" = $Note
      "Reference" = $Reference
} 
```

This allows for easy output formatting and filtering. Let's say you want to only see the persistences that will allow the attacker to re-gain access as an administrator (aka System):

```
PS C:\> Find-AllPersistence | Where-Object "Access Gained" -EQ "System"
```

![](resources/findallpersistenceexample01.png)

## Dealing with false positives
Let's face it, hunting for persistence techniques also comes with having to deal with a lot of false positives. This happens because, while some techniques are almost never legimately used, many indeed are by legit software which needs to autorun on system boot or user login.

This poses a challenge, which in many environments can be tackled by creating a CSV file containing known false positives. If your organization deploys systems using something like a golden image, you can run Persistence Sniper on a system you just created, get a CSV of the results and use it to filter out results on other machines.

`Find-AllPersistence` comes with parameters allowing direct output of the findings to a CSV file, while also being able to take a CSV file as input and diffing the results.

```
PS C:\> Find-AllPersistence -DiffCSV false_positives.csv
```

![](resources/findallpersistenceexample02.png)