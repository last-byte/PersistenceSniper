<table class="tg">
<thead>
  <tr>
    <th class="tg-0pky"><h1 align=center>PersistenceSniper</h1></th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-0pky"><p align="center">
<img src="https://github.com/last-byte/PersistenceSniper/blob/main/persistencesnipernew4.png?raw=true" width="40%">
<p align="center"><a href="https://www.powershellgallery.com/packages/PersistenceSniper/"><img src="https://img.shields.io/badge/Language-Powershell-blue" alt="language" style="text-align:center;display:block;"></a> <a href="https://www.powershellgallery.com/packages/PersistenceSniper/"><img src="https://img.shields.io/powershellgallery/v/PersistenceSniper?label=Module%20Version" alt="version shield logo" style="text-align:center;display:block;"></a> <a href="https://github.com/last-byte/PersistenceSniper/wiki/3-%E2%80%90-Detections"><img src="https://img.shields.io/badge/Persistence%20Techniques-60-brightgreen" alt="number of techniques implemented" style="text-align:center;display:block;"></a> <a href="https://www.powershellgallery.com/packages/PersistenceSniper/"><img src="https://img.shields.io/badge/Digital%20Signature-Valid-brightgreen" alt="workflow" style="text-align:center;display:block;"></a> <a href="https://www.powershellgallery.com/packages/PersistenceSniper/"><img src="https://img.shields.io/powershellgallery/dt/PersistenceSniper?label=Gallery%20Downloads" alt="gallery downloads" style="text-align:center;display:block;"></a> <a href="https://twitter.com/PersistSniper"><img src="https://img.shields.io/twitter/follow/PersistSniper?style=social" alt="twitter" style="text-align:center;display:block;"></a> <a href="https://twitter.com/last0x00"><img src="https://img.shields.io/twitter/follow/last0x00?style=social" alt="twitter" style="text-align:center;display:block;"></a> <a href="https://twitter.com/dottor_morte"><img src="https://img.shields.io/twitter/follow/dottor_morte?style=social" alt="twitter_rick" style="text-align:center;display:block;"></a> <a href="https://www.buymeacoffee.com/last0x00"><img src="https://img.shields.io/badge/buy%20me%20a-coffee-yellow" alt="buy me a coffee" style="text-align:center;display:block;"></a></p> 
<p align="center">PersistenceSniper is a Powershell module that can be used by Blue Teams, Incident Responders and System Administrators to hunt persistences implanted in Windows machines. It is also available on <a href=https://www.powershellgallery.com/packages/PersistenceSniper>Powershell Gallery</a> and it is digitally signed with a valid code signing certificate. The tool is under active development with new releases coming out by the week, so make sure to use the up-to-date version. Official Twitter/X account <a href="https://twitter.com/PersistSniper">@PersistSniper</a>.</p>
</td>
  </tr>
</tbody>
</table>

## The Why
Why writing such a tool, you might ask. Well, for starters, I tried looking around and I did not find a tool which suited my particular use case, which was looking for known persistence techniques, automatically, across multiple machines, while also being able to quickly and easily parse and compare results. Sure, [Sysinternals' Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) is an amazing tool and it's definitely worth using, but, given it outputs results in non-standard formats and can't be run remotely unless you do some shenanigans with its command line equivalent, I did not find it a good fit for me. Plus, some of the techniques I implemented so far in PersistenceSniper have not been implemented into Autoruns yet, as far as I know. Anyway, if what you need is an easy to use, GUI based tool with lots of already implemented features, Autoruns is the way to go, otherwise let PersistenceSniper have a shot, it won't miss it 😉

## The How
To learn how to use PersistenceSniper properly, head to the [Project's Wiki](https://github.com/last-byte/PersistenceSniper/wiki).

__TL;DR__
If you are too lazy to read the [Wiki](https://github.com/last-byte/PersistenceSniper/wiki) (which I highly recommend you do) you can install, import, and fire PersistenceSniper with the following three commands.
```powershell
PS> Install-Module PersistenceSniper
PS> Import-Module PersistenceSniper
PS> Find-AllPersistence
```

## Persistence techniques implemented so far
The persistence techniques implemented so far are detailed in the [Detections Page](https://github.com/last-byte/PersistenceSniper/wiki/3-%E2%80%90-Detections) of PersistenceSniper's Wiki.

## Credits
Most of this tool is based on the work of other skilled researchers, so it's right to give credit where credit's due. This project wouldn't be around if it weren't for:
- [Hexacorn](https://www.hexacorn.com/) and his never-ending [Beyond good ol' Run key series](https://www.hexacorn.com/blog/2017/01/28/beyond-good-ol-run-key-all-parts/);
- [Grzegorz Tworek](https://twitter.com/0gtweet/) and his amazing [persistence-info.github.io website](https://persistence-info.github.io/);
- All the other researchers who disclosed cool and unknown persistence techniques.

Furthermore, these people contributed to the project:
- [Riccardo Ancarani](https://x.com/dottor_morte)
- [Cecio](https://x.com/red5heep)
- [Vadim](https://x.com/D3F7A5105)
- [fkadibs](https://x.com/fkadibs)
- [suinswofi](https://github.com/suinswofi)
- [Antonio Blescia](https://github.com/ablescia)
- [Strassi](https://x.com/strassi7)
- [sixtyvividtails](https://x.com/sixtyvividtails)

I'd also like to give credits to my fellow mates at [@APTortellini](https://aptw.tf/about/) for the flood of ideas that helped it grow from a puny text-oriented script to a full-fledged Powershell module.

## License
This project is under the [Commons Clause version of the MIT License](https://github.com/last-byte/PersistenceSniper/blob/main/LICENSE) license. TL;DR: you can copy, modify, distribute and perform the work for whatever reason, __excluding__ commercial purposes, all without asking permission.
