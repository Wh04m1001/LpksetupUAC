# LpksetupUAC

PoC for UAC bypass using arbitrary directory delete in Lpksetup.exe. When lpksetup.exe is used to uninstall language pack it will create lpksetup directory in user temp directory, when uninstallation fails (beacuse language pack is not installed) it will delete any directory in lpksetup directory.
In this PoC I choose to uninstall French language pack, you can change that in code.


Arbitrary directory delete is abused to get SYSTEM shell using method described here https://www.thezdi.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks

This PoC will just execute cmd.exe as system so in order to performe other actions such as executing different binary new RBS file should be created (using advanced installer,wix or other  tools).

If you want to test this PoC it is the best to do it on system with minimum of 4 processor cores.
