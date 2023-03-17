
Windows Font installer script.

.\font_install.ps1 [-install] [-uninstall] [-path <path_to_fonts>]

-install : install new .ttf fonts on the system. If no parameters are provided, the default action is install.
-uninstall : compare .ttf fonts provided and uninstall them from the system.
-path <path> : custom path. Default is current directory.
-info [<filepath>] : display font information. If no optional filename is provided, we display all fonts from the -path <path> folder.

In the background, the script will copy the .ttf file(s) to the Windows Fonts directory and also edit the registry entries for each font it (un-)installs.
For the registry to work, the script reads the .ttf file(s) natively/binary, and gets the font 'Name' property directly from the .ttf file it self.
This way, the Font name is registered and shown in applications like it should be.

There is one font NotoSans-Regular.ttf provided for sake of the example.
This is the Noto Sans font, you can get this for free from https://www.google.com/get/noto/.

Real world usage:
I wrote this script for a large pool of RDS servers that run virtualized on VMWare Horizon version 8.
In the gold image, once it deploys each instance of a RDS machine, it run's a suite of scripts to ready the VM.
One of these scripts is this font_install that "injects" a whole bunch of .tff files in the instanced machines.
