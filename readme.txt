
Windows Font installer script.

.\font_install.ps1 [-install] [-uninstall] [-path <path_to_fonts>]

-install : install new .ttf fonts on the system. If no parameters are provided, the default action is install.
-uninstall : compare .ttf fonts provided and uninstall them from the system.
-patch <path> : custom path. Default is current directory.


There is one font NotoSans-Regular.ttf provided for sake of the example.
This is de Noto Sans font, you can get this for free from https://www.google.com/get/noto/.


In the background, the script will copy the .ttf file(s) to the Windows Fonts directory and also edit the registry entries for each font it (un-)installs.
For the registry to work, the script reads the .ttf file(s) and gets the font 'Name' property directly from the .ttf file.
