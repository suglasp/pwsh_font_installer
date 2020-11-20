
#
# Pieter De Ridder
# Script to install TrueType fonts (.tff files) on machine level
#
# Created : 19/11/2020
# Changed : 20/11/2020
#
# Usage : .\font_installer.ps1 [-install] [-uninstall] [-path <path>]
#
# Parameters:
# -install (default) : install listed fonts from local folder, to the %windir%\Fonts folder
# -uninstall : uninstall the listed fonts in the local folder, from the %windir%\Fonts folder
# -path <path> : custom path (default is current folder)
#
# Note : The scripts copies the .tff files, but also, opens the .tff and registers the official name in the Windows Registry Fonts hive.
#


# Powershell macro to require running as administrator
#Requires -RunAsAdministrator

#region Global variables
[string]$global:WorkDir = "$($PSScriptRoot)"
[System.IO.FileStream]$global:TTFFileHnd = $null
[System.IO.BinaryReader]$global:TTFReader = $null
[bool]$global:TTFAllocated = $false
[hashtable]$global:TrueTypePlatforms = @{"Unicode"=0; "Macintosh"=1; "ISO"=3; "Windows"=4; "Custom"=4 }
#endregion


#region BigEndian File functions
#
# Function : Read-Int16BigEndian
# Read a lump (byte array or mini byte stream so to say) from a file stream.
#
Function Read-BigEndianLump
{
    Param(
        [System.IO.BinaryReader]$RawStreamReader,
        [uint32]$Count
    )

    [byte[]] $data = $null

    try {
        $data = $RawStreamReader.ReadBytes($count);

        if ([System.BitConverter]::IsLittleEndian)
        {
            [Array]::Reverse($data);
        }
    } catch {
        Write-Warning "Could not read data from the data stream!"
    }

    return $data;
}

#
# Function : Read-Int16BigEndian
# Seek offset in a file stream (Go to position N).
#
Function Read-SeekBigEndian
{
    Param(
        [System.IO.BinaryReader]$RawStreamReader,
        [uint64]$Offset
    )

    try {
        If ($RawStreamReader) {
            [void]$RawStreamReader.BaseStream.Seek($Offset, [System.IO.SeekOrigin]::Begin)
        }
    } catch {
        Write-Warning "Could not reposition pointer in the data stream!"
    }
}

#
# Function : Read-Int16BigEndian
# Read a Signed Short.
#
Function Read-Int16BigEndian {
    Param(
        [System.IO.BinaryReader]$RawStreamReader
    )
    [byte[]]$bytes = Read-BigEndianLump -RawStreamReader $RawStreamReader -Count 2
    return [System.BitConverter]::ToInt16($bytes, 0)
}       

#
# Function : Read-UInt16BigEndian
# Read a Unsigned Short.
#
Function Read-UInt16BigEndian {
    Param(
        [System.IO.BinaryReader]$RawStreamReader
    )
    [byte[]]$bytes = Read-BigEndianLump -RawStreamReader $RawStreamReader -Count 2
    return [System.BitConverter]::ToUInt16($bytes, 0)
}     

#
# Function : Read-Int32BigEndian
# Read a Signed Integer.
#
Function Read-Int32BigEndian {
    Param(
        [System.IO.BinaryReader]$RawStreamReader
    )
    [byte[]]$bytes = Read-BigEndianLump -RawStreamReader $RawStreamReader -Count 4
    return [System.BitConverter]::ToInt32($bytes, 0)
}  

#
# Function : Read-UInt32BigEndian
# Read a Unsigned Integer.
#
Function Read-UInt32BigEndian {
    Param(
        [System.IO.BinaryReader]$RawStreamReader
    )
    [byte[]]$bytes = Read-BigEndianLump -RawStreamReader $RawStreamReader -Count 4
    return [System.BitConverter]::ToUInt32($bytes, 0)
}
 
#
# Function : Read-ASCIIBigEndian
# Read a String in ASCII.
#     
Function Read-ASCIIBigEndian {
    Param (
        [System.IO.BinaryReader]$RawStreamReader,
        [uint32]$Length
    )
    [byte[]]$bytes = $RawStreamReader.ReadBytes($Length)
    Return [System.Text.Encoding]::ASCII.GetString($bytes).Replace("\0", [string]::Empty)
}

#
# Function : Read-BigEndianUnicode
# Read a String in BigEndianUnicode.
#
Function Read-BigEndianUnicode {
    Param (
        [System.IO.BinaryReader]$RawStreamReader,
        [uint32]$Length
    )
    [byte[]]$bytes = $RawStreamReader.ReadBytes($Length)
    Return [System.Text.Encoding]::BigEndianUnicode.GetString($bytes).Replace("\0", [string]::Empty)
}

#
# Function : Read-FixedBigEndian
# Apple defined a Fixed datatype, so we mimic this in a Powershell function.
#
Function Read-FixedBigEndian {
    Param (
        [System.IO.BinaryReader]$RawStreamReader
    )
         
    $major = Read-Int16BigEndian -RawStreamReader $RawStreamReader
    $minor = Read-Int16BigEndian -RawStreamReader $RawStreamReader

    Return @($major,$minor)
}
#endregion


#region .tff File Functions
#
# Function : Open-TTFFile
# Open a .ttf file handle
#
Function Open-TTFFile {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$FontFile
    )

    If (Test-Path -Path $FontFile) {

        try {
            # open de .tff file as BigEndian (Apple file format)
            $global:TTFFileHnd = [System.IO.File]::OpenRead($FontFile)
            $global:TTFReader = New-Object System.IO.BinaryReader($global:TTFFileHnd, [System.Text.Encoding]::BigEndianUnicode)

            $global:TTFAllocated = $true
        } catch {
            Write-Warning "Error! Could not open file $(Split-Path -Path $FontFile -Leaf)!"
        }
    } Else {
        Write-Warning "Woops! Font file $(Split-Path -Path $FontFile -Leaf) not found!"
    }
}


#
# Function : Close-TTFFile
# Close a .tff file handle
#
Function Close-TTFFile {
    # close .ttf file
    If ($global:TTFAllocated) {
        # close the file stream        
        If ($global:TTFReader) {
            $global:TTFReader.Close()
            $global:TTFReader = $null
        }

        # close the file handle
        If ($global:TTFFileHnd) {
            $global:TTFFileHnd.Close()
            $global:TTFFileHnd = $null
        }
    }
}



#
# Function : Read-TTFHeader
# fetch .ttf file header
#
Function Read-TTFHeader {
    [PSObject]$TTFHeader = $null

    If ($global:TTFAllocated) {
        # beginning of file
        Read-SeekBigEndian -RawStreamReader $global:TTFReader -Offset 0

        # read the .tff file header
        $TTFHeader = New-Object PSObject
        Add-Member -InputObject $TTFHeader -MemberType NoteProperty -Name ArchiveFilePath -Value $($FontFile)

        $sntfVersion = Read-FixedBigEndian -RawStreamReader $global:TTFReader
        Add-Member -InputObject $TTFHeader -MemberType NoteProperty -Name Major -Value $sntfVersion[0]
        Add-Member -InputObject $TTFHeader -MemberType NoteProperty -Name Minor -Value $sntfVersion[1]
        Add-Member -InputObject $TTFHeader -MemberType NoteProperty -Name NumTables -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)
        Add-Member -InputObject $TTFHeader -MemberType NoteProperty -Name SearchRange -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)
        Add-Member -InputObject $TTFHeader -MemberType NoteProperty -Name EntrySelector -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)
        Add-Member -InputObject $TTFHeader -MemberType NoteProperty -Name RangeShift -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)

        Add-Member -InputObject $TTFHeader -MemberType NoteProperty -Name HeaderSize -Value "12" # Add our own paramter. The .tff header size is always 12 bytes.
    } Else {
        Write-Warning "There is no Font file allocated!"
    }

    Return $TTFHeader
}



#
# Function : Read-TTFTables
# fetch .ttf file table directory
#
Function Read-TTFTables {
    Param (
        [Parameter(Mandatory=$true)]
        [PSObject]$TTFHeader
    )

    [Hashtable]$TTFFileTables = @{}

    If ($global:TTFAllocated -and $TTFHeader) {
        # Go to offset in file
        Read-SeekBigEndian -RawStreamReader $global:TTFReader -Offset $TTFHeader.HeaderSize

        # read the .tff table directory      
        For($i = 0; $i -lt $TTFHeader.NumTables; $i++) {
            $TTFSingleNameTable = New-Object PSObject
            
            Add-Member -InputObject $TTFSingleNameTable -MemberType NoteProperty -Name Tag -Value $(Read-ASCIIBigEndian -RawStreamReader $global:TTFReader -Length 4)
            Add-Member -InputObject $TTFSingleNameTable -MemberType NoteProperty -Name Checksum -Value $(Read-UInt32BigEndian -RawStreamReader $global:TTFReader)
            Add-Member -InputObject $TTFSingleNameTable -MemberType NoteProperty -Name Offset -Value $(Read-UInt32BigEndian -RawStreamReader $global:TTFReader)
            Add-Member -InputObject $TTFSingleNameTable -MemberType NoteProperty -Name Lenght -Value $(Read-UInt32BigEndian -RawStreamReader $global:TTFReader)

            [void]$TTFFileTables.Add($TTFSingleNameTable.Tag, $TTFSingleNameTable)
        }        
    } Else {
        Write-Warning "There is no Font file allocated!"
    }

    Return $TTFFileTables
}


#
# Function : Read-TTFNameSubTable
# fetch .ttf file "name" table
#
Function Read-TTFNameSubTable {
    Param (
        [Parameter(Mandatory=$true)]
        [PSObject]$TTFHeader,
        [Parameter(Mandatory=$true)]
        [PSObject]$TTFFileTables
    )

    $NameRecords = [System.Collections.ArrayList]@()

    If ($global:TTFAllocated -and $TTFHeader -and $TTFFileTables) {
        # read the 'name' lump from the .tff file
        If ($TTFFileTables['name'].Offset -gt 0) {
            $TTFNameTableHeader = New-Object PSObject

            # We need to jump further down the line in the .tff file for the correct directory data           
            Read-SeekBigEndian -RawStreamReader $global:TTFReader -Offset $TTFFileTables['name'].Offset
                        
            # the 'name' record is also a directory with more then one possible record in it
            Add-Member -InputObject $TTFNameTableHeader -MemberType NoteProperty -Name Format -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)
            Add-Member -InputObject $TTFNameTableHeader -MemberType NoteProperty -Name Count -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)
            Add-Member -InputObject $TTFNameTableHeader -MemberType NoteProperty -Name StringOffset -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)

            # read the name records them selves
            #$NameRecords = [System.Collections.ArrayList]@()
            For ($i = 0; $i -lt $TTFNameTableHeader.Count; $i++) {
                $TTFNameTable = New-Object PSObject
                Add-Member -InputObject $TTFNameTable -MemberType NoteProperty -Name PlatformID -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)
                Add-Member -InputObject $TTFNameTable -MemberType NoteProperty -Name EncodingID -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)
                Add-Member -InputObject $TTFNameTable -MemberType NoteProperty -Name LanguageID -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)
                Add-Member -InputObject $TTFNameTable -MemberType NoteProperty -Name NameID -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)
                Add-Member -InputObject $TTFNameTable -MemberType NoteProperty -Name StringLength -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)
                Add-Member -InputObject $TTFNameTable -MemberType NoteProperty -Name StringOffset -Value $(Read-UInt16BigEndian -RawStreamReader $global:TTFReader)
                                    
                # store are current position
                [uint64]$CurrentPos = $global:TTFReader.BaseStream.Position

                # fetch the string name in UniCode Big Endian and to NameTable record
                [uint64]$NameRecordStringOffset = $TTFFileTables['name'].Offset + $TTFNameTableHeader.StringOffset + $TTFNameTable.StringOffset
                Read-SeekBigEndian -RawStreamReader $global:TTFReader -Offset $NameRecordStringOffset
                Add-Member -InputObject $TTFNameTable -MemberType NoteProperty -Name Name -Value $(Read-BigEndianUnicode -RawStreamReader $global:TTFReader -Length $TTFNameTable.StringLength)
                
                # return to old poition (read name records further)
                Read-SeekBigEndian -RawStreamReader $global:TTFReader -Offset $CurrentPos
                
                [void]$NameRecords.Add($TTFNameTable)
            }
        } Else {
            Write-Warning "Invalid TrueType font Name table?"
        }
    } Else {
        Write-Warning "There is no Font file allocated!"
    }

    Return $NameRecords
}
#endregion


#region Helper functions
#
# Function : Get-FontFilesFromFolder
#
Function Get-FontFilesFromFolder {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$SearchPath
    )

    Return @(Get-ChildItem -File -Path "$($SearchPath)" -Filter "*.ttf")
}

#
# Function : Install-FontFile
#
Function Install-FontFile {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$FontFilePath
    )

    If (Test-Path -Path $FontFilePath) {
        [string]$WindowsFontPath = "$([Environment]::GetEnvironmentVariable("windir"))\Fonts"
        [string]$LocalFontFile = "$(Split-Path -Path $FontFilePath -Leaf)"
        [string]$WindowsFontFile = "$($WindowsFontPath)\$($LocalFontFile)"

        If (-not (Test-Path -Path "$($WindowsFontFile)")) {
            Write-Host "Install font $($LocalFontFile)..."

            # -- STAGE 1 : try first, to register the font in Windows
            [bool]$Registered = $false

            # only for Windows platform                
            [UInt16]$TargetPlatform = $global:TrueTypePlatforms["ISO"]
                                
            # Register all font to Windows Registry
            $RegistryFontsHive = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
                
            # open the .tff file
            Open-TTFFile -FontFile "$($FontFilePath)"

            # read the current .tff file
            $TTF_Header = Read-TTFHeader

            If (($TTF_Header.Major -eq 1) -and ($TTF_Header.Minor -eq 0)) {
                # read .ttf tables and get the 'Name' table
                $TTF_Table_Index = Read-TTFTables -TTFHeader $TTF_Header
                $TTF_Name_Tables = Read-TTFNameSubTable -TTFHeader $TTF_Header -TTFFileTables $TTF_Table_Index

                # extract the font name for the current font .tff file
                ForEach($TTF_Name_Table in $TTF_Name_Tables) {
                    If ($TTF_Name_Table.PlatformId -eq $TargetPlatform) {
                        If ($TTF_Name_Table.NameId -eq 4) {
                            try {
                                New-ItemProperty -Path $RegistryFontsHive -Name "$($TTF_Name_Table.Name) (TrueType)" -Value $LocalFontFile -PropertyType "String" -Force | Out-Null
                                Write-Host "-> Registered font $([char](34))$($TTF_Name_Table.Name) (TrueType)$([char](34)) = $($LocalFontFile)."
                                $Registered = $true
                            } Catch {
                                Write-Warning "-> Could not register font $([char](34))$($TTF_Name_Table.Name) (TrueType)$([char](34))!" 
                            }
                        }
                    }
                }
            } Else {
                Write-Warning "-> Unsupported TrueType font file!"
            }

            # close the .tff file
            Close-TTFFile



            # -- STAGE 2 : If registration is success, then deploy the file
            If ($Registered) {
                Copy-Item -Path "$($FontFilePath)" -Destination "$($WindowsFontPath)" -Force -ErrorAction SilentlyContinue
                Write-Host "-> Font $($LocalFontFile) newly installed."
            } Else {
                Write-Warning "Something went wrong while installing $($LocalFontFile)!"
            }                     

        } Else {
            Write-Host "Font $($LocalFontFile) is already installed."
        }
    }

}



#
# Function : Uninstall-FontFile
#
Function Uninstall-FontFile {
    Param (
        [Parameter(Mandatory=$true)]
        [string]$FontFilePath
    )

    If (Test-Path -Path $FontFilePath) {
        [string]$WindowsFontPath = "$([Environment]::GetEnvironmentVariable("windir"))\Fonts"
        [string]$LocalFontFile = "$(Split-Path -Path $FontFilePath -Leaf)"
        [string]$WindowsFontFile = "$($WindowsFontPath)\$($LocalFontFile)"

        If (Test-Path -Path "$($WindowsFontFile)") {
            Write-Host "Uninstall font $($LocalFontFile)..."
            
            # -- STAGE 1 : Undeploy the file
            [bool]$uninstalledFont = $false

            try {
                Remove-Item -Path "$($WindowsFontFile)" -ErrorAction SilentlyContinue
            } Catch {
                # silence
            }
                        
            # -- STAGE 2 : Clean registry entry
            If (-not (Test-Path -Path "$($WindowsFontFile)")) {
                # only for Windows platform                
                [UInt16]$TargetPlatform = $global:TrueTypePlatforms["ISO"]
                                
                # Register all font to Windows Registry
                $RegistryFontsHive = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
                
                # open the .tff file
                Open-TTFFile -FontFile "$($FontFilePath)"

                # read the current .tff file
                $TTF_Header = Read-TTFHeader

                If (($TTF_Header.Major -eq 1) -and ($TTF_Header.Minor -eq 0)) {
                    # read .ttf tables and get the 'Name' table
                    $TTF_Table_Index = Read-TTFTables -TTFHeader $TTF_Header
                    $TTF_Name_Tables = Read-TTFNameSubTable -TTFHeader $TTF_Header -TTFFileTables $TTF_Table_Index

                    # extract the font name for the current font .tff file
                    ForEach($TTF_Name_Table in $TTF_Name_Tables) {
                        If ($TTF_Name_Table.PlatformId -eq $TargetPlatform) {
                            If ($TTF_Name_Table.NameId -eq 4) {
                                try {
                                    Remove-ItemProperty -Path $RegistryFontsHive -Name "$($TTF_Name_Table.Name) (TrueType)" -Force | Out-Null
                                    $uninstalledFont = $true
                                } Catch {
                                    Write-Warning "-> Could not unregister font $([char](34))$($TTF_Name_Table.Name) (TrueType)$([char](34))!" 
                                }
                            }
                        }
                    }
                } Else {
                    Write-Warning "-> Unsupported TrueType font file!"
                }

                # close the .tff file
                Close-TTFFile
            }
            
            # report
            If ($uninstalledFont) {
                Write-Host "-> Font $($WindowsFontFile) uninstalled."
            } Else {
                Write-Warning "-> Something went wrong during Font $($WindowsFontFile) uninstalled."
            }
        } Else {
            Write-Host "Font $($WindowsFontFile) is already uninstall."
        }
    }

}
#endregion


#region Main Function
#
# Function : Main
# The main c-style function
#
Function Main {
    Param (
        [System.Array]$Arguments
    )
    
    [bool]$Install = $true
    [string]$SearchPath = "$($global:WorkDir)"

    # extract arguments
    If ($Arguments) {
        for($i = 0; $i -lt $Arguments.Length; $i++) {
            # A pwsh Switch statement is by default always case insensitive for Strings
            Switch ($Arguments[$i]) {
                "-uninstall" {
                    $Install = $false       
                }

                "-install" {
                    $Install = $true       
                }

                "-path" {
                    If (($i +1) -le $Arguments.Length) {                
                        $SearchPath = "$($Arguments[$i+1])"
                    }      
                }

                default {
					$Install = $true
				}
            }
        }
    }

    # Show path
    Write-Host ""
    Write-Host "Path = $($SearchPath)"
    
    # Get list of fonts to install
    $FontsList = Get-FontFilesFromFolder -SearchPath $SearchPath

    If ($Install) {
        # Install all fonts from our list
        Write-Host "Mode = Install"        
        $FontsList | % { Install-FontFile $_.FullName; Write-Host "" }
    } Else {
        # Uninstall all fonts from our list
        Write-Host "Mode = Uninstall"        
        $FontsList | % { Uninstall-FontFile $_.FullName; Write-Host "" }
    }
    # exit!
    Exit (0)
}
#endregion



# -----------------------------
# call the Main function!
Main -Arguments $args

