# Windows UsnJrnl Extractor
Version 1.0

## Overview
Python3 script that can extract a compact version of the UsnJrnl from windows machines.

## Tested on:
* Windows 7
* Windows 10

## Usage
Run the script as an administrator.
You can pass the `-o` or `--output` flag to redirect the output to a path of your choice (By default the output will 
be to a file called usn.bin at the current location)

Usage example:
```shell
python3 usnjrnl_extractor.py -o C:\temp\data.bin
```

## Description
This tool is a pythonic implementation of the great [ExtractUsnJrnl](https://github.com/jschicht/ExtractUsnJrnl) by 
Joakim Schicht.

The usnjrnl:$J is an Alternate Data Stream (ADS) which contains information about changes which occur on the 
partition. Many times during DFIR operation this evidence can be useful to create the full timeline of the events 
on the host.

Some tools can extract the UsnJrnl but with a huge size and full of zeros, but Joakim's tool uses a unique technique
which extract it with much smaller size.

The original tool is written with Autoit, and we re-implemented it in python. Python is a more popular language and 
can be easily debugged, so fellow researchers will be able to walk through the code and learn from it. 

## Author
Daniel Lubel from OTORIO's IR Team.

For any questions/suggestions feel free to contact us at daniel.lubel@otorio.com


