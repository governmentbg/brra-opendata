# brra-opendata
Opendata export script for the commercial register of Bulgaria.

How to use:

    java Anonymizer <root-dir> <target-dir> <max-year=2017>

Or if used with a jar file

    java -jar brra-opendata.jar <root-dir> <target-dir> <max-year=2017>
    
Where:
- `<root-dir>` is the root directory of the export XML files
- `<target-dir>` is the target directory for the opendata-ready export files
- `<max-year>` is the maximum year until which the anonymizer will run (normally = the current year). The default value is 2017
