# write_dump
Write dump in windows and continue execution

1. Install WINSDK10 debugging tools
2. .sympath srv*c:\Symbols*https://msdl.microsoft.com/download/symbols
3. Run the following command to analize dump: cdb -z yourdump.dmp -c "!analyze -v; q"
