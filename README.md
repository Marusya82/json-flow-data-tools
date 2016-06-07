## json-flow-data-tools
#### filter_tool.py
Generates a json file with flows that satisfy the command line filter.
parsing command line:<br />
$ python filter_tool.py -ifolder ../Data/ -BE 5.0 -dp 53 -o stdout <br />
enchanced command line functionality: -ifilter "dp = 53 and be > 5.0"
#### summary_tool.py
Prints out a summary for all flows: number of flows, max/ave/standard deviation of a message length, etc.<br />
$ python summary_tool.py
