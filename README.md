# Yara-forge-C2-RAT-Process

This ruleset and accompanying Python script are individuals seeking to conduct Yara scanning on processes to detect potential Command and Control (C2) callbacks or Remote Access Trojans (RATs), as well as to identify any malicious process beacons.

While the original yara-forge core package is highly effective, its extensive ruleset, comprising over 6,000 rules, is excessively burdensome for process memory scanning tasks.

To address this issue, this small (and ugly) script designed to selectively filter the relevant C2 or RAT Yara rules. This refinement aims to lessen the computational load and more efficiently uncover potential C2 beacons.

## Now hardcoded keywords list
### C2 and RAT
```
"C2", "RAT", "Brute", "Ratel", "Cobalt", "Strike", "CoreImpact", "Empire", "Haven", "Havoc", "Merlin", "Meterpeter", "Mythic", "Nighthawk", "Nimplant", "Ninja", "Sliver", "Invisimole"
```
#### Bad hits (excluded)
```
"Linux", "Macos", "Dec2", "UNC2891", "UNC2447"
```

## Now Ruleset status
### Support Windows only.
- Around ~500 rules. 

See [Statistic](#Yara64-Statistic)

## Requirements
- Python 3.6+
- plyara `pip3 install plyara`
- Linux for running the Python script
- Windows for yara scan

## How to use - Python script
### Help Menu
```
$ python3 yara_forge_c2_rat.py -h
usage: yara_forge_c2_rat.py [-h] [-f INPUT_FILE] [-o OUTPUT_FILE]

The objective of this script to select the rules based on keywords on yara rules' names

optional arguments:
  -h, --help            show this help message and exit
  -f INPUT_FILE, --input_file INPUT_FILE
                        Optional, input yara rule file path, default: ./yara-rules-core.yar
  -o OUTPUT_FILE, --output_file OUTPUT_FILE
                        Optional, output the selected yara rules to file path, default: ./yara-rules-core-C2-RAT.yar
```

### Run and get the rule
#### Ensure the `yara-rules-core.yar` is exist or you set the input file (`-f`) argument
```
$ python3 yara_forge_c2_rat.py
[+] Now Input Yara Rules: ./yara-rules-core.yar
[+] Loading Yara Rules...
[*] Loaded number of Yara Rules: 6481
[+] Selecting Yara rules by keywords...
[!] Number of Filtered Yara Rules: 511
[+] Now Building Selected Yara Rules to: ./yara-rules-core-C2-RAT.yar
[!] Done, Selected Yara Rules Path: ./yara-rules-core-C2-RAT.yar
```

## How to use - ruleset
using VirusTotal's yara 

`yara64.exe $yarafile $pid -w -p $threads`

## Yara64 Statistic (`yara64.exe -S`)
```
size of AC transition table        : 43688
average length of AC matches lists : 1.372673
number of rules                    : 511
number of strings                  : 3270
number of AC matches               : 11282
number of AC matches in root node  : 0
```

## Credits and Respects
- YARAHQ - [yara-forge](https://github.com/YARAHQ/yara-forge)
- plyara - [plyara](https://github.com/plyara/plyara)
- VirusTotal - [yara](https://github.com/VirusTotal/yara)
- [C2Matrix](https://docs.google.com/spreadsheets/d/1b4mUxa6cDQuTV2BPC6aA-GR4zGZi0ooPYtBe4IgPsSc)

## TODO
- [ ] read file(s) to get the filter keywords
- [ ] Github CI/CD for ruleset release
- [ ] Automate update ruleset from yara forge
- [ ] Performance measurement?
- [ ] Other OS ruleset support? Linux / MacOS?
- [ ] metadata filter?
- [ ] Debug message or verbose message?