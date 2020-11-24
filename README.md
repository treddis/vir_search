Windows virus search engine
==========

![Github All Releases](https://img.shields.io/github/license/treddis/vir_search) [![Github All Releases](https://img.shields.io/github/downloads/treddis/vir_search/total.svg)]() 

CLI utility to check vulnerable places in OS Windows with ability to upload malicious file to VirusTotal for signature scanning

	usage: vir_search.py [-h] [--startup-registry] [--startup-services] [--file-scan <path_to_file>] [--startup-folder]
                     [-d] [--check-startup-registry] [--check-startup-folder] [--vt-api-key VT_API_KEY]

	Program for checking vulnerabilities places in OS Windows

	optional arguments:
	  -h, --help            show this help message and exit
	  --startup-registry    check registry autorun
	  --startup-folder      check Windows startup folder
	  --file-scan <path_to_file>
	                        send file to VirusTotal to get signature analyze result
	  -d, --debug           enable debug mode
	  --vt-api-key-folder VT_API_KEY
	                        path to file with VirusTotal API key, default is C\Users\%username%\vt_api_key	
