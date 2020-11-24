Windows virus search engine
==========

![License](https://img.shields.io/badge/licence-Apache%202.0-blue.svg) [![Github All Releases](https://img.shields.io/github/downloads/treddis/vir_search/total.svg)]() 

CLI utility to check vulnerable places in OS Windows with ability to upload malicious file to VirusTotal for signature scanning

	usage: vir_search.py [-h] [--startup-registry] [--startup-services] [--file-scan <path_to_file>] [--startup-folder]
                     [-d] [--check-startup-registry] [--check-startup-folder] [--vt-api-key VT_API_KEY]

	Program for checking vulnerabilities places in OS Windows

	optional arguments:
	  -h, --help            show this help message and exit
	  --startup-registry    check registry autorun
	  --startup-services    check services autorun
	  --file-scan <path_to_file>
	                        send file to VirusTotal to get signature analyze result
	  --startup-folder      check Windows startup folder
	  -d, --debug           enable debug mode
	  --vt-api-key VT_API_KEY
	                        path to file with VirusTotal API key, default is C\Users\%username%\vt_api_key	
