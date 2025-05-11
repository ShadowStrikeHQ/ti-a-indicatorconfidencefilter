# ti-a-IndicatorConfidenceFilter
Filters threat intelligence indicators based on confidence scores provided in a standard format (e.g., STIX). Allows specifying a minimum confidence threshold to reduce false positives. - Focused on Aggregates threat intelligence feeds from various open-source providers (e.g., VirusTotal, AlienVault OTX) into a unified format for easier analysis and consumption. Allows for automated lookups based on indicators of compromise (IOCs) like IPs, domains, and hashes.

## Install
`git clone https://github.com/ShadowStrikeHQ/ti-a-indicatorconfidencefilter`

## Usage
`./ti-a-indicatorconfidencefilter [params]`

## Parameters
- `-h`: Show help message and exit
- `-i`: Path to the input JSON file containing threat intelligence indicators.
- `-c`: No description provided
- `-o`: Path to the output JSON file to store the filtered indicators. If not specified, prints to stdout.

## License
Copyright (c) ShadowStrikeHQ
