<h1 align="center">
  <br>
  <img src="https://github.com/samjoy26/testingd/assets/64733080/c7c2e6a0-7d9e-421c-abcf-19741a2fd490" alt="Image" width="500">
  <br>
</h1>

IOC Navigator is a Web Browser Extension that simplifies the process of gathering information about Indicators of Compromise (IOCs), providing time efficiency, streamlined analysis, and customizable threat intelligence sources.

## About
The IOC Navigator offers a simplified approach to gathering information about Indicators of Compromise (IOCs). It allows users to input various types of IOCs, such as domains, IP addresses, URLs, or file hashes, and conveniently select trusted threat intelligence sources through checkbox selection. With a single click, the tool opens all selected websites that are required to analyze IOCs in separate tabs, eliminating the need for manual searches and website navigation. This efficient approach saves valuable time and effort while providing users with quick access to the relevant information needed during the IOC analysis process. 

## Features
- **Time Efficiency and Streamlined Analysis:** By automating the process of opening the required websites to analyze IOCs in one click, this solution significantly reduces the time and effort needed for manual searches and website navigation. Users can quickly access relevant information, saving valuable time and enabling more efficient decision-making and response to potential threats.
- **Customizable Threat Intelligence Sources:** The checkbox selection feature provides users with the flexibility to choose the websites they prefer for IOC analysis. This enables users to customize the tool according to their specific requirements and utilize the threat intelligence sources they trust the most.

## Installation
1. Go to the IOC Navigator Chrome Extension page on the Chrome Web Store:
2. Click "Add to Chrome".
3. Confirm the installation by clicking "Add extension".
4. Access the IOC Navigator by clicking its icon in the Chrome toolbar.

## Usage
1. Input the IOCs (Domains, IP addresses, URLs, or file hashes).
2. Select the appropriate checkboxes for the preferred threat intelligence sources.
3. Click the "Execute" button to automatically open the selected websites in separate tabs.
4. Explore the opened tabs to gather the relevant information about the IOCs efficiently.

## Analyzing IOCs: Threat Intelligence Sources and Processing Functions
I have implemented Regex to validate different types of indicators of compromise (IOCs) before embedding them into a threat intelligence platform. These regex patterns include checks for domains, IP addresses, and file hashes, ensuring that the IOCs adhere to the specified formats. This validation process helps ensure the integrity and accuracy of the IOCs being processed by the threat intelligence platform.

The specified input format mentioned below is designed to work seamlessly with the corresponding platforms.

### Data Processing Functions
| Name                 | Input Type                | Description                                                              |
|----------------------|---------------------------|--------------------------------------------------------------------------|
| URL/Base64 Decoding  | Text String               | Decodes URL or Base64 encoded text to its original format. (Implemented using JS)               |
| Unshorten[.]me API   | Shortened URL             | Expands shortened URLs to their original, full-length form. (Used Unshorten[.]me API - The API is limited to 10 requests per hour for new short URLs )  |
| Check/Uncheck All    |                           | Check or uncheck all checkboxes at once.                                 |
| Fang/Defang IOC      | IOC                       | Converts IOCs to their fanged or defanged representation, respectively. (Implemented using JS)  |


### Threat Intelligence

| Name           | Input Type              | Description                                                               |
|----------------|-------------------------|---------------------------------------------------------------------------|
| VirusTotal     | Domain, IP or File Hash | Platform for analyzing and detecting malicious files, URLs, IPs and domains. It aggregates data from various sources and leverages multiple antivirus engines to provide insights into potential threats |
| Cisco Talos    | Domain or IP            | Threat intelligence platform providing insights into known threats.       |
| ThreatMiner    | Domain, IP or File Hash | Aggregates and analyzes threat data from various sources.                 |
| AlienVault OTX | Domain, IP or File Hash | Open Threat Intelligence platform for sharing and analyzing IOCs.         |

### IP/Domain Blacklist Check

| Name           | Input Type              | Description                                                               |
|----------------|-------------------------|---------------------------------------------------------------------------|
| AbuseIPDB      | IP or Domain            | Check if an IP address or domain is reported as abusive or malicious.     |
| BlacklistAlert | IP or Domain            | Identify if an IP address or domain is blacklisted in various databases.  |
| Spamhaus       | IP or Domain            | Query the Spamhaus database to check if an IP or domain is listed.        |

### DNS Analysis

| Name           | Input Type              | Description                                                               |
|----------------|-------------------------|---------------------------------------------------------------------------|
| SecurityTrails | Domain                  | Investigate historical DNS data and track changes in DNS records.         |
| ViewDNS        | Domain                  | Perform DNS lookups, domain research, and gather various DNS information. |
| dnslytics      | Domain                  | Obtain DNS, Domain, and Ranking Information for Investigations            |

### WHOIS Lookup

| Name                 | Input Type              | Description                                                               |
|----------------------|-------------------------|---------------------------------------------------------------------------|
| Whois                | Domain or IP            | Retrieve WHOIS information for a domain or IP address.                    |
| DomainTools WHOIS    | Domain or IP            | Perform WHOIS lookups and gather detailed domain information.             |
| ViewDNS              | Domain or IP            | Retrieve WHOIS information and other domain-related details.              |

### IP Address Information

| Name           | Input Type              | Description                                                               |
|----------------|-------------------------|---------------------------------------------------------------------------|
| Ipinfo         | IP                      | Retrieve geolocation, network, and other information for an IP address.   |
| ViewDNS (Reverse IP Lookup) | IP         | Perform reverse IP lookup to identify domains sharing the same IP.        |

### Web Sandboxing Platforms

| Name           | Input Type              | Description                                                               |
|----------------|-------------------------|---------------------------------------------------------------------------|
| URLQuery       | Domain, IP or URL       | Search for existing reports.                                              |
| URLScan        | Domain, IP or File Hash | Search for existing reports.                                              |


## Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please feel free to open an issue or submit a pull request.
