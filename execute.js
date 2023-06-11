document.addEventListener('DOMContentLoaded', function() {
  // Get references to the necessary elements in the DOM
  var openPagesButton = document.getElementById('openPagesButton');
  var decodeCheckbox = document.getElementById('decodeCheckbox');

  // Add a click event listener to the "Open Pages" button
  openPagesButton.addEventListener('click', function() {
    // Get the input value and split it into individual IOCs
    var iocInput = document.getElementById('iocInput').value.trim();
    var ioCs = iocInput.split('\n').map(function(ioc) {
      return ioc.trim();
    });

    // Process each IOC
    ioCs.forEach(function(ioc) {
      // Array to store the selected websites for the current IOC
      var selectedWebsites = [];
      // Initialize the decoded IOC with the original IOC value
      var decodedIoc = ioc;

      // Decode the IOC if the checkbox is checked
      if (decodeCheckbox.checked) {
        try {
          decodedIoc = decodeIOC(ioc);
        } catch (error) {
          console.error('Error decoding IOC:', error);
        }
      }

      // Regex patterns to detect different types of IOCs
      var domainPattern = /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,})$/;
      var ipPattern = /^[\d.]+$/;
      var urlPattern = /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/i;
      var fileHashPattern = /^[a-fA-F0-9]{32}$/;

      // Check the selected websites based on the type of IOC

      //Unshorten(https[://]unshorten[.]me/)
      if (document.getElementById('unshorten').checked) {
        // Add the AbuseIPDB website URL for domain and IP types
        if (domainPattern.test(decodedIoc) || urlPattern.test(decodedIoc)) {
          selectedWebsites.push('https://unshorten.me/s/' + encodeURIComponent(decodedIoc));
        }
      }        

      //Threat Intelligence Platforms
      //VirusTotal 
      if (document.getElementById('virustotal').checked) {
        // Add the Virustotal website URL for domain, IP and File Hash
        if (domainPattern.test(decodedIoc) || ipPattern.test(decodedIoc)|| fileHashPattern.test(decodedIoc)) {
          selectedWebsites.push('https://www.virustotal.com/gui/search/' + encodeURIComponent(decodedIoc));
        }
      }

      //Cisco Talos
      if (document.getElementById('talos').checked) {
        // Add the Talos website URL for domain, IP
        if (domainPattern.test(decodedIoc) || ipPattern.test(decodedIoc)) {
          selectedWebsites.push('https://talosintelligence.com/reputation_center/lookup?search=' + encodeURIComponent(decodedIoc));
        }
      }

      //ThreatMiner
      if (document.getElementById('threatminer').checked) {
        // Add the Threatminer website URLs based on the type of IOC
        if (domainPattern.test(decodedIoc)) {
          selectedWebsites.push('https://www.threatminer.org/domain.php?q=' + encodeURIComponent(decodedIoc));
        } else if (ipPattern.test(decodedIoc)) {
          selectedWebsites.push('https://www.threatminer.org/host.php?q=' + encodeURIComponent(decodedIoc));
        } else if (fileHashPattern.test(decodedIoc)) {
          selectedWebsites.push('https://www.threatminer.org/sample.php?q=' + encodeURIComponent(decodedIoc));
        }
      }

      //AlienVault OTX
      if (document.getElementById('alienvault').checked) {
        // Add the Threatminer website URLs based on the type of IOC
        if (domainPattern.test(decodedIoc)) {
          selectedWebsites.push('https://otx.alienvault.com/indicator/domain/' + encodeURIComponent(decodedIoc));
        } else if (ipPattern.test(decodedIoc)) {
          selectedWebsites.push('https://otx.alienvault.com/indicator/ip/' + encodeURIComponent(decodedIoc));
        }
        else if (fileHashPattern.test(decodedIoc)) {
          selectedWebsites.push('https://otx.alienvault.com/indicator/file/' + encodeURIComponent(decodedIoc));
        }
      }      

      
      //IP/Domain Blacklist Check:
      //AbuseIPDB
      if (document.getElementById('abuseipdb').checked) {
        // Add the AbuseIPDB website URL for domain and IP
        if (domainPattern.test(decodedIoc) || ipPattern.test(decodedIoc)) {
          selectedWebsites.push('https://www.abuseipdb.com/check/' + encodeURIComponent(decodedIoc));
        }
      }

      //BlacklistAlert
      if (document.getElementById('blacklistalert').checked) {
        // Add the BlacklistAlert website URL for domain and IP
        if (domainPattern.test(decodedIoc) || ipPattern.test(decodedIoc)) {
          selectedWebsites.push('https://blacklistalert.org/?q=' + encodeURIComponent(decodedIoc));
        }
      }

      //Spamhaus
      if (document.getElementById('spamhaus').checked) {
        // Add the Spamhaus website URL for domain and IP
        if (domainPattern.test(decodedIoc) || ipPattern.test(decodedIoc)) {
          selectedWebsites.push('https://check.spamhaus.org/listed/?searchterm=' + encodeURIComponent(decodedIoc));
        }
      }


      //DNS Analysis
      //SecurityTrails
      if (document.getElementById('securitytrails').checked) {
        // Add the SecurityTrails website URL for domain
        if (domainPattern.test(decodedIoc)) {

        var modifiedURL = 'https://securitytrails.com/domain/{input}/dns';
        var replacedURL = modifiedURL.replace('{input}', encodeURIComponent(decodedIoc));
        selectedWebsites.push(replacedURL);
        }
      }

      //ViewDNS
      if (document.getElementById('viewdns').checked) {
        // Add the ViewDNS website URL for domain
        if (domainPattern.test(decodedIoc)) {
          selectedWebsites.push('https://viewdns.info/dnsrecord/?domain=' + encodeURIComponent(decodedIoc));
        }
      }

      //dnslytics
      if (document.getElementById('dnslytics').checked) {
        // Add the dnslytics website URL for domain
        if (domainPattern.test(decodedIoc)) {
          selectedWebsites.push('https://dnslytics.com/domain/' + encodeURIComponent(decodedIoc));
        }
      }    


      //IP/Domain WHOIS Lookup
      //whois
      if (document.getElementById('whois').checked) {
        // Add the whois website URL for domain and IP
        if (domainPattern.test(decodedIoc) || ipPattern.test(decodedIoc)) {
          selectedWebsites.push('https://www.whois.com/whois/' + encodeURIComponent(decodedIoc));
        }
      }
      
      //DomainTools
      if (document.getElementById('domaintools').checked) {
        // Add the DomainTools website URL for domain and IP
        if (domainPattern.test(decodedIoc) || ipPattern.test(decodedIoc)) {
          selectedWebsites.push('https://whois.domaintools.com/' + encodeURIComponent(decodedIoc));
        }
      }
      
      //ViewDNS
      if (document.getElementById('viewdnsw').checked) {
        // Add the ViewDNS website URL for domain and IP
        if (domainPattern.test(decodedIoc) || ipPattern.test(decodedIoc)) {
          selectedWebsites.push('https://viewdns.info/whois/?domain=' + encodeURIComponent(decodedIoc));
        }
      }     
      
      
      //IP Address Information
      //Ipinfo
      if (document.getElementById('ipinfo').checked) {
        // Add the Ipinfo website URL for IP
        if (ipPattern.test(decodedIoc)) {
          selectedWebsites.push('https://ipinfo.io/' + encodeURIComponent(decodedIoc));
        }
      }    

      //ViewDNS(Reverse IP Lookup)
      if (document.getElementById('viewdnsr').checked) {
        // Add the Ipinfo website URL for IP
        if (ipPattern.test(decodedIoc)) {
          selectedWebsites.push('https://viewdns.info/reverseip/?host=' + encodeURIComponent(decodedIoc));
        }
      }          
      
      
      //Web Sandboxing Platforms
      //URLQuery
      if (document.getElementById('urlquery').checked) {
        // Add the URLQuery website URL for domain, IP and URL
        if (domainPattern.test(decodedIoc) || ipPattern.test(decodedIoc) || urlPattern.test(decodedIoc)) {
          selectedWebsites.push('https://urlquery.net/search?q=' + encodeURIComponent(decodedIoc));
        }
      }          

      //URLScan
      if (document.getElementById('urlscan').checked) {
        // Add the URLScan website URL for domain, IP and File Hashes
        if (domainPattern.test(decodedIoc) || ipPattern.test(decodedIoc) || fileHashPattern.test(decodedIoc)) {
          selectedWebsites.push('https://urlscan.io/search/#' + encodeURIComponent(decodedIoc));
        }
      }   

      // Open each selected website in a new tab
      selectedWebsites.forEach(function(website) {
        window.open(website, '_blank');
      });
    });

    // Update the input box with the decoded IOCs
    if (decodeCheckbox.checked) {
      // Decode and update each IOC in the input box
      var decodedIOCs = ioCs.map(function(ioc) {
        try {
          return decodeIOC(ioc);
        } catch (error) {
          console.error('Error decoding IOC:', error);
          return ioc;
        }
      });
      document.getElementById('iocInput').value = decodedIOCs.join('\n');
    }
  });

  // Function to decode an IOC
  function decodeIOC(ioc) {
    if (isBase64Encoded(ioc)) {
      return atob(ioc);
    } else {
      return decodeURIComponent(ioc);
    }
  }

  // Function to check if an IOC is base64 encoded
  function isBase64Encoded(input) {
    try {
      return btoa(atob(input)) === input;
    } catch (error) {
      return false;
    }
  }
});


// Check/Uncheck All Checkbox
document.addEventListener('DOMContentLoaded', function() {
  var uncheckAllCheckbox = document.getElementById('uncheck-all');
  uncheckAllCheckbox.addEventListener('change', function() {
    var checkboxes = document.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(function(checkbox) {
      checkbox.checked = uncheckAllCheckbox.checked;
    });
  });
});


// Fange/Defange IOC
document.addEventListener('DOMContentLoaded', function() {
  // Get references to the necessary elements in the DOM
  var openPagesButton = document.getElementById('openPagesButton');
  var fangeCheckbox = document.getElementById('fangeCheckbox');
  var defangeCheckbox = document.getElementById('defangeCheckbox');

  // Add click event listener to the "Execute" button
  openPagesButton.addEventListener('click', function() {
    // Update the input box based on the selected IOC operations
    var selectedIOCs = iocInput.value.split('\n');
    var updatedIOCs = selectedIOCs.map(function(ioc) {
      if (fangeCheckbox.checked) {
        ioc = fangeIOC(ioc);
      }
      if (defangeCheckbox.checked) {
        ioc = defangIOC(ioc);
      }
      return ioc;
    });
    iocInput.value = updatedIOCs.join('\n');
  });

  // Function to fange an IOC
  function fangeIOC(ioc) {
    // Perform fanging operations on the IOC (e.g., replace characters, add brackets, etc.)
    var fangedIOC = ioc.replace(/\./g, '[.]');
    return fangedIOC;
  }

  // Function to defang an IOC
  function defangIOC(ioc) {
    // Perform defanging operations on the IOC (e.g., remove brackets, replace characters, etc.)
    var defangedIOC = ioc.replace(/\[\.\]/g, '.');
    return defangedIOC;
  }
});
