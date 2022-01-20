                                                                         Welcome to
                                                ____  _____ _____ ____   ___    ____  _____    _    ____   ____ _   _ 
                                               |  _ \| ____|_   _|  _ \ / _ \  / ___|| ____|  / \  |  _ \ / ___| | | |
                                               | |_) |  _|   | | | |_) | | | | \___ \|  _|   / _ \ | |_) | |   | |_| |
                                               |  _ <| |___  | | |  _ <| |_| |  ___) | |___ / ___ \|  _ <| |___|  _  |
                                               |_| \_\_____| |_| |_| \_\\___/  |____/|_____/_/   \_\_| \_\\____|_| |_|

                                                            Travel back in time and identify IOC!


This Python3 Script will allow you to retroactively search for Atomic Indicators (IPs, Domains, and MD5 Hashes) in Security Onion 2. The atomic indicators need to be placed in the following files:
   - IPs: retrosearch_ip.dat
   - Domains: retrosearch_domain.dat
   - Hashes: retrosearch_domain.dat

Usage: Retrosearch can be run interactively or through command-line arguments.
   - Interactive mode:
      - Usage: sudo Python3 retro_search.py
   
   - Commandline mode:
      - Usage: python3 retrosearch.py <Type(IP, DOMAIN, HASH)> <Timeframe(in days)>
      - example: sudo python3 retroseach.py IP 2
     
Installation:
  - Retrosearch is designed to run on the Security Onion Manager node and supports Elastic Authentication. It utilizes the Elasticsearexich python3 module and requires the following packages:
      - pip3 install elasticsearch
      - pip3 install elasticsearch_dsl
