#!/usr/bin/python3
#Purpose: This script will read IOC's from a file and retroactively search Elasticsearch for any matches.
# Author Bryant Treacle
#############
#  Imports  #
#############
from datetime import datetime
from elasticsearch import Elasticsearch
import time
import requests
import requests.packages
import elasticsearch.helpers
import os
import json
import urllib3
import sys
from elasticsearch_dsl import Search
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Suppress the insecure warning while using verify = False
import warnings
warnings.filterwarnings('ignore', '.*verify_cert*', )

#######################
#Define time frame for #
#searching.           #
#######################
TIME_FRAME = "1"

#########
# Usage #
#########
RETRO_USAGE = """CLI Usage: python3 retrosearch.py [Type(IP, DOMAIN, HASH, WILDCARD)] [Timeframe(in days)]
example: sudo python3 retroseach.py IP 2
"""

#################################	
# elasticsearch config settings #
#################################
with open("/opt/so/conf/elasticsearch/curl.config") as ELASTIC_CRED:
	for line in ELASTIC_CRED:
		ELASTIC_PASS = (line.split(':')[-1].strip('"'))
es = Elasticsearch("https://localhost:9200", http_auth=("so_elastic", ELASTIC_PASS), verify_certs=False) 


############################
# Wildcard search Function #
############################
def RETRO_WILDCARD_SEARCH(SEARCH_TIME_FRAME):
	with open('retrosearch_wildcard.dat') as file_object:
		for line in file_object:
			WILDCARD_ITEM = (line.rstrip())
			resp = es.search(index="*:so-*", body={"query": {"bool": {"must": [{"query_string": {"query": WILDCARD_ITEM }}, {"range":{"@timestamp":{"gte": SEARCH_TIME_FRAME, "lt": "now"}}}]}}},filter_path=['hits.hits._source'], size=1)
			resp_filter = resp.get('hits', {}).get('hits')
			resp_string = str(resp_filter)
			if len(resp_string) >= 5:
				resp_source = resp_filter[0]
				for resp_dict in resp_source:
					MESSAGE = str(resp_source.get('_source', []).get('message'))
					# Write output to a file
					file_output = open("retrosearch_wildcard_results.txt", "a")
					file_output.write("\n")
					file_output.write("IOC " + WILDCARD_ITEM + " Found! Below is the original message:")
					file_output.write("\n")
					file_output.write(MESSAGE)
					file_output.write("\n")
					file_output.close
					print("Found the following IOC: " + WILDCARD_ITEM)
	return

#######################
# IP search function  #
#######################
def RETRO_IP_SEARCH(SEARCH_TIME_FRAME):
	with open('retrosearch_ip.dat') as file_object:
		for line in file_object:
			IP_ADDRESS = (line.rstrip())
			resp = es.search(index="*:so-zeek-*", body={"query": {"bool": {"must": [{"wildcard": {"destination.ip.keyword": IP_ADDRESS }},{"range":{"@timestamp":{"gte": SEARCH_TIME_FRAME, "lt": "now"}}}]}}}, filter_path=['hits.hits._source'], size=1)
			resp_filter = resp.get('hits', {}).get('hits')
			resp_string = str(resp_filter)
			if len(resp_string) >= 5:
				resp_source = resp_filter[0]
				for resp_dict in resp_source:
					MESSAGE = str(resp_source.get('_source', []).get('message'))
					# Write output to a file
					file_output = open("retrosearch_ip_results.txt", "a")
					file_output.write("\n")
					file_output.write("IOC " + IP_ADDRESS + " Found! Below is the original message:")
					file_output.write("\n")
					file_output.write(MESSAGE)
					file_output.write("\n")
					file_output.close
					print("Found the following IOC: " + IP_ADDRESS) 
	return

##########################
# Domain search function #
##########################
def RETRO_DOMAIN_SEARCH(SEARCH_TIME_FRAME):
	with open('retrosearch_domain.dat') as file_object:
		for line in file_object:
			DOMAIN_WILDCARD = (line.rstrip())
			DOMAIN_NAME = "*" + DOMAIN_WILDCARD + "*"
			resp = es.search(index="*:so-zeek-*", body={"query": {"bool": {"must": [{"wildcard": {"dns.query.name.keyword": DOMAIN_NAME}},{"range":{"@timestamp":{"gte": SEARCH_TIME_FRAME, "lt": "now"}}}]}}}, filter_path=['hits.hits._source'], size=1)
			resp_filter = resp.get('hits', {}).get('hits')
			resp_string = str(resp_filter)
			if len(resp_string) >= 5:
				resp_source = resp_filter[0]
				for resp_dict in resp_source:
					MESSAGE = str(resp_source.get('_source', []).get('message'))
					# Write output to a file
					file_output = open("retrosearch_domain_results.txt", "a")
					file_output.write("\n")
					file_output.write("IOC " + DOMAIN_WILDCARD + " Found! Below is the original message:")
					file_output.write("\n")
					file_output.write(MESSAGE)
					file_output.write("\n")
					file_output.close
					print("Found the following IOC: " + DOMAIN_WILDCARD) 
	return

########################
# Hash search Function #
########################
def RETRO_HASH_SEARCH(SEARCH_TIME_FRAME):
	with open('retrosearch_hash.dat') as file_object:
		for line in file_object:
			FILE_HASH = (line.rstrip())
			resp = es.search(index="*:so-zeek-*", body={"query": {"bool": {"must": [{"wildcard": {"hash.md5": FILE_HASH}},{"range":{"@timestamp":{"gte": SEARCH_TIME_FRAME, "lt": "now"}}}]}}}, filter_path=['hits.hits._source'], size=1)
			resp_filter = resp.get('hits', {}).get('hits')
			resp_string = str(resp_filter)
			if len(resp_string) >= 5:
				resp_source = resp_filter[0]
				for resp_dict in resp_source:
					MESSAGE = str(resp_source.get('_source', []).get('message'))
					# Write output to a file
					file_output = open("retrosearch_hash_results.txt", "a")
					file_output.write("\n")
					file_output.write("IOC " + FILE_HASH + " Found! Below is the original message:")
					file_output.write("\n")
					file_output.write(MESSAGE)
					file_output.write("\n")
					file_output.close
					print("Found the following IOC: " + FILE_HASH) 
	return

#####################
#Check for CLI args #
#####################
if len(sys.argv) > 1:
	RETRO_SEARCH_TYPE = sys.argv[1]
	RETRO_SEARCH_TIMEFRAME = sys.argv[2]
	if RETRO_SEARCH_TYPE == "IP":
		SEARCH_TIME_FRAME = "now-" + RETRO_SEARCH_TIMEFRAME + "d/d"
		RETRO_IP_SEARCH(SEARCH_TIME_FRAME)
		sys.exit()
	elif RETRO_SEARCH_TYPE == "DOMAIN":
		SEARCH_TIME_FRAME = "now-" + RETRO_SEARCH_TIMEFRAME + "d/d"
		RETRO_DOMAIN_SEARCH(SEARCH_TIME_FRAME)
		sys.exit()
	elif RETRO_SEARCH_TYPE == "HASH":
		SEARCH_TIME_FRAME = "now-" + RETRO_SEARCH_TIMEFRAME + "d/d"
		RETRO_HASH_SEARCH(SEARCH_TIME_FRAME)
		sys.exit()
	elif RETRO_SEARCH_TYPE == "WILDCARD":
		SEARCH_TIME_FRAME = "now-" + RETRO_SEARCH_TIMEFRAME + "d/d"
		RETRO_WILDCARD_SEARCH(SEARCH_TIME_FRAME)
		sys.exit()
	elif RETRO_SEARCH_TYPE != "IP" or "DOMAIN" or "HASH" or "WILDCARD":
		print(" ")
		print("Input not recognized! Please use the following format:")
		print(RETRO_USAGE)
		sys.exit()

###########################
# Initial Prompt function #
###########################
def RETRO_INITIAL_PROMPT():
	#Define time frame for searching.
	global TIME_FRAME
	SEARCH_TIME_FRAME = "now-" + TIME_FRAME + "d/d"
	INTRO_PROMPT = """
                                 Welcome to
   ____  _____ _____ ____   ___    ____  _____    _    ____   ____ _   _ 
  |  _ \| ____|_   _|  _ \ / _ \  / ___|| ____|  / \  |  _ \ / ___| | | |
  | |_) |  _|   | | | |_) | | | | \___ \|  _|   / _ \ | |_) | |   | |_| |
  |  _ <| |___  | | |  _ <| |_| |  ___) | |___ / ___ \|  _ <| |___|  _  |
  |_| \_\_____| |_| |_| \_\\\___/  |____/|_____/_/   \_\_| \_\\\____|_| |_|

                     Travel back in time and identify IOC's
"""

	INITIAL_PROMPT = """
##########################################################################################
#  To retroactively search for IP addresses: Press 1                                     #
#    Note: Place IP IOCs in the following file: retrosearch_ip.dat                       #
#          Results can be found in the following file: retrosearch_ip_results.txt        #
#                                                                                        #
#  To retroactively search for Domains: Press 2                                          #  
#    Note: Place Domain IOCs in the following file: retrosearch_domain.dat               #
#          Results can be found in the following file: retrosearch_domain_results.txt    #
#                                                                                        #
#  To retroactively search for md5 file hashes: Press 3                                  #
#    Note: Place Hash IOCs in the following file: retrosearch_hash.dat                   #
#          Results can be found in the following file: retrosearch_hash_results.txt      #
#                                                                                        #
#  To retroactivly search for wildcard queries: Press 4                                  #
#    Note: Wildcard Queries can retrun a larger number of false positive results         #
#          Place the wildcard string in the following file: retrosearch_wildcard.dat     #
#	   Results can be found in the following file: retrosearch_wildcard_results.txt  #
#                                                                                        #
#  To change the search time frame: Press 8                                              #  
#                                                                                        #
#  To Exit Retrosearch: Press 9                                                          #
##########################################################################################
"""
	print(INTRO_PROMPT)
	print("                    The current time frame settings is: " + str(TIME_FRAME) + " day(s)") 
	print(INITIAL_PROMPT)
	USER_SELECTION = input("Please choose from the above options:")
	if USER_SELECTION == str(1):  
		RETRO_IP_SEARCH(SEARCH_TIME_FRAME)
		RETRO_INITIAL_PROMPT()
	elif USER_SELECTION == str(2):
		RETRO_DOMAIN_SEARCH(SEARCH_TIME_FRAME)
		RETRO_INITIAL_PROMPT()
	elif USER_SELECTION == str(3):
		RETRO_HASH_SEARCH(SEARCH_TIME_FRAME)
		RETRO_INITIAL_PROMPT()
	elif USER_SELECTION == str(4):
		RETRO_WILDCARD_SEARCH(SEARCH_TIME_FRAME)
		RETRO_INITIAL_PROMPT()
	elif USER_SELECTION == str(8):
		TIME_FRAME = input("Please input the number of days you would like to search: ")
		RETRO_INITIAL_PROMPT()
	elif USER_SELECTION == str(9):
		exit
	else:
		RETRO_INITIAL_PROMPT()
	return
RETRO_INITIAL_PROMPT()

