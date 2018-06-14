import os
import sys, getopt
import re
import json
from pprint import pprint
import binascii
import operator

import time
import csv
import subprocess
import re
from more_itertools import unique_everseen
import datetime

def removeDuplicates(filename):
    print 'Remove duplicates'

    tempFile = 'temp_dupl.csv'
    with open(filename, 'r') as in_file, open(tempFile, 'w') as out_file:
        out_file.writelines(unique_everseen(in_file))
    os.remove(filename)
    os.rename(tempFile,filename)

def generateIpsToScan():
    print 'Generate IPs'

    process = subprocess.Popen("masscan -iL \"" + IP_RANGE_FILENAME + "\" -sL > \"" + IP_TOSCAN_FILENAME + "\"",stdout=subprocess.PIPE, shell=True)
    (output, err) = process.communicate()
    removeDuplicates(IP_TOSCAN_FILENAME)


def createIpRangeFile():
    countryId = ''
    with open(GEOLITE_COUTRY_LOCATION,'r') as csvFile:
        csvReader = csv.DictReader(csvFile)
        for line in csvReader:
            if line['country_name'] == COUNTRY:
                countryId = line['geoname_id']
                break

    if countryId == '':
        sys.exit('Country not found')

    print 'Country ID: ' + countryId

    with open(GEOLITE_IP_RANGE, 'r') as csvFileToRead:
        csvReader = csv.DictReader(csvFileToRead)

        with open(IP_RANGE_FILENAME, 'w') as csvFileToWrite:
            wr = csv.writer(csvFileToWrite)

            for line in csvReader:
                if line['geoname_id'] ==  countryId:
                    wr.writerow([line['network']])





#This product includes GeoLite2 data created by MaxMind, available from
# <a href="http://www.maxmind.com">http://www.maxmind.com</a>.
'''
init
'''

if __name__ == "__main__":

    ts = time.time()
    TIME_STAMP = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H-%M')

    COUNTRY ='Spain' #Same has in geoiplookup
    GEOLITE_FOLDER = 'GeoLite2-Country-CSV_20180403'
    GEOLITE_COUTRY_LOCATION = GEOLITE_FOLDER + '/GeoLite2-Country-Locations-en.csv'
    GEOLITE_IP_RANGE = GEOLITE_FOLDER + '/GeoLite2-Country-Blocks-IPv4.csv'
    IP_RANGE_FILENAME = COUNTRY + '/'+ TIME_STAMP + '_ipRange.csv'
    IP_TOSCAN_FILENAME = COUNTRY + '/'+ TIME_STAMP + '_ipToScan.csv'

    if not os.path.exists(COUNTRY):
        os.makedirs(COUNTRY)

    createIpRangeFile()
    generateIpsToScan()
