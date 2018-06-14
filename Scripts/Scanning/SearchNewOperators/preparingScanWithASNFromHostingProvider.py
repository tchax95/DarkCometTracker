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

def getAllRoutesFromOrigin(originRoute):
    process = subprocess.Popen("whois -h whois.ripe.net -- '-r -a -T route  -i origin " + originRoute + "'",stdout=subprocess.PIPE, shell=True)
    (output, err) = process.communicate()

    listOfRoutes = output.split('% Information related to ')
    resultList = []
    if len(listOfRoutes) <= 1:
        return resultList
    for routeElem  in listOfRoutes[1:] :
        try:
            patternRoute = re.compile("route:\s*(.*)\n")
            route = patternRoute.search(routeElem).group(1)
            patternDescr = re.compile("descr:\s*(.*)\n")
            descrList = patternDescr.findall(routeElem)
            descr = '/'.join(descrList)

            print route + "   " + descr
            resultList.append([route,descr])
        except Exception as e:
            print 'not a route element'
            print routeElem
    return resultList

def removeDuplicates(filename):
    tempFile = 'temp_dupl.csv'
    with open(filename, 'r') as in_file, open(tempFile, 'w') as out_file:
        out_file.writelines(unique_everseen(in_file))
    os.remove(filename)
    os.rename(tempFile,filename)


def generateIpsToScan():
    process = subprocess.Popen("masscan -iL \"" + IP_RANGE_FILENAME + "\" -sL > \"" + IP_TOSCAN_FILENAME + "\"",stdout=subprocess.PIPE, shell=True)
    (output, err) = process.communicate()
    removeDuplicates(IP_TOSCAN_FILENAME)


def createIpRangeFile(asnFile):
    with open(asnFile,'r') as myFile:
        originList = csv.reader(myFile)
        with open(IP_RANGE_FILENAME, 'w') as ipRangeFile:

            for origin in originList:
                time.sleep(60)
                IpRangeInfos = getAllRoutesFromOrigin(origin[0])
                for ipRange in IpRangeInfos:
                    ipRangeFile.write(ipRange[0] + " #" + ipRange[1] +"\n")
'''
init
'''

if __name__ == "__main__":
    INPUT_FILE = 'asnFile.csv'

    ts = time.time()
    TIME_STAMP = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H-%M')
    FOLDER_NAME ='Akamai'
    IP_RANGE_FILENAME = FOLDER_NAME + '/'+ TIME_STAMP + '_ipRange.csv'
    IP_TOSCAN_FILENAME = FOLDER_NAME + '/'+ TIME_STAMP + '_ipToScan.csv'

    if not os.path.exists(FOLDER_NAME):
        os.makedirs(FOLDER_NAME)

    createIpRangeFile(INPUT_FILE)
    generateIpsToScan()
