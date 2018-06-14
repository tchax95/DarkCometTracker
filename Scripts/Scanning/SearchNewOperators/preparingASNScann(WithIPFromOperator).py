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

def getRipeRouteInfosFromIP(ip):
    process = subprocess.Popen("whois -h whois.ripe.net -- '-r -a -T route " + ip + "'",stdout=subprocess.PIPE, shell=True)
    (output, err) = process.communicate()

    try:
        patternRoute = re.compile("route:\s*(.*)\n")
        route = patternRoute.search(output).group(1)
        patternOrigin = re.compile("origin:\s*(.*)\n")
        origin = patternOrigin.search(output).group(1)
        patternDescr = re.compile("descr:\s*(.*)\n")
        descrList = patternDescr.findall(output)
        descr = '/'.join(descrList)

        print ip + " " + route + " " + origin + " " + descr

        return [route, origin, descr]
    except Exception as e:
        print 'ERROR GET RIPE INFOS FOR IP : ' + ip
        print output
        return []

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
    process = subprocess.Popen("masscan -iL \"" + IP_RANGE_FILENAME + "\" -sL > \"" + IP_GENERATED_FILENAME + "\"",stdout=subprocess.PIPE, shell=True)
    (output, err) = process.communicate()
    removeDuplicates(IP_GENERATED_FILENAME)

#The ips come from results from Shodan
def createRouteOriginFile(filenameIpsSource):
    with open(filenameIpsSource,'r') as myFile:
        ipList = csv.reader(myFile)
        with open(ORIGIN_ROUTE_IP_FILENAME, 'w') as originFile:
            wrOriginFile = csv.writer(originFile)

            with open(COUNTRY+'/'+ TIME_STAMP + '_sourcesIp.csv', 'w') as infosFile:
                wrInfosFile = csv.writer(infosFile)

                first = True
                for ip in ipList:
                    if first:
                        first = False
                    else:
                        time.sleep(60)
                    routeInfos = getRipeRouteInfosFromIP(ip[0])
                    if routeInfos:
                        wrOriginFile.writerow([routeInfos[1]])
                        wrInfosFile.writerow([ip[0],routeInfos[0],routeInfos[1],routeInfos[2]])
    removeDuplicates(ORIGIN_ROUTE_IP_FILENAME)


def createIpRangeFile():
    with open(ORIGIN_ROUTE_IP_FILENAME,'r') as myFile:
        originList = csv.reader(myFile)
        with open(IP_RANGE_FILENAME, 'w') as ipRangeFile:

            for origin in originList:
                time.sleep(60)
                IpRangeInfos = getAllRoutesFromOrigin(origin[0])
                for ipRange in IpRangeInfos:
                    ipRangeFile.write(ipRange[0] + " #" + ipRange[1] +"\n")

def searchCountry(host):
	process = subprocess.Popen("geoiplookup "+host,stdout=subprocess.PIPE, shell=True)
	(output, err) = process.communicate()
	secondPart = output.split("GeoIP Country Edition: ", 1)[1]
	country = secondPart.split("\nGeoIP City Edition", 1)[0]
	return country

def removeIpsNotFromCountry():
    with open(IP_GENERATED_FILENAME,'r') as myFile:
        ipList = csv.reader(myFile)
        with open(IP_TOSCAN_FILENAME, 'w') as ipToScanFile:
            wrIpToScanFile = csv.writer(ipToScanFile)

            with open(COUNTRY+'/'+ TIME_STAMP + '_ipTrash', 'w') as ipTrashFile:
                wrIpTrashFile = csv.writer(ipTrashFile)

                for ip in ipList:
                    ipCountry = searchCountry(ip[0])
                    if COUNTRY in ipCountry:
                        wrIpToScanFile.writerow([ip[0]])
                    else:
                        wrIpTrashFile.writerow([ip[0],ipCountry])



'''
init
'''

if __name__ == "__main__":
    INPUT_FILE = 'ipFile.csv'

    ts = time.time()
    TIME_STAMP = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H-%M')
    COUNTRY ='United States' #Same has in geoiplookup
    ORIGIN_ROUTE_IP_FILENAME = COUNTRY + '/'+ TIME_STAMP + '_originSourceIPs.csv'
    IP_RANGE_FILENAME = COUNTRY + '/'+ TIME_STAMP + '_ipRange.csv'
    IP_GENERATED_FILENAME = COUNTRY + '/'+ TIME_STAMP + '_ipGenerated.csv'
    IP_TOSCAN_FILENAME = COUNTRY + '/'+ TIME_STAMP + '_ipToScan.csv'

    if not os.path.exists(COUNTRY):
        os.makedirs(COUNTRY)

    createRouteOriginFile(INPUT_FILE)
    createIpRangeFile()
    generateIpsToScan()
    removeIpsNotFromCountry()
