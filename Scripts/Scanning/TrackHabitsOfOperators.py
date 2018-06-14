#!/usr/bin/python
import sys, getopt
from pprint import pprint
import binascii

import csv
import datetime
import operator
import os
import re
import socket
import subprocess
import time


def addNewOperators():

	newOperatorFile= BASEPATH + 'newOperators.csv'

	if not os.path.isfile(newOperatorFile):
		print("Nothing to add to scan")
		return

	print("New samples while be sorted and added to scan")

	ts = time.time()
	timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')
	#--------------------HANDLE NEW OPERATORS-----------------------------
	sortedlistNewSamples = []
	with open(newOperatorFile,'r') as csvFileNewSamples:
		readerNewSamples = csv.DictReader(csvFileNewSamples)
		sortedlistNewSamples = sorted(readerNewSamples, key=operator.itemgetter('HOST', 'PORT')) #Sort Port as text and not as number!

	if not sortedlistNewSamples:
		print("File is empty")
		return
		
	operatorList = []
	lastRow=sortedlistNewSamples[0]
	if lastRow['COUNTRY'] == '':
		lastRow['COUNTRY'] = searchCountry(lastRow['HOST'])
	operatorList.append(lastRow)

	for newSample in sortedlistNewSamples:
		if lastRow['HOST'] == newSample['HOST'] and lastRow['PORT'] == newSample['PORT']:
			continue
		if newSample['COUNTRY'] == '':
			newSample['COUNTRY'] = searchCountry(newSample['HOST'])
		lastRow=newSample
		operatorList.append(newSample)

	#----------------- MERGE  NEW OPERATORS WITH TARGET FILE------------------------
	targetFileOperator = []
	with open(targetFile,'r') as csvFileTarget:
		readerTarget = csv.DictReader(csvFileTarget)
		targetFileOperator = sorted(readerTarget, key=operator.itemgetter('HOST', 'PORT')) #Sort Port as text and not as number!

	with open(targetFile, 'a') as myfile:
		wr = csv.writer(myfile)
		for newOperator in operatorList:
			isAlreadyInTarget = False
			for oldOperator in targetFileOperator:
				if newOperator['HOST'] == oldOperator['HOST'] and newOperator['PORT'] == oldOperator['PORT']:
					isAlreadyInTarget = True
				if oldOperator['HOST'] > newOperator['HOST'] : #If we have already past it
					break
			if isAlreadyInTarget == False:
				wr.writerow([newOperator['HOST'],newOperator['PORT'],newOperator['COUNTRY'], newOperator['SOURCE'], timestamp])
	os.remove(newOperatorFile)

def searchCountry(host):
	process = subprocess.Popen("geoiplookup "+host,stdout=subprocess.PIPE, shell=True)
	(output, err) = process.communicate()
	secondPart = output.split("GeoIP Country Edition: ", 1)[1]
	country = secondPart.split("\nGeoIP City Edition", 1)[0]
	return country

def addHeaderToCSVIfNecessery(filePath):
	if not os.path.isfile(filePath):
		with open(filePath, 'a') as f:
			wr = csv.writer(f)
			wr.writerow(['DATE','HOST','PORT', 'COUNTRY', 'SOURCE','DATEADDTOSCAN'])

def getBanner(answerScan):
	#TODO : error handeling
	secondPart = answerScan.split(", Banner: ", 1)[1]
	return secondPart[:12]

def scan():
	ts = time.time()
	timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')

	darkCometScript = BASEPATH + 'script.nse'
	messageScan = 'Bern University https://bfhthesisnoscan.wixsite.com/noscan'
	resultLog = BASEPATH + 'results/result.txt'

	trashLog = BASEPATH + 'results/trash.csv'
	trashFile = BASEPATH + 'results/'+timestamp+'_trash.csv'
	activityLog = BASEPATH + 'results/activity.csv'
	tempFile = BASEPATH + "temp.csv"

	print("startScanning---" + timestamp)
	addHeaderToCSVIfNecessery(trashLog)
	addHeaderToCSVIfNecessery(activityLog)

	with open(targetFile,'r') as csvFile:
		targetList = csv.DictReader(csvFile)
		with open(tempFile, 'w') as f:
			wrTemp = csv.writer(f)
			wrTemp.writerow(['HOST', 'PORT', 'COUNTRY', 'SOURCE', 'DATEADDTOSCAN'])
			for target in targetList:
				#TODO: Solve Python problem which doesn't recognise format [command,arg1,arg2]
				process = subprocess.Popen("sudo nmap -p "+target['PORT']+" -n --data-string \""+messageScan+"\" --script "+darkCometScript+" --append-output -oN "+resultLog+" "+target['HOST'],stdout=subprocess.PIPE, shell=True)
				(output, err) = process.communicate()

				if "0 IP addresses" in output:
					#Means the domain name could not be resolved
					print(target['HOST']+" --> Goes to trash")
					addHeaderToCSVIfNecessery(trashFile)
					row = [timestamp,target['HOST'],target['PORT'],target['COUNTRY'],target['SOURCE'],target['DATEADDTOSCAN']]
					with open(trashFile, 'a') as f:
						wr = csv.writer(f)
						wr.writerow(row)
				elif "|_script: DarkComet" in output:
					#Means the operator is active
					#print(target['HOST']+"--> Operator is active")
					banner = getBanner(output)
					row = [timestamp,target['HOST'],target['PORT'],target['COUNTRY'],target['SOURCE'],target['DATEADDTOSCAN'], banner]
					with open(activityLog, 'a') as f:
						wr = csv.writer(f)
						wr.writerow(row)
					wrTemp.writerow([target['HOST'], target['PORT'],target['COUNTRY'],target['SOURCE'],target['DATEADDTOSCAN']])
				else:
					#Means the operator is not active at this moment but could it be later
					wrTemp.writerow([target['HOST'], target['PORT'],target['COUNTRY'],target['SOURCE'],target['DATEADDTOSCAN']])
	os.remove(targetFile)
	os.rename(tempFile,targetFile)
	#-------------------REMOVE OPERATORS WHO ARE NO MORE VALID FROM TARGET LIST-----------------------------
	if os.path.isfile(trashFile):
		print("There are hosts in the trash")
		try:
			host = socket.gethostbyname("www.google.com")
			socket.create_connection((host,80),2)
			print("Connected to internet -- hosts in trash are removed")
			with open(trashFile,'r') as csvFile:
				trashList = csv.DictReader(csvFile)
				with open(trashLog, 'a') as f:
					wr = csv.writer(f)
					for trash in trashList:
						wr.writerow([timestamp, trash['HOST'], trash['PORT'],trash['COUNTRY'],trash['SOURCE'], trash['DATEADDTOSCAN']])
			os.remove(trashFile)
		except:
			print("No internet - the hosts will be replaced in target")
			with open(trashFile,'r') as csvFile:
				trashList = csv.DictReader(csvFile)
				with open(targetFile, 'a') as f:
					wr = csv.writer(f)
					for trash in trashList:
						wr.writerow([trash['HOST'], trash['PORT'],trash['COUNTRY'],trash['SOURCE'], trash['DATEADDTOSCAN']])
			os.remove(trashFile)

'''
init
'''

if __name__ == "__main__":
	BASEPATH ='/home/scan/Documents/TrackHabitsOfOperators/'
	targetFile = BASEPATH + 'target.csv'
	addNewOperators()
	scan()
