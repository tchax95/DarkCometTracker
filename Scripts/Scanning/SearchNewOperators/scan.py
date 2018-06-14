import os
import sys, getopt
import re
import json
from pprint import pprint
import binascii
import operator
import csv
import time
import datetime
import subprocess
import socket

def nmap_scan():
	darkcomet_script = 'script.nse'
	message_scan = 'Bern University https://bfhthesisnoscan.wixsite.com/noscan'
	result_log = 'results/'+ TIME_STAMP+'_nmapLog.txt'

	operator_active_result = 'results/'+ TIME_STAMP+'_OperatorActiveNmapResult.txt'
	operator_ip_list = 'results/'+ TIME_STAMP+'_IpsOperator.txt'

	with open(TARGET_FILE_NMAP,'r') as temp_file:
		targetList = csv.reader(temp_file)
		for target in targetList:
			#TODO: Solve Python problem which doesn't recognise format [command,arg1,arg2]
			process = subprocess.Popen("sudo nmap -p " + target[1] + " --data-string \""+message_scan+"\" --script "+darkcomet_script+" --append-output -oN \""+result_log+"\" "+target[0],stdout=subprocess.PIPE, shell=True)
			(output, err) = process.communicate()
			print output
			if "|_script: DarkComet" in output:
				#Means there is an operator who is active
				print "--> Operator is active"
				with open(operator_active_result, 'a') as f:
					f.write(output +"\n")
				with open(operator_ip_list, 'a') as f:
					wr = csv.writer(f)
					wr.writerow([target[0], target[1]])

def masscan_scan():
	print "Masscan started"

	target_file = 'toScanMasscan.csv'
	temp_result_file = 'results/'+TIME_STAMP+'_MasscanTemp'
	masscan_results_file = 'results/'+TIME_STAMP +'_masscan.csv'

	#TODO: Solve Python problem which doesn't recognise format [command,arg1,arg2]
	process = subprocess.Popen("sudo masscan -p " + PORTS + " --interactive -iL \"" + target_file + "\" -oL \"" + temp_result_file + "\"",stdout=subprocess.PIPE, shell=True)
	(output, err) = process.communicate()
	print output

	if os.stat(temp_result_file).st_size == 0:
		print "--> No results"
		os.remove(temp_result_file)
	else:
		print"--> Found results"
		prepare_nmap_target_file(temp_result_file)

		with open(temp_result_file,'r') as tempFile:
			resultList = csv.reader(tempFile)

			with open(masscan_results_file, 'a') as temp_file:
				wr = csv.writer(temp_file)

				for result in resultList:
					wr.writerow([result[0]])

		nmap_scan()
		os.remove(temp_result_file)

def prepare_nmap_target_file(masscan_file):
	lines_masscan=[]
	with open(masscan_file,'r') as temp_file:
		lines_masscan = list(temp_file.readlines()[1:-1])
	with open(masscan_file,'w') as temp_file:
		temp_file.writelines(lines_masscan)

	with open(masscan_file,'r') as temp_file:
		openPortList = csv.reader(temp_file, delimiter=' ')

		with open(TARGET_FILE_NMAP, 'w') as temp_file:
			wr = csv.writer(temp_file)

			for openPort in openPortList:
				wr.writerow([openPort[3], openPort[2]])


def prepare_masscan_target_file(number_ips):
	file_to_scan = 'toScanMasscan.csv'
	file_to_wait = 'toScanSecondRound.csv'

	with open(TARGET_FILE, 'r') as temp_file:
		reader = temp_file.readlines()
		with open(file_to_scan, 'w') as writerNow:
			with open(file_to_wait, 'w') as writerLater:
				counter = 0
				for row in reader:
					if counter < number_ips:
						writerNow.write(row)
					else:
						writerLater.write(row)
					counter = counter+1
	os.remove(TARGET_FILE)
	os.rename(file_to_wait,TARGET_FILE)


# def checkInternetConnection():
# 		try:
# 			host = socket.gethostbyname("www.google.com")
# 			socket.create_connection((host,80),2)
# 			print "Connected to internet"
# 		except:
# 			print "No internet - scann will be stopped"
# 			sys.exit("No internet!!!!")

'''
init
'''

if __name__ == "__main__":
	ts = time.time()
	TIME_STAMP = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H-%M')

	PORTS = '1604' #Comma separated value (without space!!! Otherwise it will produce errrors)
	TARGET_FILE='toScan.csv'
	TARGET_FILE_NMAP = 'toScanNmap.csv'
	while os.stat(TARGET_FILE).st_size > 0:
		prepare_masscan_target_file(60000)
		masscan_scan()
