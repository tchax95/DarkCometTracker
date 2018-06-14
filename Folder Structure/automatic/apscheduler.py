import schedule
import os
import subprocess
import commands
import socket
import csv
import re
import random
from datetime import datetime, timedelta
import time
import operator
import sys
import hashlib

def get_date_time_now():
    """
    Get the time now formatted like 2018-01-30 15:30:00
    :return: the time now formatted
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def dowload_vt():
    """
    The idea was to execute the query to VirusTotal API and download the samples to 1_VT
    """
    print get_date_time_now() + " ==> Download VT Samples started!"
    print get_date_time_now() + " ==> Nothing downloaded"


def offline():
    """
    If there are samples in 1_VT, it submits them to cuckoo to extract their configuration from memory
    """
    print "Offline analyse started!"
    if os.listdir(BASE_PATH+"1_VT/"):
        global MACHINE_COUNTER_OFFLINE

        #Rename files to sha256 hex digest
        for filename in os.listdir(BASE_PATH+"1_VT/"):
            file_data = open(BASE_PATH+"1_VT/"+filename, 'rb').read()
            hash_value = hashlib.sha256(file_data).hexdigest()
            os.rename(BASE_PATH+"1_VT/"+filename, BASE_PATH+"1_VT/"+hash_value)

        #Submit samples
        for file in os.listdir(BASE_PATH+"1_VT/"):
            if os.path.isfile(BASE_PATH+"1_VT/"+file):
                subprocess.Popen("mv "+ BASE_PATH + "1_VT/" + file + " " + BASE_PATH + "1_BeingAnalysed/", shell=True).wait()
                subprocess.Popen("cuckoo submit --custom offline --memory --options human=1,free=yes,screenshots=0 --timeout 50 --machine "+ machines_offline[MACHINE_COUNTER_OFFLINE] + " " + BASE_PATH + "1_BeingAnalysed/" + file, shell=True).wait()

                if MACHINE_COUNTER_OFFLINE == len(machines_offline):
                    MACHINE_COUNTER_OFFLINE = 1
                else:
                    MACHINE_COUNTER_OFFLINE += 1


def getBanner(outputScan):
    """
    Gets Banner from zmap output

    :param outputScan: the output where to search the Banner
    :return: the hexadecimal value of the banner
    """
    try:
        return str(outputScan.split(", Banner: ", 1)[1][:12])
        #banner = re.search(r"[0-9A-F]{12}",outputScan, re.MULTILINE).group()
        #return str(banner)
    except Exception as e:
        print '\033[91m'+"ERROR_BANNER"
        return "BANNER_ERROR"

def scan():
    """
    Performs the scan using nmap and the script to detect if there is a darkcomet operator online.
    In the end, calls online() to start an analysis session with the online operators.
    :return:
    """
    print "Filtering started"
    #filter new CC & merche
    filterNewOperators()

    #add the sample-info to 4_Analysed.csv, with hash, ip, port
    readd_to_toscan()

    print "Scann started"
    timestampFile = datetime.now()

    addHeaderToCSVIfNecessery(trashLog)
    # addHeaderToCSVIfNecessery(activityLog)
    if os.path.isfile(liveAnalysisFile):
        with open(liveAnalysisFile, 'r') as csvFile:
            targetList = csv.DictReader(csvFile)
            for target in targetList:
                process = subprocess.Popen("sudo nmap -p " + target['PORT'] + " -n --data-string \"" + messageScan + "\" --script " + darkCometScript + " --append-output -oN " + resultLog + " " + target['HOST'], stdout=subprocess.PIPE, shell=True)
                (output, err) = process.communicate()
                print output
                if err is not None:
                    print err
                if "|_script: DarkComet" in output:
                    # Means the operator is active
                    print "--> Operator is active: "+target["FILE HASH"]
                    row = [timestampFile, target['HOST'], target['PORT'], target['FILE HASH']]
                    with open(activityLog, 'a') as f:
                        banner = getBanner(output)
                        row.append(banner)
                        wr = csv.writer(f)
                        wr.writerow(row)
    counter = 0
    with open(targetFile, 'r') as csvFile:
        targetList = csv.DictReader(csvFile)
        with open(tempFile, 'w') as f:
            wrTemp = csv.writer(f)
            wrTemp.writerow(['HOST', 'PORT', 'FILE HASH'])
            for target in targetList:
                # TODO: Solve Python problem which doesn't recognise format [command,arg1,arg2]
                process = subprocess.Popen("sudo nmap -p " + target[
                    'PORT'] + " -n --data-string \"" + messageScan + "\" --script " + darkCometScript + " --append-output -oN " + resultLog + " " +
                                           target['HOST'], stdout=subprocess.PIPE, shell=True)
                (output, err) = process.communicate()
                print output

                if "0 IP addresses" in output:
                    # Means the domain name could not be resolved
                    print "--> Goes to trash"
                    addHeaderToCSVIfNecessery(trashFile)
                    row = [timestampFile, target['HOST'], target['PORT'], target['FILE HASH']]
                    with open(trashFile, 'a') as f:
                        wr = csv.writer(f)
                        wr.writerow(row)
                elif "|_script: DarkComet" in output:
                    # Means the operator is active
                    print "--> Operator is active"

                    addHeaderToCSVIfNecessery(liveAnalysisFile)
                    row = [timestampFile, target['HOST'], target['PORT'], target['FILE HASH']]
                    with open(activityLog, 'a') as f:
                        wr = csv.writer(f)
                        banner = getBanner(output)
                        row.append(banner)
                        wr.writerow(row)
                    if counter < 6:
                        with open(liveAnalysisFile, 'a') as f:
                            wr = csv.writer(f)
                            wr.writerow(row)
                        with open(onlineFile, 'a') as f:
                            wr = csv.writer(f)
                            wr.writerow([target['FILE HASH']])
                        counter += 1
                    else:
                        print "--> to many to analyse, not added!"
                        wrTemp.writerow([target['HOST'], target['PORT'], target['FILE HASH']])
                else:
                    # Means the operator is now not active but could it be later
                    wrTemp.writerow([target['HOST'], target['PORT'], target['FILE HASH']])
    os.remove(targetFile)
    os.rename(tempFile, targetFile)
    if os.path.isfile(trashFile):
        print "There are hosts in the trash"
        try:
            host = socket.gethostbyname("www.google.com")
            socket.create_connection((host, 80), 2)
            print "Connected to internet -- hosts in trash are removed"
            with open(trashFile, 'r') as csvFile:
                trashList = csv.DictReader(csvFile)
                with open(trashLog, 'a') as f:
                    wr = csv.writer(f)
                    for trash in trashList:
                        wr.writerow([timestampFile, trash['HOST'], trash['PORT'], trash['FILE HASH']])
            os.remove(trashFile)
        except:
            print "No internet - the hosts will be replaced in target"
            with open(trashFile, 'r') as csvFile:
                trashList = csv.DictReader(csvFile)
                with open(targetFile, 'a') as f:
                    wr = csv.writer(f)
                    for trash in trashList:
                        wr.writerow([trash['HOST'], trash['PORT'], trash['FILE HASH']])
            os.remove(trashFile)
    online()

def checkHost(host):
    """
    Checks if a host is valid. Valid means that it is not a private, localhost or APIPA address
    :param host: the host to check
    :return: True if is valid, false otherwise
    """
    if "192.168." in host:
        return False
    elif "169.254." in host: #APIPA (Automatic Private Internet Protocol Addressing)
        return False
    elif re.match("^(127\.)",host):
        return False
    elif re.match("^(10\.)",host):
        return False
    elif re.match("^(172\.1[6-9]\.)|(172\.2[0-9]\.)|(172\.3[0-1]\.)",host):
        return False
    else:
        return True

def checkPort(port):
    """
    Checks if the port is in the range 1 - 65535
    :param port: the port to check
    :return: True if the port is in the range, False otherwise
    """
    try:
        p = int(port)
        if p >= 1 and p<= 65535:
            return True
        else:
            return False
    except ValueError:
        return False

def check_if_new_operators_in_live_analysis_file(listNewOp):
    """
    Checks if new operators are in the analysis file, in positive case adds it to the To_Scan list
    :param listNewOp: the base list
    :return: the list of new operators in the live analysis file
    """
    if os.path.isfile(liveAnalysisFile):
        resultList = []
        onlineOperatorList = []
        with open(liveAnalysisFile,'r') as csvFile:
            reader = csv.DictReader(csvFile)
            onlineOperatorList = list(reader)
        isInFile = False
        for element in listNewOp:
            for operatorActive in onlineOperatorList :
                if element['HOST'] == operatorActive['HOST'] and element['PORT'] == operatorActive['PORT']:
                    isInFile = True
                    break
            if not isInFile:
                resultList.append(element)
            isInFile = False
        return resultList

def filterNewOperators():
    """
    Filters operators by searching if there are new operators, in positive case adds them to To_scan and sorts the new list
    """
    if not os.path.isfile(newSamplesFile):
        print("Nothing to add to scan")
        return

    print("New samples will be sorted and added to scan")
    # --------------------HANDLE NEW OPERATORS-----------------------------
    sortedlistNewSamples = []
    with open(newSamplesFile,'r') as csvFileNewSamples:
        readerNewSamples = csv.DictReader(csvFileNewSamples)
        sortedlistNewSamples = sorted(readerNewSamples, key=operator.itemgetter('HOST', 'PORT')) #Sort Port as text and not as number!

    operatorList = []
    lastRow=sortedlistNewSamples[0]
    if checkHost(lastRow['HOST']) and checkPort(lastRow['PORT']):
        operatorList.append(lastRow)

    for newSample in sortedlistNewSamples:
        if lastRow['HOST'] == newSample['HOST'] and lastRow['PORT'] == newSample['PORT']:
            continue
        lastRow=newSample
        if checkHost(newSample['HOST']) and checkPort(newSample['PORT']):
            operatorList.append(newSample)

    operatorList = check_if_new_operators_in_live_analysis_file(operatorList) # check if they are in liveAnalysisFile

    #----------------- MERGE  NEW OPERATORS WITH TARGET FILE------------------------

    if not os.path.isfile(targetFile):
        with open(targetFile, 'w') as myfile:
            wr = csv.writer(myfile)
            wr.writerow(['HOST','PORT','FILE HASH'])
    sortedlistOperator = []
    with open(targetFile,'r') as csvFileTarget:
        readerTarget = csv.DictReader(csvFileTarget)
        operatorList.extend(readerTarget)
        sortedlistOperator = sorted(operatorList, key=operator.itemgetter('HOST', 'PORT')) #Sort Port as text and not as number!

    with open(tempTargetFile, 'w') as myfile:
        wr = csv.writer(myfile)
        wr.writerow(['HOST','PORT','FILE HASH'])

        lastOp = sortedlistOperator[0]
        wr.writerow([lastOp['HOST'],lastOp['PORT'],lastOp['FILE HASH']])
        for  op in sortedlistOperator:
            if lastOp['HOST'] != op['HOST'] or lastOp['PORT'] != op['PORT']:
                wr.writerow([op['HOST'],op['PORT'],op['FILE HASH']])
            lastOp = op
    os.remove(targetFile)
    os.rename(tempTargetFile,targetFile)
    os.remove(newSamplesFile)


def searchCountry(host):
    """
    Given a host, searches the country location using geoiploockup
    :param host: the host to get the country
    :return: returns the country of the host by geoiplookup, not found or can't resolve in case of error
    """
    process = subprocess.Popen("geoiplookup "+host,stdout=subprocess.PIPE, shell=True)
    (output, err) = process.communicate()
    secondPart = output.split("GeoIP Country Edition: ", 1)[1]
    country = secondPart.split("\nGeoIP City Edition", 1)[0]
    return country


def addHeaderToCSVIfNecessery(filePath):
    """
    Adds a standard header to a file
    :param filePath: the path to file to handle
    """
    if not os.path.isfile(filePath):
        with open(filePath, 'a') as f:
            wr = csv.writer(f)
            wr.writerow(["DATE", "HOST", "PORT", "FILE HASH"])


def readd_to_toscan():
    """
    Re-adds an operator to the To_scan list if it is in the waiting queue, which means a live analyse has been performed in the last 4 hours
    """
    list = []
    #respecting the Time-delta, re-add to the 3_ToScan
    with open(BASE_PATH + "4_Analysed.csv", 'r') as analysed_file:
        analysed_reader = csv.DictReader(analysed_file)
        #analysed_reader.next()
        for row in analysed_reader:
            now = datetime.now()
            past = now - timedelta(minutes=deltaTime)
            if (now - datetime.strptime(row["DATE"], '%Y-%m-%d %H:%M:%S.%f')) > (now - past):
                with open(BASE_PATH + "3_ToScan.csv", 'a') as file:
                    writer = csv.writer(file)
                    writer.writerow([row["HOST"], row["PORT"], row["FILE HASH"]])
                    print "RE-ADD DONE"
            else:
                list.append((row["DATE"], row["HOST"], row["PORT"], row["FILE HASH"]))

    #refresh 4_Analysed (minus the re-added one)
    os.remove(liveAnalysisFile)
    addHeaderToCSVIfNecessery(liveAnalysisFile)
    with open(BASE_PATH + "4_Analysed.csv", 'a') as analysed_file:
        analysed_writer = csv.writer(analysed_file)
        for date, host, port, hash in list:
            analysed_writer.writerow([date, host, port, hash])


def online():
    """
    If there are operators online, it submits their sample to cuckoo to perform a live analysis
    """
    global MACHINE_COUNTER_ONLINE
    print get_date_time_now() + " ==> online analysis started"
    checklist = []
    with open(BASE_PATH + "4_Online.csv", 'r') as online_file:
        online_reader = csv.reader(online_file)
        for row in online_reader:
            if row[0] not in checklist:
                subprocess.Popen("cuckoo submit --custom online --options human=0,screenshots=0 --timeout 3600 --machine " + machines_online[MACHINE_COUNTER_ONLINE] + " " + BASE_PATH + "2_DarkComet/" +row[0], shell=True)
                checklist.append(row[0])

                if MACHINE_COUNTER_ONLINE == len(machines_online):
                    MACHINE_COUNTER_ONLINE = 1
                else:
                    MACHINE_COUNTER_ONLINE += 1

    #delete all rows
    with open(BASE_PATH + "4_Online.csv", 'w') as online_file:
        online_file.truncate()


if __name__ == "__main__":
    BASE_PATH = "/home/proj2/Desktop/automatic/"
    CSV_CONFIGS_PATH = "/home/proj2/.cuckoo/results/results.csv"

    machines_online = {1:"Machine01", 2:"Machine02", 3:"Machine03", 4:"Machine04", 5:"Machine05", 6:"Machine06"}
    machines_offline = {1:"Machine_Offline01", 2:"Machine_Offline02", 3:"Machine_Offline03"}
    MACHINE_COUNTER_ONLINE = 1
    MACHINE_COUNTER_OFFLINE = 1

    #rosas global vars
    targetFile = BASE_PATH+'3_ToScan.csv'
    darkCometScript = BASE_PATH+'script.nse'
    messageScan = 'Bern University https://bfhthesisnoscan.wixsite.com/noscan'
    resultLog = BASE_PATH+'3_ScanningResults/result.txt'
    trashLog = BASE_PATH+'3_ScanningResults/trash.csv'
    activityLog = BASE_PATH+'3_ScanningResults/activity.csv'
    liveAnalysisFile = BASE_PATH+'4_Analysed.csv'
    onlineFile = BASE_PATH+'4_Online.csv'
    tempFile = BASE_PATH+"temp.csv"
    trashFile = BASE_PATH+'3_ScanningResults/temp_trash.csv'

    newSamplesFile=BASE_PATH+'temp_results.csv' #results (only new ones)
    tempTargetFile = BASE_PATH+'temp_target.csv'
    deltaTime = 260  # 4 hours + 20 min buffer

    print get_date_time_now() + " ==> Program started"

    schedule.every().day.at("02:00").do(dowload_vt)
    schedule.every().day.at("04:00").do(offline)
    schedule.every(60).minutes.do(scan)

    try:
        while True:
            schedule.run_pending()
            time.sleep(60)
            print get_date_time_now() + " ==> -----"
    except Exception as e:
        print e
        print "\n\nbye bye!!"
        sys.exit(0)