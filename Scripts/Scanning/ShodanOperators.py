import csv
import os
import shodan
from datetime import datetime, timedelta
from more_itertools import unique_everseen


def get_shodan_results():
    #SHODAN_API_KEY is available in my account on Shodan's website
    api = shodan.Shodan(SHODAN_API_KEY)

    yesterday = (datetime.utcnow()-timedelta(1)).strftime('%d/%m/%Y')

    try:
        results = api.search('product:"DarkComet trojan" after:'+yesterday, limit=300)
        return results
    except shodan.APIError as e:
        print 'AN ERROR OCCURED during the search'
        return []

def create_file_if_necessary():
    if not os.path.isfile(SHODAN_RESULTS_FILE):
		with open(SHODAN_RESULTS_FILE, 'a') as f:
			wr = csv.writer(f)
			wr.writerow(['IP', 'HOSTNAME', 'PORT', 'COUNTRY', 'COUNTRY_CODE', 'IDTYPE', 'TIMESTAMP', 'ASN', 'ISP'])

    if not os.path.isfile(ADD_OPERATORS_TO_SCAN_FILE):
		with open(ADD_OPERATORS_TO_SCAN_FILE, 'a') as f:
			wr = csv.writer(f)
			wr.writerow(['HOST', 'PORT', 'COUNTRY', 'SOURCE'])

def remove_duplicates(filename):
    tempFile = 'temp_dupl.csv'
    with open(filename, 'r') as in_file, open(tempFile, 'w') as out_file:
        out_file.writelines(unique_everseen(in_file))
    os.remove(filename)
    os.rename(tempFile,filename)

def save_results_shodan(results):
    create_file_if_necessary()

    with open(SHODAN_RESULTS_FILE, 'a') as resultFile:
        wrResult = csv.writer(resultFile)

        with open(ADD_OPERATORS_TO_SCAN_FILE, 'a') as addScanFile:
            wrAddScan = csv.writer(addScanFile)

            for result in results['matches']:
                try:
                    stringHostname = ''
                    isAdddedToScan = False
                    if result['hostnames']:
                        counter = 0
                        for hostname in result['hostnames']:
                            if counter > 0:
                                stringHostname = stringHostname + '/'

                            stringHostname = stringHostname + hostname
                            wrAddScan.writerow([hostname, result['port'], result['location']['country_name'], 'Shodan'])
                            isAdddedToScan = True

                            counter += 1

                    isp = ''
                    if not result['isp'] is None:
                        isp = result['isp'].encode('utf-8')

                    if not 'asn' in result:
                        wrResult.writerow([result['ip_str'], stringHostname, result['port'], result['location']['country_name'], result['location']['country_code'], result['data'], result['timestamp'],'', isp])
                    else:
                        wrResult.writerow([result['ip_str'], stringHostname, result['port'], result['location']['country_name'], result['location']['country_code'], result['data'], result['timestamp'], result['asn'], isp])

                    if not isAdddedToScan:
                        wrAddScan.writerow([result['ip_str'], result['port'], result['location']['country_name'], 'Shodan'])

                    print result['ip_str'] + ':'+ str(result['port'])

                except Exception as e:
                    print e
                    print 'ERROR WITH RESULT : ' + str(result)

    remove_duplicates(SHODAN_RESULTS_FILE) #TODO improve method when  the file becomes bigger


'''
init
'''

if __name__ == "__main__":
    BASEPATH ='/home/scan/Documents/'

    SHODAN_RESULTS_FILE = BASEPATH + 'ShodanOperators.csv'
    ADD_OPERATORS_TO_SCAN_FILE = BASEPATH + 'TrackHabitsOfOperators/newOperators.csv'

    print (datetime.utcnow()).strftime('%Y-%m-%d %H-%M UCT') + ' ----------- ADD SHODAN OPERATORS START-----------------'
    results = get_shodan_results()
    save_results_shodan(results)
