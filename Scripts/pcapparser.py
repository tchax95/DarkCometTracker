from cuckoo.common.abstracts import Processing
import sys, os
import re
import csv
import json
import operator
from datetime import datetime

class PcapParser(Processing):

    def run(self):
        self.key = "pcapparser"

        analyse_type = self.task["custom"]

        if analyse_type is not None:
            if "offline" in analyse_type:
                print "Analyse Type: Offline"
                return
            elif "online" in analyse_type:
                flag = False
                port_address = ""
                password = ""
                hash_value = ""
                tcpdump = ""
                task = ""

                print self.task["machine"]

                with open('/home/proj2/Desktop/automatic/results.csv', 'r') as csvfile:
                    reader = csv.DictReader(csvfile)
                    task_matcher = re.search(r"(?<=\/analyses\/)\d+", self.analysis_path)
                    target_matcher = re.search(r"(?<=\/)[0-9a-f]{55,75}", self.task["target"])
                    if task_matcher:
                        task = task_matcher.group()
                    if target_matcher:
                        hash_value = target_matcher.group()

                    for row in reader:
                        if str(hash_value) in row["FILE HASH"]:
                            port_address = row["PORT"]
                            password = row["DK_VERSION"]+row["PASSWORD"]
                            pcapPath = self.pcap_path
                            flag = True

                    if flag == False:
                        print "NOT A DARKCOMET"
                        return

                print str(hash_value)
                print str(port_address)
                print password
                print self.pcap_path
                print flag.__repr__()

                os.system('tshark -Y  tcp.port==' + str(port_address) + ' -t ad -T json -x -r ' + pcapPath + ' > ' + self.analysis_path + '/resultPcap.json')
                with open(self.analysis_path + '/resultPcap.json', 'r') as jsonresultfile:
                    data = json.load(jsonresultfile)

                '''
                global vars
                '''
                data_list = []
                time_array = []
                result_dictionary = {}
                result_array = []

                filter_list = ["KEEPALIVE", "backinfoes", "RefreshSIN"]

                counter = 1

                for item in data:
                    json_frame = None
                    if "tcp" in item['_source']['layers']:
                        if "tcp.payload" in item['_source']['layers']['tcp']:
                            json_frame = item['_source']['layers']["tcp"]["tcp.payload"]
                    elif "data" in item['_source']['layers']:
                        if "data.data" in item['_source']['layers']['data']:
                            json_frame = item['_source']['layers']['data']['data.data']
                    try:
                        if json_frame is not None:
                            hex_data = json_frame.replace(':', '')
                            command = rc4(hex_data.decode('hex').decode('hex'), password)
                            if any(x in command for x in filter_list):
                                continue
                            data_list.append(command)
                        else:
                            raise Exception("No data.data or tcp.payload")
                        time_array.append(item['_source']['layers']['frame']['frame.time'])

                    except Exception:
                        counter += 1

                print "Data exeptions: " + str(counter)

                if len(data_list) == 0:
                    print "NO DATA"
                    return

                sorted_result_dictionary = list(reversed(sorted(result_dictionary.items(), key=operator.itemgetter(1))))

                time = datetime.now()

                time_active = parse_CEST_datetime(time_array[len(time_array)-1]) - parse_CEST_datetime(time_array[0])

                with open('/home/proj2/.cuckoo/results/pcap_results/'+ str(hash_value) +'_' + time.strftime("%Y-%m-%d__%H-%M-%S") + '.csv', 'w') as myfile:
                    wr = csv.writer(myfile)
                    wr.writerow(["Analysis-Machine",self.task["machine"]])
                    wr.writerow(["Sample-Hash", hash_value])
                    wr.writerow(["Analysis Time", time_active])
                    wr.writerow(["----"])
                    wr.writerow(["Name of Command", "TimeStamp"])
                    i = 0
                    for item in data_list:
                        wr.writerow([item, time_array[i]])
                        i += 1

            else:
                print "Analyse Type not defined!"

'''
rc4: - decrypt using the password
'''
def rc4(data, key):
    """RC4 encryption and decryption method."""
    S, j, out = list(range(256)), 0, []

    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for ch in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(ch) ^ S[(S[i] + S[j]) % 256]))

    return "".join(out)

def parse_CEST_datetime(string):
    print string
    months = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10,
              "Nov": 11, "Dec": 12}

    month = months[re.search(r"[A-Z][a-z]{2}", string).group()]
    day = int(re.search(r"(\d{1,2}),", string).group(1))
    year = int(re.search(r"(?<=, )\d{4}", string).group())
    hours = int(re.search(r"(?<=, \d{4} )\d{2}", string).group())
    minutes = int(re.search(r"(?<=, \d{4} \d{2}:)\d{2}", string).group())
    seconds = int(re.search(r"(?<=, \d{4} \d{2}:\d{2}:)\d{2}", string).group())



    return datetime(year, month, day, hours, minutes, seconds)