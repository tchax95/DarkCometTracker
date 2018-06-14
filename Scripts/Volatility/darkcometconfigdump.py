import volatility.utils as utils
import volatility.plugins.taskmods as taskmods
import volatility.debug as debug
import volatility.win32.tasks as tasks
import volatility.plugins.malware.malfind as malfind
import codecs
import csv
import yara
import re
import hashlib
import os
import subprocess

"""
sigs = {
    'darkcomet_config': 'rule darkcomet_config {strings: $a = "#BEGIN DARKCOMET DATA --" ascii nocase condition: $a}',
    'version': 'rule version {strings: $a = /#KCMDDC\d+#-890/ ascii nocase condition: $a}',
}
"""

sigs = {
    'darkcomet_config': 'rule darkcomet_config {strings: $a = "MUTEX" ascii nocase condition: $a}',
    'version': 'rule version {strings: $a = /#KCMDDC\d+#-890/ ascii nocase condition: $a}',
}


class darkcometconfigdump(taskmods.PSList):
    """Dump darkcomet rat config"""
    number = None

    def setNumber(self, number, file_path):
        self.number = number
        self.file_path = file_path

    def get_vad_base(self, task, address):
        """ Get the VAD starting address"""

        for vad in task.VadRoot.traverse():
            if vad.End >= address >= vad.Start:
                return vad.Start
        return None

    def searchCountry(self, host):
        process = subprocess.Popen("geoiplookup " + host, stdout=subprocess.PIPE, shell=True)
        (output, err) = process.communicate()
        try:
            #country = output.split("GeoIP Country Edition: ", 1)[1].split("\nGeoIP City Edition", 1)[0]
            country = re.search(r"(?<=GeoIP Country Edition: ).*", output).group().split(", ")
            if "not found" in country[0]:
                country = ["","NOT_IN_DB"]
            if "can\'t resolve hostname" in country[0]:
                country = ["","NOT_RESOLVED"]
        except Exception as e:
            country = ["","PARSING_ERROR"]
        return country

    def addHeaderToCSVIfNecessery(self, filePath):
        if not os.path.isfile(filePath):
            with open(filePath, 'w') as f:
                wr = csv.writer(f)
                wr.writerow(["TASK", "PATH", "FILE HASH", "PROCESS", "HOST", "PORT", "PASSWORD", "FIREWALL", "KEYLOGGER", "DK_VERSION", "CTRY_CODE", "COUNTRY"])

    def calculate(self):

        addr_space = utils.load_as(self._config)
        rules = yara.compile(sources=sigs)

        filepath = "/home/proj2/Desktop/automatic/results.csv"
        tempfilepath = "/home/proj2/Desktop/automatic/temp_results.csv"

        self.addHeaderToCSVIfNecessery(filepath)
        self.addHeaderToCSVIfNecessery(tempfilepath)

        with open(tempfilepath, 'a') as tempfile:
            tempwriter = csv.writer(tempfile)

            with open(filepath, 'a') as csvfile:
                csvwriter = csv.writer(csvfile)
                counter = 1
                #debug.warning("double with")

                for task in self.filter_tasks(tasks.pslist(addr_space)):
                    if (str(task.ImageFileName).find("pythonw.exe") == -1) or (str(task.ImageFileName).find("qbittorrent.exe") == -1):
                        #debug.warning("first for "+str(counter)+": "+task.ImageFileName)
                        scanner = malfind.VadYaraScanner(task=task, rules=rules)
                        config = False
                        start_add = False
                        stop_add = False
                        dk_version = False
                        hosts = []

                        for hit, address in scanner.scan():
                            #debug.warning("second for")
                            if str(hit) == "version":
                                # config = hit
                                start_add = address
                                stop_add = address + 0xA
                                proc_addr_space = task.get_process_address_space()
                                version_raw = proc_addr_space.read(start_add, stop_add - start_add)
                                ves = str(version_raw)
                                version_matcher = re.search(r"#KCMDDC\d+#",ves)
                                dk_version = version_matcher.group()
                                dk_version = dk_version+"-890"
                                # debug.warning(dk_version)

                            if str(hit) == 'darkcomet_config':
                                #debug.warning("match found")
                                config = hit
                                start_add = address - 0x30
                                stop_add = address + 0x512

                            if config and start_add and stop_add:
                                #debug.warning("Config: "+str(config))
                                #debug.warning("Start addr: "+str(start_add))
                                #debug.warning("End addr: "+str(stop_add))
                                dk_config_port = ""
                                dk_config_password = ""
                                dk_config_firewall = ""
                                dk_config_keylogger = ""
                                path = ""
                                hash = ""

                                proc_addr_space = task.get_process_address_space()
                                dk_config = proc_addr_space.read(start_add, stop_add - start_add)
                                dk_config = str(dk_config)
                                # debug.warning(dk_config)

                                if str(dk_version).find("51") == -1:
                                    net_data_matcher = re.finditer(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}|([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}:\d{1,5}", dk_config)

                                    if net_data_matcher:
                                        for matchNum, match in enumerate(net_data_matcher):
                                            element = match.group()
                                            if not element in hosts:
                                                hosts.append(element)

                                else:
                                    net_data_matcher = re.search(r"(?<=NETDATA={).*(?=})", dk_config)
                                    if net_data_matcher:
                                        net_data_string = net_data_matcher.group()
                                        dk_config_host_matcher = re.finditer(
                                            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}|([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}:\d{1,5}", net_data_string)
                                        for matchNum, match in enumerate(dk_config_host_matcher):
                                            hosts.append(match.group())

                                # debug.warning(hosts)

                                dk_config_password_matcher = re.search(r"(?<=PWD={)\S+(?=})", dk_config)
                                if dk_config_password_matcher:
                                    dk_config_password = dk_config_password_matcher.group()

                                dk_config_firewall_matcher = re.search(r"(?<=FWB={)\S+(?=})", dk_config)
                                if dk_config_firewall_matcher:
                                    dk_config_firewall = dk_config_firewall_matcher.group()

                                dk_config_keylogger_matcher = re.search(r"(?<=OFFLINEK={)\S+(?=})", dk_config)
                                if dk_config_keylogger_matcher:
                                    dk_config_keylogger = dk_config_keylogger_matcher.group()

                                path = "/home/proj2/Desktop/automatic/2_DarkComet/"

                                if len(hosts) > 0 and dk_version is not False:
                                    for h in hosts:
                                        split = h.split(":")
                                        if not self.RepresentsInt(split[0]):
                                            file_data = open(self.file_path, 'rb').read()
                                            hash = hashlib.sha256(file_data).hexdigest()
                                            row =[self.number, path, hash, task.ImageFileName, str(split[0]), str(split[1]), dk_config_password, dk_config_firewall, dk_config_keylogger, dk_version]
                                            row.extend(self.searchCountry(str(split[0])))
                                            csvwriter.writerow(row)
                                            tempwriter.writerow(row)
                                    return "darkcomet"
                                #yield task, config, start_add, stop_add
                            else:
                                pass
                    counter += 1
        return "none"


    def RepresentsInt(self, a):
        try:
            int(a)
            return True
        except ValueError:
            return False