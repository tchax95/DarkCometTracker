import sys,os,csv,json,re
from Crypto.Cipher import ARC4

def decrypt_traffic(text, enc_key):
    """
    Method to decrypt network traffic using RC4 and a password
    :param text: the text to decrypt
    :param enc_key: key to decrypt the network connection
    :return: the dectypted command or message
    """
    try:
        new_text = text.decode('hex')
        cipher = ARC4.new(enc_key)
        v = cipher.decrypt(new_text)
        return v
    except Exception as e:
        return e

def check_flags():
    """
    Method to print the type of packet when no data is provided
    :return: the type of packet if no data is provided
    """
    if "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.ack'] and "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.syn']:
        return "SYN - ACK"
    elif "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.ack'] and "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.fin']:
        return "FIN - ACK"
    elif "0" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.ack'] and "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.syn']:
        return "SYN"
    elif "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.ack'] and "0" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.syn']:
        return "ACK"
    else:
        return "NOTHING"

def check_source_ip():
    """
    Method to print if the packet (or message) comes from the victim or from the operator
    :return: a string containing the direction of the message
    """
    if victim_ip in item['_source']['layers']['ip']['ip.src']:
        return "victim --> operator"
    elif operator_ip in item['_source']['layers']['ip']['ip.src']:
        return "operator --> victim"
    else:
        return "Message not from victim or operator \nSrc: " + item['_source']['layers']['ip']['ip.src'] + "\nDst: " + item['_source']['layers']['ip']['ip.dst']


if __name__ == "__main__":
    basepath = "C:\\Users\\a\\Desktop\\dc\\wireshark_exports\\"
    password = "#KCMDDC51#-890testpassword"
    port = "100"
    victim_ip = "192.168.81.128"
    operator_ip = "192.168.81.129"

    filter_list = ["KEEPALIVE", "backinfoes", "IDTYPE", "GetSIN", "RefreshSIN"]
    filter_activator = True

    csv_commands_file_path = basepath + "commands.csv"
    commandsList = []

    #clean screen
    os.system("cls")

    json_file = None

    if len(sys.argv) == 3 and "-f" in sys.argv[1]:
        if os.path.exists(sys.argv[2]+".json"):
            print "\nNo need to convert pcap --> json already exists"
        else:
            os.system("tshark.exe -Y tcp.port==" + port + " -t ad -T json -x -r " + sys.argv[2] + " > " + sys.argv[2] + ".json")

        json_file = sys.argv[2] + ".json"

    elif len(sys.argv) == 3 and "-j" in sys.argv[1]:
        if os.path.exists(sys.argv[2]):
            json_file = sys.argv[2]
        else:
            print "file does not exit!"
            sys.exit(1)
    else:
        print "\nUSAGE: decryptdc.py -f relative\path\\to\pcapfile.pcapng\n"
        print "or\n"
        print "\nUSAGE: decryptdc.py -j relative\path\\to\json_file.json\n\n\n\n"
        print "Current Basepath is: "+ basepath + "\n\n\n\n"
        sys.exit(1)

    print "\n\n"

    with open(csv_commands_file_path, "r") as csv_commands_file:
        reader = csv.reader(csv_commands_file)
        for row in reader:
            commandsList.append(row[0])

    with open(json_file, 'r') as json_result_file:
        data = json.load(json_result_file)

    with open(sys.argv[2] + ".output.txt", "w") as output_file:

        data_list = []
        time_list = []
        result_dictionary = {}
        result_list = []

        dataflux_flag = False
        dataflux_data = ""
        dataflux_file_counter = 1

        no_care_dataflux = False

        transfer_flag = False
        upload_file_count = 0
        transfer_direction = ""
        transfer_counter = 0
        packets_to_pass = 0

        sessionport = None

        textfile_transfer_flag = False
        textfile_transfer_counter = 0

        exceptions_counter = 0
        packet_counter = 0

        for item in data:
            packet_counter += 1
            #print "c: "+str(packet_counter)
            #print "textfile transfer: " + transfer_flag.__repr__()
            #print "Direction: " + transfer_direction
            json_frame = None

            #print check_source_ip()
            #output_file.write(check_source_ip()+"\n")

            #print "dataflux: " + dataflux_flag.__repr__()

            try:
                if no_care_dataflux:
                    # print "No care: "+ no_care_dataflux.__repr__()
                    if "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.fin']:
                        no_care_dataflux = False
                    else:
                        pass
                    continue
                if textfile_transfer_flag:
                    #print "textfile transfer: " + textfile_transfer_flag.__repr__()
                    if "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.fin']:
                        with open(json_file + ".export_" + str(dataflux_file_counter) + ".txt", "w") as exportFile:
                            exportFile.write(dataflux_data)
                        print "\n\n"+dataflux_data+"\n\n"
                        output_file.write("\n\n"+dataflux_data+"\n\n")

                        textfile_transfer_flag = False
                        dataflux_data = ""
                        continue
                    else:
                        if operator_ip in item['_source']['layers']['ip']['ip.src']:
                            if "data" in item['_source']['layers']:
                                rawdata = item['_source']['layers']['data']['data.data']
                                #print rawdata
                                if (len(rawdata) %2 == 0) or (len(rawdata) > 8):
                                    dataflux_data += rawdata.replace(":","").decode("hex")
                                    #print  dataflux_data
                    continue

                if transfer_flag:
                    if "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.fin']:
                        with open(json_file + ".export_" + str(dataflux_file_counter) + ".png", "wb") as exportFile:
                            exportFile.write(bytes(dataflux_data.decode("hex")))
                        transfer_flag = False
                        upload_file_count = 0
                        transfer_counter = 0
                        continue
                    else:
                        source = None
                        if "upload" in transfer_direction:
                            source = operator_ip
                        elif "download" in transfer_direction:
                            source = victim_ip

                        #print "ip"+source
                        transfer_counter += 1
                        #print "Transfer counter: " + str(transfer_counter)
                        if transfer_counter >= packets_to_pass:
                            if source in item['_source']['layers']['ip']['ip.src'] and source is not None:
                                if "data" in item['_source']['layers']:
                                    rawdata = item['_source']['layers']['data']['data.data']
                                    if len(rawdata) %2 == 1:
                                        # print rawdata
                                        # rawdata = rawdata.decode("hex")
                                        dataflux_data += rawdata.replace(":","")
                        else:
                            pass
                            # print rawdata
                            #print "nothing for this packet"
                    #print("-------------------------------------------------------------------------------------")
                    continue
                if dataflux_flag:
                    if "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.fin']:
                        decrypted_dataflux = decrypt_traffic(dataflux_data,password)
                        with open(json_file + ".export_" + str(dataflux_file_counter) + ".txt", "w") as exportFile:
                            exportFile.write(decrypted_dataflux)
                        print decrypted_dataflux
                        output_file.write(decrypted_dataflux)
                        dataflux_data = ""
                        dataflux_flag = False
                        dataflux_file_counter += 1
                    else:
                        if victim_ip in item['_source']['layers']['ip']['ip.src']:
                            if "data" in item['_source']['layers']:
                                data = item['_source']['layers']['data']['data.data'].replace(":","").decode("hex")
                                dataflux_data += data
                        continue

                    #print check_flags()
                    #output_file.write(check_flags())
                    #print("-------------------------------------------------------------------------------------")
                    #output_file.write("-------------------------------------------------------------------------------------")


                else:
                    if "data" in item['_source']['layers']:
                        if "data.data" in item['_source']['layers']['data']:
                            json_frame = item['_source']['layers']['data']['data.data']
                            hex_data = json_frame.replace(':', '')
                            if (len(hex_data.decode("hex")) % 2 == 0) and (len(hex_data)/2 <= 1024):
                                t = decrypt_traffic(hex_data.decode("hex"), password)
                                if t is not None:
                                    if "UPLOADFILE" in t or "DOWNLOADFILE" in t:
                                        if "UPLOADFILE" in t:
                                            transfer_direction = "upload"
                                            packets_to_pass = 6
                                        else:
                                            transfer_direction = "download"
                                            packets_to_pass = 4

                                    if "FILETRANSFER" in t or "UPLOADFILE" in t or "DOWNLOADFILE" in t:
                                        #print "upload file count : " + str(upload_file_count)
                                        upload_file_count += 1
                                        if upload_file_count == 2:
                                            transfer_flag = True
                                            print t
                                            output_file.write(t)
                                            print(
                                            "-------------------------------------------------------------------------------------")
                                            output_file.write(
                                                "\n-------------------------------------------------------------------------------------\n")
                                            continue
                                    """
                                    if "TRANSFER" in t:
                                        transfer_flag = True
                                    """

                                    if ("QUICKUP" in t and "|HOSTS" in t) or ("QUICKUP" in t and "|UPLOADEXEC" in t) or ("QUICKUP" in t and "|BATCH" in t):
                                        textfile_transfer_counter += 1
                                        if textfile_transfer_counter == 2:
                                            textfile_transfer_flag = True
                                            # continue

                                    if "DATAFLUX" in t:
                                        dataflux_flag = True
                                        dataflux_file_name = t
                                        print t
                                        output_file.write(t)
                                        print(
                                        "-------------------------------------------------------------------------------------")
                                        output_file.write(
                                            "\n-------------------------------------------------------------------------------------\n")
                                        continue

                                    temp_desktop_matcher = re.search(r"DESKTOP\d{1,5}",t)
                                    if ("CAMERA" in t) or ("QUICKUP" in t and "SOUND" in t) or ("SOUND" in t) or temp_desktop_matcher or ("QUICKUP" in t and "|PLUGINPASSWORD" in t):
                                        no_care_dataflux = True
                                        print t
                                        output_file.write(t)
                                        print(
                                        "-------------------------------------------------------------------------------------")
                                        output_file.write(
                                            "\n-------------------------------------------------------------------------------------\n")
                                        continue

                                    try:
                                        if "\n" in t or "\r" in t:
                                            t = t.replace('\n','')
                                            t = t.replace('\r','')
                                    except Exception as ex:
                                        print "begin replace exception"
                                        print ex
                                        print "end replace exception"

                                    if not any(x in t for x in filter_list) and filter_activator:
                                        print(t)
                                        output_file.write(t)
                                        print("-------------------------------------------------------------------------------------")
                                        output_file.write(
                                            "\n-------------------------------------------------------------------------------------\n")

                                    sessionport = item['_source']['layers']['ip']['ip.src']

                                    if not t in commandsList:
                                        commandsList.append(t)
                    else:
                        pass
                        #print check_flags()
                        #output_file.write(check_flags())


            except Exception as e:
                print("Error " + str(exceptions_counter) + ": ");print(e)
                output_file.write("Error " + str(exceptions_counter) + ": ");output_file.write(e)
                exceptions_counter += 1



        #sort commands list
        commandsList = sorted(commandsList)

        # print commandsList
        try:
            with open(csv_commands_file_path, "w") as csv_commands_file:
                writer = csv.writer(csv_commands_file)
                for elem in commandsList:
                    writer.writerow([elem])
        except Exception as e:
            print e

        print "Data exeptions: " + str(exceptions_counter)
        output_file.write("Data exeptions: " + str(exceptions_counter))