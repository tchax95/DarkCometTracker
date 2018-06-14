import sys,os,csv,json,re


def rc4crypt(data, key):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))

    return ''.join(out)

def decrypt_traffic(text, enc_key):
    """
    Method to decrypt network traffic using RC4 and a password
    :param text: the text to decrypt
    :param enc_key: key to decrypt the network connection
    :return: the dectypted command or message
    """
    try:
        new_text = text.decode('hex')
        #cipher = ARC4.new(enc_key)
        #v = cipher.decrypt(new_text)
        #return v
        return rc4crypt(new_text,enc_key)
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

def checksourceip():
    """
    Method to print if the packet (or message) comes from the victim or from the operator
    :return: a string containing the direction of the message
    """
    if victim_ip in item['_source']['layers']['ip']['ip.src']:
        return "Victim -> Operator: "
    elif operator_ip in item['_source']['layers']['ip']['ip.src']:
        return "Operator -> Victim: "
    else:
        return "Message not from victim or operator \nSrc: " + item['_source']['layers']['ip']['ip.src'] + "\nDst: " + item['_source']['layers']['ip']['ip.dst']


if __name__ == "__main__":
    base_path = r"C:\Users\sandro\OneDrive\HoneyPot-SharedSpace\thesis\Documentation\2_Workspace\DarkCometCommandsDocumentation\wireshark_exports\\"
    password = "#KCMDDC51#-890testpassword"
    port = "100"
    victim_ip = "192.168.81.128"
    operator_ip = "192.168.81.129"

    #clean screen
    os.system("cls")

    json_file = None

    if len(sys.argv) == 3 and "-f" in sys.argv[1]:
        if os.path.exists(sys.argv[2]+".json"):
            print("\nNo need to convert pcap --> json already exists")
        else:
            os.system("tshark.exe -Y tcp.port==" + port + " -t ad -T json -x -r " + sys.argv[2] + " > " + sys.argv[2] + ".json")

        json_file = sys.argv[2] + ".json"

    elif len(sys.argv) == 3 and "-j" in sys.argv[1]:
        if os.path.exists(sys.argv[2]):
            json_file = sys.argv[2]
        else:
            print("file does not exit!")
            sys.exit(1)
    else:
        print("\nUSAGE: create_diagrams_decryptdc.py -f relative\path\\to\pcapfile.pcapng\n")
        print("or\n")
        print("\nUSAGE: create_diagrams_decryptdc.py -j relative\path\\to\json_file.json\n\n\n\n")
        print("Current base_path is: "+ base_path + "\n\n\n\n")
        sys.exit(1)

    print("\n\n")

    with open(json_file, 'r') as jsonresultfile:
        data = json.load(jsonresultfile)

    with open(sys.argv[2] + ".schema.txt","w") as schema_file:
        #schema_file.write("@startuml\n")

        data_list = []
        time_list = []
        result_dictionary = {}
        result_list = []

        dataflux_flag = False
        dataflux_data = ""
        dataflux_file_counter = 1

        no_care_dataflux = False

        schema_data_counter = 0
        schema_data_max = 2

        transfer_flag = False
        upload_file_count = 0
        transfer_direction = ""
        transfer_counter = 0
        packets_to_pass = 0

        session_port = None

        textfile_transfer_flag = False
        textfile_transfer_counter = 0

        exceptions_counter = 0
        packet_counter = 0

        filter_list = ["KEEPALIVE"]

        data_iterator = iter(data)
        for item in data_iterator:
            packet_counter += 1
            #print "c: "+str(packet_counter)
            #print "textfile transfer: " + transfer_flag.__repr__()
            #print "Direction: " + transfer_direction
            jsonFrame = None

            #print(checksourceip())
            #outputFile.write(checksourceip()+"\n")

            #print "dataflux: " + dataflux_flag.__repr__()

            try:
                if no_care_dataflux:
                    if "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.fin']:
                        no_care_dataflux = False
                        schema_file.write(checksourceip() + "TCP.FIN\n")
                        schema_data_counter = 0
                    else:
                        if schema_data_counter < schema_data_max:
                            schema_file.write(checksourceip() + "Data\n")
                            schema_data_counter += 1
                    continue
                if textfile_transfer_flag:
                    #print "textfile transfer: " + textfile_transfer_flag.__repr__()
                    if "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.fin']:
                        with open(json_file + ".export_" + str(dataflux_file_counter) + ".txt", "w") as exportFile:
                            exportFile.write(dataflux_data)
                        print( "\n\n"+dataflux_data+"\n\n")
                        #outputFile.write("\n\n"+dataflux_data+"\n\n")
                        schema_file.write(checksourceip() + "...\n")
                        schema_file.write(checksourceip() + "TCP.FIN\n")
                        schema_data_counter = 0
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
                                    if schema_data_counter < schema_data_max:
                                        schema_file.write(checksourceip() + "Data\n")
                                        schema_data_counter += 1
                                    #print  dataflux_data
                    continue

                if transfer_flag:
                    if "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.fin']:
                        with open(json_file + ".export_" + str(dataflux_file_counter) + ".png", "wb") as exportFile:
                            exportFile.write(bytes(dataflux_data.decode("hex")))
                        transfer_flag = False
                        upload_file_count = 0
                        transfer_counter = 0
                        schema_file.write(checksourceip() + "...\n")
                        schema_file.write(checksourceip() + "TCP.FIN\n")
                        schema_data_counter = 0
                        continue
                    else:
                        source = None
                        if "upload" in transfer_direction:
                            source = victim_ip
                        elif "download" in transfer_direction:
                            source = operator_ip

                        #print "ip"+source
                        transfer_counter += 1
                        #print( "Transfer counter: " + str(transfer_counter))
                        if transfer_counter >= packets_to_pass:
                            if source in item['_source']['layers']['ip']['ip.src'] and source is not None:
                                if "data" in item['_source']['layers']:
                                    rawdata = item['_source']['layers']['data']['data.data']
                                    if schema_data_counter < schema_data_max:
                                        schema_file.write(checksourceip() + "Data\n")
                                        schema_data_counter += 1
                                    if len(rawdata) % 2 == 1:
                                        # print rawdata
                                        # rawdata = rawdata.decode("hex")
                                        dataflux_data += rawdata.replace(":","")
                        else:
                            # print rawdata
                            #print("nothing for this packet")
                            pass
                    print("-------------------------------------------------------------------------------------")
                    continue
                if dataflux_flag:
                    if "1" in item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.fin']:
                        decrypted_dataflux = decrypt_traffic(dataflux_data,password)
                        with open(json_file + ".export_" + str(dataflux_file_counter) + ".txt", "w") as exportFile:
                            exportFile.write(decrypted_dataflux)
                        print(decrypted_dataflux)
                        #outputFile.write(decrypted_dataflux)
                        dataflux_data = ""
                        dataflux_flag = False
                        dataflux_file_counter += 1
                        schema_file.write(checksourceip() + "...\n")
                        schema_file.write(checksourceip() + "TCP.FIN\n")
                        schema_data_counter = 0
                    else:
                        if victim_ip in item['_source']['layers']['ip']['ip.src']:
                            if "data" in item['_source']['layers']:
                                data = item['_source']['layers']['data']['data.data'].replace(":","").decode("hex")
                                dataflux_data += data
                                if schema_data_counter < schema_data_max:
                                    schema_file.write(checksourceip() + "Data\n")
                                    schema_data_counter += 1

                    #print check_flags()
                    #outputFile.write(check_flags())
                    #print("-------------------------------------------------------------------------------------")
                    #outputFile.write("-------------------------------------------------------------------------------------")
                    continue

                else:
                    if "data" in item['_source']['layers']:
                        if "data.data" in item['_source']['layers']['data']:
                            jsonFrame = item['_source']['layers']['data']['data.data']
                            hex_data = jsonFrame.replace(':', '')
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
                                    #print( "upload file count : " + str(upload_file_count))
                                    upload_file_count += 1
                                    if upload_file_count == 2:
                                        transfer_flag = True
                                        print(t)
                                        schema_file.write(checksourceip() + t + "\n")
                                        #outputFile.write(t)
                                        continue

                                if "DATAFLUX" in t:
                                    dataflux_flag = True
                                    dataflux_file_name = t
                                    print( t)
                                    schema_file.write(checksourceip() + t + "\n")
                                    #outputFile.write(t)
                                    continue

                                if ("QUICKUP" in t and "|HOSTS" in t) or ("QUICKUP" in t and "|UPLOADEXEC" in t) or ("QUICKUP" in t and "|BATCH" in t):
                                    textfile_transfer_counter += 1
                                    if textfile_transfer_counter == 2:
                                        textfile_transfer_flag = True
                                        # continue

                                if ("CAMERA" in t) or ("QUICKUP" in t and "SOUND" in t) or ("SOUND" in t) or (re.search(r"^DESKTOP\d{1,5}",t)) or ("QUICKUP" in t and "|PLUGINPASSWORD" in t):
                                    no_care_dataflux = True
                                    print( t)
                                    schema_file.write(checksourceip() + t + "\n")
                                    #outputFile.write(t)
                                    continue

                                try:
                                    if "\n" in t or "\r" in t:
                                        t = t.replace('\n','')
                                        t = t.replace('\r','')
                                except Exception as ex:
                                    print( "begin replace exception")
                                    print( ex)
                                    print( "end replace exception")

                                print(t)
                                if not any(x in t for x in filter_list) and not "CHATOUTSEPARATOR" in t:
                                    schema_file.write(checksourceip() + t + "\n")
                                elif "CHATOUTSEPARATOR" in t:
                                    schema_file.write("Note over Operator,Victim: New Command Set\n")
                                    _ = next(data_iterator)
                                else:
                                    _ = next(data_iterator)
                                    continue

                                session_port = item['_source']['layers']['ip']['ip.src']

                                #if not t in commandsList:
                                #   commandsList.append(t)
                    else:
                        print(check_flags())
                        #direction = checksourceip().replace(" -> "," --> ")
                        #schema_file.write(direction + check_flags() + "\n")
                        #outputFile.write(check_flags())


            except Exception as e:
                print("Error " + str(exceptions_counter) + ": ");print(e)
                #outputFile.write("Error " + str(exceptions_counter) + ": ");outputFile.write(e)
                exceptions_counter += 1
            print("-------------------------------------------------------------------------------------")
            #outputFile.write("\n-------------------------------------------------------------------------------------\n")
        print( "Data exeptions: " + str(exceptions_counter))
        #outputFile.write("Data exeptions: " + str(exceptions_counter))