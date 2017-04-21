#!/usr/bin/env python
#(c) Copyright 2017 Hewlett Packard Enterprise Development Company, L.P.

import logging
import argparse
import xml.etree.cElementTree as ET
import os
import datetime
import subprocess
import sys
from argparse import ArgumentParser
print("Configuring silent_install.xml")

def silent_installXml(contentPath, ipaddCSA, portCSA, userCSA, passwordCSA, proto, forceimport='false', ooonly='false', preserveexisting='false'):


    #logPath = contentPath

    #if not logPath.endswith("/"):
        #logfilePath = logPath + "/"


    #else:
        #logfilePath = logPath

    #     Setting up Logger
    #logfileTimestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    #LOG_FILENAME = logfilePath + 'contentInstall_' + logfileTimestamp +'.log'
    #logging.basicConfig(filename=LOG_FILENAME,filemode='w', format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s', datefmt='%H:%M:%S',level=logging.DEBUG)
    #print("Log File: " + LOG_FILENAME)

    contPath = contentPath
    contentlist = []
    print("List of ContentPacks")
    logging.debug("List of ContentPacks")
    for file in os.listdir(contentPath):
        if file.endswith(".zip"):
            print ("ContentPack: " + contentPath + "/" + file)
            logging.debug("ContentPack: " + contentPath + "/" + file)
            contentlist.append(contentPath + "/" + file)
    if len(contentlist) == 0:
        print("No ContentPack zip Found at: " + contPath + "/")
        logging.debug("No ContentPack zip Found at: " + contPath + "/")
        exit(1)
    """
    Edit silent_install.xml

    """
    filename = '/contentInstaller/silent_install.xml'
    # filename = 'C:\content\silent_install.xml'
    try:
        xmlD = ET.parse(filename)
        if xmlD:
            print("silent_install.xml obtained")
            logging.debug("silent_install.xml obtained")
            root = xmlD.getroot()
            contentpack = root.find('contentpack')


            # Removing old contentpack tags
            logging.debug("Removing old contentpack tags")
            removeList = list()
            for element in root.getiterator('contentpath'):
                if element.tag == 'contentpath':
                    removeList.append(element)

            for tag in removeList:
                parent = root.find('contentpack')
                parent.remove(tag)

            # Adding new contentpack file path
            for x in contentlist:
                contentpath = ET.SubElement(contentpack, "contentpath")
                contentpath.text = str(x)

            # Populating tags based on user Input
            host_txt = ipaddCSA
            user_txt = userCSA
            port_txt = portCSA
            password_txt = passwordCSA
            protocol_txt = proto
            fi = forceimport
            ooo = ooonly
            psrv = preserveexisting

            if fi is not None:
                sh = root.find('installtype')
                sh.set('forceImportBlueprints', fi)
                logging.debug("ForceImport: " + fi)
            if ooo is not None:
                sh = root.find('installtype')
                sh.set('ooonly', ooo)
                logging.debug("InstallType: " + ooo)
            if psrv is not None:
                sh = root.find('installtype')
                sh.set('updatePreserveExisting', psrv)
                logging.debug("PreserveExisting: " + psrv)

            for host in root.getiterator("host"):
                # print(host)
                host.text = str(host_txt)
            for user in root.getiterator("user"):
                # print(user)
                user.text = str(user_txt)
            for port in root.getiterator("port"):
                # print(port)
                port.text = str(port_txt)
            for password in root.getiterator("password"):
                # print(password)
                password.text = str(password_txt)
            for protocol in root.getiterator("protocol"):
                # print(protocol)
                protocol.text = str(protocol_txt)
            xmlD.write(filename)
            logging.debug("silent_install.xml modified")
            print("silent_install.xml modified")

            try:
                # nwprocess = os.system('java -jar /contentInstaller/CapsuleInstaller*.jar -silent silent_install.xml')
                # nwprocess = os.system('java -jar /contentInstaller/CapsuleInstaller*.jar -silent silent_install.xml')
                # os.system('cd /contentInstaller')
                realpath = '/contentInstaller/'
                files = os.listdir(realpath)
                files_txt = [i for i in files if i.endswith('.jar')]
                myString = " ".join(files_txt)
                capsuleJarLoc = realpath + myString
                print("Capsule Installer Used: " + capsuleJarLoc)
                nwprocess = subprocess.Popen(['java', '-jar', capsuleJarLoc, '-silent', 'silent_install.xml'], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd='/contentInstaller')
                nwt = nwprocess.communicate()

                #with open(LOG_FILENAME, 'a+') as log_file:
                    #logging.debug(nwt[0].decode('utf-8'))
                    #print(nwt[0].decode('utf-8'))

                    #logging.debug("Capsule Installer return code: ")
                    #print("Capsule Installer return code: ")

                    #logging.debug(str(nwprocess.returncode))
                    #print(str(nwprocess.returncode))

                    #logging.debug("\n")

            except Exception as e:
                                    print (e)
                                    logging.debug(e)
                                    return -1
        else:
            logging.debug("silent_install.xml Parsing Failed")
            raise Exception


    except Exception as e:
        print("Error Occured\n" + str(e))
        logging.debug("Error Occured\n" + str(e))
        return -1





# MAIN

parser = argparse.ArgumentParser()

parser.add_argument('-cp', '--contentpath',
                    required=True,
                    action='store',
                    help='Content Path Location')
parser.add_argument('-ip', '--ipadd',
                    required=True,
                    action='store',
                    help='CSA ip address')
parser.add_argument('-us', '--username',
                    required=True,
                    action='store',
                    help='CSA username')
parser.add_argument('-pass', '--password',
                    required=True,
                    action='store',
                    help='CSA password')
parser.add_argument('-po', '--port',
                    required=True,
                    action='store',
                    help='CSA Port')
parser.add_argument('-pr', '--protocol',
                    required=True,
                    action='store',
                    help='CSA Protocol')
parser.add_argument('-fi', '--forceimport',
                    required=False,
                    action='store',
                    help='Force Import Blueprints')
parser.add_argument('-ooo', '--ooonly',
                    required=False,
                    action='store',
                    help='OO Only')
parser.add_argument('-upe', '--preserveexisting',
                    required=False,
                    action='store',
                    help='Update Preserve Existing')

args = parser.parse_args()





if args.contentpath and args.ipadd and args.username and args.password and args.port and args.protocol is not None:
    silent_installXml(args.contentpath, args.ipadd, args.port, args.username, args.password, args.protocol, args.forceimport, args.ooonly, args.preserveexisting)

else:
    print("Unsatisfied Inputs. Check Inputs.")
    exit(0)
"""
def content_install(contentpath, ipadd, username, password, port, protocol):
    silent_installXml(contentpath, ipadd, port, username, password, protocol)
    return

"""
