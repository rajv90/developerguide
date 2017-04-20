import subprocess
import optparse
import yaml
import os, argparse, sys
import logging
import re

from time import sleep
from sys import exit

#logging.basicConfig( filename='logging.log', level=logging.DEBUG)

def load_yaml(yaml_file):
    """
    function to load yaml file
    :param yaml_file:
    :return:
    """
    try:
        with open(yaml_file) as data_file:
            return yaml.load(data_file)
    except:
        print "Could not load config file settings."
        exit(1)

def update_yaml(product_name, yaml_path, value):
    """
    Function to update the hcm-csa.yaml file with ALLOW_NOT_SIGNED
    """
    yaml_data = load_yaml(yaml_path)
    for yaml_value in yaml_data["spec"]["template"]["spec"]["containers"][1]["env"]:
        if yaml_value["name"] == "CSA_PROP_CONTENT_INSTALLATION_CONTENT_SIGNATURE_VERIFICATION_LEVEL":
           yaml_value["value"] = value

    print yaml.dump(yaml_data,default_flow_style=False)
    
    with open(yaml_path, 'w') as file_obj:
        file_obj.write(yaml.dump(yaml_data,default_flow_style=False))
    
def updateYAML(args):
    """
    function to update itom_input values with FQDN and IP Address
    :pasing --filename arguments with itom_input.json
    :passing -s arguments with FQDN    :passing -i arguments with IP Address
    """
    #os.chdir("/var/vols/itom/core/suite-install/hcm/output/")
    yaml_path = args.fname.format(os.getcwd())
    update_yaml("env", yaml_path, "ALLOW_NOT_SIGNED")
    yaml_data = load_yaml(yaml_path)
    for yaml_data in yaml_data["spec"]["template"]["spec"]["containers"][1]["env"]:
        if yaml_data["name"] == "CSA_PROP_CONTENT_INSTALLATION_CONTENT_SIGNATURE_VERIFICATION_LEVEL":
           print  yaml_data["value"]

def run_command(command, shell=False, communicate=False):
    # logging.info(command)
    try:
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=shell)
    except Exception as e:
        print e

    if communicate:
        out, err = p.communicate()
        print out
        print err
        return out
    else:
        while p.poll() is None:
            line = p.stdout.read(1)
            sys.stdout.write(line)
            sys.stdout.flush()

def kube_delete():
    status = False
    try:
        os.chdir("/var/vols/itom/core/suite-install/hcm/output/")
    except OSError:
        print "/var/vols/itom/core/suite-install/hcm/output/ is not found"
        exit(1)

    timeout = 1200
    while timeout:
        # cmd = '''./kube-status.sh'''
        cmd = '''kubectl delete -f hcm-csa.yaml'''
        out = run_command(cmd, shell=True, communicate=True)
        #  Sleeping 5 seconds
        if 'deployment "hcm-csa" deleted' in out:
            sleep(5)
            timeout -= 5
        else:
            status=True
            break    
        
    return status

def kube_create():
    status = False
    try:
        os.chdir("/var/vols/itom/core/suite-install/hcm/output/")
    except OSError:
        print "/var/vols/itom/core/suite-install/hcm/output/ is not found"
        exit(1)

    timeout = 1200
    while timeout:
        # cmd = '''./kube-status.sh'''
        cmd = '''kubectl create -f hcm-csa.yaml'''
        out = run_command(cmd, shell=True, communicate=True)
        #  Sleeping 5 seconds
        if 'deployment "hcm-csa" created' in out:
            sleep(5)
            timeout -= 5
        else:
           status=True
           break    
        
    return status

def kube_pods_check():
    #status = False
    try:
        os.chdir("/var/vols/itom/core/suite-install/hcm/output/")
    except OSError:
        print "/var/vols/itom/core/suite-install/hcm/output/ is not found"
        exit(1)
    # cmd = '''./kube-status.sh'''
    cmd = '''kubectl get pods --namespace hcm1'''
    out = run_command(cmd, shell=True, communicate=True)
	#SLeeping 180 seconds
    sleep(180)
	print out
        
def main():
    try:
        parser = argparse.ArgumentParser(add_help=True)
        parser.add_argument('-f', '--fname', action="store", dest="fname")
        args = parser.parse_args()
        
        print "File Name to modify: {0}".format(args.fname)
 
        if args.fname is not None:
            print "Updating hcm_csa.yaml file"
            updateYAML(args)
            print "Deleting hcm-csa.yaml file"
            kube_delete()
            print "Creating hcm-csa.yaml file"
            kube_create()
            print "Checking hcm1 get pods hcm-csa.yaml file"
            kube_pods_check()
            
    except Exception as e:
        logging.info(e)
        exit(1)

if __name__ == '__main__':
    main()

