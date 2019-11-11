import requests
from collections import defaultdict
import getpass
from cryptography.fernet import Fernet
import base64
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json
import argparse

parser = argparse.ArgumentParser(description='This script is meant to connect to an existing enSilo console and prepare it for first use in a POC. The intent is to go beyond the default setup to make it easier for the intial testers to be able to have different groups to be able to test with if they want to start blocking without going through the burn in period.')

parser.add_argument('--newGroup', required=False, type=str, help="Name for the new Collector Group - Default is 'Protected'")
parser.add_argument('--executionPolicySource', required=False, type=str, help="Which Execution Policy will be cloned? Default is -Execution Prevention-")
parser.add_argument('--executionPolicyDestination', required=False, type=str, help="What will the cloned Execution Policy be called? Default prepends source with newGroup")
parser.add_argument('--exfiltrationPolicySource', required=False, type=str, help="Which Exfiltration Policy will be cloned? Default is -Exfiltration Prevention-")
parser.add_argument('--exfiltrationPolicyDestination', required=False, type=str, help="What will the cloned Exfiltration Policy be called? Default prepends source with newGroup")
parser.add_argument('--ransomwarePolicySource', required=False, type=str, help="Which Ransomware Policy will be cloned? Default is -Ransomware Prevention-")
parser.add_argument('--ransomwarePolicyDestination', required=False, type=str, help="What will the cloned Ransomware Policy be called? Default prepends source with newGroup")
parser.add_argument('--playbookPolicySource', required=False, type=str, help="Which Playbook Policy will be cloned? Default is -Default Playbook-")
parser.add_argument('--playbookPolicyDestination', required=False, type=str, help="What will the cloned Playbook Policy be called?  Default prepends source with newGroup")
parser.add_argument('--version', action='version', version='%(prog)s 1.0')
parser.add_argument('--un', required=True, type=str, help='Username to log into the enSilo console with') #unhandled
parser.add_argument('--pw', required=True, type=str, help='Password to log into the enSilo console with') #unhandled
parser.add_argument('--instanceName', required=True, type=str, help='Instance name of the enSilo console (THIS.console.ensilo.com)') #unhandled
parser.add_argument('--setProtectionOff', action='store_true', help='This will set the Policies to Simulation when cloned')

args = parser.parse_args()

newGroup = 'Protected' if args.newGroup is None else args.newGroup
executionPolicySource = 'Execution Prevention' if args.executionPolicySource is None else args.executionPolicySource
executionPolicyDestination = f'{newGroup} {executionPolicySource}' if args.executionPolicyDestination is None else args.executionPolicyDestination
exfiltrationPolicySource = 'Exfiltration Prevention' if args.exfiltrationPolicySource is None else args.exfiltrationPolicySource
exfiltrationPolicyDestination = f'{newGroup} {exfiltrationPolicySource}' if args.exfiltrationPolicyDestination is None else args.exfiltrationPolicyDestination
ransomwarePolicySource = 'Ransomware Prevention' if args.ransomwarePolicySource is None else args.ransomwarePolicySource
ransomwarePolicyDestination = f'{newGroup} {ransomwarePolicySource}' if args.ransomwarePolicyDestination is None else args.ransomwarePolicyDestination
playbookPolicySource = 'Default Playbook' if args.playbookPolicySource is None else args.playbookPolicySource
playbookPolicyDestination = f'{newGroup} {playbookPolicySource}' if args.playbookPolicyDestination is None else args.playbookPolicyDestination
username = args.un
instanceName = args.instanceName


'''
Usage: prepareNewPOC.py --un brandon --pw some-password123 --newGroup MyNewGroup --executionPolicySource 'This policy'
                        --exfiltrationPolicySource 'That policy' --ransomwarePolicySource 'The other policy' 
                        --playbookPolicySource 'Magic policy' --setProtectionOff --instanceName 'myInstance'

This will connet to 'https://myInstance.console.ensilo.com' and set the new group's name to MyNewGroup which will then be prepended to all the cloned policies using the source 
policy's name, e.g. the new execution policy will be called 'MyNewGroup This policy' using 'This policy' from the source and
'MyNewGroup' name. The formula used is '{newGroup} {executionPolicySource}' 

These are things that need to be added but are not supported on enSilo API as of Nov/11/2019
Unassign 'High Security Collector Group' from default groups ----- enSilo does not support unassigning through API
Assign 'High Security Collector Group' to Protected Policies
'''

class Credentials:
  def __init__(self):
    self.crypt_key = Fernet.generate_key()
    self.f = Fernet(self.crypt_key)
    self.un = username
    self.pw = self.f.encrypt(args.pw.encode())

  def decrypt_pw(self):
    return self.f.decrypt(self.pw)

creds = Credentials()

class GetListOf:
    def __init__(self):
        print(f'**INIT** Getting Groups/Policies/Playbooks')
        self.PlaybooksJSON = defaultdict()
        self.GroupsJSON = defaultdict()
        self.PoliciesJSON = defaultdict()
        self.GroupsList = self._createList('groups')
        self.PoliciesList = self._createList('policies')
        self.PlaybooksList = self._createList('playbooks')
        print(f'**INIT** Completed getting Groups/Policies/Playbooks')
    
    def Update(self,requestType):
        if requestType == 'groups':
            newList = self._createList(requestType)
            self.GroupsList = newList
        if requestType == 'policies':
            newList = self._createList(requestType)
            self.PoliciesList = newList
        if requestType == 'playbooks':
            newList = self._createList(requestType)
            self.PlaybooksList = newList

    def _createURL(self,requestType):
        request_type = requestType
        URLDict = {'policies':f'policies/list-policies',
                        'playbooks':f'playbooks-policies/list-policies',
                        'groups':f'inventory/list-groups'}
        url = f'https://{instanceName}.console.ensilo.com/management-rest/{URLDict[request_type]}'
        return url
    
    def _createList(self,requestType):
        requestJSON = self.sendRequest('get','',self._createURL(requestType)).json()
        if requestType == 'playbooks':
            self.PlaybooksJSON = requestJSON
        if requestType == 'groups':
            self.GroupsJSON = requestJSON
            return requestJSON
        if requestType == 'policies':
            self.PoliciesJSON = requestJSON
        listOfNames =[]
        for each in requestJSON:
            listOfNames.append(each['name'])
        return listOfNames

    def sendRequest(self,request_method,URLParams,url):
        if request_method == 'get':
            api_request = requests.get(url, auth=requests.auth.HTTPBasicAuth(creds.un, creds.decrypt_pw()), verify=False, params=URLParams)
        if request_method == 'post':
            api_request = requests.post(url, auth=requests.auth.HTTPBasicAuth(creds.un, creds.decrypt_pw()), verify=False, params=URLParams)
        if request_method == 'put':
            api_request = requests.put(url, auth=requests.auth.HTTPBasicAuth(creds.un, creds.decrypt_pw()), verify=False, params=URLParams)
        if api_request.status_code == 200:
            print(f'Successful response')
            if request_method == 'get':
                return api_request
        else:
            error = f'Error in response while trying to retrieve. HTML Code {api_request.status_code} received'
            print(f'{error}')

items = GetListOf()


def create_group(groupName):
    if groupName not in items.GroupsList:
        print(f'**CREATE GROUP** Sending request to create group {groupName}')
        url = f'https://{instanceName}.console.ensilo.com/management-rest/inventory/create-collector-group'
        items.sendRequest('post',{'name':groupName},url)
        print(f'**CREATE GROUP** Sending request to update groups')
        items.Update('groups')
        if groupName in items.GroupsList:
            print(f'**CREATE GROUP** {groupName} successfully created')
        else:
            print(f'**CREATE GROUP** Could not verify that {groupName} was created')
    else:
        print(f'**CREATE GROUP** {groupName} already exists')

def clone_playbook(sourcePolicyName,newPolicyName):
    if sourcePolicyName in items.PlaybooksList:
        if newPolicyName not in items.PlaybooksList:
            print(f'**CLONE PLAYBOOK** Sending request to clone Playbook {sourcePolicyName} to {newPolicyName}')
            url = f'https://{instanceName}.console.ensilo.com/management-rest/playbooks-policies/clone'
            items.sendRequest('post',{'sourcePolicyName': sourcePolicyName,'newPolicyName': newPolicyName},url)
            print(f'**CLONE PLAYBOOK** Sending request to update playbooks')
            items.Update('playbooks')
            if newPolicyName in items.PlaybooksList:
                print(f'**CLONE PLAYBOOK** {newPolicyName} successfully cloned')
            else:
                print(f'**CLONE PLAYBOOK** Could not verify that {newPolicyName} was created')
        else:
            print(f'**CLONE PLAYBOOK** {newPolicyName} is already listed in the Playbooks list')
    else:
        print(f'**CLONE PLAYBOOK** {sourcePolicyName} not found in Playbooks list')

def assign_playbook(policyName,collectorGroupName):
    if policyName in items.PlaybooksList:
        policy = _checkItemInList('playbooks',policyName)
        if policy == False:
            print(f'**ASSIGN POLICY** Error checking the list of Collectors for Playbook: {policyName}')
        else:
            if collectorGroupName not in policy['collectorGroups']:
                print(f'**ASSIGN PLAYBOOKS** Sending request to assign group {collectorGroupName} to Playbook {policyName}')
                url = f'https://{instanceName}.console.ensilo.com/management-rest/playbooks-policies/assign-collector-group'
                items.sendRequest('put',{'policyName': policyName,'collectorGroupNames': collectorGroupName},url)
                print(f'**ASSIGN PLAYBOOKS** Sending request to update playbooks')
                items.Update('playbooks')
                playbookJSON = _checkItemInList('playbooks',policyName)
                if playbookJSON == False:
                    print(f'**ASSIGN PLAYBOOKS** Error getting list of Collectors for Playbook policy: {policyName}')
                else:
                    if collectorGroupName in playbookJSON['collectorGroups']:
                        print(f'**ASSIGN PLAYBOOKS** Successfully assigned {collectorGroupName} to {policyName} Playbook policy')
                    else:
                        print(f'**ASSIGN PLAYBOOKS** Could not verify {collectorGroupName} was added to Playbook {policyName}')
            else:
                print(f'**ASSIGN PLAYBOOKS** {collectorGroupName} is already assigned to {policyName}')
    else:
        print(f'**ASSIGN PLAYBOOKS** Playbook polciy {policyName} not found')
    
def clone_policy(sourcePolicyName,newPolicyName):
    if sourcePolicyName in items.PoliciesList:
        if newPolicyName not in items.PoliciesList:
            print(f'**CLONE POLICY** Sending request to clone {sourcePolicyName} to Policy {newPolicyName}')
            url = f'https://{instanceName}.console.ensilo.com/management-rest/policies/clone'
            items.sendRequest('post',{'sourcePolicyName': sourcePolicyName,'newPolicyName': newPolicyName},url)
            print(f'**CLONE POLICY** Sending request to update policies')
            items.Update('policies')
            if newPolicyName in items.PoliciesList:
                print(f'**CLONE POLICY** Successfully cloned {sourcePolicyName} to {newPolicyName}')
        else:
            print(f'**CLONE POLICY** {newPolicyName} already exists')
    else:
        print(f'**CLONE POLICY** {sourcePolicyName} not found')

def assign_collector(policyName,collectorsGroupName):
    if policyName in items.PoliciesList:
        if collectorsGroupName in items.GroupsList:
            policy = _checkItemInList('policies',policyName)
            if policy == False:
                print(f'**ASSIGN POLICY** There was a problem getting group list ')
            else:
                if collectorsGroupName not in policy['agentGroups']:
                    print(f'**ASSIGN POLICY** Sending request to assign group {collectorsGroupName} to Policy {policyName}')
                    url = f'https://{instanceName}.console.ensilo.com/management-rest/policies/assign-collector-group'
                    items.sendRequest('put',{'policyName': policyName,'collectorsGroupName': collectorsGroupName},url)
                    if policy['operationMode'] == 'Simulation':
                        print(f'{policyName} will be set to Prevention ')
                        items.sendRequest('put',{'policyName':policyName,'mode':'Prevention',url})
                    if policy['operationMode'] == 'Prevention':
                        if args.setProtectionOff:
                            print(f'setProtectionOff argument set, {policyName} will be set to Simulation')
                            items.sendRequest('put',{'policyName':policyName,'mode':'Simulation'},url)
                        else:
                            print(f'{policyName} is already set to Prevention ')
                    print(f'**ASSIGN POLICY** Sending request to update policies')
                    items.Update('policies')
                    policyJSON = _checkItemInList('policies',policyName)
                    if policyJSON == False:
                        print(f'**ASSIGN POLICY** Command sent to assign but there was an error getting the list of Collectors for policy: {policyName}')
                    else:
                        if collectorsGroupName in policyJSON['agentGroups']:
                            print(f'**ASSIGN POLICY** Successfully assigned {collectorsGroupName} to {policyName} policy')
                        else:
                            print(f'**ASSIGN POLICY** Could not verify {collectorsGroupName} was added to {policyName}')
                        
                        if args.setProtectionOff:
                            if policyJSON['operationMode'] == 'Simulation':
                                print(f'Confirmed {policyName} is set to Simulation')
                            if policyJSON['operationMode'] == 'Prevention':
                                print(f'setProtectionOff is set, error setting {policyName} to Prevention')
                        else:
                            if policyJSON['operationMode'] == 'Simulation':
                                print(f'Error setting {policyName} to Prevention')
                            if policyJSON['operationMode'] == 'Prevention':
                                print(f'Confirmed {policyName} is set to Prevention')
                else:
                    print(f'**ASSIGN POLICY** {collectorsGroupName} is already assigned to {policyName}')
        else:
            print(f'**ASSIGN POLICY** {collectorsGroupName} not found, cannot add group that does not exist)')
    else:
        print(f'**ASSIGN POLICY** {policyName} not found, cannot assign to a policy that does not exist')

def _checkItemInList(objectType,policyName):
    dict = {'policies':lambda: next((item for item in items.PoliciesJSON if item['name'] == policyName), False),
            'playbooks':lambda: next((item for item in items.PlaybooksJSON if item['name'] == policyName), False) }
    return dict[objectType]()


create_group(newGroup)
clone_policy(executionPolicySource,executionPolicyDestination)
clone_policy(exfiltrationPolicySource,exfiltrationPolicyDestination)
clone_policy(ransomwarePolicySource,ransomwarePolicyDestination)
assign_collector(executionPolicyDestination,newGroup)
assign_collector(exfiltrationPolicyDestination,newGroup)
assign_collector(ransomwarePolicyDestination,newGroup)
clone_playbook(playbookPolicySource,playbookPolicyDestination)
assign_playbook(playbookPolicyDestination,newGroup)