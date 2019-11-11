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

parser = argparse.ArgumentParser(description='These arguments are needed to create the objects')

parser.add_argument('--newGroup', required=False, type=str, help="Name for the new Collector Group - Default is 'Protected'")
parser.add_argument('--executionPolicySource', required=False, type=str, help="Which Execution Policy will be cloned? Default is -Execution Prevention-")
parser.add_argument('--executionPolicyDestination', required=False, type=str, help="What will the cloned Execution Policy be called? Default prepends source with newGroup")
parser.add_argument('--exfiltrationPolicySource', required=False, type=str, help="Which Exfiltration Policy will be cloned? Default is -Exfiltration Prevention-")
parser.add_argument('--exfiltrationPolicyDestination', required=False, type=str, help="What will the cloned Exfiltration Policy be called? Default prepends source with newGroup")
parser.add_argument('--ransomwarePolicySource', required=False, type=str, help="Which Ransomware Policy will be cloned? Default is -Ransomware Prevention-")
parser.add_argument('--ransomwarePolicyDestination', required=False, type=str, help="What will the cloned Ransomware Policy be called? Default prepends source with newGroup")
parser.add_argument('--playbookPolicySource', required=False, type=str, help="Which Playbook Policy will be cloned? Default is -Default Playbook-")
parser.add_argument('--playbookPolicyDestination', required=False, type=str, help="What will the cloned Playbook Policy be called?  Default prepends source with newGroup")
parser.add_argument('--version', action='version', version='%(prog)s 0.9')
parser.add_argument('--un', required=True, type=str, help='Username to log into the enSilo console with') #unhandled
parser.add_argument('--pw', required=True, type=str, help='Password to log into the enSilo console with') #unhandled
parser.add_argument('--instance', required=True, type=str, help='Instance name of the enSilo console (THIS.console.ensilo.com)') #unhandled

args = parser.parse_args()

if args.newGroup is not None:
    newGroup = args.newGroup
else:
    newGroup = 'Protected'

if args.executionPolicySource is not None:
    executionPolicySource = args.executionPolicySource
else:
    executionPolicySource = 'Execution Prevention'

if args.executionPolicyDestination is not None:
    executionPolicyDestination = args.executionPolicyDestination
else:
    executionPolicyDestination = f'{newGroup} {executionPolicySource}'

if args.exfiltrationPolicySource is not None:
    exfiltrationPolicySource = args.exfiltrationPolicySource
else:
    exfiltrationPolicySource = 'Exfiltration Prevention'

if args.exfiltrationPolicyDestination is not None:
    exfiltrationPolicyDestination = args.exfiltrationPolicyDestination
else:
    exfiltrationPolicyDestination = f'{newGroup} {exfiltrationPolicySource}'

if args.ransomwarePolicySource is not None:
    ransomwarePolicySource = args.ransomwarePolicySource
else:
     ransomwarePolicySource= 'Ransomware Prevention'

if args.ransomwarePolicyDestination is not None:
    ransomwarePolicyDestination = args.ransomwarePolicyDestination
else:
    ransomwarePolicyDestination = f'{newGroup} {ransomwarePolicySource}'

if args.playbookPolicySource is not None:
    playbookPolicySource = args.playbookPolicySource
else:
    playbookPolicySource = 'Default Playbook'

if args.playbookPolicyDestination is not None:
    playbookPolicyDestination = args.playbookPolicyDestination
else:
    playbookPolicyDestination = f'{newGroup} {playbookPolicySource}'

# newGroup = 'Protected'
# executionPolicySource = 'Execution Prevention'
# executionPolicyDestination = f'{newGroup} {executionPolicySource}'
# exfiltrationPolicySource = 'Exfiltration Prevention'
# exfiltrationPolicyDestination = f'{newGroup} {exfiltrationPolicySource}'
# ransomwarePolicySource = 'Ransomware Prevention'
# ransomwarePolicyDestination = f'{newGroup} {ransomwarePolicySource}'
# playbookPolicySource = 'Default Playbook'
# playbookPolicyDestination = f'{newGroup} {playbookPolicySource}'


'''
Unassign 'High Security Collector Group' from default groups ----- enSilo does not support unassigning through API
Assign 'High Security Collector Group' to Protected Policies
'''
customer_name = input(f'What is the customer name? (This will be for the URL - HERE.console.ensilo.com): ')

class Credentials:
  def __init__(self):
    self.crypt_key = Fernet.generate_key()
    self.f = Fernet(self.crypt_key)
    self.un = input('Username (User must have Rest API role within WebGUI): ')
    self.pw = self.encrypt_pw()

  def encrypt_pw(self):
    pw_encrypted = self.f.encrypt(getpass.getpass(prompt='Password: ').encode())
    return pw_encrypted

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
        url = f'https://{customer_name}.console.ensilo.com/management-rest/{URLDict[request_type]}'
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
        url = f'https://{customer_name}.console.ensilo.com/management-rest/inventory/create-collector-group'
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
            url = f'https://{customer_name}.console.ensilo.com/management-rest/playbooks-policies/clone'
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
        check = _checkItemInList('playbooks',policyName)
        if check == False:
            print(f'**ASSIGN POLICY** Error checking the list of Collectors for Playbook: {policyName}')
        else:
            if collectorGroupName not in check['collectorGroups']:
                print(f'**ASSIGN PLAYBOOKS** Sending request to assign group {collectorGroupName} to Playbook {policyName}')
                url = f'https://{customer_name}.console.ensilo.com/management-rest/playbooks-policies/assign-collector-group'
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
            url = f'https://{customer_name}.console.ensilo.com/management-rest/policies/clone'
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
            check = _checkItemInList('policies',policyName)
            if check == False:
                print(f'**ASSIGN POLICY** There was a problem getting group list ')
            else:
                if collectorsGroupName not in check['agentGroups']:
                    print(f'**ASSIGN POLICY** Sending request to assign group {collectorsGroupName} to Policy {policyName}')
                    url = f'https://{customer_name}.console.ensilo.com/management-rest/policies/assign-collector-group'
                    items.sendRequest('put',{'policyName': policyName,'collectorsGroupName': collectorsGroupName},url)
                    print(f'**ASSIGN POLICY** Sending request to update policies')
                    items.Update('policies')
                    playbookJSON = _checkItemInList('policies',policyName)
                    if playbookJSON == False:
                        print(f'**ASSIGN POLICY** Command sent to assign but there was an error getting the list of Collectors for policy: {policyName}')
                    else:
                        if collectorsGroupName in playbookJSON['agentGroups']:
                            print(f'**ASSIGN POLICY** Successfully assigned {collectorsGroupName} to {policyName} policy')
                        else:
                            print(f'**ASSIGN POLICY** Could not verify {collectorsGroupName} was added to {policyName}')
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