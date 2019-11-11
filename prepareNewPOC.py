import requests
from collections import defaultdict
import getpass
from cryptography.fernet import Fernet
import base64
import re
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import json

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
    pw = getpass.getpass(prompt='Password: ')
    pw_encrypted = self.f.encrypt(pw.encode())
    return pw_encrypted

  def decrypt_pw(self):
    return self.f.decrypt(self.pw)
creds = Credentials()

class GetListOf:
    def __init__(self):
        print(f'**INIT** Getting Groups/Policies/Playbooks')
        self.GroupsList = self._createList('groups')
        self.PoliciesList = self._createList('policies')
        self.PlaybooksList = self._createList('playbooks')
        print(f'**INIT** Completed getting Groups/Policies/Playbooks')
        self.PlaybooksJSON = defaultdict()
        self.GroupsJSON = defaultdict()
        self.PoliciesJSON = defaultdict()
    
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
            print(f'**ASSIGN PLAYBOOKS** Sending request to assign group {collectorGroupName} to Playbook {policyName}')
            url = f'https://{customer_name}.console.ensilo.com/management-rest/playbooks-policies/assign-collector-group'
            items.sendRequest('put',{'policyName': policyName,'collectorGroupNames': collectorGroupName},url)
            print(f'**ASSIGN PLAYBOOKS** Sending request to update playbooks')
            items.Update('playbooks')
            collectorsList = _checkItemInList('playbooks',policyName)
            if collectorsList == False:
                print(f'**ASSIGN PLAYBOOKS** Error getting list of Collectors for Playbook policy: {policyName}')
            else:
                if collectorGroupName in collectorsList:
                    print(f'**ASSIGN PLAYBOOKS** Successfully assigned {collectorGroupName} to {policyName} Playbook policy')
                else:
                    print(f'**ASSIGN PLAYBOOKS** Could not verify {collectorGroupName} was added to Playbook {policyName}')
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
                    collectorsList = _checkItemInList('policies',policyName)
                    if collectorsList == False:
                        print(f'**ASSIGN POLICY** Command sent to assign but there was an error getting the list of Collectors for policy: {policyName}')
                    else:
                        if collectorsGroupName in collectorsList['agentGroups']:
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




create_group('Protected')
clone_policy('Execution Prevention','Protected Execution Prevention')
clone_policy('Exfiltration Prevention','Protected Exfiltration Prevention')
clone_policy('Ransomware Prevention','Protected Ransomware Prevention')
assign_collector('Protected Execution Prevention','Protected')
assign_collector('Protected Exfiltration Prevention','Protected')
assign_collector('Protected Ransomware Prevention','Protected')
clone_playbook('Default Playbook','Protected Playbook')
assign_playbook('Protected Playbook','Protected')