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

class GetListOf:
    def __init__(self):
        self.GroupsList = _createList('groups')
        self.PoliciesList = _createList('policies')
        self.PlaybooksList = _createList('playbooks')
        self.PlaybooksJSON = defaultdict()
        self.GroupsJSON = defaultdict()
        self.PoliciesJSON = defaultdict()
    
    def Update(self,requestType):
        if requestType == 'groups':
            newList = _createList(requestType)
            self.GroupsList = newList
        if requestType == 'policies':
            newList = _createList(requestType)
            self.PoliciesList = newList
        if requestType == 'playbooks':
            newList = _createList(requestType)
            self.PlaybooksList = newList

    def _createURL(self,requestType):
        request_type = request_type
        URLDict = {'base':f'https://{customer_name}.console.ensilo.com/management-rest/',
                        'policies':f'policies/list-policies',
                        'playbooks':f'playbooks-policies/list-policies',
                        'groups':f'inventory/list-groups'}
        url = f'{self.URLDict[base]}{self.URLDict[request_type]}'
        return url
    
    def _createList(self,requestType):
        requestJSON = sendRequest('get','',_createURL(requestType)).json()
        if requestType == 'playbooks':
            self.PlaybooksJSON = requestJSON
        if requestType == 'groups':
            self.GroupsJSON = requestJSON
        if requestType == 'policies'
            self.PoliciesJSON
        listOfNames = []
        for each in requestJSON:
            listOfNames.append(each['name']
        return listOfNames

items = GetListOf()

def create_group(groupName):
    if groupName not in items.GroupsList:
        url = f'https://{customer_name}.console.ensilo.com/management-rest/inventory/create-collector-group'
        sendRequest('post',{'name':groupName},url)
        items.Update('groups')
        if groupName in items.GroupsList:
            print(f'{GroupName} successfully created')
        else:
            print(f'Could not verify that {GroupName} was created')
    else:
        print(f'{GroupName} already exists')

def clone_playbook(sourcePolicyName,newPolicyName):
    if sourcePolicyName in items.PlaybooksList:
        if newPolicyName not in items.PlaybooksList:
            url = f'https://{customer_name}.console.ensilo.com/management-rest/playbooks-policies/clone'
            sendRequest('post',{'sourcePolicyName': sourcePolicyName,'newPolicyName': newPolicyName},url)
            items.Update('playbooks')
            if newPolicyName in items.PlaybooksList:
                print(f'{newPolicyName} successfully cloned')
            else:
                print(f'Could not verify that {newPolicyName} was created')
        else:
            print(f'{newPolicyName} is already listed in the Playbooks list')
    else:
        print(f'{sourcePolicyName} not found in Playbooks list')

def assign_playbook(policyName,collectorGroupName):
    if policyName in items.PlaybooksList:
        url = f'https://{customer_name}.console.ensilo.com/management-rest/playbooks-policies/assign-collector-group'
        sendRequest('put',{'policyName': policyName,'collectorGroupName': collectorGroupName},url)
        items.Update('playbooks')
        if collectorGroupName in items.PlaybooksJSON[policyName]['collectorGroups']:
            print(f'Successfully added {collectorGroupName} to {policyName} playbook')
        else:
            print(f'Could not verify {collectorGroupName} was added to {policyName} playbook')
    else:
        print(f'Playbook polciy {policyName} not found')
    
def clone_policy(sourcePolicyName,newPolicyName):
    if sourcePolicyName in items.PoliciesList:
        if newPolicyName not in items.PoliciesList:
            url = f'https://{customer_name}.console.ensilo.com/management-rest/policies/clone'
            sendRequest('post',{'sourcePolicyName': sourcePolicyName,'newPolicyName': newPolicyName},url)
            items.Update('policies')
            if newPolicyName in items.PoliciesList:
                print(f'Successfully cloned {sourcePolicyName} to {newPolicyName}')
        else:
            print(f'{newPolicyName} already exists')
    else:
        print(f'{sourcePolicyName} not found')

def assign_collector(policyName,collectorsGroupName):
    if policyName in items.PoliciesList:
        if collectorsGroupName in items.GroupsList:
            url = f'https://{customer_name}.console.ensilo.com/management-rest/policies/assign-collector-group'
            sendRequest('put',{'policyName': policyName,'collectorsGroupName': collectorsGroupName},url)
            items.Update('policies')
            if collectorsGroupName in items.GroupsJSON[policyName][agentGroups]:
                print(f'Successfully assigned {collectorsGroupName} to {policyName} policy')
            else:
                print(f'Could not verify {collectorsGroupName} was added to {policyName}')
        else:
            print(f'{collectorsGroupName} not found, cannot add group that does not exist)'
    else:
        print(f'{policyName} not found, cannot assign to a policy that does not exist)

def sendRequest(request_method,URLParams,url):
    if request_method == 'get':
        api_request = requests.get(url, auth=requests.auth.HTTPBasicAuth(creds.un, creds.decrypt_pw()), verify=False, params=URLParams)
    if request_method == 'post':
        api_request = requests.post(url, auth=requests.auth.HTTPBasicAuth(creds.un, creds.decrypt_pw()), verify=False, params=URLParams)
    if request_method == 'put':
        api_request = requests.put(url, auth=requests.auth.HTTPBasicAuth(creds.un, creds.decrypt_pw()), verify=False, params=URLParams)
    print(f'{request_method} request sent to {url}')
    if api_request.status_code == 200:
        print(f'Successful response')
        if request_method == 'get':
            return api_request
    else:
        error = f'Error in response while trying to retrieve. HTML Code {api_request.status_code} received'
        print(f'{error}')

customer_name = input(f'What is the customer name? (This will be for the URL - HERE.console.ensilo.com): ')
creds = Credentials()

create_group('Protected')
clone_policy('Execution Prevention','Protected Execution Prevention')
clone_policy('Exfiltration Prevention','Protected Exfiltration Prevention')
clone_policy('Ransomware Prevention','Protected Ransomware Prevention')
assign_collector('Protected Execution Prevention','Protected')
assign_collector('Protected Exfiltration Prevention','Protected')
assign_collector('Protected Ransomware Prevention','Protected')
clone_playbook('Default Playbook','Protected Playbook')
assign_playbook('Protected Playbook','Protected')