'''
Simple honeypot-lure that listens on a set port and triggers an API call to Cisco XDR to create an incident

Mitre Tactic TA0007 Discovery, Technique T1046 Network Service Discovery

To use it will need to have the CLIENT_ID and CLIENT_PASSWORD from your XDR API

 CLIENT_ID = 'client-----client ID-----'
 CLIENT_PASSWORD = '< ----Client Password-------- >'

XDR>Administration>API Clients
5-17-2024 -v2
 '''
# This script successfully reads the bundle json and manipulates the IDs and successfully creates an XDR incident


import socket
import requests
import json
import crayons
import time
import hashlib
from datetime import datetime
import threading




def create_jwt():
    """ This function requests the Oauth Web Token"""
    # Your client id and password (See the Authentication page for more details.)
    CLIENT_ID = 'client-----client ID-----'
    CLIENT_PASSWORD = '< ----Client Password-------- >'

    # Generate new access token
    url = 'https://visibility.amp.cisco.com/iroh/oauth2/token'

    headers = {
                'Content-Type':'application/x-www-form-urlencoded',
                'Accept':'application/json'
    }

    payload = {
                'grant_type':'client_credentials'
    }

    response = requests.post(url, headers=headers, auth=(CLIENT_ID, CLIENT_PASSWORD), data=payload)
   # print(crayons.blue(response.text))

    if response.status_code == 200:
        # convert the response to a dict object
        response_json = json.loads(response.text)

        # get the access token
        access_token = response_json['access_token']

        # get the scope of the token
        scope = response_json['scope']

        # get the duration that the token is valid
        expires_in = response_json['expires_in']
    return(access_token,scope,expires_in)


# function to create incident IDs
def create_incident_external_id(incident_title):
    hash_strings = [incident_title + str(time.time())]
    hash_input = "|".join(hash_strings)
    hash_value = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    incident_external_id = 'xdr-automation-incident-' + hash_value
    return incident_external_id

def create_sighting_external_id():
    # hash sighting without transient ID
    hash_input = '<TODO: TRANSIENT-ID>'+ str(time.time())
    hash_value = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    sighting_external_id = "xdr-automation-sighting-" + hash_value
    return sighting_external_id


def create_sighting_transient_id():
    # hash sighting without transient ID
    hash_input = '<TODO: TRANSIENT-ID>'+ str(time.time())
    hash_value = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    sighting_transient_id = "transient:xdr-automation-sighting-" + hash_value
    return  sighting_transient_id

# function to create external IDs for relationship objects
def generate_relationship_xid(source_xid, target_xid):
    hash_value = hashlib.sha1((source_xid + target_xid).encode('utf-8'))
    hash_value = hash_value.hexdigest()
    relationship_xid = "xdr-automation-relationship-" + hash_value
    return relationship_xid

def handle_client(client_socket):
    with client_socket as sock:
        request = sock.recv(1024)
        print(crayons.green(f'[*] Received: {request.decode("utf-8")}'))
        sock.send(b'ACK')



def judge_me(threat_client, creds, opened_time):
        # creates a judgement for an observable
    bearer_token = 'Bearer ' + creds
    url = 'https://private.intel.amp.cisco.com/ctia/judgement'

    headers = {
                'Authorization': bearer_token,
                'Content-Type':'application/json',
                'Accept':'application/json'
    }

    payload = {
        'observable': {
            'value': threat_client,
            'type': 'ip',
        },
        'type': 'judgement',
        'source': 'my-feed',
        'disposition': 3,
        'reason': 'Suspicious Behavior',
        'disposition_name': 'Suspicious',
        'priority': 95,
        'severity': 'High',
        'timestamp': opened_time,
        'confidence': 'Medium'
    }

    response = requests.post(url, headers=headers, data=json.dumps(payload))
    print(crayons.magenta(response.text))

    if response.status_code == 201:
        # convert the response to a dict object
        response_json = json.loads(response.text)

        # get the judgement (remainder values are accessed in the same way)
        id = response_json['id']
        severity = response_json['severity']
        priority = response_json['priority']





# main code block

# Define listening socket
ip = '0.0.0.0'
PORT = 445
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((ip, PORT))
server.listen(5)

while True:
    
    no_connection = 1
    server.close
    server.shutdown

    while no_connection:
        # Loop 
        print(crayons.green(f'[*] Listening on {ip}:{PORT}'))
        client, address = server.accept()
        print(crayons.green(f'[*] Accepted connection from {address[0]}:{address[1]}'))
        client_handler = threading.Thread(target = handle_client, args=(client,))
        client_handler.start()
        no_connection = 0
        print(crayons.yellow(f'Gathered details: {address[0]}'))
        

    creds=[]
    creds = create_jwt()
    #print(creds)



    honeypot_object = []

    # Convert JSON file to Python dictionary
    honey_file = open('honeypot_bundle_2.json')
    honeypot_object = json.load(honey_file)

    # Get the current date/time
    current_time = datetime.now()
    opened_time = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    judge_me(address[0],creds[0],opened_time)

    incident_title = honeypot_object['incidents'][0]['title']
    incident_external_id = create_incident_external_id(incident_title)
    incident_transient_id = 'transient:' + incident_external_id

    # Build the incident object
    honeypot_object['incidents'][0]['title'] = honeypot_object['incidents'][0]['title'] + " " + opened_time
    honeypot_object['incidents'][0]['id'] = incident_transient_id
    honeypot_object['incidents'][0]["external_ids"] = [incident_external_id]
    honeypot_object['incidents'][0]["incident_time"] = {"opened":opened_time}

    #print(crayons.green(honeypot_object['incidents'][0]['incident_time']))

    honeypot_object['sightings'][0]['external_ids'] = [create_sighting_external_id()]
    honeypot_object['sightings'][0]['id'] = create_sighting_transient_id()
    
    # add the list of Transient IDs of the Sightings
    sightings_transient_ids = ["TODO:transient:xdr-automation-sighting-1234","TODO:transient:xdr-automation-sighting-5678"]
    #relationships_dict = []

    sighting_id = honeypot_object['sightings'][0]['id']

    # loop through sightings and create relationships
    relationship_xid=generate_relationship_xid(sighting_id,incident_transient_id)
    #    relationship=create_relationship_object(sighting_id,incident_transient_id,relationship_xid,"member-of")
    relationship_type = "member-of"
    honeypot_object['relationships'][0]["external_ids"] = [relationship_xid]
    honeypot_object['relationships'][0]["source_ref"] = sighting_id
    honeypot_object['relationships'][0]["target_ref"] = incident_transient_id
    honeypot_object['relationships'][0]["source"] = "Network Based Lure trigger"
    honeypot_object['relationships'][0]["relationship_type"] = relationship_type
    honeypot_object['relationships'][0]["type"] = "relationship"
    honeypot_object['relationships'][0]["id"] = "transient:"+relationship_xid
    honeypot_object['relationships'][0]["timestamp"] = opened_time
    # Insert the adversary IP into the bundle
    honeypot_object['sightings'][0]['targets'][0]['observables'][0]['value'] = address[0]
    honeypot_object['sightings'][0]['relations'][0]['source']['value'] = address[0]
    # Mark sighting with opened time stamp
    honeypot_object['sightings'][0]['observed_time']['start_time'] = opened_time
    honeypot_object['sightings'][0]['observed_time']['end_time'] = opened_time
    honeypot_object['sightings'][0]['targets'][0]['observed_time']['start_time'] = opened_time
    honeypot_object['sightings'][0]['targets'][0]['observed_time']['end_time'] = opened_time

    honeymix_json = json.dumps(honeypot_object, indent=4)
    #post the bundle
    url2 = "https://visibility.amp.cisco.com/iroh/private-intel/bundle/import"

    headers2 = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + creds[0],
    }

    print(f" JSON: {honeymix_json}")
    response = requests.request('POST', url2, headers = headers2, data = honeymix_json)
    if response.status_code == 200:
        print(crayons.green("Success!"))
    elif response.status_code == 401:
        print(crayons.yellow("Unauthorized."))
    elif response.status_code == 404:
        print(crayons.yellow("Not Found."))
    elif response.status_code == 400:
        print(crayons.red("Bad Request, malformed syntax."))
    #print(crayons.red(response))
    time.sleep(30)
