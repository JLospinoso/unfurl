import httplib2
import os
import json
import base64
import argparse

from apiclient import discovery, errors
from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage

# If modifying these scopes, delete your previously saved credentials
# at ~/.credentials/gmail-python-quickstart.json
SCOPES = 'https://www.googleapis.com/auth/gmail.readonly'
CLIENT_SECRET_FILE = 'client_secret.json'
APPLICATION_NAME = 'Gmail API Python Quickstart'


def get_credentials():
    home_dir = os.path.expanduser('~')
    credential_dir = os.path.join(home_dir, '.credentials')
    if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
    credential_path = os.path.join(credential_dir, 'gmail-python-quickstart.json')
    store = Storage(credential_path)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
        flow.user_agent = APPLICATION_NAME
        credentials = tools.run(flow, store)
        print('Storing credentials to ' + credential_path)
    return credentials


def push_messages(service, page):
    if 'messages' in page:
        for message in page['messages']:
            try:
                msg_id = message['id']
                path = os.path.join("emails", "{}.json".format(msg_id))
                if(os.path.exists(path)):
                    continue
                message = service.users().messages().get(userId="me", id=msg_id, format='raw').execute()
                message['raw'] = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
                message['id'] = int(message['id'], 16)
                message['historyId'] = int(message['historyId'])
                message['internalDate'] = int(message['internalDate'])
                message['threadId'] = int(message['threadId'], 16)
                del message['snippet']
                del message['sizeEstimate'])
                with open(path, "w") as file:
                    try:
                        message['raw'] = message['raw'].decode("ascii")
                    except Exception as e:
                        message['raw'] = ""
                    file.write(json.dumps(message))
            except Exception as e:
                print('[-] Error: {}'.format(e))

def main():
    credentials = get_credentials()
    print("[+] Gmail credentials obtained")
    http = credentials.authorize(httplib2.Http())
    service = discovery.build('gmail', 'v1', http=http)
    print("[+] Connection to Gmail established.")
    response = service.users().messages().list(userId="me").execute()
    print("[+] Parsing first page of emails.")
    messages = push_messages(service, response)
    while 'nextPageToken' in response:
        page_token = response['nextPageToken']
        response = service.users().messages().list(userId="me", pageToken=page_token).execute()
        messages = push_messages(service, response)
    print(json.dumps(messages))

if __name__ == '__main__':
    main()
