# pylint: disable=c0301,c0325,c0111,c0103
# This will check if all the requests return either 200 if correctly called, or 405 if the incorrect method is used.
# Calls returning a 500 code, will be listed, indicating a mistake in the api-code.
import requests
from requests.auth import HTTPBasicAuth


totest = [('/', {'get': None}),
          ('/users/create', {'get': None, 'post': {'username': 'test', 'password': 'test'}}),
          ('/models/create', {'get': None, 'post': {'modelname': 'testmodel'}}),
          ('/models/testmodel/status', {'get': None}),
          ('/models/testmodel/applications/appname/config', {'get': None}),
          ('/users/credentials.zip', {'get': None}),
         ]
url = 'http://{}:5000'.format(input('Give the ipaddress of the API: '))
auth = HTTPBasicAuth(input('API username: '), input('API password: '))
for call in totest:
    for k, v in call[1].items():
        if k == 'get':
            r = requests.get('{}{}'.format(url, call[0]), v, auth=auth)
        elif k == 'head':
            r = requests.head('{}{}'.format(url, call[0]), auth=auth)
        elif k == 'post':
            r = requests.post('{}{}'.format(url, call[0]), v, auth=auth)
        elif k == 'put':
            r = requests.put('{}{}'.format(url, call[0]), v, auth=auth)
        elif k == 'delete':
            r = requests.delete('{}{}'.format(url, call[0]), auth=auth)
        try:
            print ('{}{}|{}: {}, {}'.format(url, call[0], k, r.status_code, r.reason))
        except NameError:
            print('{}{}-{}: Incorrect or not implemented HTTP Method'.format(url, call, k))
