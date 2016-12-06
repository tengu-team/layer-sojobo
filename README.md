# API - Calls
/controllers/create
Method: POST
Data: {'api-key': <api-key>,
       'type': <controller-type>,
       'name': <controller-name>,
       'region': <region-or-maas-url>,
       'credentials': <dictionary-with-credentials>}
The credentials - dictionary structure depends on the type of cloud:
aws: {'access-key': <access-key>, 'secret-key': <secret-key>}
maas: {'user': <username>, 'password': <password>}
