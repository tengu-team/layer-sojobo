All GET-requests send their data using url-parameters. Other requests use json.

**/controllers/`<controller>`**
* Request type: PUT
* Required header: api-key
* Required data: model

**/controllers/`<controller>`/models/`<model>`**
* Request type: GET, DELETE
* Required header: api-key

**/controllers/`<controller>`/models/`<model>`/sshkey**
* Request type: POST. DELETE
* Required header: api-key
* Required data: ssh_key
