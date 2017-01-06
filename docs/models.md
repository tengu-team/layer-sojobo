All GET-requests send their data using url-parameters. Other requests use json.

**/controllers/`<controller>`**
* Request type: PUT
* Required data: api_key, model

**/controllers/`<controller>`/models/`<model>`**
* Request type: GET, DELETE
* Required data: api_key

**/controllers/`<controller>`/models/`<model>`/sshkey**
* Request type: POST. DELETE
* Required data: api_key, ssh_key
