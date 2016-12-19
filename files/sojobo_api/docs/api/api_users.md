# Info
The `api_users.py` provides all the calls to interact with users.

# Routes
* `/users/`
  * HTTP Method: ALL
  * Required data: None
  * Response codes:
    * 200: `{'name': 'Controllers API', 'version': <version>}`
* `/users/create`
  * HTTP Method: POST
  * Required data: api_key, username, password
  * Response codes: 200, 400, 403
* `/users/makeadmin`
  * HTTP Method: POST
  * Required data: api_key, username
  * Response codes: 200, 400, 403
* `/users/delete`
  * HTTP Method: DELETE
  * Required data: api_key, username
  * Response codes: 200, 400, 403
* `/users/changepassword`
  * HTTP Method: PUT
  * Required data: api_key, username, password
  * Response codes: 200, 400, 403
* `/users/addtocontroller`
  * HTTP Method: PUT
  * Required data: api_key, controller, username, access
  * Response codes: 200, 400, 403
* `/users/removefromcontroller`
  * HTTP Method: DELETE
  * Required data: api_key, controller, username
  * Response codes: 200, 400, 403
* `/users/addtomodel`
  * HTTP Method: PUT
  * Required data: api_key, controller, model, username, access
  * Response codes: 200, 400, 403
* `/users/removefrommodel`
  * HTTP Method: DELETE
  * Required data: api_key, controller, username
  * Response codes: 200, 400, 403
