# Info
The `api_controllers.py` provides all the calls to interact with cloud controllers.

# Routes
* `/controllers/`
  * HTTP Method: ALL
  * Required data: None
  * Response codes:
    * 200: `{'controllers': <list of available controllers>, 'version': <version>}`
* `/controllers/create`
  * HTTP Method: POST
  * Required data: api_key, type, name, region, credentials
  * Response codes: 200, 400, 403
* `/controllers/delete`
  * HTTP Method: DELETE
  * Required data: api_key, controller
  * Response codes: 200, 400, 403
* `/controllers/backup`
  * HTTP Method: GET
  * Required data: api_key
  * Response codes:
    * 200: zipfile
    * 400, 403
* `/controllers/getcontrollers`
  * HTTP Method: GET
  * Required data: api_key
  * Response codes: 200, 400, 403
