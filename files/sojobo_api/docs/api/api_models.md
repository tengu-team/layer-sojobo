# Info
The `api_models.py` provides all the calls to interact with models.

# Routes
* `/models/`
  * HTTP Method: ALL
  * Required data: None
  * Response codes:
    * 200: `{'name': 'Controllers API', 'version': <version>}`
* `/models/create`
  * HTTP Method: POST
  * Required data: api_key, controller, model, ssh_key(optional)
  * Response codes: 200, 400, 403
* `/models/delete`
  * HTTP Method: DELETE
  * Required data: api_key, controller, model
  * Response codes: 200, 400, 403
* `/models/addsshkey`
  * HTTP Method: PUT
  * Required data: api_key, controller, model, ssh_key
  * Response codes: 200, 400, 403
* `/models/removesshkey`
  * HTTP Method: GET
  * Required data: api_key, controller, model, ssh_key
  * Response codes: 200, 400, 403
* `/models/<controllername>/<modelname>/status`
  * HTTP Method: PUT
  * Required data: api_key
  * Response codes: 200, 400, 403
* `/models/getmodels/<controllername>`
  * HTTP Method: GET
  * Required data: api_key
  * Response codes: 200, 400, 403
