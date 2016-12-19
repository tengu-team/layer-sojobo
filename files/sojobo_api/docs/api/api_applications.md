# Info
The `api_applications.py` provides all the calls to interact with applications.

# Routes
* `/applications/`
  * HTTP Method: ALL
  * Required data: None
  * Response codes:
    * 200: `{'name': 'Controllers API', 'version': <version>}`
* `/applications/addapp`
  * HTTP Method: PUT
  * Required data: api_key, controller, model, app_name, series(optional), target(optional)
  * Response codes: 200, 400, 403
* `/applications/removeapp`
  * HTTP Method: DELETE
  * Required data: api_key, controller, model, app_name
  * Response codes: 200, 400, 403
* `/applications/addmachine`
  * HTTP Method: PUT
  * Required data: api_key, controller, model, series(optional)
  * Response codes: 200, 400, 403
* `/applications/removemachine`
  * HTTP Method: DELETE
  * Required data: api_key, controller, model, machine
  * Response codes: 200, 400, 403
* `/applications/addunit`
  * HTTP Method: PUT
  * Required data: api_key, controller, model, app_name, target(optional)
  * Response codes: 200, 400, 403
* `/applications/removeunit`
  * HTTP Method: DELETE
  * Required data: api_key, controller, model, unit
  * Response codes: 200, 400, 403
* `/applications/addrelation`
  * HTTP Method: PUT
  * Required data: api_key, controller, model, app1, app2
  * Response codes: 200, 400, 403
* `/applications/removerelation`
  * HTTP Method: DELETE
  * Required data: api_key, controller, model, app1, app2
  * Response codes: 200, 400, 403
* `/applications/config/<controllername>/<modelname>/<appname>`
  * HTTP Method: GET
  * Required data: api_key
  * Response codes: 200, 400, 403
* `/applications/info/<controllername>/<modelname>/<appname>`
  * HTTP Method: GET
  * Required data: api_key
  * Response codes: 200, 400, 403
