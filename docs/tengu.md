# Tengu-API Documentation

The Tengu-API is a blueprint, automaticaly deployed when installing the Sojobo-API. It contains all the calls to use JuJu, excluding calls handling users.

# ToDo
- implement JSON web tokens

**Currently, all the calls must be made with BasicAuth in the request!**

## API Calls
- [/login](#login)
- [/tengu/controllers](#controllers)
- [/tengu/controllers/[controller]](#controller)
- [/tengu/controllers/[controller]/models](#models)
- [/tengu/controllers/[controller]/models/[model]](#model)
- [/tengu/controllers/[controller]/models/[model]/applications](#applications)
- [/tengu/controllers/[controller]/models/[model]/applications/[application]](#application)
- [/tengu/controllers/[controller]/models/[model]/applications/[application]/units](#units)
- [/tengu/controllers/[controller]/models/[model]/applications/[application]/units/[unitnumber]](#unit)
- [/tengu/controllers/[controller]/models/[model]/machines/](#machines)
- [/tengu/controllers/[controller]/models/[model]/machines/[machine]](#machine)
- [/tengu/controllers/[controller]/models/[model]/relations](#relations)
- [/tengu/controllers/[controller]/models/[model]/relations/[application]](#relation-add)
- [/tengu/controllers/[controller]/models/[model]/relations/[app1]/[app2]](#relation-del)
- [/tengu/backup](#backup)

## **/login** <a name="login"></a>
#### **Request Type**: POST
* **Description**:
  Verifies the provided BasicAuth.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**

* **Successful response**:
  - code: 200
  - message:
  ```json
  "Success"
  ```
## **/tengu/controllers** <a name="controllers"></a>
#### **Request type**: GET
* **Description**:
  Returns a list of all the controllers the user has access to.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [
      "controller1-name",
      "controller2-name"
  ]
  ```

#### **Request type**: POST
* **Description**:
  - Bootstraps a new controller with the given name and in the given region.
  - The required credentials depend of the type of cloud.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - controller
  - type
  - region
  - credentials
* **Successful response**:
  - code: 200
  - message:
  ```json
  {
    "name": "controller1-name",
    "models": [
        "controller",
        "default"
    ],
    "type": "google",
    "users": [
        "admin"
    ]
}
  ```

## **/tengu/controllers/[controller]** <a name="controller"></a>
#### **Request type**: GET
* **Description**:
  Returns all the information of a controller (models, type and users) the user has access to.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  {
    "name": "controller1-name",
    "models": [
        "controller",
        "default"
    ],
    "type": "google",
    "users": [
        "admin"
    ]
}
  ```

#### **Request type**: DELETE
* **Description**:
  Removes the given controller
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [
      "controller1-name"
  ]
  ```

## **/tengu/controllers/[controller]/models** <a name="models"></a>
#### **Request type**: GET
* **Description**:
  - Returns a list of all the models on a controller if the user has access to this controller or models.
  - The api checks if the controller exists
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [
      "controller",
      "default",
      "model3-name"
  ]          
  ```

#### **Request type**: POST
* **Description**:
  Creates a new model on a controller. It checks if the model already exists and if the user is allowed to create a model on the given controller
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - model
  - credentials
* **Successful response**:
  - code: 202
  - message:
  ```json
  "Model is being deployed"        
  ```

## **/tengu/controllers/[controller]/models/[model]** <a name="model"></a>
#### **Request type**: GET
* **Description**:
  Returns all the information of a model (applications, machines, units and users) if the user has access.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  {
    "ssh-keys": {
        "result": null,
        "error": null
    },
    "name": "model_name",
    "applications": [],
    "juju-gui-url": "https://xxx.xxx.xxx.xxx:17070/gui/0f71dff7-29ae-4cc8-8664-66563860cbd5",
    "status": "ready",
    "machines": [],
    "users": [
        {
            "user": "admin",
            "access": "admin"
        }
    ],
    "credentials":[<credential JSON>]
  }          
  ```
#### **Request type**: POST
* **Description**:
  - Deploys a bundle to a model.
  - The bundle should be given in a jsonformat, using the JuJu bundle syntax
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - bundle
* **Successful response**:
  - code: 202
  - message:
  ```json
  "Bundle is being deployed"          
  ```

#### **Request type**: DELETE
* **Description**:
  Destroys a model on the given controller, including all the deployes application and created machines.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  "Model testmodel02 is being deleted"          
  ```

## **/tengu/controllers/[controller]/models/[model]/applications** <a name="applications"></a>
#### **Request type**: GET
* **Description**:
      Returns all the applications in a given model if the user has access.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [
      {
          "units": [
              {
                  "ports": [],
                  "series": "xenial",
                  "name": "mysql/0",
                  "machine": "0",
                  "private-ip": "",
                  "public-ip": ""
              }
          ],
          "name": "mysql",
          "charm": "cs:mysql-57",
          "status": {
              "message": "waiting for machine",
              "since": "2017-06-23T13:23:14.999857294Z",
              "current": "waiting",
              "version": ""
          },
          "relations": [
              {
                  "interface": "cluster",
                  "with": "mysql"
              }
          ],
          "exposed": false
      }
  ]
  ```

#### **Request type**: POST
* **Description**:
  - Deploys an application from the JuJu charm store to a model if the user has access. Checks if the application already exists in the model.
  - If the application name is preceeded with `local:` it will look for the charm in the local charm repo **Not Tested**
  - If the application is preseeded with `github:[url]` it will look for the application in the given repo. Only public repos are possible **Not Tested** **Expand: to allow private repos**
  - A specific series can be chosen for an application. It will check if the application is available in that series **Not Tested**
  - A specific machine can be chosen to deploy to. It will check if the machine exists. If the machine is preceeded with `lxd:`
  it will deploy the application in an lxd container. It will check if the controller supports lxd containers. **Not Tested**
  - If both a series and target is given, checks will be made if both the application and machine support the given series **Not Tested**
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - application
* **Optional body**:
  - series
  - target
* **Successful response**:
  - code: 200
  - message:
  ```json
  {
      "units": [
          {
              "ports": [],
              "series": "xenial",
              "name": "mysql/0",
              "machine": "",
              "private-ip": "",
              "public-ip": ""
          }
      ],
      "name": "mysql",
      "charm": "cs:mysql-57",
      "status": {
          "message": "waiting for machine",
          "since": "2017-06-23T13:23:14.999857294Z",
          "current": "waiting",
          "version": ""
      },
      "relations": [
          {
              "interface": "cluster",
              "with": "mysql"
          }
      ],
      "exposed": false
  }
  ```

## **/tengu/controllers/[controller]/models/[model]/applications/[application]** <a name="application"></a>
#### **Request type**: GET
* **Description**:
  Returns the info of an application if the user has access.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  {
      "units": [
          {
              "ports": [],
              "series": "xenial",
              "name": "mysql/0",
              "machine": "0",
              "private-ip": "",
              "public-ip": ""
          }
      ],
      "name": "mysql",
      "charm": "cs:mysql-57",
      "status": {
          "message": "waiting for machine",
          "since": "2017-06-23T13:23:14.999857294Z",
          "current": "waiting",
          "version": ""
      },
      "relations": [
          {
              "interface": "cluster",
              "with": "mysql"
          }
      ],
      "exposed": false
  }
  ```
#### **Request type**: PUT
* **Description**:
  Exposes or unexposes an application.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - expose
* **Successful response**:
  - code: 200
  - message:
  ```json
  {
      "units": [
          {
              "ports": [],
              "series": "xenial",
              "name": "mysql/0",
              "machine": "0",
              "private-ip": "",
              "public-ip": ""
          }
      ],
      "name": "mysql",
      "charm": "cs:mysql-57",
      "status": {
          "message": "waiting for machine",
          "since": "2017-06-23T13:23:14.999857294Z",
          "current": "waiting",
          "version": ""
      },
      "relations": [
          {
              "interface": "cluster",
              "with": "mysql"
          }
      ],
      "exposed": false
  }
  ```

#### **Request type**: DELETE
* **Description**:
  Removes an application. Checks if the application exists
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 202
  - message:
  ```json
    "The application is being removed"
  ```

## **/tengu/controllers/[controller]/models/[model]/applications/[application]/config** <a name="config"></a>
#### **Request type**: GET
* **Description**:
  Return all the config values of the given application.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  {
    "backup_dir": {
        "default": true,
        "description": "Directory where backups will be stored",
        "type": "string",
        "value": "/var/lib/mysql/backups"
    },
    "backup_retention_count": {
        "default": true,
        "description": "Number of recent backups to retain.",
        "type": "int",
        "value": 7
    },
    "backup_schedule": {
        "default": true,
        "description": "Cron schedule used for backups. If empty backups are disabled\n",
        "type": "string",
        "value": ""
    }
  }  
  ```

#### **Request type**: PUT
* **Description**:
  Change a specific config value of an application
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - config
* **Successful response**:
  - code: 202
  - message:
  ```json
    "The config parameter is being changed"
  ```

## **/tengu/controllers/[controller]/models/[model]/applications/[application]/units** <a name="units"></a>
#### **Request type**: GET
* **Description**:
  Returns the info of all the units of a given application.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [
      {
          "ports": [],
          "series": "trusty",
          "name": "wordpress/0",
          "machine": "1",
          "private-ip": "",
          "public-ip": ""
      },
      {
          "ports": [],
          "series": "trusty",
          "name": "wordpress/1",
          "machine": "2",
          "private-ip": "",
          "public-ip": ""
      }
  ]
  ```

#### **Request type**: POST
* **Description**:
  Adds a unit to a given application
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Optional body**:
  - amount
  - target
* **Successful response**:
  - code: 202
  - message:
  ```json
    "Units being added"
  ```

## **/tengu/controllers/[controller]/models/[model]/applications/[application]/units/[unitnumber]** <a name="unit"></a>
#### **Request type**: GET
* **Description**:
  Returns the info of a single unit.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  {
      "ports": [],
      "series": "trusty",
      "name": "wordpress/0",
      "machine": "1",
      "private-ip": "",
      "public-ip": ""
  }
  ```

#### **Request type**: DELETE
* **Description**:
  Removes the unit.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 202
  - message:
  ```json
    "Unit is being removed"
  ```

## **/tengu/controllers/[controller]/models/[model]/machines/** <a name="machines"></a>
#### **Request type**: GET
* **Description**:
  Return the info of all the machines of a given model.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [
      {
          "instance-id": "juju-b7313c-0",
          "ip": {
              "external_ip": "104.155.26.44",
              "internal_ip": "10.132.0.35"
          },
          "containers": [],
          "series": "xenial",
          "name": "0",
          "hardware-characteristics": {
              "mem": 1700,
              "availability-zone": "europe-west1-b",
              "root-disk": 10240,
              "arch": "amd64",
              "cpu-power": 138,
              "cpu-cores": 1
          }
      },
      {
          "instance-id": "juju-b7313c-2",
          "ip": {
              "external_ip": "35.187.84.154",
              "internal_ip": "10.132.0.39"
          },
          "containers": [],
          "series": "trusty",
          "name": "2",
          "hardware-characteristics": {
              "mem": 1700,
              "availability-zone": "europe-west1-b",
              "root-disk": 10240,
              "arch": "amd64",
              "cpu-power": 138,
              "cpu-cores": 1
          }
      }
  ]
  ```

#### **Request type**: POST
* **Description**:
  - Adds a machine
  - If a series is given, it will check if the cloud supports it **Not Tested**
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Optional body**:
  - series
* **Successful response**:
    - code: 200
    - message:
    ```json
"Machine is being deployed"
    ```

## **/tengu/controllers/[controller]/models/[model]/machines/[machine]** <a name="machine"></a>
#### **Request type**: GET
* **Description**:
  Return the info of a machine in a given model.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  {
      "instance-id": "juju-b7313c-0",
      "ip": {
          "external_ip": "104.155.26.44",
          "internal_ip": "10.132.0.35"
      },
      "containers": [],
      "series": "xenial",
      "name": "0",
      "hardware-characteristics": {
          "mem": 1700,
          "availability-zone": "europe-west1-b",
          "root-disk": 10240,
          "arch": "amd64",
          "cpu-power": 138,
          "cpu-cores": 1
      }
  }
  ```

#### **Request type**: DELETE
* **Description**:
  Removes a machine
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 202
  - message:
  ```json
    "machine is being deleted"
  ```

## **/tengu/controllers/[controller]/models/[model]/relations** <a name="relations"></a>
#### **Request type**: GET
* **Description**:
  Shows all the relations of a given model
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [
      {
          "name": "wordpress",
          "relations": [
              {
                  "interface": "loadbalancer",
                  "with": "wordpress"
              }
          ]
      },
      {
          "name": "mysql",
          "relations": [
              {
                  "interface": "cluster",
                  "with": "mysql"
              }
          ]
      }
  ]
  ```

#### **Request type**: PUT
* **Description**:
  - Adds a relation between the given application. Checks if the applications exist
  - Checks if the relation is possible between the applications **ToDo**
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - app1
  - app2
* **Successful response**:
  - code: 200
  - message:
  ```json
  [
      {
          "name": "wordpress",
          "relations": [
              {
                  "interface": "loadbalancer",
                  "with": "wordpress"
              },
              {
                  "interface": "db",
                  "with": "mysql"
              }
          ]
      },
      {
          "name": "mysql",
          "relations": [
              {
                  "interface": "cluster",
                  "with": "mysql"
              },
              {
                  "interface": "db",
                  "with": "wordpress"
              }
          ]
      }
  ]
  ```

## **/tengu/controllers/[controller]/models/[model]/relations/[application]** <a name="relation-add"></a>
#### **Request type**: GET
* **Description**:
  - Gets the relations of the given application
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [
      {
          "interface": "loadbalancer",
          "with": "wordpress"
      },
      {
          "interface": "db",
          "with": "mysql"
      }
  ]
  ```

## **/tengu/controllers/[controller]/models/[model]/relations/[app1]/[app2]** <a name="relation-del"></a>
#### **Request type**: DELETE
* **Description**:
  Removes the relation between the 2 given applications. Checks if the applications exist>
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message:
  ```json
  [
      {
          "name": "wordpress",
          "relations": [
              {
                  "interface": "loadbalancer",
                  "with": "wordpress"
              },
              {
                  "interface": "db",
                  "with": "mysql"
              }
          ]
      },
      {
          "name": "mysql",
          "relations": [
              {
                  "interface": "cluster",
                  "with": "mysql"
              },
              {
                  "interface": "db",
                  "with": "wordpress"
              }
          ]
      }
  ]
  ```

## **/tengu/backup** <a name="backup"></a>
#### **Request type**: GET
* **Description**:
  Backups the currently configured clouds, credentials and bootstrapped controllers. **This is just a backup for the Sojobo-setup, not the actual configured models, machines or applications!**
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Successful response**:
  - code: 200
  - message: Zipfile
