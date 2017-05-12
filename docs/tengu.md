# ToDo
- Finish small ToDo's and testing mentioned below.
- Output charm name/info with application info
- Prevent KeyErrors in w_juju.py to ensure correct html status codes
- Proper json output: no longer output empty keys
- Copy a model from one controller and deploy it to another, with the correct configs

# Tengu-API Documentation

The Tengu-API is a blueprint, automaticaly deployed when installing the Sojobo-API. It contains all the calls to use JuJu,
excluding calls handling users.

**Currently, all the calls must be made with BasicAuth in the request!**

## API Calls
- [/tengu/controllers](#controllers)
- [/tengu/controllers/[controller]](#controller)
- [/tengu/controllers/[controller]/models](#models)
- [/tengu/controllers/[controller]/models/[model]](#model)
- [/tengu/controllers/[controller]/models/[model]/sshkey](#sshkey)
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

## **/tengu/controllers** <a name="controllers"></a>
#### **Request type**: GET
* **Description**:
  Returns all the information of all the controllers, models, applications, machines, units and users the user has access to.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"name": "controller-name",
    "type": "controller-type",
    "users": [{"name": "username",
               "access": "controller-access"}],
    "models": [{"name": "modelname",
                "ssh-keys": "ssh-keys with access to all the machines in model",
                "juju-gui-url": "Using the user login and password, the juju GUI can be used",
                "users": [{"name": "username",
                           "access": "model-access"}],
                "machines": [{"name": "machine-name",
                              "instance-id": "juju-id",
                              "ip": "ip-address",
                              "series": "Ubuntu OS version name",
                              "containers": [{"name": "container-name",
                                              "ip": "ip-address",
                                              "series": "Ubuntu OS version name"}]
                            }],
                "applications": [{"name": "application name",
                                  "units": [{"name": "unit-name",
                                             "ip": "ip-address",
                                             "port": "used ports",
                                             "machine": "machine name"}],
                                  "relations": [{"interface": "interface-name",
                                                 "with": "name of the other application"}],
                                  "charm-name": "Name of the charm build",
                                  "exposed": "Whether or not the application is publicly accessible",
                                  "series": "Ubuntu series of the application"
                                }]
              }]           
  }]
  ```

#### **Request type**: POST
* **Description**:
  - Bootstraps a new controller with the given name and in the given region.
  - The required credentials depend of the type of cloud. Some clouds use a file for credentials. This file must be send
  with the request under `file`, then `credentials` is not used
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - controller
  - type
  - region
  - credentials or file
* **Succesful response**:
  - code: 200
  - message:
  ```json
  {"name": "controller-name",
   "type": "controller-type",
   "users": [{"name": "username",
              "access": "controller-access"}],
   "models": [{"name": "modelname",
               "ssh-keys": "ssh-keys with access to all the machines in model",
               "juju-gui-url": "Using the user login and password, the juju GUI can be used",
               "users": [{"name": "username",
                          "access": "model-access"}],
               "machines": [{"name": "machine-name",
                             "instance-id": "juju-id",
                             "ip": "ip-address",
                             "series": "Ubuntu OS version name",
                             "containers": [{"name": "container-name",
                                             "ip": "ip-address",
                                             "series": "Ubuntu OS version name"}]
                           }],
               "applications": [{"name": "application name",
                                 "units": [{"name": "unit-name",
                                            "ip": "ip-address",
                                            "port": "used ports",
                                            "machine": "machine name"}],
                                 "relations": [{"interface": "interface-name",
                                                "with": "name of the other application"}],
                                 "charm-name": "Name of the charm build",
                                 "exposed": "Whether or not the application is publicly accessible",
                                 "series": "Ubuntu series of the application"
                               }]
             }]           
  }
  ```

## **/tengu/controllers/[controller]** <a name="controller"></a>
#### **Request type**: GET
* **Description**:
  Returns all the information of a controller (models, applications, machines, units and users) the user has access to.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  {"name": "controller-name",
   "type": "controller-type",
   "users": [{"name": "username",
              "access": "controller-access"}],
   "models": [{"name": "modelname",
               "ssh-keys": "ssh-keys with access to all the machines in model",
               "juju-gui-url": "Using the user login and password, the juju GUI can be used",
               "users": [{"name": "username",
                          "access": "model-access"}],
               "machines": [{"name": "machine-name",
                             "instance-id": "juju-id",
                             "ip": "ip-address",
                             "series": "Ubuntu OS version name",
                             "containers": [{"name": "container-name",
                                             "ip": "ip-address",
                                             "series": "Ubuntu OS version name"}]
                           }],
               "applications": [{"name": "application name",
                                 "units": [{"name": "unit-name",
                                            "ip": "ip-address",
                                            "port": "used ports",
                                            "machine": "machine name"}],
                                 "relations": [{"interface": "interface-name",
                                                "with": "name of the other application"}],
                                 "charm-name": "Name of the charm build",
                                 "exposed": "Whether or not the application is publicly accessible",
                                 "series": "Ubuntu series of the application"
                               }]
             }]           
  }
  ```

#### **Request type**: DELETE
* **Description**:
  Removes the given controller
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"name": "controller-name",
    "type": "controller-type",
    "users": [{"name": "username",
               "access": "controller-access"}],
    "models": [{"name": "modelname",
                "ssh-keys": "ssh-keys with access to all the machines in model",
                "juju-gui-url": "Using the user login and password, the juju GUI can be used",
                "users": [{"name": "username",
                           "access": "model-access"}],
                "machines": [{"name": "machine-name",
                              "instance-id": "juju-id",
                              "ip": "ip-address",
                              "series": "Ubuntu OS version name",
                              "containers": [{"name": "container-name",
                                              "ip": "ip-address",
                                              "series": "Ubuntu OS version name"}]
                            }],
                "applications": [{"name": "application name",
                                  "units": [{"name": "unit-name",
                                             "ip": "ip-address",
                                             "port": "used ports",
                                             "machine": "machine name"}],
                                  "relations": [{"interface": "interface-name",
                                                 "with": "name of the other application"}],
                                  "charm-name": "Name of the charm build",
                                  "exposed": "Whether or not the application is publicly accessible",
                                  "series": "Ubuntu series of the application"
                                }]
              }]           
  }]
  ```

## **/tengu/controllers/[controller]/models** <a name="models"></a>
#### **Request type**: GET
* **Description**:
  - Returns all the information of all the models (applications, machines, units and users) on a controller if the user has access to this controller or models.
  - The api checks if the controller exists
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"name": "modelname",
    "ssh-keys": "ssh-keys with access to all the machines in model",
    "juju-gui-url": "Using the user login and password, the juju GUI can be used",
    "users": [{"name": "username",
               "access": "model-access"}],
    "machines": [{"name": "machine-name",
                  "instance-id": "juju-id",
                  "ip": "ip-address",
                  "series": "Ubuntu OS version name",
                  "containers": [{"name": "container-name",
                                  "ip": "ip-address",
                                  "series": "Ubuntu OS version name"}]
                }],
    "applications": [{"name": "application name",
                      "units": [{"name": "unit-name",
                                 "ip": "ip-address",
                                 "port": "used ports",
                                 "machine": "machine name"}],
                      "relations": [{"interface": "interface-name",
                                     "with": "name of the other application"}],
                      "charm-name": "Name of the charm build",
                      "exposed": "Whether or not the application is publicly accessible",
                      "series": "Ubuntu series of the application"
                    }]
  }]           
  ```

#### **Request type**: POST
* **Description**:
  Creates a new model on a controller. It checks if the model already exists and if the user is allowed to create a model on
  the given controller
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - model
* **Optional body**:
  - ssh-key
* **Succesful response**:
  - code: 200
  - message:
  ```json
  {"name": "modelname",
   "ssh-keys": "ssh-keys with access to all the machines in model",
   "juju-gui-url": "Using the user login and password, the juju GUI can be used",
   "users": [{"name": "username",
              "access": "model-access"}],
   "machines": [{"name": "machine-name",
                 "instance-id": "juju-id",
                 "ip": "ip-address",
                 "series": "Ubuntu OS version name",
                 "containers": [{"name": "container-name",
                                 "ip": "ip-address",
                                 "series": "Ubuntu OS version name"}]
               }],
   "applications": [{"name": "application name",
                     "units": [{"name": "unit-name",
                                "ip": "ip-address",
                                "port": "used ports",
                                "machine": "machine name"}],
                     "relations": [{"interface": "interface-name",
                                    "with": "name of the other application"}],
                     "charm-name": "Name of the charm build",
                     "exposed": "Whether or not the application is publicly accessible",
                     "series": "Ubuntu series of the application"
                   }]
  }]           
  ```

## **/tengu/controllers/[controller]/models/[model]** <a name="model"></a>
#### **Request type**: GET
* **Description**:
  Returns all the information of a model (applications, machines, units and users) if the user has access.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  {"name": "modelname",
   "ssh-keys": "ssh-keys with access to all the machines in model",
   "juju-gui-url": "Using the user login and password, the juju GUI can be used",
   "users": [{"name": "username",
              "access": "model-access"}],
   "machines": [{"name": "machine-name",
                 "instance-id": "juju-id",
                 "ip": "ip-address",
                 "series": "Ubuntu OS version name",
                 "containers": [{"name": "container-name",
                                 "ip": "ip-address",
                                 "series": "Ubuntu OS version name"}]
               }],
   "applications": [{"name": "application name",
                     "units": [{"name": "unit-name",
                                "ip": "ip-address",
                                "port": "used ports",
                                "machine": "machine name"}],
                     "relations": [{"interface": "interface-name",
                                    "with": "name of the other application"}],
                     "charm-name": "Name of the charm build",
                     "exposed": "Whether or not the application is publicly accessible",
                     "series": "Ubuntu series of the application"
                   }]
  }]           
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
* **Succesful response**:
  - code: 200
  - message:
  ```json
  {"name": "modelname",
   "ssh-keys": "ssh-keys with access to all the machines in model",
   "juju-gui-url": "Using the user login and password, the juju GUI can be used",
   "users": [{"name": "username",
              "access": "model-access"}],
   "machines": [{"name": "machine-name",
                 "instance-id": "juju-id",
                 "ip": "ip-address",
                 "series": "Ubuntu OS version name",
                 "containers": [{"name": "container-name",
                                 "ip": "ip-address",
                                 "series": "Ubuntu OS version name"}]
               }],
   "applications": [{"name": "application name",
                     "units": [{"name": "unit-name",
                                "ip": "ip-address",
                                "port": "used ports",
                                "machine": "machine name"}],
                     "relations": [{"interface": "interface-name",
                                    "with": "name of the other application"}],
                     "charm-name": "Name of the charm build",
                     "exposed": "Whether or not the application is publicly accessible",
                     "series": "Ubuntu series of the application"
                   }]
  }]           
  ```

#### **Request type**: DELETE
* **Description**:
  Destroys a model on the given controller, including all the deployes application and created machines.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"name": "modelname",
    "ssh-keys": "ssh-keys with access to all the machines in model",
    "juju-gui-url": "Using the user login and password, the juju GUI can be used",
    "users": [{"name": "username",
               "access": "model-access"}],
    "machines": [{"name": "machine-name",
                  "instance-id": "juju-id",
                  "ip": "ip-address",
                  "series": "Ubuntu OS version name",
                  "containers": [{"name": "container-name",
                                  "ip": "ip-address",
                                  "series": "Ubuntu OS version name"}]
                }],
    "applications": [{"name": "application name",
                      "units": [{"name": "unit-name",
                                 "ip": "ip-address",
                                 "port": "used ports",
                                 "machine": "machine name"}],
                      "relations": [{"interface": "interface-name",
                                     "with": "name of the other application"}],
                      "charm-name": "Name of the charm build",
                      "exposed": "Whether or not the application is publicly accessible",
                      "series": "Ubuntu series of the application"
                    }]
  }]           
  ```

## **/tengu/controllers/[controller]/models/[model]/sshkey** <a name="sshkey"></a>
#### **Request type**: GET
* **Description**:
      Returns all the ssh-keys of a model if the user has access.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message: `[ssh-key]`

#### **Request type**: POST
* **Description**:
  Adds the given ssh-key to the model
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - ssh-key
* **Succesful response**:
  - code: 200
  - message: `[ssh-key]`

#### **Request type**: DELETE
* **Description**:
  Removes the given ssh-key from the model. The ssh-key must be given, not it"s fingerprint
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - ssh-key
* **Succesful response**:
  - code: 200
  - message: `[ssh-key]`

## **/tengu/controllers/[controller]/models/[model]/applications** <a name="applications"></a>
#### **Request type**: GET
* **Description**:
      Returns all the applications in a given model if the user has access.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"name": "application name",
    "units": [{"name": "unit-name",
               "ip": "ip-address",
               "port": "used ports",
               "machine": "machine name"}],
    "relations": [{"interface": "interface-name",
                   "with": "name of the other application"}],
    "charm-name": "Name of the charm build",
    "exposed": "Whether or not the application is publicly accessible",
    "series": "Ubuntu series of the application"
  }]
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
* **Succesful response**:
  - code: 200
  - message:
  ```json
  {"name": "application name",
   "units": [{"name": "unit-name",
              "ip": "ip-address",
              "port": "used ports",
              "machine": "machine name"}],
   "relations": [{"interface": "interface-name",
                  "with": "name of the other application"}],
   "charm-name": "Name of the charm build",
   "exposed": "Whether or not the application is publicly accessible",
   "series": "Ubuntu series of the application"
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

* **Succesful response**:
  - code: 200
  - message:
  ```json
  {"name": "application name",
   "units": [{"name": "unit-name",
              "ip": "ip-address",
              "port": "used ports",
   "machine": "machine name"}],
   "relations": [{"interface": "interface-name",
                  "with": "name of the other application"}],
   "charm-name": "Name of the charm build",
   "exposed": "Whether or not the application is publicly accessible",
   "series": "Ubuntu series of the application"
  }
  ```

#### **Request type**: DELETE
* **Description**:
  Removes an application. Checks if the application exists
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"name": "application name",
    "units": [{"name": "unit-name",
               "ip": "ip-address",
               "port": "used ports",
               "machine": "machine name"}],
    "relations": [{"interface": "interface-name",
                   "with": "name of the other application"}],
    "charm-name": "Name of the charm build",
    "exposed": "Whether or not the application is publicly accessible",
    "series": "Ubuntu series of the application"
  }]
  ```

## **/tengu/controllers/[controller]/models/[model]/applications/[application]/units** <a name="units"></a>
#### **Request type**: GET
* **Description**:
  Returns the info of all the units of a given application.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"name": "unit-name",
    "ip": "ip-address",
    "port": "used ports",
    "machine": "machine name"}]
  }]
  ```

#### **Request type**: POST
* **Description**:
  Adds a unit to a given application
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"name": "unit-name",
    "ip": "ip-address",
    "port": "used ports",
    "machine": "machine name"}]
  }]
  ```

## **/tengu/controllers/[controller]/models/[model]/applications/[application]/units/[unitnumber]** <a name="unit"></a>
#### **Request type**: GET
* **Description**:
  Returns the info of a single unit.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  {"name": "unit-name",
   "ip": "ip-address",
   "port": "used ports",
   "machine": "machine name"}
  }
  ```

#### **Request type**: DELETE
* **Description**:
  Removes the unit.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"name": "unit-name",
    "ip": "ip-address",
    "port": "used ports",
    "machine": "machine name"}]
  }]
  ```

## **/tengu/controllers/[controller]/models/[model]/machines/** <a name="machines"></a>
#### **Request type**: GET
* **Description**:
  Return the info of all the machines of a given model.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"name": "machine-name",
    "instance-id": "juju-id",
    "ip": "ip-address",
    "series": "Ubuntu OS version name",
    "containers": [{"name": "container-name",
                    "ip": "ip-address",
                    "series": "Ubuntu OS version name"}]
  }]
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
* **Succesful response**:
    - code: 200
    - message:
    ```json
    {"name": "unit-name",
     "ip": "ip-address",
     "port": "used ports",
     "machine": "machine name"}]
    }
    ```

## **/tengu/controllers/[controller]/models/[model]/machines/[machine]** <a name="machine"></a>
#### **Request type**: GET
* **Description**:
  Return the info of a machine in a given model.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  {"name": "machine-name",
   "instance-id": "juju-id",
   "ip": "ip-address",
   "series": "Ubuntu OS version name",
   "containers": [{"name": "container-name",
                   "ip": "ip-address",
                   "series": "Ubuntu OS version name"}]
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
  - code: 200
  - message:
  ```json
  [{"name": "unit-name",
    "ip": "ip-address",
    "port": "used ports",
    "machine": "machine name"}]
  }]
  ```

## **/tengu/controllers/[controller]/models/[model]/relations** <a name="relations"></a>
#### **Request type**: GET
* **Description**:
  Shows all the relations of a given model
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"name": "application name",
    "relations": [{"interface": "interface-name",
                   "with": "name of the other application"}]
  }]
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
* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"name": "application name",
    "units": [{"name": "unit-name",
               "ip": "ip-address",
               "port": "used ports",
               "machine": "machine name"}],
    "relations": [{"interface": "interface-name",
                   "with": "name of the other application"}],
    "charm-name": "Name of the charm build",
    "exposed": "Whether or not the application is publicly accessible",
    "series": "Ubuntu series of the application"
  }]
  ```

## **/tengu/controllers/[controller]/models/[model]/relations/[application]** <a name="relation-add"></a>
#### **Request type**: GET
* **Description**:
  - Gets the relations of the given application
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"interface": "interface-name",
    "with": "name of the other application"}]
  ```

## **/tengu/controllers/[controller]/models/[model]/relations/[app1]/[app2]** <a name="relation-del"></a>
#### **Request type**: DELETE
* **Description**:
  Removes the relation between the 2 given applications. Checks if the applications exist>
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message:
  ```json
  [{"interface": "interface-name",
    "with": "name of the other application"}]
  ```

## **/tengu/backup** <a name="backup"></a>
#### **Request type**: GET
* **Description**:
  Backups the currently configured clouds, credentials and bootstrapped controllers. **This is just a backup for the Sojobo-setup, not the actual configured models, machines or applications!**
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **Succesful response**:
  - code: 200
  - message: Zipfile
