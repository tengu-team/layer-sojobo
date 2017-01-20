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
- [/tengu/controllers/[controller]/models/[model]/applications/[application]/units]](#units)
- [/tengu/controllers/[controller]/models/[model]/applications/[application]/units/[unitnumber]](#unit)
- [/tengu/controllers/[controller]/models/[model]/machines/](#machines)
- [/tengu/controllers/[controller]/models/[model]/machines/[machine]](#machine)
- [/tengu/controllers/[controller]/models/[model]/relations](#relations)
- [/tengu/controllers/[controller]/models/[model]/relations/[application]](#relation-app)
- [/tengu/controllers/[controller]/models/[model]/relations/[app1]/[app2]](#relation-del)
- [/tengu/backup](#backup)

@TENGU.route('/controllers/<controller>/models/<model>/applications', methods=['GET, POST'])
@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>', methods=['GET', 'DELETE'])
@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/units', methods=['POST'])
@TENGU.route('/controllers/<controller>/models/<model>/applications/<application>/units/<unitnumber>', methods=['GET, DELETE'])
@TENGU.route('/controllers/<controller>/models/<model>/machines/', methods=['GET, POST'])
@TENGU.route('/controllers/<controller>/models/<model>/machines/<machine>', methods=['GET, DELETE'])
@TENGU.route('/controllers/<controller>/models/<model>/relations', methods=['PUT'])
@TENGU.route('/controllers/<controller>/models/<model>/relations/<application>', methods=['GET'])
@TENGU.route('/controllers/<controller>/models/<model>/relations/<app1>/<app2>', methods=['DELETE'])
@TENGU.route('/backup', methods=['GET'])


## **/tengu/controllers** <a name="controllers"></a>
#### **Request type**: GET
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **succesfull response**:
  - code: 200
  - message: `[{'name': 'controller-name',
                'type': 'controller-type',
                'users': [{'name': 'username',
                           'access': 'controller-access'}],
                'models': [{'name': 'modelname',
                            'ssh-keys': 'ssh-keys with access to all the machines in model',
                            'juju-gui-url': 'Using the user login and password, the juju GUI can be used',
                            'users': [{'name': 'username'},
                                       'access': 'model-access'}],
                            'machines': [{'name': 'machine-name',
                                          'instance-id': 'juju-id',
                                          'ip': 'ip-address',
                                          'series': 'Ubuntu OS version name',
                                          'containers': [{'name': 'container-name',
                                                          'ip': 'ip-address',
                                                          'series': 'Ubuntu OS version name'}]
                                        }],
                            'applications': [{'name': 'application name',
                                              'units': [{'name': 'unit-name',
                                                         'ip': 'ip-address',
                                                         'port': 'used ports',
                                                         'machine': 'machine name'}]
                                            }]
                          }]           
              }]`
* **description**:
  Returns all the information of all the controllers, models, applications, machines, units and users the user has access to.

#### **Request type**: POST
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - controller
  - region
  - credentials or file
* **succesfull response**:
  - code: 200
  - message: `{'name': 'controller-name',
               'type': 'controller-type',
               'users': [{'name': 'username',
                          'access': 'controller-access'}],
               'models': [{'name': 'modelname',
                           'ssh-keys': 'ssh-keys with access to all the machines in model',
                           'juju-gui-url': 'Using the user login and password, the juju GUI can be used',
                           'users': [{'name': 'username'},
                                      'access': 'model-access'}],
                           'machines': [{'name': 'machine-name',
                                         'instance-id': 'juju-id',
                                         'ip': 'ip-address',
                                         'series': 'Ubuntu OS version name',
                                         'containers': [{'name': 'container-name',
                                                         'ip': 'ip-address',
                                                         'series': 'Ubuntu OS version name'}]
                                       }],
                           'applications': [{'name': 'application name',
                                             'units': [{'name': 'unit-name',
                                                        'ip': 'ip-address',
                                                        'port': 'used ports',
                                                        'machine': 'machine name'}]
                                           }]
                         }]           
              }`
* **description**:
  - Bootstraps a new controller with the given name and in the given region.
  - The required credentials depend of the type of cloud. Some clouds use a file for credentials. This file must be send
  with the request under `file`, then `credentials` is not used

## **/tengu/controllers/[controller]** <a name="controller"></a>
#### **Request type**: GET
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **succesfull response**:
  - code: 200
  - message: `{'name': 'controller-name',
               'type': 'controller-type',
               'users': [{'name': 'username',
                          'access': 'controller-access'}],
               'models': [{'name': 'modelname',
                           'ssh-keys': 'ssh-keys with access to all the machines in model',
                           'juju-gui-url': 'Using the user login and password, the juju GUI can be used',
                           'users': [{'name': 'username'},
                                      'access': 'model-access'}],
                           'machines': [{'name': 'machine-name',
                                         'instance-id': 'juju-id',
                                         'ip': 'ip-address',
                                         'series': 'Ubuntu OS version name',
                                         'containers': [{'name': 'container-name',
                                                         'ip': 'ip-address',
                                                         'series': 'Ubuntu OS version name'}]
                                       }],
                           'applications': [{'name': 'application name',
                                             'units': [{'name': 'unit-name',
                                                        'ip': 'ip-address',
                                                        'port': 'used ports',
                                                        'machine': 'machine name'}]
                                           }]
                         }]           
              }`
* **description**:
  Returns all the information of a controller (models, applications, machines, units and users) the user has access to.

#### **Request type**: DELETE
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **succesfull response**:
  - code: 200
  - message: `[{'name': 'controller-name',
                'type': 'controller-type',
                'users': [{'name': 'username',
                           'access': 'controller-access'}],
                'models': [{'name': 'modelname',
                            'ssh-keys': 'ssh-keys with access to all the machines in model',
                            'juju-gui-url': 'Using the user login and password, the juju GUI can be used',
                            'users': [{'name': 'username'},
                                       'access': 'model-access'}],
                            'machines': [{'name': 'machine-name',
                                          'instance-id': 'juju-id',
                                          'ip': 'ip-address',
                                          'series': 'Ubuntu OS version name',
                                          'containers': [{'name': 'container-name',
                                                          'ip': 'ip-address',
                                                          'series': 'Ubuntu OS version name'}]
                                        }],
                            'applications': [{'name': 'application name',
                                              'units': [{'name': 'unit-name',
                                                         'ip': 'ip-address',
                                                         'port': 'used ports',
                                                         'machine': 'machine name'}]
                                            }]
                          }]           
              }]`
* **description**:
  Removes the given controller

## **/tengu/controllers/[controller]/models** <a name="models"></a>
#### **Request type**: GET
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **succesfull response**:
  - code: 200
  - message: `[{'name': 'modelname',
                'ssh-keys': 'ssh-keys with access to all the machines in model',
                            'juju-gui-url': 'Using the user login and password, the juju GUI can be used',
                            'users': [{'name': 'username'},
                                       'access': 'model-access'}],
                'machines': [{'name': 'machine-name',
                              'instance-id': 'juju-id',
                              'ip': 'ip-address',
                              'series': 'Ubuntu OS version name',
                              'containers': [{'name': 'container-name',
                                              'ip': 'ip-address',
                                              'series': 'Ubuntu OS version name'}]
                              }],
                'applications': [{'name': 'application name',
                                  'units': [{'name': 'unit-name',
                                             'ip': 'ip-address',
                                             'port': 'used ports',
                                             'machine': 'machine name'}]
                                }]
                }]`
* **description**:
  - Returns all the information of all the models (applications, machines, units and users) on a controller if the user has access to this controller or models.
  - The api checks if the controller exists

#### **Request type**: POST
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - model
* **succesfull response**:
  - code: 200
  - message: `{'name': 'modelname',
               'ssh-keys': 'ssh-keys with access to all the machines in model',
               'juju-gui-url': 'Using the user login and password, the juju GUI can be used',
               'users': [{'name': 'username'},
                          'access': 'model-access'}],
               'machines': [{'name': 'machine-name',
                             'instance-id': 'juju-id',
                             'ip': 'ip-address',
                             'series': 'Ubuntu OS version name',
                             'containers': [{'name': 'container-name',
                                             'ip': 'ip-address',
                                             'series': 'Ubuntu OS version name'}]
                           }],
               'applications': [{'name': 'application name',
                                 'units': [{'name': 'unit-name',
                                            'ip': 'ip-address',
                                            'port': 'used ports',
                                            'machine': 'machine name'}]
                               }]
              }`
* **description**:
  Creates a new model on a controller. It checks if the model already exists and if the user is allowed to create a model on
  the given controller

## **/tengu/controllers/[controller]/models/[model]** <a name="model"></a>
#### **Request type**: GET
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **succesfull response**:
  - code: 200
  - message: `{'name': 'modelname',
               'ssh-keys': 'ssh-keys with access to all the machines in model',
               'juju-gui-url': 'Using the user login and password, the juju GUI can be used',
               'users': [{'name': 'username'},
                          'access': 'model-access'}],
               'machines': [{'name': 'machine-name',
                             'instance-id': 'juju-id',
                             'ip': 'ip-address',
                             'series': 'Ubuntu OS version name',
                             'containers': [{'name': 'container-name',
                                             'ip': 'ip-address',
                                             'series': 'Ubuntu OS version name'}]
                           }],
              'applications': [{'name': 'application name',
                               'units': [{'name': 'unit-name',
                                          'ip': 'ip-address',
                                          'port': 'used ports',
                                          'machine': 'machine name'}]
                               }]
              }`
  * **description**:
    Returns all the information of a model (applications, machines, units and users) if the user has access.

#### **Request type**: DELETE
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **succesfull response**:
  - code: 200
  - message: `{'name': 'modelname',
                         'ssh-keys': 'ssh-keys with access to all the machines in model',
                         'juju-gui-url': 'Using the user login and password, the juju GUI can be used',
                         'users': [{'name': 'username'},
                                    'access': 'model-access'}],
                         'machines': [{'name': 'machine-name',
                                       'instance-id': 'juju-id',
                                       'ip': 'ip-address',
                                       'series': 'Ubuntu OS version name',
                                       'containers': [{'name': 'container-name',
                                                       'ip': 'ip-address',
                                                       'series': 'Ubuntu OS version name'}]
                                     }],
                         'applications': [{'name': 'application name',
                                           'units': [{'name': 'unit-name',
                                                      'ip': 'ip-address',
                                                      'port': 'used ports',
                                                      'machine': 'machine name'}]
                                         }]
                  }`
* **description**:
  Creates a new model on a controller. It checks if the model already exists and if the user is allowed to create a model on
  the given controller

## **/tengu/controllers/[controller]/models/[model]/sshkey** <a name="ssh-key"></a>
#### **Request type**: GET
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **succesfull response**:
  - code: 200
  - message: `String containing every ssh-key per \n`
* **description**:
      Returns all the ssh-keys of a model if the user has access.

#### **Request type**: POST
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - ssh-key
* **succesfull response**:
  - code: 200
  - message: `String containing every ssh-key per \n`
* **description**:
  Adds the given ssh-key to the model

#### **Request type**: DELETE
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - ssh-key
* **succesfull response**:
  - code: 200
  - message: `String containing every ssh-key per \n`
* **description**:
  Removes the given ssh-key from the model. The ssh-key must be given, not it's fingerprint

## **/tengu/controllers/[controller]/models/[model]/applications** <a name="applications"></a>
#### **Request type**: GET
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:

* **succesfull response**:
  - code: 200
  - message: `[{'name': 'application name',
                'units': [{'name': 'unit-name',
                           'ip': 'ip-address',
                           'port': 'used ports',
                           'machine': 'machine name'}]
              }]`
* **description**:
      Returns all the applications in a given model if the user has access.

#### **Request type**: POST
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Required body**:
  - application
* **Optional body**:
  - series
  - target
* **succesfull response**:
  - code: 200
  - message: `{'name': 'application name',
               'units': [{'name': 'unit-name',
                          'ip': 'ip-address',
                          'port': 'used ports',
                          'machine': 'machine name'}]
              }`
* **description**:
  - Deploys an application from the JuJu charm store to a model if the user has access. Checks if the application already exists in the model.
  - If the application name is preceeded with `local:` it will look for the charm in the local charm repo **Not Tested**
  - If the application is preseeded with `github:[url]` it will look for the application in the given repo **ToDo**
  - A specific series can be chosen for an application. It will check if the application is available in that series **Not Tested**
  - A specific machine can be chosen to deploy to. It will check if the machine exists. If the machine is preceeded with `lxd:`
  it will deploy the application in an lxd container. It will check if the controller supports lxd containers. **Not Tested**
  - If both a series and target is given, checks will be made if both the application and machine support the given series **Not Tested**
