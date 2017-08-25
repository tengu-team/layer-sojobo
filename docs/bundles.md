# Bundles-API Documentation

The Bundles-API provides an endpoint for bundles.

## API Calls
- [/bundles](#bundles)
- [/bundles/[bundle]](#bundle)

## **/bundles** <a name="bundles"></a>
#### **Request type**: GET
* **Description**:
  Returns all the available bundles
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Successful response**:
  - code: 200
  - message:
  ```json
    [
      {
        "name": "bundle-streaming",
        "description": null,
        "json": {
          "series": "trusty",
          "machines": {
            "0": {"series": "trusty"},
            "1": {"series": "trusty"},
            "2": {"series": "trusty"}
          },
          "services": {
            "apache-zookeeper": {
              "charm": "cs:~tengu-bot/apache-zookeeper-0",
              "num_units": 1,
              "to": ["0"]
            },
            "nimbus": {
              "charm": "cs:~tengu-bot/storm-2",
              "num_units": 1,
              "expose": true,
              "to": ["1"]
            },
            "worker": {
              "charm": "cs:~tengu-bot/storm-2",
              "num_units": 1,
              "to": ["2"]
            }
          },
          "relations": [
            ["worker:zookeeper", "apache-zookeeper:zookeeper"],
            ["nimbus:master", "worker:worker"],
            ["nimbus:zookeeper", "apache-zookeeper:zookeeper"]
          ]
        },
      "logo": null
      }
    ]
  ```

## **/bundles/[bundle]** <a name="bundle"></a>
#### **Request type**: GET
* **Description**:
  Gets the info of one bundle.
* **Required headers**:
  - api-key
  - Content-Type:application/json
* **Successful response**:
  - code: 200
  - message:
  ```json
    {
      "name": "bundle-streaming",
      "description": null,
      "json": {
        "series": "trusty",
        "machines": {
          "0": {"series": "trusty"},
          "1": {"series": "trusty"},
          "2": {"series": "trusty"}
        },
        "services": {
          "apache-zookeeper": {
            "charm": "cs:~tengu-bot/apache-zookeeper-0",
            "num_units": 1,
            "to": ["0"]
          },
          "nimbus": {
            "charm": "cs:~tengu-bot/storm-2",
            "num_units": 1,
            "expose": true,
            "to": ["1"]
          },
          "worker": {
            "charm": "cs:~tengu-bot/storm-2",
            "num_units": 1,
            "to": ["2"]
          }
        },
        "relations": [
          ["worker:zookeeper", "apache-zookeeper:zookeeper"],
          ["nimbus:master", "worker:worker"],
          ["nimbus:zookeeper", "apache-zookeeper:zookeeper"]
        ]
      },
    "logo": null
    }
  ```
