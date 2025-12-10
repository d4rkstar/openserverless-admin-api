# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

from openserverless import app
import openserverless.common.response_builder as res_builder

@app.route('/system/info')
def info():
    """
    Info Endpoint
    ---
    securityDefinitions:
        openwhiskBasicAuth:
            type: basic
            description: OpenWhisk basic authentication using UUID:KEY format
    definitions:
      Message:
        type: object
        properties:
          message:
            type: string
          status: 
            type: string
      MessageData:
        type: object
        properties:
          message:
            type: object
          status: 
            type: string
      User:
        type: object
        properties:
          username:
            type: string
          email: 
            type: string
          name:
            type: string
          password:
            type: string
          token:
            type: string
        required:
        - username
        - email
        - name
        - password
        - token    
      LoginUpdateData:
        type: object
        properties:
          password:
            type: string
          new_password:
            type: string
        required:
        - password
        - new_password
      LoginData:
        type: object
        properties:
          login:
            type: string
          password:
            type: string
        required:
        - login
        - password
    tags:
      - Info
    responses:
      200:
        description: Info Endpoint
        schema:
          $ref: '#/definitions/Message'     
    """
    return res_builder.build_response_message("Welcome to OpenServerless system admin API.")

@app.route('/system/config')
def config():
    """
    Config Endpoint
    ---
    tags:
      - Config
    summary: Get API configuration data
    description: Returns basic configuration data used by this API
    operationId: getConfig
    responses:
      200:
        description: Configuration data retrieved successfully
        schema:
          $ref: '#/definitions/MessageData'
    """
    config = {
        
    }
    return res_builder.build_response_with_data(config)