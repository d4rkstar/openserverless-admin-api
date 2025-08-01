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
from flask import jsonify, make_response


def build_error_message(
    message: str, status_code=400, headers={"Content-Type": "application/json"}
):
    return make_response(
        jsonify({"message": message, "status": "ko"}), status_code, headers
    )


def build_response_message(
    message: str, status_code=200, headers={"Content-Type": "application/json"}
):
    return make_response(
        jsonify({"message": message, "status": "ok"}), status_code, headers
    )


def build_response_with_data(
    data, status_code=200, headers={"Content-Type": "application/json"}
):
    if isinstance(data, dict):
        return make_response(jsonify(data), status_code, headers)
    return make_response(data, status_code, headers)


def build_response_raw(
    message: str, status_code=200, headers={"Content-Type": "application/json"}
):
    return make_response(message, status_code, headers)


def build_error_raw(
    message: str, status_code=400, headers={"Content-Type": "application/json"}
):
    return make_response(message, status_code, headers)
