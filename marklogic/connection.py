#
# Copyright 2015 MarkLogic Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# File History
# ------------
#
# Paul Hoehne       03/01/2015     Initial development
#

import json
import logging
import time
from http.client import BadStatusLine
from requests.auth import HTTPDigestAuth
from requests.exceptions import ConnectionError
from requests.exceptions import ReadTimeout
from requests.packages.urllib3.exceptions import ProtocolError
from requests.packages.urllib3.exceptions import ReadTimeoutError
from requests.packages import urllib3
import requests
from marklogic.exceptions import UnexpectedManagementAPIResponse
from marklogic.exceptions import UnauthorizedAPIRequest
from marklogic.exceptions import UnsupportedOperation
from marklogic.endpoint import Endpoint

"""
Connection related classes and method to connect to MarkLogic.
"""

class Connection:
    """
    The connection class encapsulates the information to connect to
    a MarkLogic server.
    """
    def __init__(self, host, auth,
                 mgmt_port=8002, mgmt_root="/manage/v2",
                 client_port=8000, client_root="/v1"):
        self.host = host
        self.auth = auth

        self.mgmt = Endpoint(host, mgmt_port, auth, mgmt_root)
        self.client = Endpoint(host, client_port, auth, client_root)
        self.admin = Endpoint(host, 8001, auth, "/admin/v1")
        self.response = None
        self.verify = False

        self.logger = logging.getLogger("marklogic.connection")
        self.payload_logger = logging.getLogger("marklogic.connection.payloads")

    def resource_path(self, kind, name, properties="/properties"):
        if properties is None:
            properties = ""
        if kind is None:
            kind = ""
        if kind != "":
            kind = kind + "/"
        return "{0}{1}{2}".format(kind, name, properties)

    def head(self, path):
        self.response = self.mgmt.head(path)
        return self._response()

    def client_head(self, path):
        self.response = self.client.head(path)
        return self._client_response()

    def get(self, path,
            accept="application/json", headers=None, parameters=None):
        self.response = self.mgmt.get(path, accept=accept,
                                      headers=headers, parameters=parameters)
        return self._response()

    def client_get(self, path, accept="application/json", headers=None, parameters=None):
        self.response = self.client.get(path, accept=accept,
                                        headers=headers, parameters=parameters)
        return self._client_response()

    def admin_get(self, path, accept="application/json", headers=None, parameters=None):
        self.response = self.admin.get(path, accept=accept,
                                       headers=headers, parameters=parameters)
        return self._client_response()

    def post(self, path, payload=None, etag=None, headers=None, parameters=None,
             content_type="application/json", accept="application/json"):
        self.response = self.mgmt.post(path, payload=payload, etag=etag,
                                       headers=headers, parameters=parameters,
                                       content_type=content_type, accept=accept)
        return self._response()

    def client_post(self, path, payload=None, etag=None, headers=None, parameters=None,
                    content_type="application/json", accept="application/json"):
        self.response = self.client.post(path, payload=payload, etag=etag,
                                         headers=headers, parameters=parameters,
                                         content_type=content_type, accept=accept)
        return self._client_response()

    def admin_post(self, path, payload=None, etag=None, headers=None, parameters=None,
                    content_type="application/json", accept="application/json"):
        self.response = self.admin.post(path, payload=payload, etag=etag,
                                        headers=headers, parameters=parameters,
                                        content_type=content_type, accept=accept)
        return self._client_response()

    def put(self, path, payload=None, etag=None, headers=None, parameters=None,
             content_type="application/json", accept="application/json"):
        self.response = self.mgmt.put(path, payload=payload, etag=etag,
                                      headers=headers, parameters=parameters,
                                      content_type=content_type, accept=accept)
        return self._response()

    def client_put(self, path, payload=None, etag=None, headers=None, parameters=None,
                    content_type="application/json", accept="application/json"):
        self.response = self.client.put(path, payload=payload, etag=etag,
                                        headers=headers, parameters=parameters,
                                        content_type=content_type, accept=accept)
        return self._client_response()

    def delete(self, path, payload=None, etag=None, headers=None, parameters=None,
               content_type="application/json", accept="application/json"):
        self.response = self.mgmt.delete(path, payload=payload, etag=etag,
                                         headers=headers, parameters=parameters,
                                         content_type=content_type, accept=accept)
        return self._response()

    def client_delete(self, path, payload=None, etag=None, headers=None, parameters=None,
                      content_type="application/json", accept="application/json"):
        self.response = self.client.delete(path, payload=payload, etag=etag,
                                           headers=headers, parameters=parameters,
                                           content_type=content_type, accept=accept)
        return self._client_response()

    def admin_delete(self, path, payload=None, etag=None, headers=None, parameters=None,
                      content_type="application/json", accept="application/json"):
        self.response = self.admin.delete(path, payload=payload, etag=etag,
                                           headers=headers, parameters=parameters,
                                           content_type=content_type, accept=accept)
        return self._client_response()

    def _client_response(self):
        response = self.response

        self.logger.debug("Status code: %d", response.status_code)
        self.payload_logger.debug(response.text)

        if response.status_code < 300:
            pass
        elif response.status_code == 404:
            pass
        elif response.status_code == 401:
            raise UnauthorizedAPIRequest(response.text)
        else:
            raise UnexpectedManagementAPIResponse(response.text)

        return response

    def _response(self):
        response = self._client_response()

        if response.status_code == 202:
            data = json.loads(response.text)
            # restart isn't in data, for example, if you execute a shutdown
            if "restart" in data:
                self.wait_for_restart(data["restart"]["last-startup"][0]["value"])

        return response

    def wait_for_restart(self, last_startup, timestamp_uri="/admin/v1/timestamp"):
        """Wait for the host to restart.

        :param last_startup: The last startup time reported in the
        restart message
        """

        done = False
        count = 24
        while not done:
            try:
                self.logger.debug("Waiting for restart of %s", self.host)
                response = self.admin_get("/timestamp",
                                          headers={'accept': 'application/json'})
                done = (response.status_code == 200
                        and response.text != last_startup)
            except TypeError:
                self.logger.debug("Type error...")
            except BadStatusLine:
                self.logger.debug("Bad status line...")
            except ProtocolError:
                self.logger.debug("Protocol error...")
            except ReadTimeoutError:
                self.logger.debug("ReadTimeoutError error...")
            except ReadTimeout:
                self.logger.debug("ReadTimeout error...")
            except ConnectionError:
                self.logger.debug("Connection error...")
            except UnexpectedManagementAPIResponse:
                self.logger.debug("Unexpected response...")
            time.sleep(4)  # Sleep one more time even after success...
            count -= 1

            if count <= 0:
                raise UnexpectedManagementAPIResponse("Restart hung?")

        self.logger.debug("%s restarted", self.host)

    @classmethod
    def make_connection(cls, host, username, password):
        return Connection(host, HTTPDigestAuth(username, password))
