#
# Copyright 2017 MarkLogic Corporation
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
# Norman WAlsh      04/18/2017     Initial development
#

import json
import logging
from marklogic.exceptions import UnsupportedOperation
from requests.exceptions import ConnectionError
from requests.packages import urllib3
import requests

"""
Endpoint is an abstraction for a MarkLogic server endpoint.
"""

class Endpoint:
    """
    The endpoint class encapsulates the host, port, protocol and
    authentication used to communicate with a MarkLogic application
    server.
    """
    def __init__(self, host, port, auth, root=None):
        self.logger = logging.getLogger("marklogic.connection")
        self.payload_logger = logging.getLogger("marklogic.connection.payloads")

        self.verify = False # Danger, Will Robinson!
        urllib3.disable_warnings()

        self.logger.debug("START %s %s", host, port)

        # Is this an http or https connection? Assume HEAD on host:port/ will work.
        success = False
        protocol = "http"
        auth_str = None
        uri = "{0}://{1}:{2}/".format(protocol, host, port)
        try:
            # http with digest auth?
            http_auth = auth.digest_auth()
            auth_str = "digest"
            resp = requests.head(uri, auth=http_auth, verify=False)
            success = resp.status_code < 400
        except ConnectionError:
            pass

        if not success:
            self.logger.debug("HEAD %s failed", uri)
            protocol = "https"
            uri = "{0}://{1}:{2}/".format(protocol, host, port)
            try:
                # https with digest auth?
                http_auth = auth.digest_auth()
                auth_str = "digest"
                resp = requests.head(uri, auth=http_auth, verify=False)
                success = resp.status_code < 400
            except ConnectionError:
                pass

        if not success:
            self.logger.debug("HEAD %s failed (w/digest auth)", uri)
            try:
                # https with basic auth
                http_auth = auth.basic_auth()
                auth_str = "basic"
                resp = requests.head(uri, auth=http_auth, verify=False)
                success = resp.status_code < 400
            except ConnectionError:
                pass

        if not success:
            self.logger.debug("HEAD %s failed (w/basic auth)", uri)
            raise UnsupportedOperation \
                ("Cannot get authenticated response from endpoint")

        self.host = host
        self.port = port
        self.auth = auth
        self.root = root
        self.protocol = protocol
        self.http_auth = http_auth

        self.logger.debug("Endpoint: %s://%s:%d%s (%s)", protocol, host, port, root, auth_str)

    def uri(self, path, parameters=None):
        """
        Returns a URI composed from the properties of the endpoint
        augmented with the path and optional parameters.
        """
        if not path.startswith("/"):
            path = "/" + path

        if self.root is not None:
            path = self.root + path

        uri = "{0}://{1}:{2}{3}" \
              .format(self.protocol, self.host, self.port, path)

        if parameters is not None:
            uri = uri + "?" + "&".join(parameters)

        return uri

    def get_host(self):
        """ Return the current host """
        return self.host

    def get_port(self):
        """ Return the current port """
        return self.port

    def get_auth(self):
        """ Return the current auth """
        return self.auth

    def get_root(self):
        """ Return the current root """
        return self.root

    def get_protocol(self):
        """ Return the current protocol """
        return self.protocol

    def head(self, path):
        """ Return an HTTP HEAD response """
        uri = self.uri(path)
        self.logger.debug("HEAD %s...", uri)
        return requests.head(uri, auth=self.http_auth, verify=self.verify)

    def get(self, path, accept="application/json", headers=None, parameters=None):
        """ Return an HTTP GET response """
        uri = self.uri(path, parameters)
        if headers is None:
            headers = {'accept': accept}
        else:
            headers['accept'] = accept

        self.logger.debug("GET  %s...", uri)
        self.payload_logger.debug("Headers:")
        self.payload_logger.debug(json.dumps(headers, indent=2))

        return requests.get(uri, auth=self.http_auth,
                            headers=headers, verify=self.verify)

    def post(self, path, payload=None, etag=None, headers=None, parameters=None,
             content_type="application/json", accept="application/json"):
        """ Return an HTTP POST response """
        uri = self.uri(path, parameters)
        if headers is None:
            headers = {}

        headers['content-type'] = content_type
        headers['accept'] = accept

        if etag is not None:
            headers['if-match'] = etag

        self.logger.debug("POST %s...", uri)
        self.payload_logger.debug("Headers:")
        self.payload_logger.debug(json.dumps(headers, indent=2))
        if payload is not None:
            self.payload_logger.debug("Payload:")
            if content_type == 'application/json':
                self.payload_logger.debug(json.dumps(payload, indent=2))
            else:
                self.payload_logger.debug(payload)

        if payload is None:
            return requests.post(uri, auth=self.http_auth, headers=headers,
                                 verify=self.verify)
        else:
            if content_type == "application/json":
                return requests.post(uri, json=payload,
                                     auth=self.http_auth, headers=headers,
                                     verify=self.verify)
            else:
                return requests.post(uri, data=payload,
                                     auth=self.http_auth, headers=headers,
                                     verify=self.verify)

    def put(self, path, payload=None, etag=None, headers=None, parameters=None,
            content_type="application/json", accept="application/json"):
        """ Return an HTTP PUT response """
        uri = self.uri(path, parameters)

        if headers is None:
            headers = {}

        headers['content-type'] = content_type
        headers['accept'] = accept

        if etag is not None:
            headers['if-match'] = etag

        self.logger.debug("PUT  %s...", uri)
        self.payload_logger.debug("Headers:")
        self.payload_logger.debug(json.dumps(headers, indent=2))
        if payload is not None:
            self.payload_logger.debug("Payload:")
            if content_type == 'application/json':
                self.payload_logger.debug(json.dumps(payload, indent=2))
            else:
                self.payload_logger.debug(payload)

        if payload is None:
            return requests.put(uri, auth=self.http_auth, headers=headers,
                                verify=self.verify)
        else:
            if content_type == "application/json":
                return requests.put(uri, json=payload,
                                    auth=self.http_auth, headers=headers,
                                    verify=self.verify)
            else:
                return requests.put(uri, data=payload,
                                    auth=self.http_auth, headers=headers,
                                    verify=self.verify)

    def delete(self, path, payload=None, etag=None, headers=None, parameters=None,
               content_type="application/json", accept="application/json"):
        """ Return an HTTP DELETE response """
        uri = self.uri(path, parameters)

        if headers is None:
            headers = {}

        headers['content-type'] = content_type
        headers['accept'] = accept

        if etag is not None:
            headers['if-match'] = etag

        self.logger.debug("DELETE %s...", uri)
        self.payload_logger.debug("Headers:")
        self.payload_logger.debug(json.dumps(headers, indent=2))
        if payload is not None:
            self.payload_logger.debug("Payload:")
            if content_type == 'application/json':
                self.payload_logger.debug(json.dumps(payload, indent=2))
            else:
                self.payload_logger.debug(payload)

        if payload is None:
            return requests.delete(uri, auth=self.http_auth, headers=headers,
                                   verify=self.verify)
        else:
            if content_type == "application/json":
                return requests.delete(uri, json=payload,
                                       auth=self.http_auth, headers=headers,
                                       verify=self.verify)
            else:
                return requests.delete(uri, data=payload,
                                       auth=self.http_auth, headers=headers,
                                       verify=self.verify)
