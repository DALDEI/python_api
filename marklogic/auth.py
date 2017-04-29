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

from requests.auth import HTTPDigestAuth
from requests.auth import HTTPBasicAuth

"""
Auth is an abstraction for authentication to MarkLogic Server.
We provide our own abstraction in preparation for supporting certificate
based authentication and also because we need to be able to switch
between digest and basic auth.
"""

class Auth:
    """
    The auth class encapsulates username and password for logins
    and will eventually encapsulate certificate details.
    """
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def basic_auth(self):
        """ Returns an HTTPBasicAuth for this identity. """
        return HTTPBasicAuth(self.username, self.password)

    def digest_auth(self):
        """ Returns an HTTPDigestAuth for this identity. """
        return HTTPDigestAuth(self.username, self.password)
