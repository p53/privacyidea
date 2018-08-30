# -*- coding: utf-8 -*-
#
#  Copyright (C) 2014 Cornelius Kölbel
#  License:  AGPLv3
#  contact:  cornelius@privacyidea.org
#
#  2016-07-15 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#             Add sha512 PHP hash as suggested by Rick Romero
#  2016-04-08 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#             Simplifying out of bounds check
#             Avoid repetition in comparison
#
# This code is free software; you can redistribute it and/or
# modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
# License as published by the Free Software Foundation; either
# version 3 of the License, or any later version.
#
# This code is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU AFFERO GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
__doc__ = """This is the resolver to find users in Cassandra databases.

The file is tested in tests/test_lib_resolver.py
"""

import logging
import yaml

from UserIdResolver import UserIdResolver

import traceback
from base64 import (b64decode,
                    b64encode)
import hashlib
from privacyidea.lib.crypto import urandom, geturandom
from privacyidea.lib.utils import (is_true, hash_password, PasswordHash,
                                   check_sha, check_ssha, otrs_sha256)

log = logging.getLogger(__name__)
ENCODING = "utf-8"

try:
    from cassandra.cluster import Cluster
except ImportError:  # pragma: no cover
    log.debug("Cassandra driver could not be loaded!")

from cassandra.auth import PlainTextAuthProvider

class IdResolver (UserIdResolver):

    searchFields = {"username": "text",
                    "phone": "text",
                    "mobile": "text",
                    "surname": "text",
                    "givenname": "text",
                    "email": "text",
                    "description": "text",
                    }

    # If the resolver could be configured editable
    updateable = False

    @staticmethod
    def setup(config=None, cache_dir=None):
        """
        this setup hook is triggered, when the server
        starts to serve the first request

        :param config: the privacyidea config
        :type  config: the privacyidea config dict
        """
        log.info("Setting up the CassandraResolver")

    def __init__(self):
        self.resolverId = ""
        self.server = ""
        self.driver = ""
        self.database = ""
        self.port = 0
        self.limit = 100
        self.user = ""
        self.password = ""
        self.table = ""
        self.map = {}
        self.reverse_map = {}
        self.where = ""
        self.encoding = ""
        self.conParams = ""
        self.connect_string = ""
        self.session = None
        self.pool_size = 10
        self.pool_timeout = 120
        self.engine = None
        self._editable = False
        self.password_hash_type = None
        return

    def getSearchFields(self):
        return self.searchFields

    def checkPass(self, uid, password):
        """
        This function checks the password for a given uid.
        If ``password`` is a unicode object, it is converted to the database encoding first.
        - returns true in case of success
        -         false if password does not match

        """
        res = False
        userinfo = self.getUserInfo(uid)

        if isinstance(password, unicode):
            password = password.encode(self.encoding)

        database_pw = userinfo.get("password", "XXXXXXX")
        if database_pw[:2] in ["$P", "$S"]:
            # We have a phpass (wordpress) password
            PH = PasswordHash()
            res = PH.check_password(password, userinfo.get("password"))
        # check salted hashed passwords
#        elif database_pw[:2] == "$6":
#            res = sha512_crypt.verify(password, userinfo.get("password"))
        elif database_pw[:6].upper() == "{SSHA}":
            res = check_ssha(database_pw, password, hashlib.sha1, 20)
        elif database_pw[:9].upper() == "{SSHA256}":
            res = check_ssha(database_pw, password, hashlib.sha256, 32)
        elif database_pw[:9].upper() == "{SSHA512}":
            res = check_ssha(database_pw, password, hashlib.sha512, 64)
        # check for hashed password.
        elif userinfo.get("password", "XXXXX")[:5].upper() == "{SHA}":
            res = check_sha(database_pw, password)
        elif len(userinfo.get("password")) == 64:
            # OTRS sha256 password
            res = otrs_sha256(database_pw, password)

        return res

    def getUserInfo(self, userId):
        """
        This function returns all user info for a given userid/object.

        :param userId: The userid of the object
        :type userId: string
        :return: A dictionary with the keys defined in self.map
        :rtype: dict
        """
        userinfo = {}

        try:
            conditions = []
            userid_field = self.map.get("userid")

            query_string = "SELECT * FROM {}.{} WHERE {}={}"
            query = query_string.format(
                self.database,
                self.table,
                userid_field,
                userId
            )

            rows = self.session.exec(query)

            for r in rows:
                if userinfo.keys():  # pragma: no cover
                    raise Exception("More than one user with userid {0!s} found!".format(userId))
                userinfo = self._get_user_from_mapped_object(r)
        except Exception as exx:  # pragma: no cover
            log.error("Could not get the userinformation: {0!r}".format(exx))

        return userinfo

    def getUsername(self, userId):
        """
        Returns the username/loginname for a given userid
        :param userid: The userid in this resolver
        :type userid: string
        :return: username
        :rtype: string
        """
        column = self.map.get("username")
        info = self.getUserInfo(userId)
        return info.get(column, "")

    def getUserId(self, LoginName):
        """
        resolve the loginname to the userid.

        :param LoginName: The login name from the credentials
        :type LoginName: string
        :return: UserId as found for the LoginName
        """
        userid = ""
        userid_field = self.map.get("userid")

        try:
            conditions = []
            column = self.map.get("username")

            query_string = "SELECT {} FROM {}.{} WHERE {}='{}'"
            query = query_string.format(
                userid_field,
                self.database,
                self.table,
                column,
                LoginName
            )

            rows = self.session.exec(query)

            for r in rows:
                if userid != "":    # pragma: no cover
                    raise Exception("More than one user with loginname"
                                    " %s found!" % LoginName)
                user = self._get_user_from_mapped_object(r)
                userid = user['id']
        except Exception as exx:    # pragma: no cover
            log.error("Could not get the userinformation: {0!r}".format(exx))

        return userid

    def _get_user_from_mapped_object(self, ro):
        """
        :param ro: row
        :type ro: Mapped Object
        :return: User
        :rtype: dict
        """
        r = ro.__dict__
        user = {}
        try:
            if self.map.get("userid") in r:
                user["id"] = r[self.map.get("userid")]
        except UnicodeEncodeError:  # pragma: no cover
            log.error("Failed to convert user: {0!r}".format(r))
            log.debug("{0!s}".format(traceback.format_exc()))

        for key in self.map.keys():
            try:
                raw_value = r.get(self.map.get(key))
                if raw_value:
                    if type(raw_value) == str:
                        val = raw_value.decode(self.encoding)
                    else:
                        val = raw_value
                    user[key] = val

            except UnicodeDecodeError:  # pragma: no cover
                user[key] = "decoding_error"
                log.error("Failed to convert user: {0!r}".format(r))
                log.debug("{0!s}".format(traceback.format_exc()))

        return user

    def getUserList(self, searchDict=None):
        """
        :param searchDict: A dictionary with search parameters
        :type searchDict: dict
        :return: list of users, where each user is a dictionary
        """
        users = []
        conditions = []

        if searchDict is None:
            searchDict = {}
        for key in searchDict.keys():
            column = self.map.get(key)
            value = searchDict.get(key)
            value = value.replace("*", "%")
            condition = "{} like '{}'".format(column, value)
            conditions.append(condition)

        filter_condition = ' and '.join(conditions)

        query = "SELECT FROM {}.{} WHERE {} LIMIT {}"
        query_string = query.format(filter_condition, self.limit)

        rows = self.session.exec(query)

        for r in rows:
            user = self._get_user_from_mapped_object(r)
            if "id" in user:
                users.append(user)

        return users

    def getResolverId(self):
        """
        Returns the resolver Id
        This should be an Identifier of the resolver, preferable the type
        and the name of the resolver.
        """
        return "nosql." + self.resolverId

    @staticmethod
    def getResolverClassType():
        return 'cassandraresolver'

    @staticmethod
    def getResolverType():
        return IdResolver.getResolverClassType()

    def loadConfig(self, config):
        """
        Load the config from conf.

        :param config: The configuration from the Config Table
        :type config: dict
        """
        self.server = config.get('Server', "")
        self.driver = config.get('Driver', "")
        self.database = config.get('Database', "")
        self.resolverId = self.database
        self.port = config.get('Port', "")
        self.limit = config.get('Limit', 100)
        self.user = config.get('User', "")
        self.password = config.get('Password', "")
        self.table = config.get('Table', "")
        self._editable = config.get("Editable", False)
        self.password_hash_type = config.get("Password_Hash_Type")
        usermap = config.get('Map', {})
        self.map = yaml.safe_load(usermap)
        self.reverse_map = dict([[v, k] for k, v in self.map.items()])
        self.where = config.get('Where', "")
        self.encoding = str(config.get('Encoding') or "utf-8")

        if ',' in self.server:
            self.contact_points = split(',', self.server)
        else:
            self.contact_points = [self.server]

        auth_provider = PlainTextAuthProvider(
            username=self.user,
            password=self.password
        )

        # create the connectstring like
        params = {
            'port': self.port,
            'contact_points': self.contact_points,
            'auth_provider': auth_provider,
        }

        log.info("using parameters {0!s}".format(self.params))

        try:
            self.engine = Cluster(**params)
        except e:
            # The DB Engine/Poolclass might not support the pool_size.
            log.error("Error while connecting to Cassandra %s".format(e))

        # create a configured "Session" class
        session = self.engine.connect(self.database)

        # create a Session
        self.session = session

        return self

    @classmethod
    def getResolverClassDescriptor(cls):
        descriptor = {}
        typ = cls.getResolverType()
        descriptor['clazz'] = "useridresolver.CassandraIdResolver.IdResolver"
        descriptor['config'] = {'Server': 'string',
                                'Database': 'string',
                                'User': 'string',
                                'Password': 'password',
                                'Password_Hash_Type': 'string',
                                'Port': 'int',
                                'Table': 'string',
                                'Map': 'string',
                                'Where': 'string',
                                'Editable': 'int',
                                'Encoding': 'string'}
        return {typ: descriptor}

    @staticmethod
    def getResolverDescriptor():
        return IdResolver.getResolverClassDescriptor()

    @classmethod
    def testconnection(cls, param):
        """
        This function lets you test the to be saved Cassandra connection.

        :param param: A dictionary with all necessary parameter
                        to test the connection.
        :type param: dict

        :return: Tuple of success and a description
        :rtype: (bool, string)

        Parameters are: Server, Driver, Database, User, Password, Port,
                        Limit, Table, Map
                        Where, Encoding, conParams

        """
        num = -1
        desc = None

        engine = None

        try:
            engine = Cluster(**params)
        except e:
            # The DB Engine/Poolclass might not support the pool_size.
            log.error("Error while connecting to Cassandra %s".format(e))

        # create a configured "Session" class
        session = engine.connect(self.database)

        try:
            query_string = "SELECT * FROM {}.{} LIMIT 1"
            query = query_string.format(self.database, self.table)

            result = session.exec(query)

            num = len(result)
            desc = "Found {0:d} users.".format(num)
        except Exception as exx:
            desc = "failed to retrieve users: {0!s}".format(exx)

        return num, desc

    def add_user(self, attributes=None):
        """
        Add a new user to the Cassandra database.

        attributes are these
        "username", "surname", "givenname", "email",
        "mobile", "phone", "password"

        :param attributes: Attributes according to the attribute mapping
        :return: The new UID of the user. The UserIdResolver needs to
        determine the way how to create the UID.
        """
        attributes = attributes or {}
        if "password" in attributes and self.password_hash_type:
            attributes["password"] = hash_password(attributes["password"],
                                                   self.password_hash_type)

        kwargs = self._attributes_to_db_columns(attributes)

        log.debug("Insert new user with attributes {0!s}".format(kwargs))

        query_string = "INSERT INTO {}.{} ({}) VALUES ({})"
        query = query_string.format(
            self.database,
            self.table,
            kwargs.keys(),
            kwargs.values()
        )

        self.session.exec(query)

        userid_field = self.map.get("userid")

        query_string = (
                            "SELECT {},dateOf({}) FROM {}.{} "
                            "WHERE username='{}' LIMIT 1"
                        )

        query = query_string.format(
            userid_field,
            userid_field,
            self.database,
            self.table,
            params['username']
        )

        rows = self.session.exec(query)

        # Return the UID of the new object
        return getattr(rows[0][userid_field], self.map.get("userid"))

    def _attributes_to_db_columns(self, attributes):
        """
        takes the attributes and maps them to the DB columns
        :param attributes:
        :return: dict with column name as keys and values
        """
        columns = {}
        for fieldname in attributes.keys():
            if self.map.get(fieldname):
                if fieldname == "password":
                    password = attributes.get(fieldname)
                    # Create a {SSHA256} password
                    salt = geturandom(16)
                    hr = hashlib.sha256(password)
                    hr.update(salt)
                    hash_bin = hr.digest()
                    hash_b64 = b64encode(hash_bin + salt)
                    columns[self.map.get(fieldname)] = "{SSHA256}" + hash_b64
                else:
                    columns[self.map.get(fieldname)] = attributes.get(fieldname)
        return columns

    def delete_user(self, uid):
        """
        Delete a user from the Cassandra database.

        The user is referenced by the user id.
        :param uid: The uid of the user object, that should be deleted.
        :type uid: basestring
        :return: Returns True in case of success
        :rtype: bool
        """
        res = True
        try:
            userid_field = self.map.get("userid")

            query_string = "DELETE FROM {}.{} WHERE {}={}"
            query = query_string.format(
                self.database,
                self.table,
                userid_field,
                uid
            )

            self.session.exec(query)
        except Exception as exx:
            log.error("Error deleting user: {0!s}".format(exx))
            res = False
        return res

    def update_user(self, uid, attributes=None):
        """
        Update an existing user.
        This function is also used to update the password. Since the
        attribute mapping know, which field contains the password,
        this function can also take care for password changing.

        Attributes that are not contained in the dict attributes are not
        modified.

        :param uid: The uid of the user object in the resolver.
        :type uid: basestring
        :param attributes: Attributes to be updated.
        :type attributes: dict
        :return: True in case of success
        """
        res = True
        attributes = attributes or {}
        params = self._attributes_to_db_columns(attributes)
        userid_field = self.map.get("userid")

        pairs = []
        for (key,val) in params.items():
            pairs.append("{}='{}'".format(key,val))

        update_string = ','.join(pairs)

        query_string = "UPDATE {}.{} SET {} WHERE {}={}"
        query = query_string.format(
            self.database,
            self.table,
            update_string,
            userid_field,
            uid
        )

        try:
            self.session.exec(query)
        except exx:
            log.error("Error updating user: {0!s}".format(exx))
            res = False

        return res

    @property
    def editable(self):
        """
        Return true, if the instance of the resolver is configured editable
        :return:
        """
        # Depending on the database this might look different
        # Usually this is "1"
        return is_true(self._editable)
