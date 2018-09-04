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
import random

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
from cassandra import ConsistencyLevel
from cassandra.query import dict_factory

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
    updateable = True

    def __init__(self):
        self.resolverId = ""
        self.server = ""
        self.database = ""
        self.port = 0
        self.limit = 100
        self.user = ""
        self.password = ""
        self.table = ""
        self.map = {}
        self.reverse_map = {}
        self.encoding = ""
        self.conParams = ""
        self.connect_string = ""
        self.session = None
        self.engine = None
        self._editable = False
        self.password_hash_type = None
        return
        
    @staticmethod
    def setup(config=None, cache_dir=None):
        """
        this setup hook is triggered, when the server
        starts to serve the first request

        :param config: the privacyidea config
        :type  config: the privacyidea config dict
        """
        log.info("Setting up the CassandraResolver")

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

            query_string = "SELECT * FROM {} WHERE {}=%s"
            query = query_string.format(self.table, userid_field)
            query_params = [
                userId
            ]

            rows = self.session.execute(query, query_params)

            for r in rows:
                if userinfo.keys():  # pragma: no cover
                    raise Exception("More than one user with userid {0!s} found!".format(userId))
                userinfo = self._get_user_from_record(r)
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

            query_string = "SELECT {} FROM {} WHERE {} like %s"
            query = query_string.format(userid_field, self.table, column)
            query_params = [
                LoginName
            ]

            rows = self.session.execute(query, query_params)

            for r in rows:
                if userid != "":    # pragma: no cover
                    raise Exception("More than one user with loginname"
                                    " %s found!" % LoginName)
                user = self._get_user_from_record(r)
                userid = user['id']
        except Exception as exx:    # pragma: no cover
            log.error("Could not get the userinformation: {0!r}".format(exx))

        return userid

    def _get_user_from_record(self, r):
        """
        :param r: row
        :type r: dict
        :return: User
        :rtype: dict
        """
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
        filter_condition = ''
        
        if searchDict is None:
            searchDict = {}
        for key in searchDict.keys():
            column = self.map.get(key)
            value = searchDict.get(key)
            value = value.replace("*", "%")
            
            if '%' != value:
                condition = "{} like %({})s".format(column, column)
                searchDict[column] = value
                conditions.append(condition)

        if conditions:
            filter_condition = "WHERE {}".format(' and '.join(conditions))

        query_string = "SELECT * FROM {} {} LIMIT {}"
        query = query_string.format(self.table, filter_condition, self.limit)

        rows = self.session.execute(query, searchDict)
        for r in rows:
            user = self._get_user_from_record(r)
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
        self.encoding = str(config.get('Encoding') or "utf-8")

        if ',' in self.server:
            self.contact_points = split(',', self.server)
        else:
            self.contact_points = [self.server]

        params = {
            'port': "{0!s}".format(self.port),
            'contact_points': self.contact_points
        }

        if self.user and self.password:
            auth_provider = PlainTextAuthProvider(
                username=self.user,
                password=self.password
            )
            params['auth_provider'] = auth_provider

        log.info("using parameters {0!s}".format(params))

        try:
            self.engine = Cluster(**params)
        except Exception as e:
            # The DB Engine/Poolclass might not support the pool_size.
            log.error("Error while connecting to Cassandra {0!s}".format(e))

        # create a configured "Session" class
        session = self.engine.connect(self.database)
        session.default_consistency_level = ConsistencyLevel.QUORUM
        session.row_factory = dict_factory
        
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
                                'Limit': 'int',
                                'Table': 'string',
                                'Map': 'string',
                                'Editable': 'int',
                                'Encoding': 'string'}
        return {typ: descriptor}

    @staticmethod
    def getResolverDescriptor():
        return IdResolver.getResolverClassDescriptor()

    @classmethod
    def testconnection(cls, params):
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

        cluster_params = {}
        contact_points = []
        auth_provider = None
        
        if 'User' in params and 'Password' in params:
            user = "{0!s}".format(params['User'])
            passw = "{0!s}".format(params['Password'])
            
            auth_provider = PlainTextAuthProvider(
                username=user,
                password=passw
            )
            
            cluster_params['auth_provider'] = auth_provider
            
        server_string = "{0!s}".format(params['Server'])
        
        if ',' in server_string:
            contact_points = split(',', server_string)
        else:
            contact_points = [server_string]

        cluster_params['contact_points'] = contact_points
        cluster_params['port'] = "{0!s}".format(params['Port'])
        
        try:
            engine = Cluster(**cluster_params)
        except Exception as e:
            # The DB Engine/Poolclass might not support the pool_size.
            log.error("Error while connecting to Cassandra {0!s}".format(e))

        # create a configured "Session" class
        session = engine.connect(params['Database'])
        session.default_consistency_level = ConsistencyLevel.QUORUM
        
        try:
            query = "SELECT * FROM {} LIMIT 10".format(params['Table'])
            result = session.execute(query)

            num = len(result.current_rows)
            desc = "Fetched {0:d} users.".format(num)
        except Exception as exx:
            desc = "Failed to retrieve users: {0!s}".format(exx)

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
        
        userid_field = self.map.get("userid")
        username_field = self.map.get("username")
                
        not_used_id = None
        retries_count = 0
        max_retries = 20
        
        while not not_used_id:
            random_id = random.randint(1, 214748363)
            
            query_string = "SELECT {},dateOf(timeuid) FROM {} WHERE {}=%s LIMIT 1"
            query = query_string.format(
                userid_field,
                self.table, 
                userid_field
            )
            
            query_params = [random_id]

            rows = self.session.execute(query, query_params)

            if max_retries == retries_count:
                msg = "Not able to generate unique {}".format(userid_field)
                raise Exception(msg)
                
            if rows:
                retries_count += 1
                continue
            else:
                not_used_id = random_id
                break
                
        kwargs[userid_field] = not_used_id
        import pprint
        pprint.pprint(kwargs)
        log.debug("Insert new user with attributes {0!s}".format(kwargs))

        query_string = "INSERT INTO {} ({}) VALUES ({})"
        fields = ','.join(kwargs.keys())
        field_names = "timeuid,{}".format(fields)
        fields_vals = "%({})s".format(')s, %('.join(kwargs.keys()))
        field_values = "now(),{}".format(fields_vals)
        
        query = query_string.format(
            self.table,
            field_names,
            field_values
        )

        self.session.execute(query, kwargs)

        query_string = "SELECT {},dateOf(timeuid) FROM {} WHERE {} like %s LIMIT 1"

        query = query_string.format(
            userid_field,
            self.table, 
            username_field
        )
        
        query_params = [
            kwargs['username']
        ]

        rows = self.session.execute(query, query_params)

        new_user_id = None
        
        if rows:
            for row in rows:
                import pprint
                pprint.pprint(row)
                new_user_id = row[self.map.get("userid")]
                break
                
        # Return the UID of the new object
        return new_user_id

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

            query_string = "DELETE FROM {} WHERE {}=%s"
            query = query_string.format(self.table, userid_field)
            
            query_params = [
                uid
            ]

            self.session.execute(query, query_params)
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
            pairs.append("{}=%({})s".format(key, key))

        update_string = ','.join(pairs)

        query_string = "UPDATE {} SET {} WHERE {}=%s"
        query = query_string.format(self.table, update_string, userid_field)
        query_params = [
            uid
        ]

        try:
            self.session.execute(query, query_params)
        except Exception as exx:
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
