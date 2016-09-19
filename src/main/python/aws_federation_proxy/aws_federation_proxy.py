# -*- coding: utf-8 -*-
"""Module to provide the backend for the aws federation proxy service"""

from __future__ import print_function, absolute_import, unicode_literals, division


import json
import time
import logging
import requests

from six.moves.urllib.parse import quote_plus
from yamlreader import data_merge
from boto.sts import STSConnection

from .util import _get_item_from_module

logging.basicConfig(filename='/var/log/python/debug.log',
                    level=logging.DEBUG,
                    format='%(asctime)s %(message)s')

def log_function_call(old_func):
    """Log Timings of function calls."""
    logging.debug("start aws_federation_proxy.log_function_call")
    def new_func(self, *args, **kwargs):
        start = time.time()
        try:
            retval = old_func(self, *args, **kwargs)
        except Exception as exc:
            stop = time.time()
            self.logger.debug(
                "%s(%s, %s) raised Exception %s after %.3f seconds",
                old_func.__name__, args, kwargs, exc, stop - start)
            raise
        stop = time.time()
        self.logger.debug(
            "%s(%s, %s) took %.3f seconds and returned %s",
            old_func.__name__, args, kwargs, stop - start, retval)
        return retval
    logging.debug("finished aws_federation_proxy.log_function_call")
    return new_func


class AWSError(Exception):
    """Exception class for throwing AWSError exceptions"""
    pass


class ConfigurationError(Exception):
    """Exception class for throwing ConfigurationError exceptions"""
    pass


class PermissionError(Exception):
    """Exception class for throwing PermissionError exceptions"""
    pass


class AWSFederationProxy(object):
    """For a given user, fetch AWS accounts/roles and retrieve credentials"""

    def __init__(self, user, config, account_config, logger=None):
        logging.debug("start aws_federation_proxy.__init__")
        default_config = {
            'aws': {
                'access_key': None,
                'secret_key': None
            },
            'provider': {
                'class': 'Provider'
            }
        }
        self.logger = logger or logging.getLogger(__name__)
        self.user = user
        self.application_config = data_merge(default_config, config)
        self.account_config = account_config
        self.provider = None
        self._setup_provider()
        logging.debug("finished aws_federation_proxy.__init__")

    def _setup_provider(self):
        """Import and set up provider module from given config"""
        logging.debug("start aws_federation_proxy._setup_provider")
        try:
            provider_config = self.application_config['provider']
            logging.debug("aws_federation_proxy._setup_provider.provider_config: %r" % provider_config)
            provider_module_name = provider_config['module']
            logging.debug("aws_federation_proxy._setup_provider.provider_module_name: %r" % provider_module_name)
        except KeyError:
            message = "No module defined in 'provider' configuration."
            raise ConfigurationError(message)
        provider_class_name = self.application_config['provider']['class']
        try:
            provider_class = _get_item_from_module(provider_module_name,
                                                   provider_class_name)
        except Exception as exc:
            logging.debug("Error aws_federation_proxy._setup_provider.Exception occured")
            logging.debug(type(exc))
            logging.debug(exc.args)
            logging.debug(exc)
            raise ConfigurationError(str(exc))
        try:
            self.provider = provider_class(
                user=self.user,
                config=self.application_config['provider'],
                logger=self.logger)
        except Exception as error:
            message = 'Could not instantiate provider "{class_name}": {error}'
            raise ConfigurationError(message.format(
                class_name=provider_class_name, error=error))
        logging.debug("finished aws_federation_proxy._setup_provider")

    @log_function_call
    def get_account_and_role_dict(self):
        """Get all accounts and roles for the user"""
        logging.debug("start & finished aws_federation_proxy.get_account_and_role_dict")
        return self.provider.get_accounts_and_roles()

    def check_user_permissions(self, account_alias, role):
        """Check if a user has permissions to access a role.

        Raise exception if access is not granted."""
        logging.debug("start aws_federation_proxy.check_user_permissions")
        accounts_and_roles = self.get_account_and_role_dict()
        permitted_roles = accounts_and_roles.get(account_alias, [])
        for permitted_role, reason in permitted_roles:
            if role == permitted_role:
                self.logger.info(
                    "Giving user '%s' access to account '%s' role '%s': %s",
                    self.user, account_alias, role, reason)
                return
        message = ("User '{user}' may not access role '{role}' in "
                   "account '{account}'")
        message = message.format(user=self.user,
                                 role=role,
                                 account=account_alias)
        self.logger.warn(message)
        logging.debug("finished aws_federation_proxy.check_user_permissions")
        raise PermissionError(message)

    @log_function_call
    def get_aws_credentials(self, account_alias, role):
        """Get temporary credentials from AWS"""
        logging.debug("start aws_federation_proxy.get_aws_credentials")
        self.check_user_permissions(account_alias, role)
        try:
            account_id = self.account_config[account_alias]['id']
        except Exception:
            message = "No Configuration for account '{account}'."
            raise ConfigurationError(message.format(account=account_alias))
        arn = "arn:aws:iam::{account_id}:role/{role}".format(
            account_id=account_id, role=role)
        key_id = self.application_config['aws']['access_key']
        secret_key = self.application_config['aws']['secret_key']
        try:
            sts_connection = STSConnection(
                aws_access_key_id=key_id,
                aws_secret_access_key=secret_key)
            assumed_role_object = sts_connection.assume_role(
                role_arn=arn,
                role_session_name=self.user)
        except Exception as error:
            if getattr(error, 'status', None) == 403:
                raise PermissionError(str(error))
            self.logger.exception("AWS STS failed with: {exc_vars}".format(
                exc_vars=vars(error)))
            raise AWSError(str(error))
        logging.debug("finished aws_federation_proxy.get_aws_credentials")
        return assumed_role_object.credentials

    @staticmethod
    def _generate_urlencoded_json_credentials(credentials):
        """Return urlencoded json-string with given credentials"""
        logging.debug("start aws_federation_proxy._generate_urlencoded_json_credentials")
        json_temp_credentials = (
            '{{'
            '"sessionId":"{access_key}",'
            '"sessionKey":"{secret_key}",'
            '"sessionToken":"{session_token}"'
            '}}'
        )
        logging.debug('_generate_urlencoded_json_credentials')
        try:
            json_temp_credentials = json_temp_credentials.format(
                **credentials.to_dict())
        except KeyError as error:
            raise Exception('Missing Key {0} in credentials'.format(error))
        logging.debug("finished aws_federation_proxy._generate_urlencoded_json_credentials")
        return quote_plus(json_temp_credentials)

    @classmethod
    def _get_signin_token(cls, credentials):
        """Return signin token for given credentials"""
        logging.debug("start aws_federation_proxy._get_signin_token")
        request_url = (
            "https://signin.aws.amazon.com/federation"
            "?Action=getSigninToken"
            "&Session=" +
            cls._generate_urlencoded_json_credentials(credentials))
        reply = requests.get(request_url)
        if reply.status_code != 200:
            message = 'Could not get session from AWS: Error {0} {1}'
            raise AWSError(message.format(reply.status_code, reply.reason))
        # reply.text is a JSON document with a single element named SigninToken
        logging.debug("finished aws_federation_proxy._generate_urlencoded_json_credentials")
        return json.loads(reply.text)["SigninToken"]

    @log_function_call
    def _construct_console_url(self, signin_token, callback_url):
        """Construct and return string with URL to aws console"""
        # Create URL that will let users sign in to the console using the
        # sign-in token. This URL must be used within 15 minutes of when the
        # sign-in token was issued.
        logging.debug("start aws_federation_proxy._construct_console_url")
        request_url_template = (
            "https://signin.aws.amazon.com/federation"
            "?Action=login"
            "&Issuer={callbackurl}"
            "&Destination={destination}"
            "&SigninToken={signin_token}")
        logging.debug("finished aws_federation_proxy._construct_console_url")
        return request_url_template.format(
            callbackurl=quote_plus(callback_url),
            destination=quote_plus("https://console.aws.amazon.com/"),
            signin_token=signin_token)

    def get_console_url(self, credentials, callback_url):
        """Return Console URL for given credentials"""
        logging.debug("start aws_federation_proxy.get_console_url")
        token = self._get_signin_token(credentials)
        logging.debug("finished aws_federation_proxy.get_console_url")
        return self._construct_console_url(token, callback_url)
