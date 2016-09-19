#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function, absolute_import, unicode_literals, division

from socket import gethostbyaddr

from aws_federation_proxy import PermissionError
from aws_federation_proxy.provider import BaseProvider

import logging
logging.basicConfig(filename='/var/log/python/debug.log',
                    level=logging.DEBUG,
                    format='%(asctime)s %(message)s')

class ProviderByIP(BaseProvider):
    """Uses IP address/FQDN as username, returning exactly one role

    The account name must be configured, only the role name is determined by
    the IP/FQDN.
    """

    def get_accounts_and_roles(self):
        """Return a dict with one account and one aws role"""
        logging.debug('start provider_by_ip.ProviderByIP.get_accounts_and_roles')
        self.role_prefix = self.config.get('role_prefix', "")
        try:
            self.client_fqdn = gethostbyaddr(self.user)[0]
        except Exception as exc:
            # The exception message of gethostbyaddr() is quite useless since
            # it does not include the address that was looked up.
            message = "Lookup for '{0}' failed: {1}".format(self.user, exc)
            raise Exception(message)
        self.check_host_allowed()
        self._get_role_name()
        reason = "Machine {0} (FQDN {1}) matched the role {2}".format(
            self.user, self.client_fqdn, self.role_name)
        logging.debug('finished provider_by_ip.ProviderByIP.get_accounts_and_roles')
        return {self.config["account_name"]: set([(self.role_name, reason)])}

    def check_host_allowed(self):
        logging.debug('start provider_by_ip.ProviderByIP.check_host_allowed')
        self.client_host, self.client_domain = self.client_fqdn.split(".", 1)
        allowed_domains = self.config['allowed_domains']
        logging.debug('finished provider_by_ip.ProviderByIP.check_host_allowed')
        if self.client_domain not in allowed_domains:
            raise PermissionError("Client IP {0} (FQDN {1}) is not permitted".format(
                self.user, self.client_fqdn))

    def _get_role_name(self):
        """Translate self.user / self.client_fqdn into self.role_name"""
        logging.debug('start & finished provider_by_ip.ProviderByIP.check_host_allowed')
        raise NotImplementedError  # pragma: no cover


class Provider(ProviderByIP):
    """Apply Immobilienscout24 host name pattern, returning exactly one role"""

    def _get_role_name(self):
        """Determined the aws role name to a given ip address"""
        logging.debug('start provider_by_ip.Provider._get_role_name')
        loctyp = self._normalize_loctyp()
        self.role_name = self.role_prefix + loctyp
        logging.finished('start provider_by_ip.Provider._get_role_name')

    def check_host_allowed(self):
        logging.debug('start provider_by_ip.Provider.check_host_allowed')
        super(Provider, self).check_host_allowed()
        logging.debug('finished provider_by_ip.Provider.check_host_allowed')
        if len(self.client_host) != 8:
            raise PermissionError(
                "Client {0} has an invalid name".format(self.client_fqdn))

    def _normalize_loctyp(self):
        """Return the normalized (ber/ham -> pro) loctyp of self.client_host"""
        logging.debug('start provider_by_ip.Provider._normalize_loctyp')
        if self.client_host.startswith(("ber", "ham")):
            logging.debug('finished provider_by_ip.Provider._normalize_loctyp')
            return "pro" + self.client_host[3:6]
        else:
            logging.debug('finished provider_by_ip.Provider._normalize_loctyp')
            return self.client_host[:6]
