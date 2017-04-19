#!/usr/bin/env python
# -*- coding: utf-8 -*-

from aws_federation_proxy.provider import ProviderByGroups

import pysss
import logging
logging.basicConfig(filename='/var/log/python/debug.log',
                    level=logging.DEBUG,
                    format='%(asctime)s %(message)s')

class Provider(ProviderByGroups):
    """Uses the pysss module to retrieve group information from SSSD"""

    def get_group_list(self):
        logging.debug("start & finished sssd_provider.get_group_list")
        return pysss.getgrouplist(self.user)
