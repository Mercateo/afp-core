from __future__ import print_function, absolute_import, unicode_literals, division

from aws_federation_proxy.provider import ProviderByGroups

import grp
import logging
logging.basicConfig(filename='/var/log/python/debug.log',
                    level=logging.DEBUG,
                    format='%(asctime)s %(message)s')

class Provider(ProviderByGroups):
    """Uses the builtin grp module to retrieve group information"""

    def get_group_list(self):
        logging.debug("start & finished grp_provider.get_group_list")
        return [g.gr_name for g in grp.getgrall() if self.user.lower() in map(str.lower, g.gr_mem)]
