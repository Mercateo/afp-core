from __future__ import print_function, absolute_import, division

import logging

from pils import levelname_to_integer
logging.basicConfig(filename='/var/log/python/debug.log',
                    level=logging.DEBUG,
                    format='%(asctime)s %(message)s')

def _get_item_from_module(module_name, item_name):
    """Load classes/modules/functions/... from given config"""
    logging.debug("start util._get_item_from_module")
    try:
        logging.debug("util._get_item_from_module.module_name: %r" % module_name) 
        logging.debug("util._get_item_from_module.item_name: %r" % item_name)
        module = __import__(module_name, fromlist=[item_name])
        logging.debug("after util._get_item_from_module.__import__")
        klass = getattr(module, item_name)
        logging.debug("after util._get_item_from_module.getattr")
    except ImportError as error:
        logging.debug("Error util._get_item_from_module.ImportError occured")
        message = 'Module "{modulename}" could not be loaded: {e}'
        raise Exception(message.format(
            modulename=module_name, e=error))
    except AttributeError as error:
        logging.debug("Error util._get_item_from_module.AttributeError occured")
        message = 'No item "{itemname}" in module "{modulename}": {e}'
        raise Exception(message.format(
            modulename=module_name,
            itemname=item_name,
            e=error))
    logging.debug("finished util._get_item_from_module")
    return klass


def setup_logging(config, logger_name=''):
    logging.debug("start util.setup_logging")
    handler_config = config.get('logging_handler')
    logger = logging.getLogger(logger_name)
    if logger.handlers:
        # Was already initialized, nothing to do.
        logging.debug("util.setup_logging: already initialized")
        return logger

    log_level = config.get('log_level', 'info')
    log_level = levelname_to_integer(log_level)
    logger.setLevel(log_level)

    default_config = {
        'module': 'logging.handlers',
        'class': 'SysLogHandler',
        'args': [],
        'kwargs': {'address': '/dev/log'}}
    handler_config = handler_config or default_config
    klass = _get_item_from_module(handler_config['module'],
                                  handler_config['class'])
    args = handler_config.get('args', ())
    kwargs = handler_config.get('kwargs', {})
    try:
        handler = klass(*args, **kwargs)
    except Exception as exc:
        message = ("Could not instantiate logging handler class '{klass}' "
                   "with args '{args}', kwargs '{kwargs}': {exc}")
        raise Exception(message.format(klass=klass, args=args,
                                       kwargs=kwargs, exc=exc))

    log_format = config.get('log_format', 'afp-core: [%(levelname)s] %(message)s')
    formatter = logging.Formatter(log_format)
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logging.debug("finished util.setup_logging")
    return logger
