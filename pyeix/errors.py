# -*- coding: utf-8 -*-

ERR_UNKNOWN = {'code': 500, 'title': 'Unknown Error', 'more_info': None}


class CommonError(Exception):
    """Common exceptions"""

    def __init__(self, error=ERR_UNKNOWN, description=None, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)
        self.error = error
        self.error['description'] = description

    @property
    def code(self):
        """error code"""
        return self.error['code']

    @property
    def title(self):
        """title of the error"""
        return self.error['title']

    @property
    def description(self):
        """description of the error"""
        return self.error['description']

    @property
    def more_info(self):
        """description of the error"""
        return self.error['more_info']

    def __str__(self):
        return repr(self.description)
