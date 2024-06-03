#!/usr/bin/env python3
"""a basic access authentication module"""
from flask import request
from typing import List, TypeVar


class Auth:
    """a basic authentication class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """a simple boolean auth"""
        # return False
        if path is None:
            return True
        if not excluded_paths:
            return True

        # Ensure path always ends with a '/'
        if not path.endswith('/'):
            path += '/'

        # Check if the normalized path is in the excluded paths
        for excluded_path in excluded_paths:
            if excluded_path.endswith('/'):
                if path == excluded_path:
                    return False
            else:
                if path == excluded_path + '/':
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """ authorization header"""
        # return None
        if request is None:
            return None

        if not request.headers.get('Authorization'):
            return None

        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """ current user request """
        return None
