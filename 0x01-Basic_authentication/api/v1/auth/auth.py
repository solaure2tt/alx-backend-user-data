#!/usr/bin/env python3
"""manage the API authentication"""
from flask import Flask, jsonify, abort, request
from typing import List, TypeVar


class Auth:
    """class to manage the API authentication"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """returns False - path and excluded_paths
           Args:
             path: path of the resource
             excluded_paths: paths to exclude
           Return:
             False - path
        """
        if path is None:
            return True
        if excluded_paths is None or excluded_paths == []:
            return True
        if path in excluded_paths:
            return False
        for pa in excluded_paths:
            if pa.startswith(path):
                return False
            if path.startswith(pa):
                return False
            if pa[-1] == "*":
                if path.startswith(pa[:-1]):
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """returns None - request
           Args:
             request: the request
           Return:
             None - request
        """
        if request is None:
            return None
        header = request.headers.get('Authorization')
        if header is None:
            return None
        return header

    def current_user(self, request=None) -> TypeVar('User'):
        """returns None - request
           Args:
             request: the request
           Return:
              None - request
        """
