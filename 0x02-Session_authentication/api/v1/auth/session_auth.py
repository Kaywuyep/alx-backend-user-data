#!/usr/bin/env python3
"""
Session authentication module for a Simple API.
"""
from .auth import Auth
from models.user import User
from uuid import uuid4
from flask import request


class SessionAuth(Auth):
    """
    Session authentication class.
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
         that creates a Session ID for a user_id
        """
        if user_id is None:
            return None

        if not isinstance(user_id, str):
            return None

        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        that returns a User ID based on a Session ID
        """
        if session_id is None:
            return None

        if not isinstance(session_id, str):
            return None

        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """
         (overload) that returns a User instance based on a cookie value
        """
        user_id = self.user_id_for_session_id(self.session_cookie(request))
        return User.get(user_id)

    def destroy_session(self, request=None):
        """
        Destroys an authenticated session.
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)

        if request is None or session_id is None:
            return False

        if user_id is None:
            return False

        if session_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[session_id]
        return True
