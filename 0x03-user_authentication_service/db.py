#!/usr/bin/env python3
"""
DB class management
"""
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db",
                                     echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Create a User and save it to the database
        Args:
            email (str): user's email address
            hashed_password (str): password
        Return:
            User object
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """
        Find and return a user who has an attribute
        matching the attributes passed
        as arguments
        Args:
            attributes (dict): a dictionary of attributes to match the user
        Return:
            finding  user or error
        """
        users = self._session.query(User)
        for k, v in kwargs.items():
            if k not in User.__dict__:
                raise InvalidRequestError
            for usr in users:
                if getattr(usr, k) == v:
                    return usr
        raise NoResultFound

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Update attributes of a user
        Args:
            user_id (int): user's id
            kwargs (dict): attributes to update and the values to update
        Return:
            Nothing
        """
        try:
            user = self.find_user_by(id=user_id)
        except NoResultFound:
            raise ValueError()
        for k, v in kwargs.items():
            if hasattr(user, k):
                setattr(user, k, v)
            else:
                raise ValueError
        self._session.commit()
