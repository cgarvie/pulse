from flask import Flask

from peewee import *

from app import app

import hashlib

import os
from playhouse.db_url import connect

#db = SqliteDatabase('db.sqlite')
#db = PostgresqlDatabase('my_database', host=os.environ.get('DATABASE_URL') user='postgres')
db = connect(os.environ.get('DATABASE_URL') or 'sqlite:///db.sqlite')



# Set your classes here.


class Base(Model):
    class Meta:
        database = db


class User(Base):

    def __str__(self):
        return self.email

    #name = CharField()
    email = CharField()
    hashed_password = CharField(null=True)
    signup_ip = CharField()
    is_active = BooleanField(default=True)
    confirmed = BooleanField(default=False)
    confirmed_on = DateTimeField(null=True)

    @property
    def name(self):
        return self.email

    def is_authenticated(self):
        return self is not False

    def is_anonymous(self):
        return self is False

    def is_active(self):
        return self is not False

    def get_id(self):
        return unicode(self.id)

    # TODO: add salt
    def set_password(self, password):
        self.hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    def check_password(self, password):
        return self.hashed_password == hashlib.sha256(password.encode('utf-8')).hexdigest()


class ApiKey(Base): # things can be tracked

    def __str__(self):
        return self.key

    key = CharField(unique=True)
    user = ForeignKeyField(User, related_name='apikeys')

class Thing(Base): # things can be tracked

    def __str__(self):
        return self.name

    name = CharField()
    user = ForeignKeyField(User, related_name='things')

    class Meta:
        indexes = (
            # create a unique undex
            (('user', 'name'), True),
            )


class Event(Base):

    def __str__(self):
        return str(self.datetime) + ' ' + self.value

    datetime = DateTimeField() # when it happened
    value = CharField() # what happened
    thing = ForeignKeyField(Thing, related_name='events') # what are we talking about


# Create tables.
def create_tables():
    db.create_tables([User, Thing, Event, ApiKey])

if __name__ == '__main__':
    create_tables()
