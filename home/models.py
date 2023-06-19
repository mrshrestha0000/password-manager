from .database import Base
from sqlalchemy import Column, Integer, String, DateTime, Boolean

from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, ForeignKey

Base = declarative_base()


# User model
class user_model(Base):
    __tablename__ = "user"

    email = Column(String, primary_key=True, unique=True) #This is foreign key
    password = Column(String)
    token = Column(String, nullable=True)
    # group_table = relationship("group_model", secondary="user_group", back_populates="user")


#Passwrod 
class password_model(Base):
    __tablename__ = "password_table"

    id = Column(Integer, autoincrement=True, primary_key=True)
    username = Column(String)
    password = Column(String)
    website = Column(String)
    user_email = Column(String, ForeignKey('user.email'))
    
    relation = relationship("user_model", backref="password_table")
