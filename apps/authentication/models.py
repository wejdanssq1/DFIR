# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_login import UserMixin

from apps import db, login_manager

from apps.authentication.util import hash_pass

class Users(db.Model, UserMixin):

    __tablename__ = 'Users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    email = db.Column(db.String(64), unique=True)
    password = db.Column(db.LargeBinary)

    def __init__(self, **kwargs):
        for property, value in kwargs.items():
            # depending on whether value is an iterable or not, we must
            # unpack it's value (when **kwargs is request.form, some values
            # will be a 1-element list)
            if hasattr(value, '__iter__') and not isinstance(value, str):
                # the ,= unpack of a singleton fails PEP8 (travis flake8 test)
                value = value[0]

            if property == 'password':
                value = hash_pass(value)  # we need bytes here (not plain str)

            setattr(self, property, value)

    def __repr__(self):
        return str(self.username)

# ...

class Cases(db.Model):

    __tablename__ = 'Cases'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    case_name = db.Column(db.String(100), nullable=False)
    assigned_to = db.Column(db.String(100), nullable=False)
    ticket_id = db.Column(db.String(80), nullable=True)
    case_priority = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text)
    virustotal = db.Column(db.Boolean, default=True)
    anyrun = db.Column(db.Boolean, default=False)
    hybridanalysis = db.Column(db.Boolean, default=False)
    malwarebazaar = db.Column(db.Boolean, default=False)
    alienvault_otx = db.Column(db.Boolean, default=False)
    urlscan = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(timezone=True),server_default=db.func.now())

    def __repr__(self):
        return f'<Cases {self.case_name}>'

class APIs(db.Model):

    __tablename__ = 'APIs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    VTAPI = db.Column(db.String(100), nullable=True) # Virustotal API
    HBAPI = db.Column(db.String(100), nullable=True) # Hybrid Analysis API
    MBAPI = db.Column(db.String(100), nullable=True) # Malware Bazaar
    ARAPI = db.Column(db.String(100), nullable=True) # ANYRUN API
    URLAPI = db.Column(db.String(100), nullable=True) # URLHous API
    OTXAPI = db.Column(db.String(100), nullable=True) # Alienvault OTX API
    created_at = db.Column(db.DateTime(timezone=True),server_default=db.func.now())

    def __repr__(self):
        return f'<APIs {self.created_at}>'

class FileHash(db.Model):

    __tablename__ = 'FileHash'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    case_id = db.Column(db.Integer, nullable=False)
    analysis_id = db.Column(db.String(200), nullable=True)
    case_name = db.Column(db.String(100), nullable=True)
    priority = db.Column(db.Integer, nullable=False)
    file_name = db.Column(db.String(100), nullable=True)
    sha256 = db.Column(db.String(100), nullable=True)
    sha1 = db.Column(db.String(100), nullable=True)
    md5 = db.Column(db.String(100), nullable=True)
    size = db.Column(db.Integer, nullable=True)
    type = db.Column(db.String(100), nullable=True)
    malicious = db.Column(db.Integer, nullable=True)
    scan_status = db.Column(db.String(100), nullable=True)
    data_type = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True),server_default=db.func.now())

    def __repr__(self):
        return f'<FileHash {self.file_name}>'

class URLIP(db.Model):

    __tablename__ = 'URLIP'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    case_id = db.Column(db.Integer, nullable=False)
    analysis_id = db.Column(db.String(200), nullable=True)
    case_name = db.Column(db.String(100), nullable=True)
    priority = db.Column(db.Integer, nullable=False)
    url = db.Column(db.String(255), nullable=True)
    ip = db.Column(db.String(255), nullable=True)
    malicious = db.Column(db.Integer, nullable=True)
    scan_status = db.Column(db.String(100), nullable=True)
    data_type = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True),server_default=db.func.now())

    def __repr__(self):
        return f'<URLIP {self.case_name}>'

class PCAPS(db.Model):

    __tablename__ = 'PCAPS'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    case_id = db.Column(db.Integer, nullable=False)
    case_name = db.Column(db.String(100), nullable=True)
    file_name = db.Column(db.String(100), nullable=True)
    priority = db.Column(db.Integer, nullable=False)
    submission_ids = db.Column(db.Text)
    malicious = db.Column(db.Integer, nullable=True)
    scan_status = db.Column(db.String(100), nullable=True)
    data_type = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True),server_default=db.func.now())

    def __repr__(self):
        return f'<PCAPS {self.file_name}>'
    
@login_manager.user_loader
def user_loader(id):
    return Users.query.filter_by(id=id).first()


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    user = Users.query.filter_by(username=username).first()
    return user if user else None
