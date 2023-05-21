# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, BooleanField, SubmitField, FileField
from wtforms.validators import DataRequired, Optional

# Create Case Form

class CreateCaseForm(FlaskForm):
    case_name = StringField('Case name', validators=[DataRequired()])
    assigned_to = StringField('Analyst Name', validators=[DataRequired()])
    ticket_id = StringField('Optional', validators=[Optional()])
    description = TextAreaField('Case description', validators=[Optional()])
    case_priority = SelectField('Select Priority',
                        choices=[('', 'Select Priority'),
                                 ('1', 'Critical'),
                                 ('2', 'Hard'),
                                 ('3', 'Medium'),
                                 ('4', 'Low')],
                        validators=[DataRequired()])
    virustotal = BooleanField("VirusTotal", validators=[DataRequired()])
    anyrun = BooleanField("AnyRun", validators=[Optional()])
    hybridanalysis = BooleanField("Hybrid Analysis", validators=[Optional()])
    malwarebazaar = BooleanField("Malware Bazaar", validators=[Optional()])
    alienvault_otx = BooleanField("AlienVault OTX", validators=[Optional()])
    urlscan = BooleanField("URLHaus & URLScan", validators=[Optional()])
    submit = SubmitField("Create Now")


# Create Case Form

class CreateSettingsForm(FlaskForm):
    VTAPI = StringField('VirusTotal API', validators=[Optional()])
    HBAPI = StringField('Hybrid Analysis API', validators=[Optional()])
    MBAPI = StringField('Malware Bazaar API', validators=[Optional()])
    ARAPI = StringField('AnyRun API', validators=[Optional()])
    URLAPI = StringField('URLHaus API', validators=[Optional()])
    OTXAPI = StringField('AlienVault OTX API', validators=[Optional()])
    submit = SubmitField("Update Now")

class SubmissionForm(FlaskForm):
    file = FileField("Malware File", validators=[DataRequired()])
    hash = StringField('Malware hash', validators=[DataRequired()])
    url = StringField('Suspicious URL, IP', validators=[DataRequired()])
    pcap = FileField("PCAP File", validators=[DataRequired()])