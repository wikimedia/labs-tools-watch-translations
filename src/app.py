#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import subprocess
import yaml
from flask import redirect, request, render_template, url_for, flash, session
from flask import Flask
import click
import requests
from requests_oauthlib import OAuth1
from flask_jsonlocale import Locales
from flask_mwoauth import MWOAuth
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta

def getVersionNumber():
    shortRevId = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'])
    return shortRevId.decode('ascii').strip()


app = Flask(__name__, static_folder='../static')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Load configuration from YAML file
__dir__ = os.path.dirname(__file__)
app.config.update(
    yaml.safe_load(open(os.path.join(__dir__, os.environ.get(
        'FLASK_CONFIG_FILE', 'config.yaml')))))
locales = Locales(app)
_ = locales.get_message

mwoauth = MWOAuth(
    consumer_key=app.config.get('CONSUMER_KEY'),
    consumer_secret=app.config.get('CONSUMER_SECRET'),
    base_url=app.config.get('OAUTH_MWURI'),
)
app.register_blueprint(mwoauth.bp)

contactEmail = app.config.get('CONTACT_EMAIL')
if not contactEmail:
    print("No CONTACT_EMAIL has been set in config.yaml!")
    print("Wikimedia policy dictates that you should provide a way for system administrators to contact you.")
    print("You risk being IP-blocked if you do not comply.")
    contactEmail = "no contact provided"
useragent = "Watch-Translations-Bot/" + getVersionNumber() + " (" + contactEmail + ")"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    language = db.Column(db.String(3))
    pref_language = db.Column(db.String(3))
    frequency_hours = db.Column(db.Integer, nullable=False, default=24)
    last_emailed = db.Column(db.DateTime)
    translations = db.relationship('Translation', backref='user', lazy=True)
    token_key = db.Column(db.String(255))
    token_secret = db.Column(db.String(255))


class Translation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    language = db.Column(db.String(3))

def logged():
    return mwoauth.get_current_user() is not None

@app.before_request
def force_https():
    if request.headers.get('X-Forwarded-Proto') == 'http':
        return redirect(
            'https://' + request.headers['Host'] + request.headers['X-Original-URI'],
            code=301
        )

def get_user():
    return User.query.filter_by(
        username=mwoauth.get_current_user()
    ).first()

def mw_request(data, user=None):
    if user is None:
        access_token = session.get('mwoauth_access_token', {})
        request_token_secret = access_token.get('secret').decode('utf-8')
        request_token_key = access_token.get('key').decode('utf-8')
    else:
        request_token_secret = user.token_secret
        request_token_key = user.token_key
    auth = OAuth1(app.config.get('CONSUMER_KEY'), app.config.get('CONSUMER_SECRET'), request_token_key, request_token_secret)
    data['format'] = 'json'
    return requests.post('https://meta.wikimedia.org/w/api.php', data=data, auth=auth, headers={'User-Agent': useragent})

@app.before_request
def db_init_user():
    if logged():
        user = get_user()
        access_token = session.get('mwoauth_access_token', {})
        request_token_secret = access_token.get('secret').decode('utf-8')
        request_token_key = access_token.get('key').decode('utf-8')
        if user is None:
            user = User(
                username=mwoauth.get_current_user(),
                language=locales.get_locale(),
                token_key=request_token_key,
                token_secret=request_token_key,
            )
            db.session.add(user)
            db.session.commit()
        else:
            user.token_key = request_token_key
            user.token_secret = request_token_secret
            if user.is_active:
                locales.set_locale(user.language)
            else:
                return render_template('permission_denied.html')
            db.session.commit()

@app.context_processor
def inject_base_variables():
    return {
        "logged": logged(),
        "username": mwoauth.get_current_user(),
    }

@app.context_processor
def friendly_namer():
    def get_friendly_name(array, name):
        return next(item['label'] for item in array if item["id"] == name)

    return dict(get_friendly_name=get_friendly_name)

def get_twn_data():
    r = requests.get('https://translatewiki.net/w/api.php', params={
        'action': 'query',
        'format': 'json',
        'meta': 'messagegroups|languageinfo',
        "liprop": "code|name",
    }, headers={'User-Agent': useragent})
    return r.json()

@app.route('/')
def index():
    if logged():
        data = get_twn_data()
        return render_template(
            'index.html',
            messagegroups=data["query"]["messagegroups"],
            languages=data["query"]["languageinfo"],
            translations=Translation.query.filter_by(user=get_user())
        )
    else:
        return render_template('login.html')

@app.route('/preferences', methods=['GET', 'POST'])
def preferences():
    if logged():
        user = get_user()
        data = get_twn_data()
        if request.method == 'POST':
            user.frequency_hours = int(request.form.get('frequency-hours'))
            user.pref_language = request.form.get('pref-language')
            db.session.commit()
        return render_template(
            'preferences.html',
            user=user,
            languages=data["query"]["languageinfo"],
        )
    else:
        return render_template('permission_denied.html')

@app.route('/edit/new', methods=['GET', 'POST'])
def new():
    if request.method == 'POST':
        group = request.form.get('group')
        language = request.form.get('language')
        same_translation = Translation.query.filter_by(user=get_user(), group=group, language=language).first()
        if same_translation is None:
            translation = Translation(
                user=get_user(),
                language=language,
                group=group
            )
            db.session.add(translation)
            db.session.commit()
            return redirect(url_for('index'))
        else:
            flash(_('already-watched'))
            data = get_twn_data()
            return render_template(
                'edit.html',
                user=get_user(),
                messagegroups=data["query"]["messagegroups"],
                languages=data["query"]["languageinfo"],
                translation=Translation(),
            )
    else:
        data = get_twn_data()
        return render_template(
            'edit.html',
            user=get_user(),
            messagegroups=data["query"]["messagegroups"],
            languages=data["query"]["languageinfo"],
            translation=Translation(),
        )

@app.route('/edit/<int:translation_id>', methods=['GET', 'POST'])
def edit(translation_id):
    translation = Translation.query.filter_by(user=get_user(), id=translation_id).first()
    if request.method == 'POST':
        post_type = request.form.get('type', "edit")
        if post_type == "edit":
            group = request.form.get('group')
            language = request.form.get('language')
            same_translation = Translation.query.filter_by(user=get_user(), group=group, language=language).first()
            if same_translation is None:
                translation.group = group
                translation.language = language
                db.session.commit()
                flash(_('success-edit'))
            else:
                flash(_('duplicate-edit'))
                data = get_twn_data()
                return render_template(
                    'edit.html',
                    user=get_user(),
                    messagegroups=data["query"]["messagegroups"],
                    languages=data["query"]["languageinfo"],
                    translation=translation
                )
        elif post_type == "delete":
            db.session.delete(translation)
            db.session.commit()
            flash(_('success-delete'))
        return redirect(url_for('index'))
    else:
        data = get_twn_data()
        return render_template(
            'edit.html',
            user=get_user(),
            messagegroups=data["query"]["messagegroups"],
            languages=data["query"]["languageinfo"],
            translation=translation
        )

def get_user_email(user):
    return mw_request({
        'action': 'query',
        'meta': 'userinfo',
        'uiprop': 'email'
    }, user).json().get('query', {}).get('userinfo', {}).get('email')

@app.cli.command('send-changes')
@click.option('--no-emails', is_flag=True)
@click.option('--force', is_flag=True)
def cli_send_changes(no_emails, force):
    s = None
    if not no_emails:
        smtp_host = app.config.get('SMTP_HOST')
        if not smtp_host:
            print("No SMTP_HOST has been specified in config.yaml, so emails cannot be sent.")
            print("If you intended to test the contents of emails, use --no-emails as a flag.")
            return
        s = smtplib.SMTP(smtp_host)
    for user in User.query.all():
        if user.last_emailed is not None and (datetime.now() - user.last_emailed) < timedelta(hours=user.frequency_hours) and not force:
            continue
        notification = ""
        for translation in user.translations:
            r = requests.get('https://translatewiki.net/w/api.php', params={
                "action": "query",
                "format": "json",
                "list": "messagecollection",
                "mcgroup": translation.group,
                "mclanguage": translation.language,
                "mclimit": "max",
                "mcfilter": "!optional|!ignored|!translated"
            }, headers={'User-Agent': useragent})
            data = r.json()
            not_in_order = data["query"]["messagecollection"]
            if len(not_in_order) > 0:
                notification += "<h2>%s (%s)</h2>\n" % (translation.group, translation.language)
                notification += "<ul>\n"
                for message in not_in_order:
                    notification += "<li><a href='https://translatewiki.net/wiki/%s'>%s</a></li>\n" % (message['title'], message['key'])
                notification += "</ul>\n"
        if notification != "":
            email = get_user_email(user)
            if email:
                msg = MIMEText(notification, 'html')
                msg['From'] = app.config.get('FROM_EMAIL')
                msg['To'] = email
                msg['Subject'] = '[Watch Translations] Translations needed'
                if no_emails:
                    print(msg)
                else:
                    s.sendmail(app.config.get('FROM_EMAIL'), email, msg.as_string())
                user.last_emailed = datetime.now()
                db.session.commit()


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
