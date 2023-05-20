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
from flask_mwoauth import MWOAuth
import requests
from requests_oauthlib import OAuth1
from flask_jsonlocale import Locales
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import logging
from logging.handlers import SMTPHandler


def getVersionNumber():
    shortRevId = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'])
    return shortRevId.decode('ascii').strip()


app = Flask(__name__, static_folder='../static')

# Load configuration from YAML file
__dir__ = os.path.dirname(__file__)
app.config.update(
    yaml.safe_load(open(os.path.join(__dir__, os.environ.get(
        'FLASK_CONFIG_FILE', 'config.yaml')))))

from_email = app.config.get('FROM_EMAIL')
smtp_host = app.config.get('SMTP_HOST')
contact_email = app.config.get('CONTACT_EMAIL')

mail_handler = SMTPHandler(
    mailhost=smtp_host,
    fromaddr=from_email,
    toaddrs=[contact_email],
    subject='Application Error'
)
mail_handler.setLevel(logging.ERROR)
mail_handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
))


if not app.debug:
    if from_email and smtp_host and contact_email:
        app.logger.addHandler(mail_handler)
    else:
        app.logger.warning('No FROM_EMAIL/CONTACT_EMAIL/SMTP_HOST set in config.yaml!')

# Add databse credentials to config
if app.config.get('DBCONFIG_FILE') is not None:
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config.get('DB_URI') + '?read_default_file={cfile}'.format(cfile=app.config.get('DBCONFIG_FILE'))

db = SQLAlchemy(app)
migrate = Migrate(app, db)

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
    language = db.Column(db.String(10))
    pref_language = db.Column(db.String(10))
    frequency_hours = db.Column(db.Integer, nullable=False, default=24)
    last_emailed = db.Column(db.DateTime)
    translations = db.relationship('Translation', backref='user', lazy=True)
    token_key = db.Column(db.String(255))
    token_secret = db.Column(db.String(255))


class Translation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    language = db.Column(db.String(10))


def logged():
    return get_current_user() is not None


def get_revision():
    try:
        output = subprocess.check_output(["git", "describe", "--always"], stderr=subprocess.STDOUT).strip().decode()
        assert 'fatal' not in output
        return output
    except Exception:
        # if somehow git version retrieving command failed, just return
        return ''

def get_revision_link():
    base_link = "https://gerrit.wikimedia.org/g/labs/tools/watch-translations/"
    try:
        output = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.STDOUT).strip().decode()
        assert 'fatal' not in output
        return base_link + "+/" + output
    except Exception:
        # on fail return empty repo link
        return base_link

def form_verify(form, values, data={}):
    to_check = {}
    if form == 'component':
        to_check = {
            'language': data["query"]["languageinfo"],
            'group': [g['id'] for g in data["query"]["messagegroups"]]
        }
    elif form == 'preferences':
        to_check = {
            'freq': [24, 168],
            'lang': locales.get_locales(),
            'p_lang': data["query"]["languageinfo"]
        }
    for k in to_check:
        if values[k] is None or values[k] not in to_check[k]:
            return False
    return True

@app.before_request
def force_https():
    if request.headers.get('X-Forwarded-Proto') == 'http':
        return redirect(
            'https://' + request.headers['Host'] + request.headers['X-Original-URI'],
            code=301
        )


def get_user():
    return User.query.filter_by(
        username=get_current_user()
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
                username=get_current_user(),
                token_key=request_token_key,
                token_secret=request_token_key,
            )
            db.session.add(user)
            db.session.commit()
        else:
            user.token_key = request_token_key
            user.token_secret = request_token_secret
            if not user.is_active:
                return render_template('permission_denied.html'), 403
            if user.language:
                locales.set_locale(user.language)
            db.session.commit()


@app.context_processor
def inject_base_variables():
    return {
        "logged": logged(),
        "username": get_current_user(),
        "revision": get_revision(),
        "revision_link": get_revision_link()
    }


@app.context_processor
def friendly_namer():
    def get_friendly_name(array, name):
        for group in array:
            if group["id"] == name:
                return group["label"]
            if "groups" in group:
                if get_friendly_name(group["groups"], name) is not None:
                    return get_friendly_name(group["groups"], name)
        return None

    return dict(get_friendly_name=get_friendly_name)


def get_twn_data(tree=False):
    params = {
        'action': 'query',
        'format': 'json',
        'meta': 'messagegroups|languageinfo',
        "liprop": "code|name",
    }

    if tree:
        params["mgformat"] = "tree"
    r = requests.get('https://translatewiki.net/w/api.php', params=params, headers={'User-Agent': useragent})
    response = r.json()
    response["query"]["languageinfo"] = dict(
        sorted(
            response["query"]["languageinfo"].items(),
            key=lambda val: val[0]
        )
    )
    return response


@app.route('/')
def index():
    if logged():
        data = get_twn_data()
        return render_template(
            'index.html',
            messagegroups=data["query"]["messagegroups"],
            languages=data["query"]["languageinfo"],
            translations=Translation.query.filter_by(user=get_user()).filter(Translation.group is not None).filter(Translation.language is not None)
        )
    else:
        return render_template('login.html')


def _str(val):
    """
    Ensures that the val is the default str() type for python2 or 3
    """
    if str == bytes:
        if isinstance(val, str):
            return val
        else:
            return str(val)
    else:
        if isinstance(val, str):
            return val
        else:
            return str(val, 'ascii')


def get_current_user(cached=True):
    return mwoauth.get_current_user()

@app.route('/delete-all', methods=['POST'])
def delete_all():
    if logged():
        user = get_user()
        Translation.query.filter_by(user=user).delete()
        db.session.commit()
        flash(_('delete-all-success'), 'success')
        return redirect(url_for('index'))
    else:
        return render_template('permission_denied.html'), 403

@app.route('/preferences', methods=['GET', 'POST'])
def preferences():
    if logged():
        user = get_user()
        data = get_twn_data()
        if request.method == 'POST':
            freq = int(request.form.get('frequency-hours'))
            p_lang = request.form.get('pref-language')
            lang = request.form.get('pref-locale')
            if not form_verify('preferences', {'freq': freq, 'p_lang': p_lang, 'lang': lang}, data):
                flash(_('form-error'), 'error')
            else:
                user.frequency_hours = freq
                user.pref_language = p_lang
                user.language = lang
                db.session.commit()
                flash(_('preferences-submit'), 'success')
            if user.language:
                locales.set_locale(user.language)
        return render_template(
            'preferences.html',
            user=user,
            languages=data["query"]["languageinfo"],
            locales_list=sorted(locales.get_locales()),
            current_locale=locales.get_locale()
        )
    else:
        return render_template('permission_denied.html'), 403

@app.route('/edit/new', methods=['GET', 'POST'])
def new():
    if not logged():
        return render_template('permission_denied.html'), 403
    if request.method == 'POST':
        data = get_twn_data()
        request_success = True

        group = request.form.get('group')
        language = request.form.get('language')
        if not form_verify('component', {'group': group, 'language': language}, data):
            flash(_('form-error'), 'error')
            request_success = False

        same_translation = Translation.query.filter_by(user=get_user(), group=group, language=language).first()
        if same_translation is not None:
            flash(_('already-watched'), 'error')
            request_success = False

        if request_success:
            translation = Translation(
                user=get_user(),
                language=language,
                group=group
            )
            db.session.add(translation)
            db.session.commit()
            flash(_('success-create'), 'success')
            return redirect(url_for('index'))
    data = get_twn_data(True)
    return render_template(
        'edit.html',
        user=get_user(),
        messagegroups=data["query"]["messagegroups"],
        languages=data["query"]["languageinfo"],
        translation=None
    )

@app.route('/edit/<int:translation_id>', methods=['GET', 'POST'])
def edit(translation_id):
    translation = Translation.query.filter_by(user=get_user(), id=translation_id).first()
    if translation is None:
        return render_template('permission_denied.html'), 403
    if request.method == 'POST':
        data = get_twn_data()
        request_success = True
        post_type = request.form.get('type', "edit")
        if post_type == "edit":
            group = request.form.get('group')
            language = request.form.get('language')
            if not form_verify('component', {'group': group, 'language': language}, data):
                flash(_('form-error'), 'error')
                request_success = False

            same_translation = Translation.query.filter_by(user=get_user(), group=group, language=language).first()
            if same_translation is not None:
                if translation.group == group and translation.language == language:
                    flash(_('no-change'), 'error')
                else:
                    flash(_('duplicate-edit'), 'error')
                request_success = False
            if request_success:
                translation.group = group
                translation.language = language
                db.session.commit()
                flash(_('success-edit'), 'success')
                return redirect(url_for('index'))

        elif post_type == "delete":
            db.session.delete(translation)
            db.session.commit()
            flash(_('success-delete'), 'success')
            return redirect(url_for('index'))
    data = get_twn_data(True)
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

@app.cli.command('send-changes', help="Sends change notifications to users")
@click.option('--no-emails', is_flag=True, help="If set, the message contents will be printed instead of actually sending the messages")
@click.option('--force', is_flag=True, help="If set, an email will be sent regardless of the email frequency chosen by the user")
@click.option('--email-inactive', is_flag=True, help="If set, the messages will be also sent to inactive users")
def cli_send_changes(no_emails, force, email_inactive):
    s = None
    if not no_emails:
        smtp_host = app.config.get('SMTP_HOST')
        if not smtp_host:
            print("No SMTP_HOST has been specified in config.yaml, so emails cannot be sent.")
            print("If you intended to test the contents of emails, use --no-emails as a flag.")
            return
        s = smtplib.SMTP(smtp_host)
        if app.config.get('SMTP_AUTH'):
            s.login(app.config.get('SMTP_USERNAME'), app.config.get('SMTP_PASSWORD'))
    for user in User.query.all():
        if (not user.is_active and not email_inactive) or (user.last_emailed is not None and (datetime.now() - user.last_emailed) < timedelta(hours=user.frequency_hours) and not force):
            continue

        collections = []
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
            if 'error' in data:
                print("Error in retriving data for user {0}, translation {1}: {2}".format(user.username, str(translation.id), data['error']['info']))
                continue
            not_in_order = data["query"]["messagecollection"]
            if len(not_in_order) > 0:
                messages = []
                for message in not_in_order:
                    messages.append(message['key'])

                collections.append({
                    'group': translation.group,
                    'language': translation.language,
                    'messages': messages,
                })

        if len(collections) > 0:
            email = get_user_email(user)
            if email:
                with app.test_request_context():
                    notification = render_template(
                        'email.html',
                        username=user.username,
                        collections=collections,
                        project=app.config.get('PROJECT_URI')
                    )
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
