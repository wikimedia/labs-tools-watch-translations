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
import yaml
from flask import redirect, request, render_template, url_for, flash
from flask import Flask
import requests
from flask_jsonlocale import Locales
from flask_mwoauth import MWOAuth
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

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

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    language = db.Column(db.String(3))
    translations = db.relationship('Translation', backref='user', lazy=True)


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
            'https://' + request.headers['Host'] +
            request.headers['X-Original-URI'],
            code=301
        )

def get_user():
    return User.query.filter_by(
        username=mwoauth.get_current_user()
    ).first()

@app.before_request
def db_init_user():
    if logged():
        user = get_user()
        if user is None:
            user = User(
                username=mwoauth.get_current_user(),
                language=locales.get_locale()
            )
            db.session.add(user)
            db.session.commit()
        else:
            if user.is_active:
                locales.set_locale(user.language)
            else:
                return render_template('permission_denied.html')

@app.context_processor
def inject_base_variables():
    return {
        "logged": logged(),
        "username": mwoauth.get_current_user(),
    }

def get_twn_data():
    r = requests.get('https://translatewiki.net/w/api.php', params={
        'action': 'query',
        'format': 'json',
        'meta': 'messagegroups|languageinfo',
        "liprop": "code|name",
    })
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

@app.route('/edit/new', methods=['GET', 'POST'])
def new():
    if request.method == 'POST':
        group = request.form.get('group')
        language = request.form.get('language')
        translation = Translation(
            user=get_user(),
            language=language,
            group=group
        )
        db.session.add(translation)
        db.session.commit()
        return redirect(url_for('index'))
    else:
        data = get_twn_data()
        return render_template(
            'edit.html',
            messagegroups=data["query"]["messagegroups"],
            languages=data["query"]["languageinfo"],
            translation=Translation(),
        )

@app.route('/edit/<path:group>', methods=['GET', 'POST'])
def edit(group):
    translation = Translation.query.filter_by(user=get_user(), group=group).first()
    if request.method == 'POST':
        translation.group = request.form.get('group')
        translation.language = request.form.get('language')
        db.session.commit()
        flash(_('success-edit'))
        return redirect(url_for('index'))
    else:
        data = get_twn_data()
        return render_template(
            'edit.html',
            messagegroups=data["query"]["messagegroups"],
            languages=data["query"]["languageinfo"],
            translation=translation
        )


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
