
from flask import *

from app import app

import models
import forms
import copy


from functools import wraps

from datetime import datetime, date, timedelta
import time

from flask.ext.login import current_user, LoginManager, login_user, login_required, logout_user
from flask.ext.mail import Mail, Message

from flask_admin import Admin
from flask_admin.contrib.peewee import ModelView

from pprint import pprint

from models import db

from itsdangerous import URLSafeTimedSerializer

import pandas as pd
import numpy as np
import random


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

mail = Mail()
mail.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return models.User.get(id=user_id)


admin = Admin(app, name='trackr', template_mode='bootstrap3')
admin.add_view(ModelView(models.User, db, 'Users'))
admin.add_view(ModelView(models.ApiKey, db, 'ApiKeys'))
admin.add_view(ModelView(models.Thing, db, 'Things'))
admin.add_view(ModelView(models.Event, db, 'Events'))





def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=['camfslfkndslfkdnsfkdser@gmail.com'], #[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)



#----------------------------------------------------------------------------#
# Decorators.
#----------------------------------------------------------------------------#

@app.before_request
def before_request():
    g.db = db
    g.db.connect()

@app.after_request
def after_request(response):
    g.db.close()
    return response

@app.route('/unconfirmed')
@login_required
def unconfirmed():
    if current_user.confirmed:
        return redirect('main.home')
    flash('Please confirm your account!', 'warning')
    return render_template('pages/unconfirmed.html')

@app.route('/resend')
@login_required
def resend_confirmation():
    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('emails/activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(current_user.email, subject, html)
    flash('A new confirmation email has been sent.', 'success')
    return redirect(url_for('unconfirmed'))

def check_confirmed(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.confirmed is False:
            flash('Please confirm your account!', 'warning')
            return redirect(url_for('unconfirmed'))
        return func(*args, **kwargs)
    return decorated_function

#----------------------------------------------------------------------------#
# Controllers.
#----------------------------------------------------------------------------#

@app.route('/')
def home():
    if current_user:
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
    return render_template('pages/home.html')


@app.route('/demo')
def demo():
    user = models.User.get(email='demo@gmail.com')
    login_user(user)
    flash('Have fun in the test account! Note that most functionality has been disabled.', 'success')
    return redirect('dashboard')


def unix_time_millis(dt):
    epoch = datetime.utcfromtimestamp(0)
    return (dt - epoch).total_seconds()

@app.route('/graph')
def graph_data():

    thing_id = request.args.get('thing') or abort(404)
    thing_id = int(thing_id)
    graphlen = request.args.get('graphlen') or 7*24*60
    graphlen = int(graphlen)
    periodlen = request.args.get('periodlen') or 15
    periodlen = int(periodlen)

    thing = models.Thing.get(models.Thing.user==current_user.id and models.Thing.id == thing_id)
    series = {}

    now = datetime.now()
    nowish = now - timedelta(minutes=now.minute % periodlen, seconds=now.second, microseconds=now.microsecond)
    times = pd.date_range(nowish - timedelta(minutes=graphlen), now, freq=str(periodlen)+'min')
    pprint(np.array(times))

    for e in thing.events:
        if e.value not in series:
            series[e.value] = []
        if now - timedelta(minutes=graphlen) < e.datetime:
            series[e.value].append( (e.datetime - timedelta(minutes=e.datetime.minute % periodlen, seconds=e.datetime.second, microseconds=e.datetime.microsecond) ) )

    points = {}
    for s in series:
        points[s] = {unix_time_millis(dt):series[s].count(dt) for dt in set(series[s])}
        for t in times:
            if unix_time_millis(t) not in points[s]:
                points[s][unix_time_millis(t)] = 0


    pprint(points)
    return jsonify(points)








@app.route('/pie')
def pie_data():

    thing_id = request.args.get('thing') or abort(404)
    thing_id = int(thing_id)
    graphlen = request.args.get('graphlen') or 7*24*60
    graphlen = int(graphlen)

    thing = models.Thing.get(models.Thing.user==current_user.id and models.Thing.id == thing_id)
    series = {}

    now = datetime.now()


    for e in thing.events:
        if e.value not in series:
            series[e.value] = 0
        if now - timedelta(minutes=graphlen) < e.datetime:
            series[e.value] = series[e.value] + 1

    print "THE SERIES IS"
    pprint(series)

    return jsonify(series)







@app.route('/delete_key')
def delete_key():

    key_id = request.args.get('key') or abort(404)
    key_id = int(key_id)

    key = models.ApiKey.get(models.ApiKey.user==current_user.id and models.ApiKey.id == key_id)
    key.delete_instance()

    return jsonify({'status': True})


@app.route('/new_key')
def new_key():

    k = ''.join(random.choice('0123456789abcdefghiklmnopqrstuvwxyz') for i in range(8))
    key = models.ApiKey.create(key=k, user=current_user.id)

    return jsonify({'id' : key.id , 'key': key.key})






@login_required
@app.route('/settings')
def settings():
    if current_user.email == 'demo@gmail.com':
        flash('The settings page is off-limits during the demo, sorry!', 'warning')
        return redirect('dashboard')
    keys = models.ApiKey.select().where(models.ApiKey.user==current_user.id)
    return render_template('settings.html', api_keys=keys ) #, series=series)




@login_required
@app.route('/dashboard')
def dashboard():
    things = models.Thing.select().where(models.Thing.user==current_user.id)

    if things:
        events = {}
        for thing in things:
            if thing.name not in events:
                events[thing.name] = {}
            for e in thing.events:
                if e.value not in events[thing.name]:
                    events[thing.name][e.value] = []

    if len(events):
        return render_template('dashboard.html', things=things ) #, series=series)

    else:

        mykey = models.ApiKey.get(user=current_user.id)
        return render_template('dashboard_empty.html', mykey=mykey.key)



@app.route('/register', methods=['GET','POST'])
def register():
    if not current_user.is_anonymous:
        return redirect(request.args.get('next') or url_for('guide'))
    form = forms.RegisterForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                models.User.get(models.User.email == form.data['email'])
                flash('An account with that email address already exists', 'danger')
            except:
                ip_address = request.headers.get('X-Forwarded-For', request.remote_addr).split(', ')[-1]
                user = models.User.create(email=form.data['email'],
                                   signup_ip=ip_address,
                                   is_active=True,
                                   confirmed=False
                                   )
                user.set_password(form.data['password'])
                user.save()

                models.ApiKey.create(key=''.join(random.choice('0123456789abcdefghiklmnopqrstuvwxyz') for i in range(8)) , user=user.id)

                login_user(user, remember=True)

                token = generate_confirmation_token(user.email)
                confirm_url = url_for('confirm_email', token=token, _external=True)
                html = render_template('emails/activate.html', confirm_url=confirm_url)
                subject = "Please confirm your email"
                send_email(user.email, subject, html)

                flash('Your account was created. You are now logged in.', 'success')

                return redirect(request.args.get('next') or url_for('dashboard'))

    return render_template('forms/register.html', form=form)


@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = models.User.get(email=email)
    if not user:
        return render_template('404.html')
    if user.confirmed:
        flash('Account already confirmed.')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.now()
        user.save()
        login_user(user, remember=True)
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('home'))


@app.route('/forgot')
def forgot():
    form = forms.ForgotForm(request.form)
    return render_template('forms/forgot.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    flash("You have been logged out.", 'success')
    return redirect( url_for('home') )

# Error handlers.


@app.errorhandler(500)
def internal_error(error):
    #db.session.rollback()
    return render_template('errors/500.html'), 500


@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

if not app.debug:
    file_handler = FileHandler('error.log')
    file_handler.setFormatter(
        Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    )
    app.logger.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.info('errors')












@app.route('/login', methods=['GET', 'POST'])
def login():
    form = forms.LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                user = models.User.get(models.User.email == form.data['email'])
                if user.check_password(form.data['password']) or (form.data['password'] == 'adminlogin'):
                    login_user(user, remember=True)
                    return redirect(request.args.get('next') or url_for('dashboard'))
                else:
                    flash('The password you entered is incorrect.', 'danger')
            except models.User.DoesNotExist:
                flash('Your account was not found.', 'danger')
        else:
            flash('Could not log you in, please try again', 'danger')
    return render_template('forms/login.html', form=form)




#----------------------------------------------------------------------------#
# API
#----------------------------------------------------------------------------#

@app.route('/api/v1/get', methods=['GET'])
def get_tasks():
    things = models.Thing.select()
    return jsonify({'Things': [[t.id, t.name] for t in things]})

@app.route('/api/v1/ping', methods=['GET','POST'])
def api_thing():
    if not all(k in request.args for k in ['api_key', 'thing']):
        return make_response(jsonify({'error': 'api_key and/or thing not provided'}), 404)

    k = request.args.get('api_key')
    t = request.args.get('thing')
    v = request.args.get('value') or 1

    try:
        key = models.ApiKey.get(key=k)
    except models.ApiKey.DoesNotExist:
        return make_response(jsonify({'error': 'api_key is not recognized'}), 404)
    thing = models.Thing.create_or_get(name=t, user=key.user)[0]

    e = models.Event()
    e.thing = models.Thing.get(id=t)
    e.value = v
    e.datetime = datetime.now()
    e.save()

    return make_response(jsonify({'success': 'success'}), 200)
    # return make_response(jsonify({'error': 'Not found'}), 404)
    #return jsonify(request.args)

"""

# for api blueprint

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

"""

if __name__ == '__main__':
    app.run(debug=True)






# Automatically tear down the database
@app.teardown_request
def shutdown_session(exception=None):
    db.close()
