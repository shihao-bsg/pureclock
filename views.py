import os
from datetime import datetime
from flask import render_template, url_for, request, redirect, flash, session, abort
from flask_login import login_required, login_user, logout_user, current_user

from __init__ import app, db, login_manager, google, REDIRECT_URI
from forms import BookmarkForm, LoginForm, SignupForm, SetUsernameForm
#from models import User, Bookmark
import models
import json

@login_manager.user_loader
def load_user(userid):
    return models.User.query.get(int(userid))

def helper(access_token):
    access_token = session.get('access_token')
    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError

    headers = {'Authorization': 'OAuth ' + access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                  None, headers)
    res = urlopen(req)
    email = json.loads(res.read())['email']
    return email, res
@app.route('/')
@app.route('/index')
def index():
    access_token = session.get('access_token')
    if access_token is None:

        return redirect(url_for('login'))

    #access_token = access_token[0]
    #from urllib2 import Request, urlopen, URLError

    #headers = {'Authorization': 'OAuth '+access_token}
    #req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
    #              None, headers)
    try:
        from urllib2 import URLError
        emm, res = helper(access_token)
        tempUser = models.User.query.filter_by(email=emm).first()
        if tempUser:
            if tempUser.authority == 0:
                return render_template('verifing2.html')
            else:
                user = models.User.get_by_email(emm)
                if user is not None:
                    login_user(user)
                    #current_user.is_authenticated = True
                    flash("logged in successfully as {}".format(user.username))
                    return redirect(request.args.get('next') or url_for('user', username=user.username))
        #else:
        #    return redirect(url_for('accessVerify', email=emm))
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('access_token', None)
            return redirect(url_for('login'))
        return res.read()
    return render_template('index.html', new_bookmarks=models.Bookmark.newest(5))
    #return res.read()



@app.route('/o')
@app.route('/oindex')
def oindex():
    return render_template("index.html", new_bookmarks=models.Bookmark.newest(5))


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    form = BookmarkForm()
    if form.validate_on_submit():
        task = form.task.data
        description = form.description.data
        time = form.time.data
        company = form.company.data
        workdate = form.workdate.data
        bm = models.Bookmark(user=current_user, task=task, description=description, time=time, company=company, workdate=workdate)

        db.session.add(bm)
        db.session.commit()
        # app.logger.debug('stored url: ' + url)
        flash("stored '{}' ".format(description))
        return redirect(url_for('index'))
    return render_template("add.html", form=form)


@app.route('/edit/<int:bookmark_id>', methods=['GET','POST'])
@login_required
def edit_bookmark(bookmark_id):
    bookmark = models.Bookmark.query.get_or_404(bookmark_id)
    if current_user != bookmark.user:
        abort(403)
    form = BookmarkForm(obj=bookmark)
    if form.validate_on_submit():
        form.populate_obj(bookmark)
        db.session.commit()
        flash("Stored '{}'".format(bookmark.description))
        return redirect(url_for('user', username=current_user.username))
    return render_template('record_form.html', form=form, title="Edit Record")

@app.route('/approve/<int:application_id>', methods=['GET','POST'])
@login_required
def approve(application_id):
    application = models.User.query.get_or_404(application_id)
    #set authority to 1
    application.authority=1
    db.session.commit()
    applications = models.User.query.filter_by(authority=0)
    flash("'{}' is approved".format(application.username))
    return redirect(url_for('admin', user=current_user,applications=applications,new_bookmarks=models.Bookmark.newest(10)))


@app.route('/user/<username>')
def user(username):
    user = models.User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=user)


@app.route('/admin/<user>')
def admin(user):
    #admin = models.User.query.filter_by(username=username).first_or_404()
    applications = models.User.query.filter_by(authority=0)
    return render_template('admin.html', user=user, applications=applications,new_bookmarks=models.Bookmark.newest(10))


@app.route('/userlogin')
def userlogin():
    callback = url_for('authorized', _external=True)

    return google.authorize(callback=callback)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # login and validate the user...
        user = models.User.get_by_username(form.username.data)
        applications = models.User.query.filter_by(authority=0)
        if user is not None and user.check_password(form.password.data):
            login_user(user, form.remember_me.data)
            flash("logged in successfully as {}".format(user.username))
            if user.authority == 2:
                return redirect(request.args.get('next') or url_for('admin', user=user, applications=applications,new_bookmarks=models.Bookmark.newest(10)))
            if user.authority == 1:
                return redirect(url_for('user', username=user.username))
        flash('Incorrect username or password.')
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('index'))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = models.User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Welcome, {}! Please login.".format(user.username))
        return redirect(url_for('login'))
    return render_template("signup.html", form=form)

@app.route('/accessverify/<email>', methods=['GET', 'POST'])
def accessVerify(email):
    form = SetUsernameForm()
    if form.validate_on_submit():
        user_0 = models.User(username=form.username.data, authority=0, email=email, password=form.password.data)
        db.session.add(user_0)
        db.session.commit()
        flash("Your request is accepted")
        return render_template('verifing2.html')
    return render_template('verifing.html', form=form)

@app.route(REDIRECT_URI, methods=['GET', 'POST'])
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    e, res = helper(access_token)
    #flash("logged in successfully as {}".format(user.username))
    #return redirect(request.args.get('next') or url_for('user', username=user.username))
    user=models.User.get_by_email(e)
    login_user(user)
    if not user:
        return redirect(url_for('accessVerify', email=e))
    elif user.authority==1:
        return redirect(request.args.get('next') or url_for('user', username=user.username))
    else:
        return render_template('verifing2.html')

@google.tokengetter
def get_access_token():
    print session.get('access_token')
    return session.get('access_token')


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500


if __name__ == '__main__':
    app.run()
