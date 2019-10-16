import os
from datetime import datetime
from flask import render_template, url_for, request, redirect, flash
from flask_login import login_required, login_user, logout_user, current_user

from __init__ import app, db, login_manager
from forms import BookmarkForm, LoginForm, SignupForm
# from models import User, Bookmark
import models


@login_manager.user_loader
def load_user(userid):
    return models.User.query.get(int(userid))


@app.route('/')
@app.route('/index')
def index():
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


@app.route('/user/<username>')
def user(username):
    user = models.User.query.filter_by(username=username).first_or_404()
    return render_template('user.html', user=user)


@app.route('/admin/<username>')
def admin(username):
    admin = models.User.query.filter_by(username=username).first_or_404()
    return render_template('admin.html', user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # login and validate the user...
        user = models.User.get_by_username(form.username.data)
        if user is not None and user.check_password(form.password.data):
            login_user(user, form.remember_me.data)
            flash("logged in successfully as {}".format(user.username))
            return redirect(request.args.get('next') or url_for('user', username=user.username))
        flash('Incorrect username or password.')
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        user = models.User(email=form.email.data,username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Welcome, {}! Please login.".format(user.username))
        return redirect(url_for('login'))
    return render_template("signup.html", form=form)


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500


if __name__ == '__main__':
    app.run()
