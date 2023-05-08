import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort
from flaskblog import app, db, bcrypt
from flaskblog.forms import RegistrationForm, LoginForm, UpdateAccountForm, PostForm ,PostForm2
from flaskblog.models import User, PostMissing ,PostFinding
from flask_login import login_user, current_user, logout_user, login_required


@app.route("/")
@app.route("/home")
def home():
    db.create_all()
    posts = PostMissing.query.all()
    return render_template('home.html')

@app.route("/missing")
def missing():
    db.create_all()
    posts = PostMissing.query.all()
    return render_template('missing.html', posts=posts)

@app.route("/finding")
def finding():
    db.create_all()
    posts = PostFinding.query.all()
    return render_template('finding.html', posts=posts)


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    db.create_all()
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    db.create_all()
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    db.create_all()
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)


@app.route("/postMissing", methods=['GET', 'POST'])
@login_required
def new_post():
    db.create_all()
    form = PostForm()
    if form.validate_on_submit():
        post = PostMissing(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('missing'))
    return render_template('create_post_missing.html', title='New Post',
                        form=form, legend='New Post')

@app.route("/postFinding", methods=['GET', 'POST'])
@login_required
def new_post_2():
    db.create_all()
    form = PostForm2()
    if form.validate_on_submit():
        post = PostFinding(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('finding'))
    return render_template('create_post_finding.html', title='New Post',
                        form=form, legend='New Post')

@app.route("/postMissing/<int:post_id>")
def post(post_id):
    post = PostMissing.query.get_or_404(post_id)
    print(post)
    return render_template('post_missing.html', title=post.title, post=post)


@app.route("/postFinding/<int:post_id>")
def post2(post_id):
    post = PostFinding.query.get_or_404(post_id)
    print(post)
    return render_template('post_finding.html', title=post.title, post=post)



@app.route("/postMissing/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post_missing(post_id):
    post = PostMissing.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post_missing.html', title='Update Post',
                           form=form, legend='Update Post')


@app.route("/postFinding/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post_finding(post_id):
    post = PostFinding.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm2()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post2', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post_missing.html', title='Update Post',
                           form=form, legend='Update Post')





@app.route("/postMissing/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post_missing(post_id):
    post = PostMissing.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))


@app.route("/postFinding/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post_finding(post_id):
    post = PostFinding.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))
