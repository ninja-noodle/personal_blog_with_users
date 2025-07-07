from io import BytesIO
from dotenv import load_dotenv
from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, send_file
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
import pydenticon
import hashlib
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


app = Flask(__name__)
load_dotenv("/.venv/.env")
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)

Bootstrap5(app)

login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)


def check_if_exists(email):
    if db.session.execute(db.select(User).where(User.email == email)).first() is None:
        return False
    elif db.session.execute(db.select(User).where(User.email == email)).first() is not None:
        return True


def login_check(email, password):
    user_check = db.session.execute(db.select(User).where(User.email == email)).scalar()
    if user_check is None:
        return 'false_email'
    elif user_check is not None and check_password_hash(user_check.password, password) is False:
        return 'false_password'
    elif user_check is not None and check_password_hash(user_check.password, password) is True:
        return 'true'
    return None


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.get_id() != '1':
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates='posts')

    comments = relationship("Comment", back_populates='original_post')

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    original_post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))

    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


# avatar generator
generator = pydenticon.Generator(5, 5, digest=hashlib.sha1, 
    foreground=["#1abc9c", "#2ecc71", "#3498db", "#9b59b6", "#34495e"],
    background="#ecf0f1")


@app.route('/avatar/<username>.png')
def avatar(username):
    image = generator.generate(username, 30, 30, output_format="png")
    return send_file(BytesIO(image), mimetype='image/png')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        entered_email = register_form.data["email"]
        entered_password = generate_password_hash(register_form.data["password"], method='pbkdf2:sha256',
                                                  salt_length=10)
        entered_name = register_form.data["name"]

        if check_if_exists(entered_email):
            flash("You've already signed up with that email, log in instead.", 'error')
            return redirect(url_for('login'))

        elif not check_if_exists(entered_email):
            new_user = User(
                email=entered_email,
                password=entered_password,
                name=entered_name,
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=register_form)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        entered_email = login_form.data["email"]
        entered_password = login_form.data["password"]
        response = login_check(entered_email, entered_password)
        if response == 'true':
            user = db.session.execute(db.select(User).where(User.email == entered_email)).scalar()
            login_user(user)
            return redirect(url_for('get_all_posts'))

        elif response == 'false_email':
            flash("That email doesn't exist. Please try again.", 'error')

        elif response == 'false_password':
            flash("Password incorrect. Please try again.", 'error')

    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.", "error")
            return redirect(url_for('login'))
        elif current_user.is_authenticated:
            new_comment = Comment(
                text=comment_form.comment.data,
                comment_author=current_user,
                original_post=requested_post,
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, form=comment_form, comments=requested_post.comments)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False)
