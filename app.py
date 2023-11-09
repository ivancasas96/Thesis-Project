from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
from flask_bcrypt import Bcrypt
from datetime import datetime
from wtforms.widgets import TextArea
from flask import flash
from flask_wtf.file import FileField, FileAllowed
from flask import send_from_directory
import os 
from werkzeug.utils import secure_filename
from sqlalchemy.dialects.postgresql import BYTEA    
import os
import uuid
import time


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'images')
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

#Create a blog post model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(220))
    description = db.Column(db.Text)
    author = db.Column(db.String(250))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    price = db.Column(db.String(250))
    image_filename = db.Column(db.String(250))

# Create a Posts Form 
class PostForm(FlaskForm):
    address = StringField("Address", validators=[DataRequired()] )
    description  = StringField("Description", validators=[DataRequired()]) 
    author = StringField("Author", validators=[DataRequired()])
    price = StringField("Price", validators=[DataRequired()])
    image = FileField("Image", validators= [FileAllowed(['jpg','jpeg','png','gif'])])
    submit = SubmitField("Submit", validators=[DataRequired()])
    

# Add Post Page
@app.route('/add_post', methods=['GET', 'POST'])
def add_post():
    form = PostForm()

    if form.validate_on_submit():
        start_time = time.time()
        if form.image.data:
            image = form.image.data
            filename = secure_filename(image.filename)
            unique_filename = f"{uuid.uuid4().hex}.jpg"  # Generate a unique filename with .jpg extension
            print("Generated unique filename:", unique_filename)

            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            print("File path:", file_path)
            print(app.config['UPLOAD_FOLDER'])


            image.save(file_path)
        else:
            unique_filename = None

        post = Posts(
            address=form.address.data,
            description=form.description.data,
            author=form.author.data,
            price=form.price.data,
            image_filename=unique_filename  # Save the unique filename in the database
        )

        print("Form Address:", form.address.data)
        print("Form Description:", form.description.data)
        print("Form Author:", form.author.data)
        print("Form Price:", form.price.data)
        print("Form Image:", form.image.data)

        # Clear The Form
        form.address.data = ''
        form.description.data = ''
        form.author.data = ''
        form.price.data = ''
        form.image.data = None

        # Add Post data to the database
        db.session.add(post)
        db.session.commit()

        # Return a Message
        flash("Blog Post Submitted Successfully", "success")

        #Elapsed time
        elapsed_time = time.time() - start_time
        print(f"Time taken to register a post: {elapsed_time:.5f} seconds")

        # Redirect to the blog_post.html page with the new post's slug as a parameter
        return redirect(url_for('blog_post', price=post.price))

    return render_template("add_post.html", form=form)

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[InputRequired()])
    new_password = PasswordField('New Password', validators=[InputRequired(), Length(min=8, max=20)])
    confirm_new_password = PasswordField('Confirm New Password', validators=[InputRequired(), Length(min=8, max=20)])
    submit = SubmitField('Change Password')


@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template('index.html')

@app.route('/blog_post', methods=['GET'])
def blog_post():
    # Fetch all the blog posts from the database
    all_posts = Posts.query.all()

    # Render the blog_post.html template with the fetched posts
    return render_template('blog_post.html', posts=all_posts)
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    change_password_form = ChangePasswordForm()  # Create an instance of the form

    if change_password_form.validate_on_submit():
        user = current_user

        if bcrypt.check_password_hash(user.password, change_password_form.current_password.data):
            if change_password_form.new_password.data == change_password_form.confirm_new_password.data:
                hashed_password = bcrypt.generate_password_hash(change_password_form.new_password.data)
                user.password = hashed_password
                db.session.commit()
                flash('Password changed successfully!', 'success')
            else:
                flash('New passwords do not match.', 'danger')
        else:
            flash('Current password is incorrect.', 'danger')

        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', change_password_form=change_password_form)  # Pass the form to the template context
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()


    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/static/<path:filename>')
def serve_static(filename):
    root_dir = os.path.dirname(os.getcwd())
    return send_from_directory(os.path.join(root_dir, 'static'), filename)



if __name__ == "__main__":
    # Set up the application context before creating the database tables
    with app.app_context():
        db.create_all()
        app.run(debug = True, host='0.0.0.0', port=5050)

