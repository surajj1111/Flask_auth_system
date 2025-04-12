from flask import Flask, render_template, url_for, redirect, flash
from flask_wtf import FlaskForm 
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)  # ✅ Flask App Initialize

# ✅ Configurations
app.config['SECRET_KEY'] = 'mysecretkey'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Agar unauthorized user ho to login page pe redirect hoga


# ✅ Database Model
class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # ID se user ko database se laayega

# ✅ Registration Form
class RegistrationForm(FlaskForm):
    username = StringField("username", validators=[DataRequired(), Length(min=3, max=20)])
    email = EmailField("email", validators=[DataRequired(), Email()])
    password = PasswordField("password", validators=[DataRequired(), Length(min=6)])
    confirmpassword = PasswordField("confirmpassword", validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    
class loginform(FlaskForm):
    email = EmailField("email", validators=[DataRequired(), Email()])
    password = PasswordField("password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')


# ✅ Route for Register
@app.route('/', methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        print("✅ Form submitted and validated")
        
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered! Try logging in.", "danger")
            return redirect(url_for('register'))
        hash_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, email=form.email.data, password=hash_password)  # ✅ FIXED
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('REGISTRATION SUCCESSFUL! NOW YOU CAN LOGIN', "success")
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

# ✅ Route for Login
@app.route('/login', methods=['GET','POST'])
def login():
    
    form = loginform()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login Successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Failed! Check email and password.', 'danger')
        
    
    return render_template('login.html', form=form)

#Route for Dashboard ✅
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html',username=current_user.username)


#Route for Logout ✅
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out!", "info")
    return redirect(url_for('login'))

@app.route('/navbar')
@login_required
def navbar():
    return render_template('navbar.html')

# ✅ Creating Database Tables
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
