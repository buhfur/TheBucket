#final draft for the bucketlist app
#Ryan McVicker

from flask import Flask, render_template,redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,BooleanField
from wtforms.validators import InputRequired,Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
Bootstrap(app)

app.config['SECRET_KEY'] = 'mynewsecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///newone.db'
db = SQLAlchemy(app)
login_manager = LoginManager() #manages user sessions
login_manager.init_app(app)#starts the process of flask login
login_manager.login_view = 'login'#route where user logs in
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50),unique=True)
    password = db.Column(db.String(80))

#at the add idea page
class BucketList(db.Model):
    id = db.Column(db.Integer,primary_key=True,nullable=False)
    username = db.Column(db.String(80))
    idea_name = db.Column(db.String(80),unique=True)
    idea_desc = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):#connection between the datbase and flask-login
    return User.query.get(int(user_id)) #i dont know what this does









class LoginForm(FlaskForm):
    username= StringField('username',validators=[InputRequired(),Length(min=4,max=15)])
    password= PasswordField('password',validators=[InputRequired(),Length(min=8,max=80)])
    #remember me checkbox
    remember = BooleanField('remember me')



class RegisterForm(FlaskForm):
    email = StringField('email',validators=[InputRequired(), Email(message='Invalid email'),
    Length(max=50)])
    username= StringField('username',validators=[InputRequired(),Length(min=4,max=15)])
    password= PasswordField('password',validators=[InputRequired(),Length(min=8,max=80)])



class NewIdea(FlaskForm):
    idea_name = StringField('name',validators=[InputRequired(),Length(min=4)])
    idea_desc = StringField('description',validators=[InputRequired(),Length(min=4)])




@app.route('/')
def index():

    return render_template('index.html')


@app.route('/login',methods=['POST','GET'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        #return '<h1> {} , {}</h1>'.format(form.username.data,form.password.data)
        #check to make sure password matches the users registered password
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                #redirect to the dashboard
                #first login the user
                login_user(user, remember=form.remember.data)
                return redirect(url_for("dashboard"))

        return "Invalid username or password"


    return render_template('login.html',form=form)






@app.route('/signup',methods=['GET','POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        #return "<h1> {}, {}</h1>".format(form.username.data,form.email.data)
        #put data into database
        #hash the password
        hashed_password = generate_password_hash(form.password.data, method='sha256')#must be 80 characters long
        new_user = User(username=form.username.data,
        email=form.email.data,password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        return redirect('/')



    return render_template('signup.html',form=form)


@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():

    logout_user()
    return redirect('/') #takes them to the homepage

#page for logged in users to add ideas
#should redirect to a page titled myideas
@app.route('/idea',methods=['GET','POST'])
def idea():
    form = NewIdea()
    if form.validate_on_submit():
        #add the idea to the database
        new_idea = BucketList(username=current_user.username,
        idea_name = form.idea_name.data,
        idea_desc=form.idea_desc.data)

        db.session.add(new_idea)
        db.session.commit()#saves the changes to the table
        return redirect('/dashboard')


    return render_template('idea.html',form=form)

@app.route('/mylist')
def mylist():
    data = BucketList.query.filter_by(username=current_user.username)
    return render_template('mylist.html',results=data)#query data out of database



if __name__ == '__main__':
    db.create_all()
    app.run()
