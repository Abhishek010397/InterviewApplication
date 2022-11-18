from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired, EqualTo
from flask_wtf import FlaskForm
from Interview.models import User

class RegistrationForm(FlaskForm):

    username=StringField("Username",validators=[InputRequired(),Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField("Password",validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    confirm_password = PasswordField("Confirm Password",validators=[InputRequired(), Length(min=4, max=20),EqualTo('password')], render_kw={"placeholder": "Confirm Password"})
    role= StringField(validators=[InputRequired(),Length(min=4, max=20)])
    submit=SubmitField("Register")

    def validate_username(self,username):
        existing_username=User.query.filter_by(username=username.data).first()
        if existing_username:
            raise ValidationError("Username Already Exists!")

class LoginForm(FlaskForm):
    username=StringField(validators=[InputRequired(),Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    remember=BooleanField('Remember Me')
    submit=SubmitField("Login")

class UpdateForm(FlaskForm):
    username=StringField("Username",validators=[InputRequired(),Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField("Password",validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    role= StringField(validators=[InputRequired(),Length(min=4, max=20)])
    submit=SubmitField("Update")

    def validate_username(self,username):
        existing_username=User.query.filter_by(username=username.data).first()
        if existing_username:
            raise ValidationError("Username Already Exists!")