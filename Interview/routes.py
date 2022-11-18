from flask import render_template,url_for,redirect, flash, session,request
from Interview import app, db, bcrypt
from Interview.forms import LoginForm,RegistrationForm,UpdateForm
from Interview.models import User
from flask_login import login_user, login_required, logout_user,current_user
import datetime
import boto3
import json

iam = boto3.resource('iam')
client = boto3.client('iam')

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/error404')
def error404():
    return render_template('error404.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if  current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        missing = User.query.filter_by(username=form.username.data).first()
        if missing is None:
            flash('User Not Registered','danger')
        else:
            if bcrypt.check_password_hash(user.password, form.password.data):
                flash(f'{form.username.data} Logged in Successfully!','success')
                login_user(user)
                session.permanent = True
                return redirect(url_for('dashboard'))
            else:
                flash('Login Unsuccessful, Please Check Your Username or Password','danger')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    flash(f'Logged out  Successfully!','success')
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET','POST'])
def dashboard():
    if current_user.is_authenticated:
        return render_template('sample.html')
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    
    if not current_user.role=="admin":
        return redirect(url_for('login'))
    form=RegistrationForm()
    
    if form.validate_on_submit():
        hashed_password= bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password,role=form.role.data)
        db.session.add(new_user)
        db.session.commit()
        flash(f'{form.username.data} Registered Successfully!','success')
        return redirect(url_for('register'))

    return render_template('register.html', form=form)

@app.route('/update', methods=['GET', 'POST'])
def update():
    if  not current_user.is_authenticated:
        return render_template('logout')
    form = UpdateForm()
    user_id = current_user.id
    assigned_role = current_user.role
    user = User.query.filter_by(id=user_id).first()
    if request.method == 'POST':
        if user:
            db.session.delete(user)
            db.session.commit()
            if form.submit():
                username = form.username.data
                password = bcrypt.generate_password_hash(form.password.data)
                update_user = User(id=user_id, username=username, password=password, role=assigned_role)
                db.session.add(update_user)
                db.session.commit()
                flash('Update Successful!!')
                return redirect(url_for('logout'))

    return render_template('update.html', form=form,user=user)


@app.route('/all')
def retrieveuserlist():
    if current_user.role == 'admin':
        users = User.query.all()
        return render_template('user.html',users=users)

@app.route('/edit/<int:id>',methods=['GET', 'POST'])
def edit(id):
    if not  current_user.role == 'admin' :
        return redirect(url_for('logout'))
    user=User.query.filter_by(id=id).first()
    user_password=user.password
    form=UpdateForm()
    if request.method == 'POST':
        print("edit,inside of post")
        if user:
            db.session.delete(user)
            db.session.commit()
            if form.submit():
                username=request.form['name']
                password=request.form['password']
                if password == user_password:
                    role=form.role.data
                    updated_user=User(id=id,username=username,password=password,role=role)
                    db.session.add(updated_user)
                    db.session.commit()
                    flash(f'User Has Been Updated','success')
                    return redirect(f'/edit/{id}')
                else:
                    print('Unmatched')
                    role = form.role.data
                    updated_user = User(id=id, username=username, password=bcrypt.generate_password_hash(password),role=role)
                    db.session.add(updated_user)
                    db.session.commit()
                    flash(f'User Has Been updated','success')
                    return redirect(f'/edit/{id}')
    return render_template('edit.html', form=form)


@app.route('/delete/<int:id>')
def delete(id):
    if not current_user.role == 'admin':
        return redirect(url_for('logout'))
    user=User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User Has Been Deleted','danger')
    return redirect(url_for('retrieveuserlist'))

@app.route('/task')
def task():
    if current_user.is_authenticated:
        return render_template('task.html')

@app.route('/get_arn', methods=["GET","POST"])
def get_arn():
    if current_user.is_authenticated:
        id = current_user.id
        user = User.query.filter_by(id=id).first()
        role_name = user.username
        role_name = role_name+'Role'
        assume_role_policy_document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        })
        roles = client.list_roles()
        Roles = roles['Roles']
        res = [key for key in Roles if(key['RoleName'] in role_name)]
        print(str(bool(res)))
        if str(bool(res)) == 'True':
            for key in Roles:
                if key['RoleName'] == role_name:
                    role_arn = key['Arn']
                    messages = [{'RoleArn': role_arn}]
        if str(bool(res)) == 'False':
            role_resp = iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=assume_role_policy_document
            )
            print("Role Created")
            role_arn = role_resp.arn
            messages = [{'RoleArn': role_arn}]
        return render_template('task.html',messages = messages)




