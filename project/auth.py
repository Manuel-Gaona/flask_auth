from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash

from flask_security import login_required
from flask_security.utils import login_user, logout_user

from .models import User
from . import db, user_datastore

# Creamos el blueprint con un prefijo /security
auth = Blueprint('auth', __name__, url_prefix='/security')

@auth.route('/login')
def login():
    return render_template('/security/login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False
    
    user = User.query.filter_by(email=email).first()
    
    #Verificamos datos y si el usuario existe
    if not user or not check_password_hash(user.password, password):
        # Error loguin no valido
        flash('El email o la contraseña son incorrectos')
        return redirect(url_for('auth.login'))
    
    # Creamos una sesioin y logueamos al usuario
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/register')
def register():
    return render_template('/security/register.html')

@auth.route('/register', methods=['POST'])
def register_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    
    # Verificamos si existe un usuario con ese email
    user = User.query.filter_by(email=email).first()
    
    if user:
        flash('El correo electronico ya esta registrado')
        return redirect(url_for('auth.register'))
    
    user_datastore.create_user(name=name, email=email, 
                               password=generate_password_hash(password, method='pbkdf2:sha256'))
    
    db.session.commit()
    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    # Cerramos sesion
    logout_user()
    return redirect(url_for('main.index'))