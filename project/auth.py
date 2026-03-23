from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash

from flask_security import login_required
from flask_security.utils import login_user, logout_user

from .models import User
from . import db, user_datastore

from flask import current_app

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
        current_app.logger.warning(f'Intento de acceso fallido para: {email}')
        flash('El email o la contraseña son incorrectos')
        return redirect(url_for('auth.login'))
    
    # Creamos una sesioin y logueamos al usuario
    login_user(user, remember=remember)
    current_app.logger.info(f'Acceso exitoso: ID {user.id} - {user.email}')
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
        current_app.logger.warning(f'Intento de registro fallido para: {email}')    
        flash('El correo electronico ya esta registrado')
        return redirect(url_for('auth.register'))
    
    nuevo_usuario = user_datastore.create_user(name=name, email=email, 
                               password=generate_password_hash(password, method='pbkdf2:sha256'))
    
    user_datastore.add_role_to_user(nuevo_usuario, 'end-user')
    
    db.session.commit()
    current_app.logger.info(f'Registro exitoso para: {email}')
    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    # Cerramos sesion
    logout_user()
    return redirect(url_for('main.index'))