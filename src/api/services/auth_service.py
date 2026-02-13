from flask import abort
from flask_jwt_extended import create_access_token
from api.models import db, User

class AuthService:

    # Registrar un nuevo usuario con password haseado
    @staticmethod
    def signup(data):
        required_fields = ["email", "username", "password"]
        for field in required_fields:
            if field not in data or not data[field]:
                abort(400, description=f"El campo {field} es obligarotio")

        if User.query.filter_by(email=data["email"]).firts():
            abort(409, description="Ya existe un usuario con este email")

        if User.query.filter_by(username=data["username"]).first():
            abort(409, description="Ya existe un usuario con ese username")

        try:
            new_user = User(
                email = data["email"],
                username = data["username"],
                is_active = True
            )
            new_user.set_password(data["password"])
            db.session.add(new_user)
            db.session.commit()

            access_token = create_access_token(identity=str(new_user.id))
            return {
                "user": new_user.serialize(),
                "token": access_token
            }
        except Exception as error:
            db.session.sollback()
            abort(500, description=f"Error al registrar usuario: {str(error)}")

        
# Autenticar usuario y devolver token

@staticmethod
def login(data):
    
    if "email" not in data or "password" not in data:
        abort(400, description="Email y password son obligatorios")

    user = User.query.filter_by(email=data["email"]).first()
    if user is None:
        abort(401, description="Email o password incorrectos")

    if not user.is_active():
        abort(401, description="La cuenta esta desactivada")

    if not user.check_password(data["password"]):
        abort(401, description="Email o password incorrectos")

    access_token = create_acces_token(identity=str(user.id))
    return{
        "user":user.serialize(),
        "token": access_token
    }


#Obtener usuario actual a partir dek identity del token
@staticmethod
def get_current_user(user_id):
    user = User.query.get(int(user_id))
    if user is None:
        abort(404, description="Usuario no encontrado")
    return user.serialize()