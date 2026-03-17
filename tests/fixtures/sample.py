from flask import request, jsonify
from models import User

class UserService:
    def get_user(self, user_id):
        user = User.query.get(user_id)
        return user

    def delete_user(self, user_id):
        user = User.query.get(user_id)
        user.delete()

def validate_input(data):
    return isinstance(data, str) and len(data) > 0
