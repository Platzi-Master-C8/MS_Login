from django.contrib.auth import authenticate
from django.forms.models import model_to_dict
from authentication.models import User

import json
import jwt
import requests
import environ


env = environ.Env()
environ.Env.read_env()


def jwt_decode_token(token):
    header = jwt.get_unverified_header(token)
    jwks = requests.get('https://{}/.well-known/jwks.json'.format(env('ISSUER'))).json()
    public_key = None
    for jwk in jwks['keys']:
        if jwk['kid'] == header['kid']:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

    if public_key is None:
        raise Exception('Public key not found.')

    issuer = 'https://{}/'.format(env('ISSUER'))
    return jwt.decode(token, public_key, audience=env('JWT_AUDIENCE'), issuer=issuer, algorithms=['RS256'])


def jwt_get_username_from_payload_handler(payload):
    username = payload.get('sub').replace('|', '.')
    authenticate(remote_user=username)
    return username


def get_user_data(data: dict) -> dict:
    user = {}
    user["username"] = data.get("username", None)
    user["full_name"] = data.get("full_name", None)
    user["email"] = data.get("email", None)
    user["profile_img"] = data.get("profile_img", None)
    user["sub"] = data.get("sub", None)
    return user


def update_user(data: dict):
    for_update = User.objects.filter(sub=data["sub"])
    if data["username"]:
        for_update.update(username=data["username"])
    if data["full_name"]:
        for_update.update(full_name=data["full_name"])
    if data["email"]:
        for_update.update(email=data["email"])
    if data["profile_img"]:
        for_update.update(profile_img=data["profile_img"])


def formatting_user_response(user: User):
    user = model_to_dict(user, fields=["username", "full_name", "email", "creation_date", "profile_img"])
    return json.dumps(user)
