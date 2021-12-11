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
    user["nick_name"] = data.get("nick_name", None)
    user["full_name"] = data.get("full_name", None)
    user["email"] = data.get("email", None)
    user["is_admin"] = data.get("is_admin", False)
    user["profile_image"] = data.get("profile_image", None)
    return user


def update_user(data: dict, sub: str):
    for_update = User.objects.filter(sub=sub)
    if len(for_update) > 0:
        if data["nick_name"]:
            for_update.update(nick_name=data["nick_name"])
        if data["full_name"]:
            for_update.update(full_name=data["full_name"])
        if data["email"]:
            for_update.update(email=data["email"])
        if data["profile_image"]:
            for_update.update(profile_image=data["profile_image"])


def formatting_user_response(user: User):
    # user = model_to_dict(user, fields=["sub", "nick_name", "full_name", "email", "creation_at", "profile_image"])
    user = model_to_dict(user)
    return json.dumps(user)
