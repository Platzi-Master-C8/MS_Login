from django.forms.models import model_to_dict
from authentication.models import User

import json
import requests
import environ


env = environ.Env()
environ.Env.read_env()


def get_user_data(authorization_header, data: dict = {}) -> dict:
    headers_dict = {"Authorization": "{}".format(authorization_header)}
    payload = requests.get('https://{}/userinfo'.format(env('ISSUER')), headers=headers_dict).content
    payload = json.loads(payload)
    payload = {**payload, **data}
    return map_user(payload)


def map_user(data: dict) -> dict:
    user = {}

    if not data.get("sub", None):
        raise Exception("Bad Token: Not sub")
    user["sub"] = data["sub"]

    user["nick_name"] = data.get("nick_name", None)
    if not user["nick_name"]:
        user["nick_name"] = data.get("nickname", None)

    user["full_name"] = data.get("full_name", None)
    if not user["full_name"]:
        user["full_name"] = data.get("name", None)

    user["email"] = data.get("email", None)
    user["is_admin"] = data.get("is_admin", False)

    user["profile_image"] = data.get("profile_image", None)
    if not user["profile_image"]:
        user["profile_image"] = data.get("picture", None)

    return user


def update_user(new_data: dict, sub: str):
    for_update = User.objects.filter(sub=sub)
    if len(for_update) > 0:
        if new_data["nick_name"]:
            for_update.update(nick_name=new_data["nick_name"])
        if new_data["full_name"]:
            for_update.update(full_name=new_data["full_name"])
        if new_data["email"]:
            for_update.update(email=new_data["email"])
        if new_data["profile_image"]:
            for_update.update(profile_image=new_data["profile_image"])


def formatting_user_response(user: User):
    # user = model_to_dict(user, fields=["sub", "nick_name", "full_name", "email", "creation_at", "profile_image"])
    user = model_to_dict(user)
    return json.dumps(user)
