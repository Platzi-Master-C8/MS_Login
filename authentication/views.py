from django.http import HttpResponse
from django.http import JsonResponse
from django.http.request import HttpRequest
from django.forms.models import model_to_dict
from authentication.models import User, Country, Gender
from authentication.utils import formatting_user_response, get_user_data, update_user, jwt_decode_token
from rest_framework.decorators import api_view
from functools import wraps

import jwt


def get_token_auth_header(request):
    """Obtains the Access Token from the Authorization Header
    """
    auth = request.META.get("HTTP_AUTHORIZATION", None)
    parts = auth.split()
    token = parts[1]

    return token


def requires_scope(required_scope):
    """Determines if the required scope is present in the Access Token
    Args:
        required_scope (str): The scope required to access the resource
    """
    def require_scope(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = get_token_auth_header(args[0])
            decoded = jwt.decode(token, verify=False)
            if decoded.get("scope"):
                token_scopes = decoded["scope"].split()
                for token_scope in token_scopes:
                    if token_scope == required_scope:
                        return f(*args, **kwargs)
            response = JsonResponse({'message': 'You don\'t have access to this resource'})
            response.status_code = 403
            return response
        return decorated
    return require_scope


@api_view(['GET'])
def verify_user_token(request: HttpRequest):
    return JsonResponse({"status": "Authenticated"})


@api_view(['GET', 'PUT', 'DELETE'])
def user(request: HttpRequest):
    token = get_token_auth_header(request)
    decode_token = jwt_decode_token(token)

    if request.method == 'GET':
        user = User.objects.filter(sub=decode_token["sub"]).first()
        if user:
            response = formatting_user_response(user=user)
            return HttpResponse(response, content_type='application/json')

    elif request.method == 'PUT':
        user_data = get_user_data(request.data)
        update_user(user_data, decode_token["sub"])
        user = User.objects.filter(sub=decode_token["sub"]).first()
        if user:
            response = formatting_user_response(user=user)
            return HttpResponse(response, content_type='application/json')

    elif request.method == 'DELETE':
        User.objects.filter(sub=decode_token["sub"]).delete()
        return JsonResponse({"message": "deleted"})
    response = JsonResponse({"message": "user not found"})
    response.status_code = 404
    return response


@api_view(['POST'])
def sign_in(request: HttpRequest):
    token = get_token_auth_header(request)
    decode_token = jwt_decode_token(token)

    if decode_token["sub"]:
        user = User.objects.filter(sub=decode_token["sub"]).first()
        if user:
            response = formatting_user_response(user=user)
            return HttpResponse(response, content_type='application/json')
    response = JsonResponse({'message': 'Sign in failed'})
    response.status_code = 404
    return response


@api_view(['POST'])
def sign_up(request: HttpRequest):
    token = get_token_auth_header(request)
    decode_token = jwt_decode_token(token)
    user_data = get_user_data(request.data)

    if decode_token["sub"] and user_data["email"] and user_data["nick_name"] and user_data["full_name"]:
        user = User(
            sub=decode_token["sub"], nick_name=user_data["nick_name"], full_name=user_data["full_name"], 
            email=user_data["email"], profile_image=user_data["profile_image"], is_admin=user_data["is_admin"])
        user.save()
        user_response = formatting_user_response(user=user)
        response = HttpResponse(user_response, content_type='application/json')
        response.status_code = 201
        return response
    response = JsonResponse({'message': 'Sign up failed'})
    response.status_code = 400
    return response


@api_view(['GET'])
def country(request: HttpRequest):
    if request.method == 'GET':
        countries = Country.objects.all()
        if countries:
            response = []
            for i in countries:
                response.append(model_to_dict(i))
            return JsonResponse({"countries": response})
    response = JsonResponse({"message": "countries not found"})
    response.status_code = 404
    return response


@api_view(['GET'])
def gender(request: HttpRequest):
    if request.method == 'GET':
        genders = Gender.objects.all()
        if genders:
            response = []
            for i in genders:
                response.append(model_to_dict(i))
            return JsonResponse({"genders": genders})
    response = JsonResponse({"message": "genders not found"})
    response.status_code = 404
    return response