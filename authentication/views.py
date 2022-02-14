import code
from django.http import HttpResponse
from django.http import JsonResponse
from django.http.request import HttpRequest
from django.forms.models import model_to_dict
from authentication.models import User, Country, Gender
from authentication.utils import formatting_user_response, get_user_data, update_user
from rest_framework.decorators import api_view


@api_view(['GET', 'PUT', 'DELETE'])
def user(request: HttpRequest):
    try:
        user_data = get_user_data(request.META["HTTP_AUTHORIZATION"])
        user = User.objects.filter(sub=user_data["sub"]).first()
        if not user:
            response = JsonResponse({"message": "The user don't exist"})
            response.status_code = 404
            return response

        if request.method == 'GET':
            response = formatting_user_response(user=user)
            return HttpResponse(response, content_type='application/json')

        elif request.method == 'PUT':
            update_user(request.data, user_data["sub"])
            user = User.objects.filter(sub=user_data["sub"]).first()
            response = formatting_user_response(user=user)
            return HttpResponse(response, content_type='application/json')

        elif request.method == 'DELETE':
            User.objects.filter(sub=user_data["sub"]).delete()
            return JsonResponse({"message": "deleted"})

        response = JsonResponse({"message": "Operation failed"})
        response.status_code = 400
        return response
    except Exception as e:
        print(e)
        response = JsonResponse({"message": "Operation failed"})
        response.status_code = 400
        return response


@api_view(['POST'])
def sign_in(request: HttpRequest):
    try:
        user_data = get_user_data(request.META["HTTP_AUTHORIZATION"])
        user = User.objects.filter(sub=user_data["sub"]).first()
        if user:
            response = formatting_user_response(user=user)
            return HttpResponse(response, content_type='application/json')
        response = JsonResponse({'message': 'Sign in failed'})
        response.status_code = 404
        return response
    except Exception as e:
        print(e)
        response = JsonResponse({'message': 'Sign in failed'})
        response.status_code = 400
        return response


@api_view(['POST'])
def sign_up(request: HttpRequest):
    try:
        user_data = get_user_data(request.META["HTTP_AUTHORIZATION"], request.data)
        user = User.objects.filter(sub=user_data["sub"]).first()
        if not user:
            user = User(
                sub=user_data["sub"], nick_name=user_data["nick_name"], full_name=user_data["full_name"], 
                email=user_data["email"], profile_image=user_data["profile_image"], is_admin=user_data["is_admin"])
            user.save()
            user_response = formatting_user_response(user=user)
            response = HttpResponse(user_response, content_type='application/json')
            response.status_code = 201
            return response
        else:
            response = JsonResponse({'message': 'The user already exist'})
            response.status_code = 400
            return response
    except Exception as e:
        print(e)
        response = JsonResponse({'message': 'Sign up failed'})
        response.status_code = 400
    return response
