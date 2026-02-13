import logging

from urllib.parse import urlencode

from auth0_oauth_client import auth_client
from django.contrib.auth import authenticate
from django.contrib.auth import login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest
from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import redirect
from django.shortcuts import render
from django.template import loader
from django.urls import reverse
from django.views.decorators.http import require_GET
from django.views.decorators.http import require_http_methods

_logger = logging.getLogger(__name__)

# region Views that render pages


@require_GET
def welcome_page(request: HttpRequest):
    return render(request, "core/welcome.html")


@require_GET
@login_required
def internal_page(request: HttpRequest):
    user_info = auth_client.get_user_info(request.user.youruser.idp_username)
    return render(request, "core/internal.html", {"user_info": user_info})


@require_GET
def link_account_page(request):
    pending_account_linking = auth_client.pending_account_linking(request)
    if not pending_account_linking:
        data = {"message": "Did you start account linking? 🤔", "status": "error"}
        return redirect(f"{reverse('welcome')}?{urlencode(data)}")

    template = loader.get_template("core/account_linking.html")
    context = {
        "pending": pending_account_linking,
        "initiate_url": reverse("auth:initiate-account-linking-flow"),
        "cancel_url": reverse("auth:cancel-account-linking-flow"),
    }
    return HttpResponse(template.render(context, request))


# endregion

# region Connected Accounts Management


@login_required
@require_GET
def list_connected_accounts(request: HttpRequest):
    result = auth_client.list_connected_accounts(request)
    return JsonResponse(result, safe=False)


@require_GET
@login_required
def list_available_connections(request: HttpRequest):
    result = auth_client.list_connected_account_connections(request)
    return JsonResponse(result, safe=False)


@require_http_methods(["DELETE"])
@login_required
def delete_connected_account(request, account_id):
    auth_client.delete_connected_account(request, account_id)
    return HttpResponse(status=204)


# endregion

# region Flow initiation, cancellation, and callback


@login_required
@require_GET
def initiate_connected_account_flow(request: HttpRequest):
    connection = request.GET.get("connection")
    if not connection:
        return JsonResponse({"error": "connection is required"}, status=400)
    scopes = request.GET.getlist("scopes")
    next_url = request.GET.get("next_url", None)
    callback_url = request.build_absolute_uri(reverse("auth:callback"))
    if next_url:
        request.session["next_url"] = next_url
        request.session.modified = True
    authorization_params = {k: v for k, v in request.GET.items() if k not in ["connection", "returnTo", "scopes"]}
    flow_url = auth_client.start_connect_account(
        request,
        connection=connection,
        redirect_uri=callback_url,
        scopes=scopes or None,
        authorization_params=authorization_params or None,
    )
    return redirect(flow_url)


@require_GET
def cancel_account_linking_flow(request):
    auth_client.cancel_account_linking(request)
    data = {"message": "Account linking has been cancelled", "status": "info"}
    return redirect(f"{reverse('welcome')}?{urlencode(data)}")


@require_GET
def initiate_account_linking_flow(request):
    pending_account_linking = auth_client.pending_account_linking(request)
    if not pending_account_linking:
        data = {"message": "Did you start account linking? 🤔", "status": "error"}
        return redirect(f"{reverse('welcome')}?{urlencode(data)}")

    redirect_uri = request.build_absolute_uri(reverse("auth:callback"))
    # This bypasses the Universal Login prompt, directing users immediately to the specified identity provider.
    required_params = {"connection": pending_account_linking["primary_connection_name"]}
    flow_url = auth_client.start_login(request, redirect_uri, authorization_params=required_params)
    return redirect(flow_url)


@require_GET
def initiate_login_flow(request: HttpRequest):
    next_url = request.GET.get("next_url")
    callback_url = request.build_absolute_uri(reverse("auth:callback"))
    if next_url:
        request.session["next_url"] = next_url
        request.session.modified = True
    flow_url = auth_client.start_login(request, callback_url)
    return redirect(flow_url)


@require_GET
def finalize_login_or_connected_account_flow_callback(request: HttpRequest):
    callback_url = request.build_absolute_uri(request.get_full_path())
    data = None

    if "connect_code" in request.GET:
        auth_client.complete_connect_account(request, callback_url)
    else:
        auth_client.complete_login(request, callback_url)
        try:
            account_linking_conclusion = auth_client.complete_account_linking(request)
        except Exception:
            _logger.exception("Failed to complete account linking")
            data = {"message": "Account linking failed 🫤", "status": "error"}
            return redirect(f"{reverse('welcome')}?{urlencode(data)}")
        if account_linking_conclusion:
            if not account_linking_conclusion["success"]:
                if account_linking_conclusion["used_different_account"]:
                    data = {
                        "message": "You have to use the original account. Try again.",
                        "status": "error",
                    }
                    final_url = request.build_absolute_uri(f"{reverse('welcome')}?{urlencode(data)}")
                    logout_url = f"{reverse('auth:logout')}?{urlencode({'next_url': final_url})}"
                    return redirect(logout_url)
                data = {
                    "message": "The session has expired. Try again.",
                    "status": "error",
                }
                return redirect(f"{reverse('welcome')}?{urlencode(data)}")
            else:
                data = {
                    "message": "Account linked successfully! 🎉",
                    "status": "success",
                }
        else:
            try:
                analysis = auth_client.verify_account_linking(request)
            except Exception:
                _logger.exception("Failed to verify account linking")
                data = {
                    "message": "Account linking verification failed 🫤",
                    "status": "error",
                }
                return redirect(f"{reverse('welcome')}?{urlencode(data)}")
            if analysis["is_pending_account_linking"]:
                return redirect(reverse("link-account"))
        user = authenticate(
            request,
            auth0_username=auth_client.get_idp_username(request),
            refresh_token=auth_client.get_refresh_token(request),
        )
        if user:
            login(request, user)
    next_url = request.session.pop("next_url", None)
    default_redirect = reverse("internal")
    if data:
        default_redirect = f"{default_redirect}?{urlencode(data)}"
    return redirect(next_url if next_url else default_redirect)


# endregion


@login_required
@require_GET
def initiate_custom_login_flow(request):
    """This is for testing purpose. You can disregard it."""
    next_url = request.GET.get("next_url")
    connection = request.GET["connection"]
    scopes = request.GET.getlist("scopes")
    redirect_uri = request.build_absolute_uri(reverse("auth:callback"))
    if next_url:
        request.session["next_url"] = next_url
        request.session.modified = True
    # Know more at:
    # https://auth0.com/docs/authenticate/identity-providers/social-identity-providers/reprompt-permissions.md
    required_google_params = {"connection": connection, "prompt": "consent"}
    if scopes:
        # It's hardcoded on purpose for testing
        required_google_params["scope"] = " ".join(scopes) + " openid profile email offline_access"
    url = auth_client.start_login(
        request,
        redirect_uri,
        authorization_params=required_google_params,
    )
    return redirect(url)


@require_GET
def auth_logout(request: HttpRequest):
    next_url = request.GET.get("next_url")
    default_redirect = request.build_absolute_uri(reverse("welcome"))
    logout_url = auth_client.logout(request, return_to=next_url or default_redirect)
    django_logout(request)
    return redirect(logout_url)


@login_required
@require_GET
def spy_access_token_for_connection(request: HttpRequest):
    connection = request.GET.get("connection")
    if not connection:
        return JsonResponse({"error": "connection is required"}, status=400)
    try:
        refresh_token = request.user.youruser.idp_refresh_token
        result = auth_client.get_access_token_for_connection_using_user_refresh_token(refresh_token, connection)
        return JsonResponse(result)
    except Exception as e:
        _logger.exception("Failed to get access token for connection %s", connection)
        return JsonResponse(
            {
                "error": str(e),
                "connect_url": f"/auth/connect/?connection={connection}&returnTo=/internal/",
            },
            status=400,
        )
