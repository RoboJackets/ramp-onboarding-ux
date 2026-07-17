"""
Overengineered web form to facilitate onboarding users to Ramp
"""

import hmac
import logging
import os
from base64 import b64encode
from collections.abc import Callable
from csv import DictReader
from datetime import datetime, timezone
from email.headerregistry import Address
from functools import wraps
from hashlib import file_digest, sha256
from ipaddress import ip_address, ip_network
from json import loads
from re import fullmatch, search
from typing import Any, Dict, ParamSpec, TypeVar, Union
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from uuid import UUID, uuid4

from authlib.integrations.base_client import OAuthError
from authlib.integrations.flask_client import OAuth
from authlib.integrations.requests_client import OAuth2Session

from celery import Celery, Task, shared_task

import click

from flask import Flask, Response, redirect, render_template, request, session, url_for
from flask.helpers import get_debug_flag

from flask_caching import Cache

from flask_minify import Minify  # type: ignore

from google.auth.transport import requests
from google.oauth2 import id_token

from ldap3 import Connection, Server

from requests import post
from requests.exceptions import RequestException

import sentry_sdk
from sentry_sdk import set_user
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.pure_eval import PureEvalIntegration

from slack_sdk import WebClient, WebhookClient
from slack_sdk.errors import SlackApiError
from slack_sdk.models.blocks import (
    ActionsBlock,
    ButtonElement,
    ConfirmObject,
    ContextBlock,
    MarkdownTextObject,
    PlainTextObject,
    RichTextBlock,
    RichTextListElement,
    RichTextSectionElement,
    SectionBlock,
)
from slack_sdk.models.blocks.block_elements import RichTextElementParts
from slack_sdk.signature import SignatureVerifier

from werkzeug.exceptions import BadRequest, Conflict, Forbidden, InternalServerError, Unauthorized

USER_AGENT = (
    "RampOnboarding/"
    + os.environ.get("NOMAD_TASK_NAME", "local")
    + "/"
    + os.environ.get("NOMAD_SHORT_ALLOC_ID", "local")
)


ROLE_LABELS = {
    "BUSINESS_USER": "Employee",
    "BUSINESS_BOOKKEEPER": "Accounting",
    "BUSINESS_ADMIN": "Admin",
    "IT_ADMIN": "IT admin",
}

ADVISOR_CONSOLE_PREFIX = "[Advisor Console] "


def traces_sampler(sampling_context: Dict[str, Dict[str, str]]) -> bool:
    """
    Ignore ping events, sample all other events
    """
    try:
        request_uri = sampling_context["wsgi_environ"]["REQUEST_URI"]
    except KeyError:
        return False

    return request_uri != "/ping"


def init_celery(flask: Flask) -> Celery:
    """
    Initialize Celery
    """

    class FlaskTask(Task):  # type: ignore  # pylint: disable=abstract-method
        """
        Extend default Task class to have Flask context available

        https://flask.palletsprojects.com/en/stable/patterns/celery/
        """

        def __call__(self, *args, **kwargs):  # type: ignore
            with flask.app_context():
                return self.run(*args, **kwargs)

    new_celery_app = Celery("ramp_onboarding_ux", task_cls=FlaskTask)
    new_celery_app.config_from_object(flask.config, namespace="CELERY")
    new_celery_app.set_default()
    flask.extensions["celery"] = new_celery_app
    return new_celery_app  # type: ignore


logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
req_log = logging.getLogger("urllib3")
req_log.setLevel(logging.DEBUG)
req_log.propagate = True


sentry_sdk.init(
    debug=get_debug_flag(),
    integrations=[
        FlaskIntegration(),
        PureEvalIntegration(),
    ],
    traces_sampler=traces_sampler,
    attach_stacktrace=True,
    max_request_body_size="always",
    in_app_include=[
        "ramp_onboarding_ux",
    ],
    profiles_sample_rate=1.0,
)

app = Flask(__name__)

app.config.from_prefixed_env()


@app.after_request
def add_document_policy_header(response: Response) -> Response:
    """Enable Chromium JS Self-Profiling for Sentry browser profiling."""
    response.headers["Document-Policy"] = "js-profiling"
    return response


if not get_debug_flag():
    Minify(app=app, caching_limit=0, go=False)

celery_app = init_celery(app)

oauth = OAuth(app)  # type: ignore
oauth.register(  # type: ignore
    name="keycloak",
    server_metadata_url=app.config["KEYCLOAK_METADATA_URL"],
    client_kwargs={"scope": "openid email profile"},
)
oauth.register(  # type: ignore
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email"},
)
oauth.register(  # type: ignore
    name="microsoft",
    server_metadata_url=app.config["MICROSOFT_METADATA_URL"],
    client_kwargs={"scope": "openid email"},
)

BILL_PHYSICAL_CARD_ADDRESSES = {}

for row in DictReader(app.config["BILL_PHYSICAL_CARD_ORDERS_CSV"].split("\n")):
    if row["Order Status"] in ["Activated", "Shipped"]:
        BILL_PHYSICAL_CARD_ADDRESSES[row["Card Holder"]] = row["Shipping Address"]

ramp = OAuth2Session(
    client_id=app.config["RAMP_CLIENT_ID"],
    client_secret=app.config["RAMP_CLIENT_SECRET"],
    scope="users:read users:write cards:write departments:read locations:read business:read",  # noqa: E501
    token_endpoint=app.config["RAMP_API_URL"] + "/developer/v1/token",
)
ramp.headers["User-Agent"] = USER_AGENT  # type: ignore
ramp.fetch_token()

keycloak = OAuth2Session(
    client_id=app.config["KEYCLOAK_ADMIN_CLIENT_ID"],
    client_secret=app.config["KEYCLOAK_ADMIN_CLIENT_SECRET"],
    token_endpoint=app.config["KEYCLOAK_SERVER"] + "/realms/master/protocol/openid-connect/token",
    leeway=5,
)
keycloak.headers["User-Agent"] = USER_AGENT  # type: ignore
keycloak.fetch_token()

apiary = OAuth2Session(
    client_id=app.config["APIARY_CLIENT_ID"],
    client_secret=app.config["APIARY_CLIENT_SECRET"],
    token_endpoint=app.config["APIARY_URL"] + "/oauth/token",
)
apiary.headers["User-Agent"] = USER_AGENT  # type: ignore
apiary.fetch_token()

cache = Cache(app)

P = ParamSpec("P")
R = TypeVar("R")


def _set_sentry_user_from_session() -> None:
    """
    Attach the logged-in user from the Flask session to the current Sentry scope
    """
    set_user(
        {
            "id": session["user_id"],
            "username": session["username"],
            "email": session["email_address"],
            "ip_address": request.remote_addr,
        }
    )


def login_required(view: Callable[P, R]) -> Callable[P, R]:
    """
    Require an established user session; raise Unauthorized if missing
    """

    @wraps(view)
    def wrapped_view(*args: P.args, **kwargs: P.kwargs) -> R:
        if "user_state" not in session:
            raise Unauthorized("Not logged in")

        _set_sentry_user_from_session()
        return view(*args, **kwargs)

    return wrapped_view


def login_required_oidc_redirect(view: Callable[P, R]) -> Callable[P, R]:
    """
    Require an established user session; redirect to Keycloak OIDC if missing
    """

    @wraps(view)
    def wrapped_view(*args: P.args, **kwargs: P.kwargs) -> R:
        if "user_state" not in session:
            return oauth.keycloak.authorize_redirect(url_for("login", _external=True))  # type: ignore  # noqa: E501

        _set_sentry_user_from_session()
        return view(*args, **kwargs)

    return wrapped_view


def eligible_required(view: Callable[P, R]) -> Callable[P, R]:
    """
    Require session user_state == eligible; raise Unauthorized otherwise
    """

    @wraps(view)
    def wrapped_view(*args: P.args, **kwargs: P.kwargs) -> R:
        if session["user_state"] != "eligible":
            raise Forbidden("Not eligible")

        return view(*args, **kwargs)

    return wrapped_view


def email_verified_required(view: Callable[P, R]) -> Callable[P, R]:
    """
    Require a verified email address in session; raise BadRequest otherwise
    """

    @wraps(view)
    def wrapped_view(*args: P.args, **kwargs: P.kwargs) -> R:
        if not session["email_verified"]:
            raise BadRequest("Email address must be verified")

        return view(*args, **kwargs)

    return wrapped_view


def only_cache_if_ramp_id_present(response: Dict[str, str]) -> bool:
    """
    Only cache Ramp user lookup calls if the user has an active Ramp account
    """
    return "rampUserId" in response


def generate_subresource_integrity_hash(file: str) -> str:
    """
    Calculate the subresource integrity hash for a given file
    """
    with open(file[1:], "rb") as f:
        d = file_digest(f, "sha512")

    return "sha512-" + b64encode(d.digest()).decode("utf-8")


app.jinja_env.globals["calculate_integrity"] = generate_subresource_integrity_hash


@cache.cached(timeout=0, key_prefix="apiary_managers")
def get_apiary_managers() -> Dict[int, str]:
    """
    Get the list of managers from Apiary
    """
    apiary_managers_response = apiary.get(  # type: ignore
        url=app.config["APIARY_URL"] + "/api/v1/users/managers",
        headers={
            "Accept": "application/json",
        },
        timeout=(5, 5),
    )
    apiary_managers_response.raise_for_status()

    managers = {}

    for manager in apiary_managers_response.json()["users"]:
        managers[manager["id"]] = manager["full_name"]

    return managers


def get_ramp_object_label(
    ramp_objects: Dict[str, Dict[str, Union[str, bool]]], ramp_object_id: str
) -> str:
    """
    Get the label for a Ramp object, falling back to "Unknown" if hidden or missing
    """
    ramp_object = ramp_objects.get(ramp_object_id)
    if ramp_object is None:
        return "Unknown"

    return str(ramp_object["label"])


@cache.cached(timeout=0, key_prefix="ramp_departments")
def get_ramp_departments() -> Dict[str, Dict[str, Union[str, bool]]]:
    """
    Get the list of departments from Ramp
    """
    ramp_departments_response = ramp.get(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/departments",
        timeout=(5, 5),
    )
    ramp_departments_response.raise_for_status()

    departments = {}

    for department in ramp_departments_response.json()["data"]:
        if department["id"] == app.config["RAMP_DISABLED_DEPARTMENT"]:
            continue

        if department["name"].startswith(ADVISOR_CONSOLE_PREFIX):
            continue

        departments[department["id"]] = {
            "label": department["name"],
            "enabled": True,
        }

    return departments


@cache.cached(timeout=0, key_prefix="ramp_locations")
def get_ramp_locations() -> Dict[str, Dict[str, Union[str, bool]]]:
    """
    Get the list of locations from Ramp
    """
    ramp_locations_response = ramp.get(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/locations",
        timeout=(5, 5),
    )
    ramp_locations_response.raise_for_status()

    locations = {}

    disabled_location = app.config.get("RAMP_DISABLED_LOCATION")

    for location in ramp_locations_response.json()["data"]:
        if disabled_location is not None and location["id"] == disabled_location:
            continue

        if location["name"].startswith(ADVISOR_CONSOLE_PREFIX):
            continue

        locations[location["id"]] = {
            "label": location["name"],
            "enabled": True,
        }

    return locations


@cache.cached(timeout=0, key_prefix="ramp_users")
def get_ramp_users() -> Dict[str, Dict[str, Union[str, bool]]]:
    """
    Get the list of users from Ramp
    """
    ramp_users_response = ramp.get(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/users",
        params={
            "page_size": 100,
        },
        timeout=(5, 5),
    )
    ramp_users_response.raise_for_status()

    users = {}

    for user in ramp_users_response.json()["data"]:
        if user["department_id"] == app.config["RAMP_DISABLED_DEPARTMENT"]:
            continue

        users[user["id"]] = {
            "label": user["first_name"] + " " + user["last_name"],
            "enabled": user["status"] == "USER_ACTIVE" and user["is_manager"] is True,
            "departmentId": user["department_id"],
        }

    return users


@cache.cached(timeout=0, key_prefix="ramp_business")
def get_ramp_business() -> Dict[str, str]:
    """
    Get the business information from Ramp
    """
    ramp_business_response = ramp.get(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/business",
        timeout=(5, 5),
    )
    ramp_business_response.raise_for_status()
    return ramp_business_response.json()  # type: ignore


@cache.memoize(timeout=0, cache_none=True)
def get_slack_user_id_by_email(email: str) -> Union[str, None]:
    """
    Wrapper for the users.lookupByEmail function to memoize responses
    """
    slack = WebClient(token=app.config["SLACK_API_TOKEN"])

    try:
        slack_response = slack.users_lookupByEmail(email=email)

        if slack_response.data["ok"]:  # type: ignore
            return slack_response.data["user"]["id"]  # type: ignore
    except SlackApiError:
        # this exception is thrown if there is no user with this email (among other possibilities)
        pass

    return None


@cache.memoize(timeout=0, cache_none=True)
def get_slack_user_id(**kwargs: str) -> Union[str, None]:
    """
    Get the Slack user ID for a given Keycloak or Ramp user
    """
    if "keycloak_user_id" in kwargs and kwargs["keycloak_user_id"] is not None:
        get_keycloak_user_response = keycloak.get(  # type: ignore
            url=app.config["KEYCLOAK_SERVER"]
            + "/admin/realms/"
            + app.config["KEYCLOAK_REALM"]
            + "/users/"
            + kwargs["keycloak_user_id"],
            timeout=(5, 5),
        )
        get_keycloak_user_response.raise_for_status()

        keycloak_user = get_keycloak_user_response.json()

        if (
            "attributes" in keycloak_user
            and keycloak_user["attributes"] is not None
            and "rampLoginEmailAddress" in keycloak_user["attributes"]
            and keycloak_user["attributes"]["rampLoginEmailAddress"] is not None
            and len(keycloak_user["attributes"]["rampLoginEmailAddress"]) > 0
        ):
            slack_user_id = get_slack_user_id_by_email(
                keycloak_user["attributes"]["rampLoginEmailAddress"][0]
            )

            if slack_user_id is not None:
                return slack_user_id  # type: ignore

        if (
            "attributes" in keycloak_user
            and keycloak_user["attributes"] is not None
            and "googleWorkspaceAccount" in keycloak_user["attributes"]
            and keycloak_user["attributes"]["googleWorkspaceAccount"] is not None
            and len(keycloak_user["attributes"]["googleWorkspaceAccount"]) > 0
        ):
            slack_user_id = get_slack_user_id_by_email(
                keycloak_user["attributes"]["googleWorkspaceAccount"][0]
            )

            if slack_user_id is not None:
                return slack_user_id  # type: ignore

        if "email" in keycloak_user and keycloak_user["email"] is not None:
            slack_user_id = get_slack_user_id_by_email(keycloak_user["email"])

            if slack_user_id is not None:
                return slack_user_id  # type: ignore

        if "username" in keycloak_user and keycloak_user["username"] is not None:
            slack_user_id = get_slack_user_id_by_email(keycloak_user["username"] + "@gatech.edu")

            if slack_user_id is not None:
                return slack_user_id  # type: ignore

        if "username" in keycloak_user and keycloak_user["username"] is not None:
            apiary_user_response = apiary.get(  # type: ignore
                url=app.config["APIARY_URL"] + "/api/v1/users/" + keycloak_user["username"],
                headers={
                    "Accept": "application/json",
                },
                timeout=(5, 5),
            )

            if apiary_user_response.status_code == 200:
                apiary_user = apiary_user_response.json()["user"]

                if "gt_email" in apiary_user and apiary_user["gt_email"] is not None:
                    slack_user_id = get_slack_user_id_by_email(apiary_user["gt_email"])

                    if slack_user_id is not None:
                        return slack_user_id  # type: ignore

                if "gmail_address" in apiary_user and apiary_user["gmail_address"] is not None:
                    slack_user_id = get_slack_user_id_by_email(apiary_user["gmail_address"])

                    if slack_user_id is not None:
                        return slack_user_id  # type: ignore

                if "clickup_email" in apiary_user and apiary_user["clickup_email"] is not None:
                    slack_user_id = get_slack_user_id_by_email(apiary_user["clickup_email"])

                    if slack_user_id is not None:
                        return slack_user_id  # type: ignore

        with sentry_sdk.start_span(op="ldap.connect"):
            ldap = Connection(
                Server("whitepages.gatech.edu", connect_timeout=1),
                auto_bind=True,
                raise_exceptions=True,
                receive_timeout=1,
            )
        with sentry_sdk.start_span(op="ldap.search"):
            result = ldap.search(
                search_base="dc=whitepages,dc=gatech,dc=edu",
                search_filter="(uid=" + keycloak_user["username"] + ")",
                attributes=["mail"],
            )

        if result is True:
            for entry in ldap.entries:
                if (
                    "mail" in entry
                    and entry["mail"] is not None
                    and entry["mail"].value is not None
                ):
                    slack_user_id = get_slack_user_id_by_email(entry["mail"].value)

                    if slack_user_id is not None:
                        return slack_user_id  # type: ignore

    if "ramp_user_id" in kwargs and kwargs["ramp_user_id"] is not None:
        ramp_user_response = ramp.get(  # type: ignore
            url=app.config["RAMP_API_URL"] + "/developer/v1/users/" + kwargs["ramp_user_id"],
            timeout=(5, 5),
        )
        ramp_user_response.raise_for_status()

        slack_user_id = get_slack_user_id_by_email(ramp_user_response.json()["email"])

        if slack_user_id is not None:
            return slack_user_id  # type: ignore

        search_keycloak_user_response = keycloak.get(  # type: ignore
            url=app.config["KEYCLOAK_SERVER"]
            + "/admin/realms/"
            + app.config["KEYCLOAK_REALM"]
            + "/users",
            params={
                "q": "rampUserId:" + kwargs["ramp_user_id"],
            },
            timeout=(5, 5),
        )
        search_keycloak_user_response.raise_for_status()

        if len(search_keycloak_user_response.json()) == 1:
            return get_slack_user_id(keycloak_user_id=search_keycloak_user_response.json()[0]["id"])  # type: ignore  # noqa: E501

        if len(search_keycloak_user_response.json()) == 0:
            search_keycloak_user_response = keycloak.get(  # type: ignore
                url=app.config["KEYCLOAK_SERVER"]
                + "/admin/realms/"
                + app.config["KEYCLOAK_REALM"]
                + "/users",
                params={
                    "q": "rampLoginEmailAddress:" + ramp_user_response.json()["email"],
                },
                timeout=(5, 5),
            )
            search_keycloak_user_response.raise_for_status()

            if len(search_keycloak_user_response.json()) == 1:
                return get_slack_user_id(  # type: ignore
                    keycloak_user_id=search_keycloak_user_response.json()[0]["id"]
                )

            if len(search_keycloak_user_response.json()) == 0:
                search_keycloak_user_response = keycloak.get(  # type: ignore
                    url=app.config["KEYCLOAK_SERVER"]
                    + "/admin/realms/"
                    + app.config["KEYCLOAK_REALM"]
                    + "/users",
                    params={
                        "q": "googleWorkspaceAccount:" + ramp_user_response.json()["email"],
                    },
                    timeout=(5, 5),
                )
                search_keycloak_user_response.raise_for_status()

                if len(search_keycloak_user_response.json()) == 1:
                    return get_slack_user_id(  # type: ignore
                        keycloak_user_id=search_keycloak_user_response.json()[0]["id"]
                    )

                if len(search_keycloak_user_response.json()) == 0:
                    return None

        if len(search_keycloak_user_response.json()) > 1:
            raise Exception("Received more than one matching user from Keycloak")

    return None


@cache.cached(timeout=0, key_prefix="slack_team_id")
def get_slack_team_id() -> str:
    """
    Get the team ID for the bot user, used for generating deep links

    https://docs.slack.dev/interactivity/deep-linking#open_a_channel
    """
    slack = WebClient(token=app.config["SLACK_API_TOKEN"])

    slack_response = slack.team_info()

    return slack_response["team"]["id"]  # type: ignore


@cache.memoize(timeout=0)
def get_slack_channel_name(channel_id: str) -> str:
    """
    Get the channel name for the given channel ID
    """
    slack = WebClient(token=app.config["SLACK_API_TOKEN"])

    slack_response = slack.conversations_info(channel=channel_id)

    return slack_response["channel"]["name"]  # type: ignore


@shared_task
def remove_eligible_role(keycloak_user_id: str) -> None:
    """
    Remove the eligible role from this user in Keycloak, after they are provisioned
    """
    remove_eligible_role_response = keycloak.delete(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + keycloak_user_id
        + "/role-mappings/clients/"
        + app.config["KEYCLOAK_CLIENT_UUID"],
        timeout=(5, 5),
        json=[{"id": app.config["KEYCLOAK_CLIENT_ROLE_ELIGIBLE"], "name": "eligible"}],
    )
    remove_eligible_role_response.raise_for_status()


@shared_task(max_retries=0)
def import_user_to_org_chart(ramp_user_id: str) -> None:
    """
    Notify OrgChart after a user is invited to Ramp
    """
    org_chart_response = post(
        url=app.config["ORG_CHART_NOTIFY_URL"],
        headers={
            "Accept": "application/json",
            "Authorization": "Token " + app.config["ORG_CHART_TOKEN"],
            "User-Agent": USER_AGENT,
        },
        timeout=(5, 5),
        json={"ramp_user_id": ramp_user_id},
    )
    org_chart_response.raise_for_status()


@shared_task
def store_ramp_user_id_in_keycloak(keycloak_user_id: str, ramp_user_id: str) -> None:
    """
    Store the Ramp user ID in Keycloak
    """
    ramp_user_response = ramp.get(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/users/" + ramp_user_id,
        timeout=(5, 5),
    )
    ramp_user_response.raise_for_status()

    get_keycloak_user_response = keycloak.get(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + keycloak_user_id,
        timeout=(5, 5),
    )
    get_keycloak_user_response.raise_for_status()

    new_user = get_keycloak_user_response.json()
    if "id" in new_user:
        del new_user["id"]

    if "username" in new_user:
        del new_user["username"]

    if "attributes" not in new_user:
        new_user["attributes"] = {
            "rampLoginEmailAddress": [ramp_user_response.json()["email"]],
            "rampUserId": [ramp_user_id],
        }
    else:
        new_user["attributes"]["rampLoginEmailAddress"] = [ramp_user_response.json()["email"]]
        new_user["attributes"]["rampUserId"] = [ramp_user_id]

    update_keycloak_user_response = keycloak.put(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + keycloak_user_id,
        json=new_user,
        timeout=(5, 5),
    )
    update_keycloak_user_response.raise_for_status()


@shared_task
def notify_slack_ineligible(keycloak_user_id: str) -> None:
    """
    Send a Slack notification to the central notifications channel when an ineligible user loads
    the form
    """
    if cache.get("slack_ineligible_message_" + keycloak_user_id) is not None:
        return

    get_keycloak_user_response = keycloak.get(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + keycloak_user_id,
        timeout=(5, 5),
    )
    get_keycloak_user_response.raise_for_status()

    view_in_keycloak_button = ButtonElement(
        text="View in Keycloak",
        action_id="view_in_keycloak",
        url=urlunparse(
            (
                urlparse(app.config["KEYCLOAK_SERVER"]).scheme,
                urlparse(app.config["KEYCLOAK_SERVER"]).hostname,
                "/admin/master/console/",
                "",
                "",
                "/"
                + app.config["KEYCLOAK_REALM"]
                + "/users/"
                + str(keycloak_user_id)
                + "/settings",
            )
        ),
    )

    apiary_user_response = apiary.get(  # type: ignore
        url=app.config["APIARY_URL"]
        + "/api/v1/users/"
        + get_keycloak_user_response.json()["username"],
        headers={
            "Accept": "application/json",
        },
        timeout=(5, 5),
    )

    if apiary_user_response.status_code == 200:
        personal_pronoun_is = "they are"

        if (
            "gender" in apiary_user_response.json()["user"]
            and apiary_user_response.json()["user"]["gender"] is not None
        ):
            if str.lower(apiary_user_response.json()["user"]["gender"]) == "male":
                personal_pronoun_is = "he is"
            elif str.lower(apiary_user_response.json()["user"]["gender"]) == "female":
                personal_pronoun_is = "she is"

        actions = ActionsBlock(
            elements=[
                ButtonElement(
                    text="View in Apiary",
                    action_id="view_in_apiary",
                    url=app.config["APIARY_URL"]
                    + "/nova/resources/users/"
                    + str(apiary_user_response.json()["user"]["id"]),
                ),
                view_in_keycloak_button,
                ButtonElement(
                    text="Grant Eligibility in Keycloak",
                    action_id="grant_eligibility_in_keycloak",
                    value=keycloak_user_id,
                    style="primary",
                    confirm=ConfirmObject(
                        title="Grant Eligibility in Keycloak",
                        text="Are you sure you want to grant "
                        + get_keycloak_user_response.json()["firstName"]
                        + " eligibility for a Ramp account in Keycloak? If "
                        + personal_pronoun_is
                        + " in a leadership role, an admin should likely assign a role within Apiary instead.",  # noqa: E501
                        confirm="Grant Eligibility",
                        deny="Cancel",
                    ),
                ),
            ]
        )
    elif apiary_user_response.status_code == 404:
        actions = ActionsBlock(
            elements=[
                view_in_keycloak_button,
            ]
        )
    else:
        actions = ActionsBlock(elements=[])
        apiary_user_response.raise_for_status()

    slack_user_id = get_slack_user_id(keycloak_user_id=keycloak_user_id)

    user_name = (
        get_keycloak_user_response.json()["firstName"]
        + " "
        + get_keycloak_user_response.json()["lastName"]
    )

    if slack_user_id is None:
        user_mention = user_name
    else:
        user_mention = f"<@{slack_user_id}>"

    slack = WebClient(token=app.config["SLACK_API_TOKEN"])

    slack_response = slack.chat_postMessage(
        channel=app.config["SLACK_NOTIFY_CHANNEL"],
        text=user_name
        + " logged in to the Ramp onboarding form, but isn't eligible for a Ramp account.",
        blocks=[
            SectionBlock(
                text=user_mention
                + " logged in to the Ramp onboarding form, but isn't eligible for a Ramp account."
            ),
            actions,
        ],
    )

    cache.set("slack_ineligible_message_" + keycloak_user_id, slack_response["ts"])


@shared_task(
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    max_retries=5,
)
def notify_slack_account_created(keycloak_user_id: str, ramp_user_id: str) -> None:
    """
    Send Slack notifications to the central notifications channel, manager, and new member, when
    someone joins Ramp
    """
    if cache.get("slack_notifications_sent_" + ramp_user_id) is not None:
        logging.warning("multiple tasks triggered, returning early")
        return

    new_ramp_user_response = ramp.get(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/users/" + ramp_user_id,
        timeout=(5, 5),
    )
    new_ramp_user_response.raise_for_status()

    if new_ramp_user_response.json()["manager_id"] is None:
        ramp_manager_user_response = None
        manager_slack_user_id = None
    else:
        ramp_manager_user_response = ramp.get(  # type: ignore
            url=app.config["RAMP_API_URL"]
            + "/developer/v1/users/"
            + new_ramp_user_response.json()["manager_id"],
            timeout=(5, 5),
        )
        ramp_manager_user_response.raise_for_status()

        manager_slack_user_id = get_slack_user_id(
            ramp_user_id=new_ramp_user_response.json()["manager_id"]
        )

    new_user_slack_user_id = get_slack_user_id(
        ramp_user_id=ramp_user_id, keycloak_user_id=keycloak_user_id
    )

    slack = WebClient(token=app.config["SLACK_API_TOKEN"])

    new_user_name = (
        new_ramp_user_response.json()["first_name"]
        + " "
        + new_ramp_user_response.json()["last_name"]
    )

    if new_user_slack_user_id is None:
        new_user_mention = new_user_name
    else:
        new_user_mention = f"<@{new_user_slack_user_id}>"

    if ramp_manager_user_response is None:
        manager_mention = "—"
    elif manager_slack_user_id is None:
        manager_mention = (
            ramp_manager_user_response.json()["first_name"]
            + " "
            + ramp_manager_user_response.json()["last_name"]
        )
    else:
        manager_mention = f"<@{manager_slack_user_id}>"

    possessive_pronoun = "their"

    get_keycloak_user_response = keycloak.get(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + keycloak_user_id,
        timeout=(5, 5),
    )
    get_keycloak_user_response.raise_for_status()

    apiary_user_response = apiary.get(  # type: ignore
        url=app.config["APIARY_URL"]
        + "/api/v1/users/"
        + get_keycloak_user_response.json()["username"],
        headers={
            "Accept": "application/json",
        },
        timeout=(5, 5),
    )

    if apiary_user_response.status_code == 200:
        if (
            "gender" in apiary_user_response.json()["user"]
            and apiary_user_response.json()["user"]["gender"] is not None
        ):
            if str.lower(apiary_user_response.json()["user"]["gender"]) == "male":
                possessive_pronoun = "his"
            elif str.lower(apiary_user_response.json()["user"]["gender"]) == "female":
                possessive_pronoun = "her"
    elif apiary_user_response.status_code != 404:
        apiary_user_response.raise_for_status()

    manager_link_email_hint = []
    if manager_slack_user_id is not None:
        manager_slack_profile = slack.users_profile_get(user=manager_slack_user_id)

        if (
            manager_slack_profile.data["profile"]["email"]  # type: ignore
            != ramp_manager_user_response.json()["email"]  # type: ignore
        ):
            manager_link_email_hint = [
                ContextBlock(
                    elements=[
                        MarkdownTextObject(
                            text="If you'd like to get alerts from <@"
                            + app.config["SLACK_RAMP_BOT_USER_ID"]
                            + "> in Slack, you can add your Slack email address (*"
                            + manager_slack_profile.data["profile"]["email"]  # type: ignore
                            + "*) to <"
                            + urlunparse(
                                (
                                    "https",
                                    app.config["RAMP_UI_HOSTNAME"],
                                    "/settings/all/profile",
                                    "",
                                    "",
                                    "#:~:text=receipt%20forwarding%20email-,Slack%20email%20address,-If%20your%20Slack",  # noqa: E501
                                )
                            )
                            + "|your Ramp profile>, under the *Integrations* tab. "
                        ),
                    ]
                )
            ]

    new_user_link_email_tip = []
    new_user_activate_physical_card_tip = []
    if new_user_slack_user_id is not None:
        new_user_slack_profile = slack.users_profile_get(user=new_user_slack_user_id)

        if (
            new_user_slack_profile.data["profile"]["email"]  # type: ignore
            != new_ramp_user_response.json()["email"]
        ):
            new_user_link_email_tip = [
                RichTextSectionElement(
                    elements=[
                        RichTextElementParts.Text(text="Add your Slack email ("),
                        RichTextElementParts.Text(
                            text=new_user_slack_profile.data["profile"]["email"],  # type: ignore
                            style=RichTextElementParts.TextStyle(bold=True),
                        ),
                        RichTextElementParts.Text(text=") to "),
                        RichTextElementParts.Link(
                            url=urlunparse(
                                (
                                    "https",
                                    app.config["RAMP_UI_HOSTNAME"],
                                    "/settings/all/profile",
                                    "",
                                    "",
                                    "#:~:text=receipt%20forwarding%20email-,Slack%20email%20address,-If%20your%20Slack",  # noqa: E501
                                )
                            ),
                            text="your Ramp profile",
                        ),
                        RichTextElementParts.Text(text=", under the "),
                        RichTextElementParts.Text(
                            text="Slack email address",
                            style=RichTextElementParts.TextStyle(bold=True),
                        ),
                        RichTextElementParts.Text(text=" section, to get notifications from "),
                        RichTextElementParts.User(user_id=app.config["SLACK_RAMP_BOT_USER_ID"]),
                        RichTextElementParts.Text(text=" in Slack"),
                    ]
                )
            ]

        if cache.get("physical_card_ordered_" + keycloak_user_id):
            new_user_activate_physical_card_tip = [
                RichTextSectionElement(
                    elements=[
                        RichTextElementParts.Link(
                            url="https://support.ramp.com/activating-a-physical-card/",  # noqa: E501
                            text="Activate your physical card",
                        ),
                        RichTextElementParts.Text(text=" when it arrives"),
                    ]
                )
            ]

    notify_channel_blocks = [
        SectionBlock(
            text=new_user_mention + " joined Ramp!",
            fields=[
                MarkdownTextObject(text="*Role*"),
                MarkdownTextObject(text="*Department*"),
                PlainTextObject(text=ROLE_LABELS[new_ramp_user_response.json()["role"]]),
                PlainTextObject(
                    text=get_ramp_object_label(
                        get_ramp_departments(),
                        new_ramp_user_response.json()["department_id"],
                    )
                ),
                MarkdownTextObject(text="*Location*"),
                MarkdownTextObject(text="*Manager*"),
                PlainTextObject(
                    text=get_ramp_object_label(
                        get_ramp_locations(),
                        new_ramp_user_response.json()["location_id"],
                    )
                ),
                MarkdownTextObject(text=manager_mention),
            ],
        ),
        ActionsBlock(
            elements=[
                ButtonElement(
                    text="View in Ramp",
                    action_id="view_in_ramp",
                    url=urlunparse(
                        (
                            "https",
                            app.config["RAMP_UI_HOSTNAME"],
                            "/people/all",
                            "",
                            "",
                            "/d/user/" + new_ramp_user_response.json()["id"],
                        )
                    ),
                )
            ]
        ),
    ]

    manager_dm_text = (
        new_user_name
        + " joined Ramp! As "
        + possessive_pronoun
        + " manager, you'll be able to view "
        + possessive_pronoun
        + " activity, and request funds on "
        + possessive_pronoun
        + " behalf."
    )
    manager_dm_blocks = [
        SectionBlock(
            text=new_user_mention
            + " joined Ramp! As "
            + possessive_pronoun
            + " manager, you'll be able to view "
            + possessive_pronoun
            + " activity, and request funds on "
            + possessive_pronoun
            + " behalf."
        ),
        ActionsBlock(
            elements=[
                ButtonElement(
                    text="View in Ramp",
                    action_id="view_in_ramp",
                    url=urlunparse(
                        (
                            "https",
                            app.config["RAMP_UI_HOSTNAME"],
                            "/people/all",
                            "",
                            "",
                            "/d/user/" + new_ramp_user_response.json()["id"],
                        )
                    ),
                )
            ]
        ),
        SectionBlock(
            text="If you believe this is an error, please post in <#"
            + app.config["SLACK_SUPPORT_CHANNEL"]
            + ">."
        ),
        *manager_link_email_hint,
    ]

    new_user_dm_blocks = [
        SectionBlock(text="Welcome to Ramp! Here are some tips to help you get started."),
        RichTextBlock(
            elements=[
                RichTextListElement(
                    style="ordered",
                    elements=[
                        RichTextSectionElement(
                            elements=[
                                RichTextElementParts.Text(
                                    text="Finish setting up your account at "
                                ),
                                RichTextElementParts.Link(
                                    url=urlunparse(
                                        (
                                            "https",
                                            app.config["RAMP_UI_HOSTNAME"],
                                            "/sign-in",
                                            "",
                                            urlencode(
                                                {"email": new_ramp_user_response.json()["email"]}
                                            ),
                                            "",
                                        )
                                    ),
                                    text=app.config["RAMP_UI_HOSTNAME"],
                                ),
                            ]
                        ),
                        *new_user_link_email_tip,
                        RichTextSectionElement(
                            elements=[
                                RichTextElementParts.Text(text="Download the Ramp app for "),
                                RichTextElementParts.Link(
                                    url="https://apps.apple.com/us/app/ramp/id1628197245",
                                    text="iOS",
                                ),
                                RichTextElementParts.Text(text=" or "),
                                RichTextElementParts.Link(
                                    url="https://play.google.com/store/apps/details?id=com.ramp.android.app",  # noqa: E501
                                    text="Android",
                                ),
                            ]
                        ),
                        *new_user_activate_physical_card_tip,
                    ],
                )
            ]
        ),
        SectionBlock(
            text="You can also review the onboarding guide in the <https://support.ramp.com/getting-started-as-a-user|Ramp help center>, <https://ramp.com/training/employee-manager|join a live training session>, or <https://www.youtube.com/watch?v=l2Xr08U87vM|watch a video>."  # noqa: E501
        ),
        SectionBlock(
            text="If you have questions, or need help with anything, please post in <#"
            + app.config["SLACK_SUPPORT_CHANNEL"]
            + ">."
        ),
    ]

    slack.chat_postMessage(
        channel=app.config["SLACK_NOTIFY_CHANNEL"],
        thread_ts=cache.get("slack_ineligible_message_" + keycloak_user_id),
        reply_broadcast=True,
        text=new_user_name + " joined Ramp!",
        blocks=notify_channel_blocks,
    )

    cache.set("slack_notifications_sent_" + ramp_user_id, True, timeout=0)

    if manager_slack_user_id is not None:
        slack.chat_postMessage(
            channel=manager_slack_user_id,
            text=manager_dm_text,
            blocks=manager_dm_blocks,
        )

    if new_user_slack_user_id is not None:
        slack.chat_postMessage(
            channel=new_user_slack_user_id,
            text="Welcome to Ramp! Here are some tips to help you get started.",
            blocks=new_user_dm_blocks,
        )


@app.get("/")
@login_required_oidc_redirect
def index() -> Any:
    """
    Generates the main form or messaging if the user shouldn't fill it out
    """
    keycloak_user_response = None

    if "ramp_user_id" not in session or session["ramp_user_id"] is None:
        keycloak_user_response = keycloak.get(  # type: ignore
            url=app.config["KEYCLOAK_SERVER"]
            + "/admin/realms/"
            + app.config["KEYCLOAK_REALM"]
            + "/users/"
            + session["sub"],
            timeout=(5, 5),
        )
        keycloak_user_response.raise_for_status()

        user_json = keycloak_user_response.json()
        attributes = user_json["attributes"] if "attributes" in user_json else {}
        ramp_user_id = (
            attributes["rampUserId"][0]
            if "rampUserId" in attributes and len(attributes["rampUserId"]) > 0
            else None
        )
    else:
        ramp_user_id = session["ramp_user_id"]

    if ramp_user_id is not None:
        ramp_user_response = ramp.get(  # type: ignore
            url=app.config["RAMP_API_URL"] + "/developer/v1/users/" + ramp_user_id,
            timeout=(5, 5),
        )
        ramp_user_response.raise_for_status()

        # store the ramp user id and verified email in keycloak
        # only triggered if an invitation was found during login
        if session["email_verified"]:
            if keycloak_user_response is None:
                keycloak_user_response = keycloak.get(  # type: ignore
                    url=app.config["KEYCLOAK_SERVER"]
                    + "/admin/realms/"
                    + app.config["KEYCLOAK_REALM"]
                    + "/users/"
                    + session["sub"],
                    timeout=(5, 5),
                )
                keycloak_user_response.raise_for_status()

            new_user = keycloak_user_response.json()
            if "id" in new_user:
                del new_user["id"]

            if "username" in new_user:
                del new_user["username"]

            if "attributes" not in new_user:
                new_user["attributes"] = {
                    "rampLoginEmailAddress": [session["email_address"]],
                    "rampUserId": [ramp_user_id],
                }
            else:
                new_user["attributes"]["rampLoginEmailAddress"] = [session["email_address"]]
                new_user["attributes"]["rampUserId"] = [ramp_user_id]

            keycloak_user_response = keycloak.put(  # type: ignore
                url=app.config["KEYCLOAK_SERVER"]
                + "/admin/realms/"
                + app.config["KEYCLOAK_REALM"]
                + "/users/"
                + session["sub"],
                json=new_user,
                timeout=(5, 5),
            )
            keycloak_user_response.raise_for_status()

        # check if the login email address in keycloak matches ramp
        keycloak_user_response = keycloak.get(  # type: ignore
            url=app.config["KEYCLOAK_SERVER"]
            + "/admin/realms/"
            + app.config["KEYCLOAK_REALM"]
            + "/users/"
            + session["sub"],
            timeout=(5, 5),
        )
        keycloak_user_response.raise_for_status()

        if (
            "attributes" not in keycloak_user_response.json()
            or "rampLoginEmailAddress" not in keycloak_user_response.json()["attributes"]
            or len(keycloak_user_response.json()["attributes"]["rampLoginEmailAddress"]) != 1
            or keycloak_user_response.json()["attributes"]["rampLoginEmailAddress"][0]
            != ramp_user_response.json()["email"]
        ):
            return (
                render_template(
                    "sso_mismatch.html",
                    slack_team_id=get_slack_team_id(),
                    slack_support_channel_id=app.config["SLACK_TECHNICAL_SUPPORT_CHANNEL"],
                    slack_support_channel_name=get_slack_channel_name(
                        app.config["SLACK_TECHNICAL_SUPPORT_CHANNEL"]
                    ),
                ),
                424,
            )

        if ramp_user_response.json()["status"] == "USER_ACTIVE":
            return render_template(
                "user_active.html",
                ramp_single_sign_on_uri=urlunparse(
                    (
                        "https",
                        app.config["RAMP_UI_HOSTNAME"],
                        "/sign-in",
                        "",
                        urlencode({"email": ramp_user_response.json()["email"]}),
                        "",
                    )
                ),
                ramp_login_hostname=app.config["RAMP_UI_HOSTNAME"],
                ramp_login_email=ramp_user_response.json()["email"],
                slack_team_id=get_slack_team_id(),
                slack_support_channel_id=app.config["SLACK_SUPPORT_CHANNEL"],
                slack_support_channel_name=get_slack_channel_name(
                    app.config["SLACK_SUPPORT_CHANNEL"]
                ),
            )

        if ramp_user_response.json()["status"] == "USER_INACTIVE":
            return (
                render_template(
                    "user_inactive.html",
                    slack_team_id=get_slack_team_id(),
                    slack_support_channel_id=app.config["SLACK_SUPPORT_CHANNEL"],
                    slack_support_channel_name=get_slack_channel_name(
                        app.config["SLACK_SUPPORT_CHANNEL"]
                    ),
                ),
                423,
            )

        if ramp_user_response.json()["status"] in ("INVITE_PENDING", "USER_ONBOARDING"):
            return render_template(
                "continue_in_ramp.html",
                ramp_single_sign_on_uri=urlunparse(
                    (
                        "https",
                        app.config["RAMP_UI_HOSTNAME"],
                        "/sign-in",
                        "",
                        urlencode({"email": ramp_user_response.json()["email"]}),
                        "",
                    )
                ),
                ramp_login_hostname=app.config["RAMP_UI_HOSTNAME"],
                ramp_login_email=ramp_user_response.json()["email"],
                slack_team_id=get_slack_team_id(),
                slack_support_channel_id=app.config["SLACK_SUPPORT_CHANNEL"],
                slack_support_channel_name=get_slack_channel_name(
                    app.config["SLACK_SUPPORT_CHANNEL"]
                ),
            )

        if ramp_user_response.json()["status"] == "INVITE_EXPIRED":
            return (
                render_template(
                    "invite_expired.html",
                    slack_team_id=get_slack_team_id(),
                    slack_support_channel_id=app.config["SLACK_SUPPORT_CHANNEL"],
                    slack_support_channel_name=get_slack_channel_name(
                        app.config["SLACK_SUPPORT_CHANNEL"]
                    ),
                ),
                423,
            )

        raise InternalServerError(
            "Unrecognized user status " + ramp_user_response.json()["status"] + " in Ramp"
        )

    if session["user_state"] == "ineligible":
        session.clear()
        return (
            render_template(
                "ineligible.html",
                slack_team_id=get_slack_team_id(),
                slack_support_channel_id=app.config["SLACK_SUPPORT_CHANNEL"],
                slack_support_channel_name=get_slack_channel_name(
                    app.config["SLACK_SUPPORT_CHANNEL"]
                ),
            ),
            424,
        )

    if session["is_student"]:
        default_department = app.config["RAMP_DEFAULT_DEPARTMENT_STUDENTS"]
    else:
        default_department = app.config["RAMP_DEFAULT_DEPARTMENT_NON_STUDENTS"]

    if (
        session["is_student"]  # pylint: disable=too-many-boolean-expressions
        or session["zip_code"][:2] == "30"
        or ip_address(request.remote_addr).is_private  # type: ignore
        or ip_address(request.remote_addr) in ip_network("128.61.0.0/16")  # type: ignore
        or ip_address(request.remote_addr) in ip_network("130.207.0.0/16")  # type: ignore
        or ip_address(request.remote_addr) in ip_network("143.215.0.0/16")  # type: ignore
    ):
        default_location = app.config["RAMP_DEFAULT_LOCATION_STUDENTS"]
    else:
        default_location = app.config["RAMP_DEFAULT_LOCATION_NON_STUDENTS"]

    ramp_manager_id = session.get("manager_ramp_id")

    apiary_managers = get_apiary_managers()

    ramp_managers = get_ramp_users()

    if session["can_request_it_admin"]:
        default_role_id = "IT_ADMIN"
    elif session.get("is_finance_team_member"):
        default_role_id = "BUSINESS_BOOKKEEPER"
    else:
        default_role_id = "BUSINESS_USER"

    return render_template(
        "form.html",
        business_legal_name=get_ramp_business()["business_name_legal"],
        sentry_browser_config={
            "dsn": os.environ.get("SENTRY_DSN") or None,
            "environment": os.environ.get("SENTRY_ENVIRONMENT"),
            "release": os.environ.get("SENTRY_RELEASE"),
            "debug": get_debug_flag(),
            "tracesSampleRate": 1.0,
            "profileSessionSampleRate": 1.0,
            "profileLifecycle": "trace",
            "initialScope": {"tags": {"runtime": "browser"}},
        },
        elm_model={
            "firstName": session["first_name"],
            "lastName": session["last_name"],
            "emailAddress": session["email_address"],
            "emailVerified": session["email_verified"],
            "managerApiaryId": session["manager_id"],
            "apiaryManagerOptions": apiary_managers,
            "managerRampId": ramp_manager_id,
            "rampManagerOptions": ramp_managers,
            "selfApiaryId": session["user_id"],
            "addressLineOne": session["address_line_one"],
            "addressLineTwo": session["address_line_two"],
            "city": session["city"],
            "state": session["address_state"],
            "zip": session["zip_code"],
            "googleMapsApiKey": app.config["GOOGLE_MAPS_FRONTEND_API_KEY"],
            "googleClientId": app.config["GOOGLE_CLIENT_ID"],
            "googleOneTapLoginUri": url_for("verify_google_onetap", _external=True),
            "showAdvancedOptions": (
                False
                if cache.get("force_hide_advanced_options_" + session["sub"])
                else (not session["is_student"] or default_role_id != "BUSINESS_USER")
            ),
            "departmentOptions": get_ramp_departments(),
            "departmentId": default_department,
            "locationOptions": get_ramp_locations(),
            "locationId": default_location,
            "roleOptions": {
                "BUSINESS_USER": {
                    "label": "Employee",
                    "enabled": True,
                },
                "BUSINESS_BOOKKEEPER": {
                    "label": "Accounting",
                    "enabled": True,
                },
                "BUSINESS_ADMIN": {
                    "label": "Admin",
                    "enabled": session["can_request_business_admin"],
                },
                "IT_ADMIN": {
                    "label": "IT admin",
                    "enabled": session["can_request_it_admin"],
                },
            },
            "roleId": default_role_id,
            "defaultDepartmentForStudents": app.config["RAMP_DEFAULT_DEPARTMENT_STUDENTS"],
            "defaultDepartmentForNonStudents": app.config["RAMP_DEFAULT_DEPARTMENT_NON_STUDENTS"],
            "defaultLocationForStudents": app.config["RAMP_DEFAULT_LOCATION_STUDENTS"],
            "defaultLocationForNonStudents": app.config["RAMP_DEFAULT_LOCATION_NON_STUDENTS"],
            "rampSignInUri": urlunparse(
                (
                    "https",
                    app.config["RAMP_UI_HOSTNAME"],
                    "/sign-in",
                    "",
                    urlencode({"email": session["email_address"]}),
                    "",
                )
            ),
            "businessLegalName": get_ramp_business()["business_name_legal"],
            "slackSupportChannelDeepLink": urlunparse(
                (
                    "slack",
                    "channel",
                    "",
                    "",
                    urlencode(
                        {"team": get_slack_team_id(), "id": app.config["SLACK_SUPPORT_CHANNEL"]}
                    ),
                    "",
                )
            ),
            "slackSupportChannelName": get_slack_channel_name(app.config["SLACK_SUPPORT_CHANNEL"]),
        },
    )


@app.get("/login")
def login() -> Any:
    """
    Handles the return from Keycloak and collects default values for the form
    """
    token = oauth.keycloak.authorize_access_token()
    session.clear()

    userinfo = token["userinfo"]

    username = userinfo["preferred_username"]
    session["user_id"] = None
    session["username"] = username
    session["first_name"] = (
        userinfo["given_name"]
        if "given_name" in userinfo and userinfo["given_name"] != "Confidential"
        else ""
    )
    session["last_name"] = (
        userinfo["family_name"]
        if "family_name" in userinfo and userinfo["family_name"] != "Confidential"
        else ""
    )
    session["address_line_one"] = ""
    session["address_line_two"] = ""
    session["city"] = ""
    session["address_state"] = None
    session["zip_code"] = ""
    session["manager_id"] = None
    session["manager_ramp_id"] = None
    session["sub"] = userinfo["sub"]
    session["ramp_user_id"] = userinfo["rampUserId"] if "rampUserId" in userinfo else None
    session["is_student"] = True
    session["can_request_business_admin"] = False
    session["can_request_it_admin"] = False
    session["is_finance_team_member"] = False

    if "googleWorkspaceAccount" in userinfo and userinfo["googleWorkspaceAccount"] is not None:
        session["email_address"] = userinfo["googleWorkspaceAccount"]
        session["email_verified"] = False
    else:
        session["email_address"] = userinfo["email"] if "email" in userinfo else None
        session["email_verified"] = False

    set_user(
        {
            "id": session["user_id"],
            "username": session["username"],
            "email": session["email_address"],
            "ip_address": request.remote_addr,
        }
    )

    if "rampUserId" in userinfo and userinfo["rampUserId"] is not None:
        session["user_state"] = "provisioned"
    elif "roles" in userinfo and "eligible" in userinfo["roles"]:
        session["user_state"] = "eligible"
    else:
        session["user_state"] = "ineligible"

    if session["user_state"] == "ineligible" or session["user_state"] == "eligible":
        apiary_user_response = apiary.get(  # type: ignore
            url=app.config["APIARY_URL"] + "/api/v1/users/" + username,
            headers={
                "Accept": "application/json",
            },
            params={"include": "roles,teams,assignments.travel"},
            timeout=(5, 5),
        )

        if apiary_user_response.status_code == 200:
            apiary_user = apiary_user_response.json()["user"]

            session["user_id"] = apiary_user["id"]

            set_user(
                {
                    "id": session["user_id"],
                    "username": session["username"],
                    "email": session["email_address"],
                    "ip_address": request.remote_addr,
                }
            )

            role_check = False

            if "roles" in apiary_user and apiary_user["roles"] is not None:
                for role in apiary_user["roles"]:
                    if role["name"] != "member" and role["name"] != "non-member":
                        role_check = True

                    if role["name"] == "admin":
                        session["can_request_it_admin"] = True

            if "teams" in apiary_user and apiary_user["teams"] is not None:
                for team in apiary_user["teams"]:
                    if team.get("name") == "Finance":
                        session["is_finance_team_member"] = True

            travel_check = False

            if "travel" in apiary_user and apiary_user["travel"] is not None:
                for travel in apiary_user["travel"]:
                    if datetime.now(timezone.utc) < datetime.fromisoformat(
                        travel["travel"]["return_date"][:10]
                    ).astimezone(timezone.utc):
                        travel_check = True

            if (
                apiary_user["is_active"]  # pylint: disable=too-many-boolean-expressions
                and apiary_user["is_access_active"]
                and apiary_user["signed_latest_agreement"]
                and len(apiary_user["teams"]) > 0
                and (role_check or travel_check)
            ):
                session["user_state"] = "eligible"

            if "manager" in apiary_user and apiary_user["manager"] is not None:
                session["manager_id"] = apiary_user["manager"]["id"]
            else:
                session["manager_id"] = None

            if "is_student" in apiary_user and apiary_user["is_student"] is False:
                session["can_request_business_admin"] = True
                session["is_student"] = False

        elif apiary_user_response.status_code == 404:
            pass

        else:
            apiary_user_response.raise_for_status()

    if session["user_state"] == "eligible":
        with sentry_sdk.start_span(op="ldap.connect"):
            ldap = Connection(
                Server("whitepages.gatech.edu", connect_timeout=1),
                auto_bind=True,
                raise_exceptions=True,
                receive_timeout=1,
            )
        with sentry_sdk.start_span(op="ldap.search"):
            result = ldap.search(
                search_base="dc=whitepages,dc=gatech,dc=edu",
                search_filter="(uid=" + username + ")",
                attributes=["postOfficeBox", "homePostalAddress"],
            )

        georgia_tech_mailbox = None
        home_address = None

        if result is True:
            for entry in ldap.entries:
                if (
                    "postOfficeBox" in entry
                    and entry["postOfficeBox"] is not None
                    and entry["postOfficeBox"].value is not None
                ):
                    georgia_tech_mailbox = entry["postOfficeBox"].value
                if (
                    "homePostalAddress" in entry
                    and entry["homePostalAddress"] is not None
                    and entry["homePostalAddress"].value is not None
                    and entry["homePostalAddress"].value != "UNPUBLISHED INFO"
                ):
                    home_address = entry["homePostalAddress"].value

        if (
            home_address is None
            and session["first_name"] + " " + session["last_name"] in BILL_PHYSICAL_CARD_ADDRESSES
        ):
            home_address = BILL_PHYSICAL_CARD_ADDRESSES[
                session["first_name"] + " " + session["last_name"]
            ]

        if georgia_tech_mailbox is not None:
            session["address_line_one"] = "351 Ferst Dr NW"
            session["address_line_two"] = georgia_tech_mailbox.split(",")[0]
            session["city"] = "Atlanta"
            session["address_state"] = "GA"
            session["zip_code"] = "30332"
        elif home_address is not None:
            address_validation_response = post(
                url="https://addressvalidation.googleapis.com/v1:validateAddress",
                params={"key": app.config["GOOGLE_MAPS_BACKEND_API_KEY"]},
                headers={
                    "User-Agent": USER_AGENT,
                },
                json={
                    "address": {
                        "regionCode": "US",
                        "addressLines": [home_address],
                    },
                    "enableUspsCass": True,
                },
                timeout=(5, 5),
            )
            address_validation_response.raise_for_status()

            logging.debug(address_validation_response.text)

            address_validation_json = address_validation_response.json()

            session["address_line_one"] = ""
            session["address_line_two"] = ""
            session["city"] = ""
            session["address_state"] = None

            if (
                "result" in address_validation_json
                and "address" in address_validation_json["result"]
                and "postalAddress" in address_validation_json["result"]["address"]
            ):
                if "postalCode" in address_validation_json["result"]["address"]["postalAddress"]:
                    session["zip_code"] = address_validation_json["result"]["address"][
                        "postalAddress"
                    ]["postalCode"]

                    if fullmatch(r"^\d{5}-\d{4}$", session["zip_code"]):
                        session["zip_code"] = session["zip_code"].split("-")[0]

                if "locality" in address_validation_json["result"]["address"]["postalAddress"]:
                    session["city"] = address_validation_json["result"]["address"]["postalAddress"][
                        "locality"
                    ]

                if (
                    "administrativeArea"
                    in address_validation_json["result"]["address"]["postalAddress"]
                ):
                    session["address_state"] = address_validation_json["result"]["address"][
                        "postalAddress"
                    ]["administrativeArea"]

                if (
                    "addressLines" in address_validation_json["result"]["address"]["postalAddress"]
                    and len(
                        address_validation_json["result"]["address"]["postalAddress"][
                            "addressLines"
                        ]
                    )
                    > 0
                ):
                    session["address_line_one"] = address_validation_json["result"]["address"][
                        "postalAddress"
                    ]["addressLines"][0]

                if (
                    "addressLines" in address_validation_json["result"]["address"]["postalAddress"]
                    and len(
                        address_validation_json["result"]["address"]["postalAddress"][
                            "addressLines"
                        ]
                    )
                    > 1
                ):
                    session["address_line_two"] = address_validation_json["result"]["address"][
                        "postalAddress"
                    ]["addressLines"][1]

        if session["manager_id"] is not None:
            required_department_id = (
                app.config["RAMP_DEFAULT_DEPARTMENT_STUDENTS"]
                if session["is_student"]
                else app.config["RAMP_DEFAULT_DEPARTMENT_NON_STUDENTS"]
            )

            try:
                manager_resolution = resolve_ramp_user(
                    str(session["manager_id"]),
                    required_department_id,
                )

                if "rampUserId" in manager_resolution:
                    session["manager_ramp_id"] = manager_resolution["rampUserId"]
            except RequestException:
                # frontend will retry this validation prior to submission if it doesn't succeed here
                pass

    if session["ramp_user_id"] is None:
        # check ramp to see if they already have an invitation with one of the emails from keycloak
        ramp_user = None

        if "googleWorkspaceAccount" in userinfo and userinfo["googleWorkspaceAccount"] is not None:
            ramp_users_response = ramp.get(  # type: ignore
                url=app.config["RAMP_API_URL"] + "/developer/v1/users",
                params={
                    "email": userinfo["googleWorkspaceAccount"],
                    "page_size": 100,
                },
                timeout=(5, 5),
            )
            ramp_users_response.raise_for_status()

            if len(ramp_users_response.json()["data"]) == 1:
                ramp_user = ramp_users_response.json()["data"][0]

            if len(ramp_users_response.json()["data"]) > 1:
                raise InternalServerError("More than one Ramp user returned for email search")

        if ramp_user is None and "email" in userinfo and userinfo["email"] is not None:
            ramp_users_response = ramp.get(  # type: ignore
                url=app.config["RAMP_API_URL"] + "/developer/v1/users",
                params={
                    "email": userinfo["email"],
                    "page_size": 100,
                },
                timeout=(5, 5),
            )
            ramp_users_response.raise_for_status()

            if len(ramp_users_response.json()["data"]) == 1:
                ramp_user = ramp_users_response.json()["data"][0]

            if len(ramp_users_response.json()["data"]) > 1:
                raise InternalServerError("More than one Ramp user returned for email search")

        if (
            ramp_user is not None
            and "id" in ramp_user
            and ramp_user["id"] is not None
            and "email" in ramp_user
            and ramp_user["email"] is not None
        ):
            # user has an existing ramp invite but not loaded into keycloak
            # verify email address then store in keycloak (handled in index)
            session["ramp_user_id"] = ramp_user["id"]

            return generate_redirect_for_verify_email(ramp_user["email"])

        # user does not have a ramp account but does appear to have a workspace account
        # verify workspace account during login flow
        if session["user_state"] == "eligible" and Address(
            addr_spec=session["email_address"]
        ).domain.split(".")[-2:] == ["robojackets", "org"]:
            return generate_redirect_for_verify_email(session["email_address"])

    if session["user_state"] == "ineligible":
        notify_slack_ineligible.delay(session["sub"])

    return redirect(url_for("index"))


@app.get("/verify-email")
@login_required
@eligible_required
def verify_email() -> Any:
    """
    Redirects user to mailbox provider for email address verification
    """
    return generate_redirect_for_verify_email(request.args["emailAddress"].strip())


def generate_redirect_for_verify_email(email_address: str) -> Any:
    """
    Generates redirect to mailbox provider for email address verification
    """
    email_address_domain = Address(addr_spec=email_address).domain.split(".")[-2:]

    if email_address_domain == ["robojackets", "org"]:
        if app.debug and "+" in Address(addr_spec=email_address).username:
            session["email_address"] = email_address
            session["email_verified"] = True
            return redirect(url_for("index"))

        return oauth.google.authorize_redirect(
            url_for("verify_google_complete", _external=True),
            login_hint=email_address,
            hd="robojackets.org",
        )

    if email_address_domain == ["gatech", "edu"]:
        return oauth.microsoft.authorize_redirect(
            url_for("verify_microsoft_complete", _external=True),
            login_hint=email_address,
            hd="gatech.edu",
        )

    raise BadRequest("Unexpected email address domain")


@app.get("/verify-email/google/complete")
@login_required
def verify_google_complete() -> Response:
    """
    Handles the return from Google and updates session appropriately
    """
    token = oauth.google.authorize_access_token()

    userinfo = token["userinfo"]

    if userinfo.get("hd") != "robojackets.org":
        raise Unauthorized("Invalid hd value")

    if not userinfo.get("email_verified"):
        raise Unauthorized("Email address is not verified")

    session["email_address"] = userinfo["email"]
    session["email_verified"] = True

    return redirect(url_for("index"))  # type: ignore


@app.post("/verify-email/google/complete")
@login_required
@eligible_required
def verify_google_onetap() -> Response:
    """
    Handles a Google One Tap login and updates session appropriately
    """
    userinfo = id_token.verify_oauth2_token(  # type: ignore
        request.form["credential"], requests.Request(), app.config["GOOGLE_CLIENT_ID"]
    )

    if userinfo.get("hd") != "robojackets.org":
        raise Unauthorized("Invalid hd value")

    if not userinfo.get("email_verified"):
        raise Unauthorized("Email address is not verified")

    session["email_address"] = userinfo["email"]
    session["email_verified"] = True

    return redirect(url_for("index"))  # type: ignore


@app.get("/verify-email/microsoft/complete")
@login_required
def verify_microsoft_complete() -> Any:
    """
    Handles the return from Microsoft and updates session appropriately
    """
    try:
        token = oauth.microsoft.authorize_access_token()

        userinfo = token["userinfo"]

        if Address(addr_spec=userinfo["email"]).domain.split(".")[-2:] != [
            "gatech",
            "edu",
        ]:
            raise Unauthorized("Invalid email domain")

        session["email_address"] = userinfo["email"]
        session["email_verified"] = True

        return redirect(url_for("index"))

    except OAuthError:
        return (
            render_template(
                "email_verification_unavailable.html",
                slack_team_id=get_slack_team_id(),
                slack_support_channel_id=app.config["SLACK_TECHNICAL_SUPPORT_CHANNEL"],
                slack_support_channel_name=get_slack_channel_name(
                    app.config["SLACK_TECHNICAL_SUPPORT_CHANNEL"]
                ),
            ),
            500,
        )


@app.get("/get-ramp-user/<int:apiary_id>")
@login_required
@eligible_required
@cache.cached(timeout=0, response_filter=only_cache_if_ramp_id_present)
def get_ramp_user(apiary_id: str) -> Dict[str, str]:
    """
    Provides the Ramp user ID for a given Apiary user ID, if the user has a Ramp account
    """
    # Only simple-mode users call this endpoint, and simple mode is limited to students, whose
    # department is always the students default. If non-students ever call this, the hard-coded
    # department gate will need to match the department selected in the frontend instead.
    return resolve_ramp_user(apiary_id, app.config["RAMP_DEFAULT_DEPARTMENT_STUDENTS"])  # type: ignore  # noqa: E501


@cache.memoize(timeout=0, response_filter=only_cache_if_ramp_id_present)
def resolve_ramp_user(apiary_id: str, required_department_id: Union[str, None]) -> Dict[str, str]:
    """
    Resolves an Apiary user ID to a Ramp user ID via Keycloak, with optional department gating
    """
    apiary_user_response = apiary.get(  # type: ignore
        url=app.config["APIARY_URL"] + "/api/v1/users/" + apiary_id,
        headers={
            "Accept": "application/json",
        },
        timeout=(5, 5),
    )
    apiary_user_response.raise_for_status()

    keycloak_user_response = keycloak.get(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users",
        params={
            "username": apiary_user_response.json()["user"]["uid"],
            "exact": True,
        },
        timeout=(5, 5),
    )
    keycloak_user_response.raise_for_status()

    object_pronoun = "them"
    possessive_pronoun = "their"

    if (
        "gender" in apiary_user_response.json()["user"]
        and apiary_user_response.json()["user"]["gender"] is not None
    ):
        if str.lower(apiary_user_response.json()["user"]["gender"]) == "male":
            object_pronoun = "him"
            possessive_pronoun = "his"
        elif str.lower(apiary_user_response.json()["user"]["gender"]) == "female":
            object_pronoun = "her"
            possessive_pronoun = "her"

    manager_needs_ramp_account = (
        apiary_user_response.json()["user"]["first_name"]
        + f" doesn't have a Ramp account yet. Ask {object_pronoun} to set up {possessive_pronoun} own account first."  # noqa: E501
    )

    if len(keycloak_user_response.json()) == 0:
        return {"error": manager_needs_ramp_account}

    if len(keycloak_user_response.json()) == 1:
        keycloak_user = keycloak_user_response.json()[0]
        if "attributes" in keycloak_user and "rampUserId" in keycloak_user["attributes"]:
            ramp_user_id = keycloak_user["attributes"]["rampUserId"][0]
        else:
            return {"error": manager_needs_ramp_account}
    else:
        return {"error": "More than one result for manager search in Keycloak"}

    ramp_user_response = ramp.get(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/users/" + ramp_user_id,
        timeout=(5, 5),
    )
    ramp_user_response.raise_for_status()

    if (
        required_department_id is not None
        and ramp_user_response.json()["department_id"] != required_department_id
    ):
        return {"error": "Please select a manager within your department"}

    if ramp_user_response.json()["status"] == "USER_ACTIVE":
        return {
            "rampUserId": ramp_user_id,
        }

    if ramp_user_response.json()["status"] in ("INVITE_PENDING", "USER_ONBOARDING"):
        return {
            "error": apiary_user_response.json()["user"]["first_name"]
            + f" hasn't finished setting up {possessive_pronoun} Ramp account yet. Ask {object_pronoun} to finish setting up {possessive_pronoun} own account first."  # noqa: E501
        }

    return {"error": "Unrecognized manager account status in Ramp"}


@app.post("/create-ramp-account")
@login_required
@eligible_required
@email_verified_required
def create_ramp_account() -> tuple[dict[str, Any], int]:
    """
    Creates a new Ramp account; the deferred-job ID is stored in session for status polling
    """
    if request.json["role"] not in [
        "BUSINESS_USER",
        "BUSINESS_BOOKKEEPER",
        "IT_ADMIN",
        "BUSINESS_ADMIN",
    ]:
        raise BadRequest("Invalid role")

    if (
        request.json["role"] == "BUSINESS_ADMIN"
        and session["can_request_business_admin"] is not True
    ):
        raise Unauthorized("Invalid role")

    if request.json["role"] == "IT_ADMIN" and session["can_request_it_admin"] is not True:
        raise Unauthorized("Invalid role")

    if "create_ramp_account_task_id" in session:
        raise Conflict("Create Ramp account already in progress")

    if session.get("ramp_user_id") is not None:
        raise Conflict("Ramp account already created")

    get_keycloak_user_response = keycloak.get(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + session["sub"],
        timeout=(5, 5),
    )
    get_keycloak_user_response.raise_for_status()

    new_user = get_keycloak_user_response.json()
    if "id" in new_user:
        del new_user["id"]

    if "username" in new_user:
        del new_user["username"]

    if "attributes" not in new_user:
        new_user["attributes"] = {"rampLoginEmailAddress": [session["email_address"]]}
    else:
        new_user["attributes"]["rampLoginEmailAddress"] = [session["email_address"]]

    new_user["firstName"] = request.json["firstName"].strip()
    new_user["lastName"] = request.json["lastName"].strip()

    keycloak_user_response = keycloak.put(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + session["sub"],
        json=new_user,
        timeout=(5, 5),
    )
    keycloak_user_response.raise_for_status()

    request_body = {
        "department_id": request.json["departmentId"].strip(),
        "email": session["email_address"],
        "first_name": request.json["firstName"].strip(),
        "idempotency_key": uuid4().hex,
        "last_name": request.json["lastName"].strip(),
        "location_id": request.json["locationId"].strip(),
        "role": request.json["role"].strip(),
    }

    # Ramp doesn't allow setting a manager for admins via API
    if request.json["role"] != "BUSINESS_ADMIN":
        request_body["direct_manager_id"] = request.json["directManagerId"].strip()

    cache.set(
        "physical_card_ordered_" + session["sub"],
        bool(request.json.get("orderPhysicalCard", False)),
        timeout=0,
    )

    ramp_invite_user_response = ramp.post(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/users/deferred",
        json=request_body,
        timeout=(5, 5),
    )
    ramp_invite_user_response.raise_for_status()

    session["create_ramp_account_task_id"] = ramp_invite_user_response.json()["id"]

    return {}, 202


@app.get("/create-ramp-account")
@login_required
@eligible_required
@email_verified_required
def get_ramp_account_status() -> Dict[str, str]:
    """
    Get the task status for a previous request to create a Ramp account
    """
    if "create_ramp_account_task_id" not in session:
        raise BadRequest("No pending create Ramp account task")

    task_id = session["create_ramp_account_task_id"]

    ramp_task_status = ramp.get(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/users/deferred/status/" + task_id,
        timeout=(5, 5),
    )
    ramp_task_status.raise_for_status()

    task_status = ramp_task_status.json()["status"]

    if task_status == "SUCCESS":
        session["ramp_user_id"] = ramp_task_status.json()["data"]["user_id"]
        session.pop("create_ramp_account_task_id", None)

        store_ramp_user_id_in_keycloak.delay(session["sub"], session["ramp_user_id"])
        remove_eligible_role.delay(session["sub"])
        import_user_to_org_chart.delay(session["ramp_user_id"])
        notify_slack_account_created.delay(session["sub"], session["ramp_user_id"])
    elif task_status == "ERROR":
        session.pop("create_ramp_account_task_id", None)

    return {
        "taskStatus": task_status,
    }


@app.post("/order-physical-card")
@login_required
@eligible_required
@email_verified_required
def order_physical_card() -> tuple[dict[str, Any], int]:
    """
    Order a physical card for the logged-in user
    """
    if "ramp_user_id" not in session or session["ramp_user_id"] is None:
        raise Conflict("No Ramp user ID in session")

    cache.set("physical_card_ordered_" + session["sub"], True, timeout=0)

    ramp_order_physical_card_response = ramp.post(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/cards/physical",
        json={
            "shipping_address": {
                "address1": request.json["addressLineOne"].strip(),
                "address2": (
                    request.json["addressLineTwo"].strip()
                    if request.json["addressLineTwo"].strip() != ""
                    else None
                ),
                "city": request.json["city"].strip(),
                "country": "US",
                "postal_code": request.json["zip"].strip(),
                "state": request.json["state"].strip(),
            },
            "user_id": session["ramp_user_id"],
        },
        timeout=(5, 5),
    )
    ramp_order_physical_card_response.raise_for_status()

    return {
        "cardId": ramp_order_physical_card_response.json()["id"],
    }, 201


@app.post("/slack")
def handle_slack_event() -> Dict[str, str]:
    """
    Handle an interaction event from Slack

    https://docs.slack.dev/interactivity/handling-user-interaction#payloads
    """
    verifier = SignatureVerifier(app.config["SLACK_SIGNING_SECRET"])

    if not verifier.is_valid_request(request.get_data(), request.headers):  # type: ignore
        raise Unauthorized("signature verification failed")

    payload = loads(request.form.get("payload"))  # type: ignore

    if payload["actions"][0]["action_id"] == "view_in_apiary":
        return {"status": "ok"}

    if payload["actions"][0]["action_id"] == "view_in_ramp":
        return {"status": "ok"}

    if payload["actions"][0]["action_id"] == "view_in_keycloak":
        return {"status": "ok"}

    if payload["actions"][0]["action_id"] == "grant_eligibility_in_keycloak":
        add_eligible_role_response = keycloak.post(  # type: ignore
            url=app.config["KEYCLOAK_SERVER"]
            + "/admin/realms/"
            + app.config["KEYCLOAK_REALM"]
            + "/users/"
            + str(UUID(payload["actions"][0]["value"]))
            + "/role-mappings/clients/"
            + app.config["KEYCLOAK_CLIENT_UUID"],
            timeout=(5, 5),
            json=[{"id": app.config["KEYCLOAK_CLIENT_ROLE_ELIGIBLE"], "name": "eligible"}],
        )
        add_eligible_role_response.raise_for_status()

        slack = WebhookClient(url=payload["response_url"])
        slack.send(
            text=payload["message"]["text"],
            blocks=[
                payload["message"]["blocks"][0],
                ActionsBlock(
                    elements=[
                        payload["message"]["blocks"][1]["elements"][0],
                        payload["message"]["blocks"][1]["elements"][1],
                    ]
                ),
                SectionBlock(
                    text=":white_check_mark: *<@"
                    + payload["user"]["id"]
                    + "> granted eligibility in Keycloak*"
                ),
            ],
            replace_original=True,
        )

        return {"status": "ok"}

    raise BadRequest("unrecognized action_id")


@app.get("/ping")
def ping() -> Dict[str, str]:
    """
    Returns an arbitrary successful response, for health checks
    """
    return {"status": "ok"}


@shared_task
def handle_invitation_delivery(invitation_url: str) -> None:
    """
    Process an invitation URL delivered from Postmark
    """
    query_string = parse_qs(urlparse(invitation_url).query)

    if query_string["business_id"][0] != get_ramp_business()["id"]:
        logging.warning("Received invitation for a different businessId, ignoring")

        return

    ramp_users_response = ramp.get(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/users",
        params={
            "email": query_string["email"][0],
            "page_size": 100,
        },
        timeout=(5, 5),
    )
    ramp_users_response.raise_for_status()

    if len(ramp_users_response.json()["data"]) == 0:
        raise Exception("Could not locate Ramp user for invitation")

    if len(ramp_users_response.json()["data"]) == 1:
        ramp_user = ramp_users_response.json()["data"][0]

    else:
        raise Exception("More than one Ramp user returned for email search")

    ramp_user_id = ramp_user["id"]

    search_keycloak_user_response = keycloak.get(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users",
        params={
            "q": "googleWorkspaceAccount:" + ramp_user["email"],
        },
        timeout=(5, 5),
    )
    search_keycloak_user_response.raise_for_status()

    if len(search_keycloak_user_response.json()) == 0:
        raise Exception("Could not locate Keycloak user for invitation")

    if len(search_keycloak_user_response.json()) == 1:
        keycloak_user_id = search_keycloak_user_response.json()[0]["id"]

    else:
        raise Exception("More than one Keycloak user returned for email search")

    store_ramp_user_id_in_keycloak.delay(keycloak_user_id, ramp_user_id)
    remove_eligible_role.delay(keycloak_user_id)
    import_user_to_org_chart.delay(ramp_user_id)
    notify_slack_account_created.delay(keycloak_user_id, ramp_user_id)


@app.post("/postmark")
def handle_postmark_inbound_event() -> Any:
    """
    Handle an inbound email from Postmark
    """
    if (
        "Authorization" not in request.headers
        or request.headers["Authorization"] is None
        or request.headers["Authorization"] != app.config["POSTMARK_AUTHORIZATION"]
    ):
        raise Unauthorized("authorization does not match")

    if "TextBody" not in request.json or request.json["TextBody"] is None:
        raise BadRequest("missing TextBody")

    results = search(
        r"\[(?P<invitation_url>https://[a-z]+\.ramp\.com/s/app/invite-sign-up.+)\]",
        request.json["TextBody"],
    )

    if results is None:
        return {"status": "ok"}

    handle_invitation_delivery.delay(results.group("invitation_url"))

    return {"status": "ok"}, 202


def verify_ramp_webhook_signature(raw_body: bytes, signature: str, secret: str) -> bool:
    """
    Verify the X-Ramp-Signature header against the raw request body
    """
    digest = hmac.new(secret.encode("utf-8"), raw_body, sha256).digest()
    expected_hex = digest.hex()
    expected_base64 = b64encode(digest).decode("utf-8")

    return hmac.compare_digest(signature, expected_hex) or hmac.compare_digest(
        signature, expected_base64
    )


def find_keycloak_user_id_for_ramp_user(ramp_user_id: str, ramp_user_email: str) -> str:
    """
    Find the Keycloak user ID for a Ramp user, searching by rampUserId then email attributes
    """
    search_keycloak_user_response = keycloak.get(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users",
        params={
            "q": "rampUserId:" + ramp_user_id,
        },
        timeout=(5, 5),
    )
    search_keycloak_user_response.raise_for_status()

    if len(search_keycloak_user_response.json()) == 1:
        return str(search_keycloak_user_response.json()[0]["id"])

    if len(search_keycloak_user_response.json()) > 1:
        raise Exception("More than one Keycloak user returned for rampUserId search")

    search_keycloak_user_response = keycloak.get(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users",
        params={
            "q": "rampLoginEmailAddress:" + ramp_user_email,
        },
        timeout=(5, 5),
    )
    search_keycloak_user_response.raise_for_status()

    if len(search_keycloak_user_response.json()) == 1:
        return str(search_keycloak_user_response.json()[0]["id"])

    if len(search_keycloak_user_response.json()) > 1:
        raise Exception("More than one Keycloak user returned for rampLoginEmailAddress search")

    search_keycloak_user_response = keycloak.get(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users",
        params={
            "q": "googleWorkspaceAccount:" + ramp_user_email,
        },
        timeout=(5, 5),
    )
    search_keycloak_user_response.raise_for_status()

    if len(search_keycloak_user_response.json()) == 0:
        raise Exception("Could not locate Keycloak user for Ramp user")

    if len(search_keycloak_user_response.json()) == 1:
        return str(search_keycloak_user_response.json()[0]["id"])

    raise Exception("More than one Keycloak user returned for googleWorkspaceAccount search")


def provision_ramp_user(keycloak_user_id: str, ramp_user_id: str) -> None:
    """
    Run the standard post-provisioning tasks for a newly active Ramp user
    """
    store_ramp_user_id_in_keycloak.delay(keycloak_user_id, ramp_user_id)
    remove_eligible_role.delay(keycloak_user_id)
    import_user_to_org_chart.delay(ramp_user_id)
    notify_slack_account_created.delay(keycloak_user_id, ramp_user_id)


@shared_task
def verify_ramp_webhook_subscription(challenge: str) -> None:
    """
    Verify a pending Ramp webhook subscription using the challenge from webhooks.verification
    """
    ramp_webhooks_response = ramp.get(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/webhooks",
        timeout=(5, 5),
    )
    ramp_webhooks_response.raise_for_status()

    for subscription in ramp_webhooks_response.json():
        if subscription["status"] != "pending_verification":
            continue

        try:
            verify_response = ramp.post(  # type: ignore
                url=app.config["RAMP_API_URL"]
                + "/developer/v1/webhooks/"
                + subscription["id"]
                + "/verify",
                json={"challenge": challenge},
                timeout=(5, 5),
            )
            verify_response.raise_for_status()
        except RequestException:
            logging.exception(
                "Failed to verify webhook subscription %s",
                subscription["id"],
            )


@shared_task
def handle_invite_accepted(ramp_user_id: str) -> None:
    """
    Process a users.invite_accepted webhook event from Ramp
    """
    ramp_user_response = ramp.get(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/users/" + ramp_user_id,
        timeout=(5, 5),
    )
    ramp_user_response.raise_for_status()

    keycloak_user_id = find_keycloak_user_id_for_ramp_user(
        ramp_user_id, ramp_user_response.json()["email"]
    )

    provision_ramp_user(keycloak_user_id, ramp_user_id)


@app.post("/ramp")
def handle_ramp_webhook_event() -> Any:
    """
    Handle a webhook event from Ramp
    """
    raw_body = request.get_data()
    webhook_secret = app.config.get("RAMP_WEBHOOK_SECRET")

    if webhook_secret is not None:
        signature = request.headers.get("X-Ramp-Signature")

        if signature is None or not verify_ramp_webhook_signature(
            raw_body, signature, webhook_secret
        ):
            raise Unauthorized("signature verification failed")

        logging.info("Ramp webhook signature verified")
    else:
        logging.warning("RAMP_WEBHOOK_SECRET is not set, skipping signature verification")

    payload = loads(raw_body)
    logging.info("Received Ramp webhook: %s", raw_body.decode("utf-8"))

    if "business_id" in payload and payload["business_id"] != get_ramp_business()["id"]:
        logging.warning("Received webhook for a different business_id, ignoring")

        return {"status": "ok"}

    if "id" in payload:
        cache_result = cache.cache.inc("ramp_webhook_event_" + payload["id"])
        if cache_result is not None and cache_result > 1:
            logging.warning("duplicate Ramp webhook event %s, returning early", payload["id"])
            return {"status": "ok"}

    if payload["type"] == "webhooks.verification":
        verify_ramp_webhook_subscription.delay(payload["challenge"])
    elif payload["type"] == "users.invite_accepted":
        handle_invite_accepted.delay(payload["object"]["id"])
    else:
        logging.info("Ignoring unrecognized Ramp webhook event type %s", payload["type"])

    return {"status": "ok"}, 202


@app.cli.command("clear-cache")
def clear_cache() -> None:
    """
    Clears the cache
    """
    cache.clear()
    print("Cache cleared.")


@app.cli.command("force-hide-advanced-options")
@click.argument("keycloak_user_id")
def force_hide_advanced_options(keycloak_user_id: str) -> None:
    """
    Force showAdvancedOptions=false for a Keycloak user (smoke testing).
    """
    cache.set("force_hide_advanced_options_" + keycloak_user_id, True, timeout=0)
    print("Forced hide advanced options for " + keycloak_user_id + ".")


@app.cli.command("send-slack-messages")
@click.argument("ramp_user_id")
def send_slack_messages(ramp_user_id: str) -> None:
    """
    Manually send Slack welcome messages for a given user
    """
    search_keycloak_user_response = keycloak.get(  # type: ignore
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users",
        params={
            "q": "rampUserId:" + ramp_user_id,
        },
        timeout=(5, 5),
    )
    search_keycloak_user_response.raise_for_status()

    if len(search_keycloak_user_response.json()) == 1:
        keycloak_user_id = search_keycloak_user_response.json()[0]["id"]
    else:
        raise Exception("Did not find exactly one match in Keycloak")

    notify_slack_account_created(keycloak_user_id, ramp_user_id)

    print("Slack messages sent.")


@app.cli.command("create-ramp-webhook-subscription")
def create_ramp_webhook_subscription() -> None:
    """
    Create a Ramp webhook subscription for users.invite_accepted events.

    Requires SERVER_NAME to be configured. After creation, set FLASK_RAMP_WEBHOOK_SECRET to the
    returned secret and restart the application to enable signature verification.
    """
    endpoint_url = url_for("handle_ramp_webhook_event", _external=True, _scheme="https")

    ramp_webhook_response = ramp.post(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/webhooks",
        json={
            "endpoint_url": endpoint_url,
            "event_types": [
                "users.invite_accepted",
                "tests.test_event",
            ],
        },
        timeout=(5, 5),
    )
    ramp_webhook_response.raise_for_status()

    subscription = ramp_webhook_response.json()

    print("Webhook subscription created:")
    print("  id:", subscription["id"])
    print("  status:", subscription["status"])
    print("  endpoint_url:", endpoint_url)
    print("  secret:", subscription["secret"])
    print()
    print("Set FLASK_RAMP_WEBHOOK_SECRET to the secret above and restart the application.")


@app.cli.command("send-mock-ramp-webhook-event")
def send_mock_ramp_webhook_event() -> None:
    """
    Send a mock tests.test_event webhook to confirm delivery and signature verification
    """
    ramp_mock_webhook_response = ramp.post(  # type: ignore
        url=app.config["RAMP_API_URL"] + "/developer/v1/webhooks/mock-webhook-event",
        json={
            "event_type": "tests.test_event",
            "object_id": str(uuid4()),
            "object_metadata": {},
        },
        timeout=(5, 5),
    )
    ramp_mock_webhook_response.raise_for_status()

    print(ramp_mock_webhook_response.json())
