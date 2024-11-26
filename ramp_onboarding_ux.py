"""
Overengineered web form to facilitate onboarding users to Ramp
"""

from csv import DictReader
from datetime import datetime, timezone
from email.headerregistry import Address
from re import fullmatch
from typing import Any, Dict, Union
from uuid import UUID, uuid4

from authlib.integrations.flask_client import OAuth  # type: ignore

from flask import Flask, Response, redirect, render_template, request, session, url_for
from flask.helpers import get_debug_flag

from google.auth.transport import requests
from google.oauth2 import id_token

from ldap3 import Connection, Server

from requests import delete, get, post, put

import sentry_sdk
from sentry_sdk import capture_message, set_user
from sentry_sdk.integrations.flask import FlaskIntegration
from sentry_sdk.integrations.pure_eval import PureEvalIntegration

from werkzeug.exceptions import BadRequest, InternalServerError, Unauthorized


def traces_sampler(sampling_context: Dict[str, Dict[str, str]]) -> bool:
    """
    Ignore ping events, sample all other events
    """
    try:
        request_uri = sampling_context["wsgi_environ"]["REQUEST_URI"]
    except KeyError:
        return False

    return request_uri != "/ping"


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

oauth = OAuth(app)
oauth.register(
    name="keycloak",
    server_metadata_url=app.config["KEYCLOAK_METADATA_URL"],
    client_kwargs={"scope": "openid email profile"},
)
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email"},
)
oauth.register(
    name="microsoft",
    server_metadata_url=app.config["MICROSOFT_METADATA_URL"],
    client_kwargs={"scope": "openid email"},
)

BILL_PHYSICAL_CARD_ADDRESSES = {}

for row in DictReader(app.config["BILL_PHYSICAL_CARD_ORDERS_CSV"].split("\n")):
    if row["Order Status"] in ["Activated", "Shipped"]:
        BILL_PHYSICAL_CARD_ADDRESSES[row["Card Holder"]] = row["Shipping Address"]


def get_keycloak_access_token() -> Union[str, None]:
    """
    Get an access token for Keycloak.
    """
    keycloak_access_token_response = post(
        url=app.config["KEYCLOAK_SERVER"] + "/realms/master/protocol/openid-connect/token",
        data={
            "client_id": app.config["KEYCLOAK_ADMIN_CLIENT_ID"],
            "client_secret": app.config["KEYCLOAK_ADMIN_CLIENT_SECRET"],
            "grant_type": "client_credentials",
        },
        timeout=(5, 5),
    )

    if keycloak_access_token_response.status_code == 200:
        return keycloak_access_token_response.json()["access_token"]  # type: ignore

    print("Keycloak returned status code:", keycloak_access_token_response.status_code)
    print("Response body:", keycloak_access_token_response.text)

    return None


def get_ramp_access_token(scope: str) -> Union[str, None]:
    """
    Get an access token for Ramp.
    """
    ramp_access_token_response = post(
        url=app.config["RAMP_API_URL"] + "/developer/v1/token",
        data={
            "grant_type": "client_credentials",
            "scope": scope,
        },
        auth=(
            app.config["RAMP_CLIENT_ID"],
            app.config["RAMP_CLIENT_SECRET"],
        ),
        timeout=(5, 5),
    )

    if ramp_access_token_response.status_code == 200:
        return ramp_access_token_response.json()["access_token"]  # type: ignore

    print("Ramp returned status code:", ramp_access_token_response.status_code)
    print("Response body:", ramp_access_token_response.text)

    return None


@app.get("/")
def index() -> Any:  # pylint: disable=too-many-branches,too-many-locals,too-many-statements
    """
    Generates the main form or messaging if the user shouldn't fill it out
    """
    if "user_state" not in session:
        return oauth.keycloak.authorize_redirect(url_for("login", _external=True))

    set_user(
        {
            "id": session["user_id"],
            "username": session["username"],
            "email": session["email_address"],
            "ip_address": request.remote_addr,
        }
    )

    if "ramp_user_id" not in session or session["ramp_user_id"] is None:
        keycloak_access_token = get_keycloak_access_token()

        if keycloak_access_token is None:
            raise InternalServerError("Failed to retrieve access token for Keycloak")

        keycloak_user_response = get(
            url=app.config["KEYCLOAK_SERVER"]
            + "/admin/realms/"
            + app.config["KEYCLOAK_REALM"]
            + "/users/"
            + session["sub"],
            headers={
                "Authorization": "Bearer " + keycloak_access_token,
            },
            timeout=(5, 5),
        )

        if keycloak_user_response.status_code != 200:
            print("Keycloak returned status code:", keycloak_user_response.status_code)
            print("Response body:", keycloak_user_response.text)
            raise InternalServerError("Failed to retrieve user from Keycloak")

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
        ramp_access_token = get_ramp_access_token("users:read")

        if ramp_access_token is None:
            raise InternalServerError("Failed to retrieve access token for Ramp")

        ramp_user_response = get(
            url=app.config["RAMP_API_URL"] + "/developer/v1/users/" + ramp_user_id,
            headers={
                "Authorization": "Bearer " + ramp_access_token,
            },
            timeout=(5, 5),
        )

        if ramp_user_response.status_code != 200:
            print("Ramp returned status code:", ramp_user_response.status_code)
            print("Response body:", ramp_user_response.text)
            raise InternalServerError("Failed to retrieve user from Ramp")

        if ramp_user_response.json()["status"] == "USER_ACTIVE":
            session.clear()
            return render_template(
                "provisioned.html",
                ramp_login_hostname=app.config["RAMP_UI_HOSTNAME"],
                ramp_login_email=ramp_user_response.json()["email"],
            )

        if ramp_user_response.json()["status"] in ("INVITE_PENDING", "USER_ONBOARDING"):
            return render_template(
                "continue_in_ramp.html",
                ramp_login_hostname=app.config["RAMP_UI_HOSTNAME"],
                ramp_login_email=ramp_user_response.json()["email"],
            )

        raise InternalServerError(
            "Unrecognized user status " + ramp_user_response.json()["status"] + " in Ramp"
        )

    if session["user_state"] == "ineligible":
        session.clear()
        return render_template("ineligible.html")

    apiary_managers_response = get(
        url=app.config["APIARY_URL"] + "/api/v1/users/managers",
        headers={
            "Authorization": "Bearer " + app.config["APIARY_TOKEN"],
            "Accept": "application/json",
        },
        timeout=(5, 5),
    )

    managers = {}

    if apiary_managers_response.status_code == 200:
        apiary_managers_json = apiary_managers_response.json()

        for manager in apiary_managers_json["users"]:
            managers[manager["id"]] = manager["full_name"]
    else:
        print("Apiary returned status code:", apiary_managers_response.status_code)
        print("Response body:", apiary_managers_response.text)
        raise InternalServerError("Unable to load managers from Apiary")

    ramp_access_token = get_ramp_access_token("departments:read locations:read")

    if ramp_access_token is None:
        raise InternalServerError("Failed to retrieve access token for Ramp")

    ramp_departments_response = get(
        url=app.config["RAMP_API_URL"] + "/developer/v1/departments",
        headers={
            "Authorization": "Bearer " + ramp_access_token,
        },
        timeout=(5, 5),
    )

    if ramp_departments_response.status_code != 200:
        print("Ramp returned status code:", ramp_departments_response.status_code)
        print("Response body:", ramp_departments_response.text)
        raise InternalServerError("Failed to retrieve departments from Ramp")

    departments = {}

    for department in ramp_departments_response.json()["data"]:
        departments[department["id"]] = {
            "label": department["name"],
            "enabled": department["id"] != app.config["RAMP_DISABLED_DEPARTMENT"],
        }

    ramp_locations_response = get(
        url=app.config["RAMP_API_URL"] + "/developer/v1/locations",
        headers={
            "Authorization": "Bearer " + ramp_access_token,
        },
        timeout=(5, 5),
    )

    if session["is_student"]:
        default_department = app.config["RAMP_DEFAULT_DEPARTMENT_STUDENTS"]
    else:
        default_department = app.config["RAMP_DEFAULT_DEPARTMENT_NON_STUDENTS"]

    if ramp_locations_response.status_code != 200:
        print("Ramp returned status code:", ramp_locations_response.status_code)
        print("Response body:", ramp_locations_response.text)
        raise InternalServerError("Failed to retrieve locations from Ramp")

    locations = {}

    for location in ramp_locations_response.json()["data"]:
        locations[location["id"]] = {
            "label": location["name"],
            "enabled": True,
        }

    if session["is_student"] or session["zip_code"][:2] == "30":
        default_location = app.config["RAMP_DEFAULT_LOCATION_STUDENTS"]
    else:
        default_location = app.config["RAMP_DEFAULT_LOCATION_NON_STUDENTS"]

    return render_template(
        "form.html",
        elm_model={
            "firstName": session["first_name"],
            "lastName": session["last_name"],
            "emailAddress": session["email_address"],
            "emailVerified": session["email_verified"],
            "managerId": session["manager_id"],
            "managerOptions": managers,
            "selfId": session["user_id"],
            "addressLineOne": session["address_line_one"],
            "addressLineTwo": session["address_line_two"],
            "city": session["city"],
            "state": session["address_state"],
            "zip": session["zip_code"],
            "googleMapsApiKey": app.config["GOOGLE_MAPS_FRONTEND_API_KEY"],
            "googleClientId": app.config["GOOGLE_CLIENT_ID"],
            "googleOneTapLoginUri": url_for("verify_google_onetap", _external=True),
            "showAdvancedOptions": not session["is_student"],
            "departmentOptions": departments,
            "departmentId": default_department,
            "locationOptions": locations,
            "locationId": default_location,
            "roleOptions": {
                "BUSINESS_USER": {
                    "label": "Employee",
                    "enabled": True,
                },
                "BUSINESS_BOOKKEEPER": {
                    "label": "Bookkeeper",
                    "enabled": True,
                },
                "BUSINESS_ADMIN": {
                    "label": "Admin",
                    "enabled": not session["is_student"],
                },
            },
            "roleId": "BUSINESS_USER",
            "defaultDepartmentForStudents": app.config["RAMP_DEFAULT_DEPARTMENT_STUDENTS"],
            "defaultDepartmentForNonStudents": app.config["RAMP_DEFAULT_DEPARTMENT_NON_STUDENTS"],
            "defaultLocationForStudents": app.config["RAMP_DEFAULT_LOCATION_STUDENTS"],
            "defaultLocationForNonStudents": app.config["RAMP_DEFAULT_LOCATION_NON_STUDENTS"],
        },
    )


@app.get("/login")
def login() -> Any:  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
    """
    Handles the return from Keycloak and collects default values for the form
    """
    token = oauth.keycloak.authorize_access_token()

    userinfo = token["userinfo"]

    username = userinfo["preferred_username"]
    session["user_id"] = None
    session["username"] = username
    session["first_name"] = userinfo["given_name"] if "given_name" in userinfo else None
    session["last_name"] = userinfo["family_name"] if "family_name" in userinfo else None
    session["address_line_one"] = ""
    session["address_line_two"] = ""
    session["city"] = ""
    session["address_state"] = None
    session["zip_code"] = ""
    session["manager_id"] = None
    session["sub"] = userinfo["sub"]
    session["ramp_user_id"] = userinfo["rampUserId"] if "rampUserId" in userinfo else None
    session["is_student"] = True

    if "googleWorkspaceAccount" in userinfo:
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
        apiary_user_response = get(
            url=app.config["APIARY_URL"] + "/api/v1/users/" + username,
            headers={
                "Authorization": "Bearer " + app.config["APIARY_TOKEN"],
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
                session["is_student"] = False

        else:
            print("Apiary returned status code:", apiary_user_response.status_code)
            print("Response body:", apiary_user_response.text)
            raise InternalServerError("Unable to retrieve user information from Apiary")

    if session["user_state"] == "eligible":  # pylint: disable=too-many-nested-blocks
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
                json={
                    "address": {
                        "regionCode": "US",
                        "addressLines": [home_address],
                    },
                    "enableUspsCass": True,
                },
                timeout=(5, 5),
            )

            print(address_validation_response.status_code)
            print(address_validation_response.text)

            if address_validation_response.status_code == 200:
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
                    if (
                        "postalCode"
                        in address_validation_json["result"]["address"]["postalAddress"]
                    ):
                        session["zip_code"] = address_validation_json["result"]["address"][
                            "postalAddress"
                        ]["postalCode"]

                        if fullmatch(r"^\d{5}-\d{4}$", session["zip_code"]):
                            session["zip_code"] = session["zip_code"].split("-")[0]

                    if "locality" in address_validation_json["result"]["address"]["postalAddress"]:
                        session["city"] = address_validation_json["result"]["address"][
                            "postalAddress"
                        ]["locality"]

                    if (
                        "administrativeArea"
                        in address_validation_json["result"]["address"]["postalAddress"]
                    ):
                        session["address_state"] = address_validation_json["result"]["address"][
                            "postalAddress"
                        ]["administrativeArea"]

                    if (
                        "addressLines"
                        in address_validation_json["result"]["address"]["postalAddress"]
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
                        "addressLines"
                        in address_validation_json["result"]["address"]["postalAddress"]
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
            else:
                capture_message(
                    "Failed to validate homePostalAddress from Whitepages: "
                    + address_validation_response.text
                )

    return redirect(url_for("index"))


@app.get("/verify-email")
def verify_email() -> Any:
    """
    Redirects user to mailbox provider for email address verification
    """
    if "user_state" not in session:
        raise Unauthorized("Not logged in")

    set_user(
        {
            "id": session["user_id"],
            "username": session["username"],
            "email": session["email_address"],
            "ip_address": request.remote_addr,
        }
    )

    if session["user_state"] != "eligible":
        raise Unauthorized("Not eligible")

    if app.debug and "force" in request.args and request.args["force"] == "true":
        session["email_address"] = request.args["emailAddress"]
        session["email_verified"] = True
        return redirect(url_for("index"))

    email_address_domain = Address(addr_spec=request.args["emailAddress"]).domain.split(".")[-2:]

    if email_address_domain == ["robojackets", "org"]:
        return oauth.google.authorize_redirect(
            url_for("verify_google_complete", _external=True),
            login_hint=request.args["emailAddress"],
            hd="robojackets.org",
        )

    if email_address_domain == ["gatech", "edu"]:
        return oauth.microsoft.authorize_redirect(
            url_for("verify_microsoft_complete", _external=True),
            login_hint=request.args["emailAddress"],
            hd="gatech.edu",
        )

    raise BadRequest("Unexpected email address domain")


@app.get("/verify-email/google/complete")
def verify_google_complete() -> Response:
    """
    Handles the return from Google and updates session appropriately
    """
    if "user_state" not in session:
        raise Unauthorized("Not logged in")

    set_user(
        {
            "id": session["user_id"],
            "username": session["username"],
            "email": session["email_address"],
            "ip_address": request.remote_addr,
        }
    )

    token = oauth.google.authorize_access_token()

    userinfo = token["userinfo"]

    session["email_address"] = userinfo["email"]
    session["email_verified"] = True

    return redirect(url_for("index"))  # type: ignore


@app.post("/verify-email/google/complete")
def verify_google_onetap() -> Response:
    """
    Handles a Google One Tap login and updates session appropriately
    """
    if "user_state" not in session:
        raise Unauthorized("Not logged in")

    set_user(
        {
            "id": session["user_id"],
            "username": session["username"],
            "email": session["email_address"],
            "ip_address": request.remote_addr,
        }
    )

    userinfo = id_token.verify_oauth2_token(  # type: ignore
        request.form["credential"], requests.Request(), app.config["GOOGLE_CLIENT_ID"]  # type: ignore  # noqa: E501
    )

    if userinfo["hd"] != "robojackets.org":
        raise Unauthorized("Invalid hd value")

    session["email_address"] = userinfo["email"]
    session["email_verified"] = userinfo["email_verified"]

    return redirect(url_for("index"))  # type: ignore


@app.get("/verify-email/microsoft/complete")
def verify_microsoft_complete() -> Response:
    """
    Handles the return from Microsoft and updates session appropriately
    """
    if "user_state" not in session:
        raise Unauthorized("Not logged in")

    set_user(
        {
            "id": session["user_id"],
            "username": session["username"],
            "email": session["email_address"],
            "ip_address": request.remote_addr,
        }
    )
    token = oauth.microsoft.authorize_access_token()

    userinfo = token["userinfo"]

    session["email_address"] = userinfo["email"]
    session["email_verified"] = True

    return redirect(url_for("index"))  # type: ignore


@app.get("/get-ramp-user/<apiary_id>")
def get_ramp_user(  # pylint: disable=too-many-return-statements,too-many-branches
    apiary_id: str,
) -> Dict[str, str]:
    """
    Provides the Ramp user ID for a given Apiary user ID, if the user has a Ramp account.
    """
    if "user_state" not in session:
        raise Unauthorized("Not logged in")

    set_user(
        {
            "id": session["user_id"],
            "username": session["username"],
            "email": session["email_address"],
            "ip_address": request.remote_addr,
        }
    )

    apiary_user_response = get(
        url=app.config["APIARY_URL"] + "/api/v1/users/" + apiary_id,
        headers={
            "Authorization": "Bearer " + app.config["APIARY_TOKEN"],
            "Accept": "application/json",
        },
        timeout=(5, 5),
    )

    if apiary_user_response.status_code != 200:
        print("Apiary returned status code:", apiary_user_response.status_code)
        print("Response body:", apiary_user_response.text)
        return {"error": "Failed to retrieve manager information from Apiary"}

    keycloak_access_token = get_keycloak_access_token()

    if keycloak_access_token is None:
        return {"error": "Failed to retrieve access token for Keycloak"}

    keycloak_user_response = get(
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users",
        params={
            "username": apiary_user_response.json()["user"]["uid"],
            "exact": True,
        },
        headers={
            "Authorization": "Bearer " + keycloak_access_token,
        },
        timeout=(5, 5),
    )

    if keycloak_user_response.status_code != 200:
        print("Keycloak returned status code:", keycloak_user_response.status_code)
        print("Response body:", keycloak_user_response.text)
        return {"error": "Failed to search for manager in Keycloak"}

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
        + f" doesn't have a Ramp account yet. Ask {object_pronoun} to set up {possessive_pronoun} own account first."  # noqa
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

    ramp_access_token = get_ramp_access_token("users:read")

    if ramp_access_token is None:
        return {"error": "Failed to retrieve access token for Ramp"}

    ramp_user_response = get(
        url=app.config["RAMP_API_URL"] + "/developer/v1/users/" + ramp_user_id,
        headers={
            "Authorization": "Bearer " + ramp_access_token,
        },
        timeout=(5, 5),
    )

    if ramp_user_response.status_code != 200:
        print("Ramp returned status code:", ramp_user_response.status_code)
        print("Response body:", ramp_user_response.text)
        return {"error": "Failed to retrieve manager from Ramp"}

    if ramp_user_response.json()["status"] == "USER_ACTIVE":
        return {
            "rampUserId": ramp_user_id,
        }

    if ramp_user_response.json()["status"] in ("INVITE_PENDING", "USER_ONBOARDING"):
        return {
            "error": apiary_user_response.json()["user"]["first_name"]
            + f" hasn't finished setting up {possessive_pronoun} Ramp account yet. Ask {object_pronoun} to finish setting up {possessive_pronoun} own account first."  # noqa
        }

    return {"error": "Unrecognized manager account status in Ramp"}


@app.post("/create-ramp-account")
def create_ramp_account() -> (
    Dict[str, str]
):  # pylint: disable=too-many-branches,too-many-statements
    """
    Creates a new Ramp account and returns the task status for the browser to poll.
    """
    if "user_state" not in session:
        raise Unauthorized("Not logged in")

    set_user(
        {
            "id": session["user_id"],
            "username": session["username"],
            "email": session["email_address"],
            "ip_address": request.remote_addr,
        }
    )

    if not session["email_verified"]:
        raise BadRequest("Email address must be verified")

    if request.json["role"] not in ["BUSINESS_USER", "BUSINESS_BOOKKEEPER", "BUSINESS_ADMIN"]:  # type: ignore  # noqa
        raise BadRequest("Invalid role")

    if request.json["role"] == "BUSINESS_ADMIN" and session["is_student"] is True:  # type: ignore
        raise Unauthorized("Invalid role")

    keycloak_access_token = get_keycloak_access_token()

    if keycloak_access_token is None:
        raise InternalServerError("Failed to retrieve access token for Keycloak")

    get_keycloak_user_response = get(
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + session["sub"],
        headers={
            "Authorization": "Bearer " + keycloak_access_token,
        },
        timeout=(5, 5),
    )

    if get_keycloak_user_response.status_code != 200:
        print("Keycloak returned status code:", get_keycloak_user_response.status_code)
        print("Response body:", get_keycloak_user_response.text)
        raise InternalServerError("Failed to retrieve user from Keycloak")

    new_user = get_keycloak_user_response.json()
    if "id" in new_user:
        del new_user["id"]

    if "username" in new_user:
        del new_user["username"]

    if "attributes" not in new_user:
        new_user["attributes"] = {"googleWorkspaceAccount": [session["email_address"]]}
    else:
        new_user["attributes"]["googleWorkspaceAccount"] = [session["email_address"]]

    new_user["firstName"] = request.json["firstName"]  # type: ignore
    new_user["lastName"] = request.json["lastName"]  # type: ignore

    keycloak_user_response = put(
        url=app.config["KEYCLOAK_SERVER"]
        + "/admin/realms/"
        + app.config["KEYCLOAK_REALM"]
        + "/users/"
        + session["sub"],
        json=new_user,
        headers={
            "Authorization": "Bearer " + keycloak_access_token,
        },
        timeout=(5, 5),
    )

    if keycloak_user_response.status_code != 204:
        print("Keycloak returned status code:", keycloak_user_response.status_code)
        print("Response body:", keycloak_user_response.text)
        raise InternalServerError("Failed to update name and email address in Keycloak")

    request_body = {
        "department_id": request.json["departmentId"],  # type: ignore
        "email": session["email_address"],
        "first_name": request.json["firstName"],  # type: ignore
        "idempotency_key": uuid4().hex,
        "last_name": request.json["lastName"],  # type: ignore
        "location_id": request.json["locationId"],  # type: ignore
        "role": request.json["role"],  # type: ignore
    }

    # Ramp doesn't allow setting a manager for admins via API
    if request.json["role"] != "BUSINESS_ADMIN":  # type: ignore
        request_body["direct_manager_id"] = request.json["directManagerId"]

    ramp_access_token = get_ramp_access_token("users:write")

    if ramp_access_token is None:
        raise InternalServerError("Failed to retrieve access token for Ramp")

    ramp_invite_user_response = post(
        url=app.config["RAMP_API_URL"] + "/developer/v1/users/deferred",
        headers={
            "Authorization": "Bearer " + ramp_access_token,
        },
        json=request_body,
        timeout=(5, 5),
    )

    if ramp_invite_user_response.status_code != 201:
        print("Ramp returned status code:", ramp_invite_user_response.status_code)
        print("Response body:", ramp_invite_user_response.text)
        raise InternalServerError("Failed to create user invitation")

    return {
        "taskId": ramp_invite_user_response.json()["id"],
    }


@app.get("/create-ramp-account/<task_id>")
def get_ramp_account_status(task_id: str) -> Dict[str, str]:
    """
    Get the task status for a previous request to create a Ramp account.
    """
    ramp_access_token = get_ramp_access_token("users:write")

    if ramp_access_token is None:
        raise InternalServerError("Failed to retrieve access token for Ramp")

    ramp_task_status = get(
        url=app.config["RAMP_API_URL"] + "/developer/v1/users/deferred/status/" + task_id,
        headers={
            "Authorization": "Bearer " + ramp_access_token,
        },
        timeout=(5, 5),
    )

    if ramp_task_status.status_code != 200:
        print("Ramp returned status code:", ramp_task_status.status_code)
        print("Response body:", ramp_task_status.text)
        raise InternalServerError("Failed to get task status")

    if ramp_task_status.json()["status"] == "SUCCESS":
        session["ramp_user_id"] = ramp_task_status.json()["data"]["user_id"]

        keycloak_access_token = get_keycloak_access_token()

        if keycloak_access_token is None:
            return {
                "taskStatus": ramp_task_status.json()["status"],
            }

        get_keycloak_user_response = get(
            url=app.config["KEYCLOAK_SERVER"]
            + "/admin/realms/"
            + app.config["KEYCLOAK_REALM"]
            + "/users/"
            + session["sub"],
            headers={
                "Authorization": "Bearer " + keycloak_access_token,
            },
            timeout=(5, 5),
        )

        if get_keycloak_user_response.status_code != 200:
            print("Keycloak returned status code:", get_keycloak_user_response.status_code)
            print("Response body:", get_keycloak_user_response.text)
            return {
                "taskStatus": ramp_task_status.json()["status"],
            }

        new_user = get_keycloak_user_response.json()
        if "id" in new_user:
            del new_user["id"]

        if "username" in new_user:
            del new_user["username"]

        if "attributes" not in new_user:
            new_user["attributes"] = {"rampUserId": [ramp_task_status.json()["data"]["user_id"]]}
        else:
            new_user["attributes"]["rampUserId"] = [ramp_task_status.json()["data"]["user_id"]]

        update_keycloak_user_response = put(
            url=app.config["KEYCLOAK_SERVER"]
            + "/admin/realms/"
            + app.config["KEYCLOAK_REALM"]
            + "/users/"
            + session["sub"],
            json=new_user,
            headers={
                "Authorization": "Bearer " + keycloak_access_token,
            },
            timeout=(5, 5),
        )

        if update_keycloak_user_response.status_code != 204:
            print("Keycloak returned status code:", update_keycloak_user_response.status_code)
            print("Response body:", update_keycloak_user_response.text)

        remove_eligible_role_response = delete(
            url=app.config["KEYCLOAK_SERVER"]
            + "/admin/realms/"
            + app.config["KEYCLOAK_REALM"]
            + "/users/"
            + session["sub"]
            + "/role-mappings/clients/"
            + app.config["KEYCLOAK_CLIENT_UUID"],
            headers={
                "Authorization": "Bearer " + keycloak_access_token,
            },
            timeout=(5, 5),
            json=[{"id": app.config["KEYCLOAK_CLIENT_ROLE_ELIGIBLE"], "name": "eligible"}],
        )

        if remove_eligible_role_response.status_code != 204:
            print("Keycloak returned status code:", remove_eligible_role_response.status_code)
            print("Response body:", remove_eligible_role_response.text)

    return {
        "taskStatus": ramp_task_status.json()["status"],
    }


@app.post("/order-physical-card")
def order_physical_card() -> Dict[str, str]:
    """
    Order a physical card for the logged-in user.
    """
    if "user_state" not in session:
        raise Unauthorized("Not logged in")

    set_user(
        {
            "id": session["user_id"],
            "username": session["username"],
            "email": session["email_address"],
            "ip_address": request.remote_addr,
        }
    )

    if "ramp_user_id" not in session or session["ramp_user_id"] is None:
        raise InternalServerError("No Ramp user ID in session")

    ramp_access_token = get_ramp_access_token("cards:write")

    if ramp_access_token is None:
        raise InternalServerError("Failed to retrieve access token for Ramp")

    ramp_order_physical_card_response = post(
        url=app.config["RAMP_API_URL"] + "/developer/v1/cards/deferred/physical",
        headers={
            "Authorization": "Bearer " + ramp_access_token,
        },
        json={
            "display_name": "Physical Card",
            "fulfillment": {
                "shipping": {
                    "recipient_address": {
                        "address1": request.json["addressLineOne"],  # type: ignore
                        "address2": (
                            request.json["addressLineTwo"]  # type: ignore
                            if request.json["addressLineTwo"] != ""  # type: ignore
                            else None
                        ),
                        "city": request.json["city"],  # type: ignore
                        "country": "US",
                        "first_name": request.json["firstName"],  # type: ignore
                        "last_name": request.json["lastName"],  # type: ignore
                        "postal_code": request.json["zip"],  # type: ignore
                        "state": request.json["state"],  # type: ignore
                    }
                }
            },
            "idempotency_key": uuid4().hex,
            "spending_restrictions": {
                "amount": 1,
                "currency": "USD",
                "interval": "TOTAL",
            },
            "user_id": session["ramp_user_id"],
        },
        timeout=(5, 5),
    )

    if ramp_order_physical_card_response.status_code != 200:
        print("Ramp returned status code:", ramp_order_physical_card_response.status_code)
        print("Response body:", ramp_order_physical_card_response.text)
        raise InternalServerError("Failed to order physical card")

    return {
        "taskId": ramp_order_physical_card_response.json()["id"],
    }


@app.get("/order-physical-card/<task_id>")
def get_physical_card_status(task_id: str) -> Dict[str, str]:
    """
    Get the task status for a previous request to order a physical card.
    """
    ramp_access_token = get_ramp_access_token("cards:write")

    if ramp_access_token is None:
        raise InternalServerError("Failed to retrieve access token for Ramp")

    ramp_task_status = get(
        url=app.config["RAMP_API_URL"] + "/developer/v1/cards/deferred/status/" + task_id,
        headers={
            "Authorization": "Bearer " + ramp_access_token,
        },
        timeout=(5, 5),
    )

    if ramp_task_status.status_code != 200:
        print("Ramp returned status code:", ramp_task_status.status_code)
        print("Response body:", ramp_task_status.text)
        raise InternalServerError("Failed to get task status")

    return {
        "taskStatus": ramp_task_status.json()["status"],
    }


@app.get("/ping")
def ping() -> Dict[str, str]:
    """
    Returns an arbitrary successful response, for health checks
    """
    return {"status": "ok"}
