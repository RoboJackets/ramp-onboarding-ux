port module Main exposing (..)

import Browser
import Browser.Dom exposing (focus)
import Browser.Navigation as Nav
import Char exposing (isDigit)
import Dict exposing (Dict, toList)
import Email
import Html exposing (Attribute, Html, a, button, div, h1, input, label, option, p, pre, select, strong, text)
import Html.Attributes exposing (attribute, autocomplete, checked, class, classList, disabled, for, href, id, maxlength, novalidate, placeholder, readonly, rel, selected, style, target, type_)
import Html.Events exposing (on, onCheck, onClick, onInput, onSubmit, preventDefaultOn, targetValue)
import Html.Events.Extra exposing (targetValueIntParse)
import Http exposing (expectJson, expectWhatever, jsonBody)
import Json.Decode exposing (Decoder, Value, andThen, at, bool, decodeString, decodeValue, dict, fail, field, int, keyValuePairs, maybe, nullable, string, succeed)
import Json.Encode
import List exposing (sortBy, sortWith, take)
import Maybe exposing (withDefault)
import Regex
import Svg exposing (Svg, path, svg)
import Svg.Attributes exposing (d)
import Task
import Time exposing (Month(..), Posix, Weekday(..), Zone, millisToPosix, posixToMillis, toDay, toMonth, toWeekday)
import Tuple exposing (first, second)
import Url
import Url.Builder



-- LEGAL


termsOfService : List ( String, String )
termsOfService =
    [ ( "Ramp Platform Agreement", "https://ramp.com/legal/customer-terms/platform-agreement/platform-agreement" )
    , ( "Ramp Cookie Policy", "https://ramp.com/legal/privacy-terms/privacy-terms/cookie-policy" )
    , ( "Ramp Privacy Policy", "https://ramp.com/legal/privacy-terms/privacy-terms/privacy-policy" )
    , ( "Ramp Authorized User Agreement", "https://ramp.com/legal/customer-terms/additional-customer-terms/authorized-user-terms" )
    , ( "Ramp Authorized User Payment Card Addendum", "https://ramp.com/legal/customer-terms/additional-customer-terms/authorized-user-card-addendum" )
    , ( "Sutton Bank Cardholder Terms", "https://ramp.com/legal/customer-terms/financial-institution-partner-agreements/sutton-bank-cardholder-terms" )
    , ( "Sutton Bank Privacy Policy", "https://www.suttonbank.com/_/kcms-doc/85/49033/WK-Privacy-Disclosure-1218.pdf" )
    , ( "Celtic Bank Accountholder Terms", "https://ramp.com/legal/customer-terms/financial-institution-partner-agreements/celtic-bank-accountholder-terms" )
    , ( "Celtic Bank Privacy Policy", "https://www.celticbank.com/privacy" )
    , ( "Lead Bank Accountholder Terms", "https://ramp.com/legal/customer-terms/financial-institution-partner-agreements/lead-bank-accountholder-terms" )
    , ( "Lead Bank Privacy Policy", "https://www.lead.bank/privacy-and-terms" )
    , ( "Georgia Institute of Technology Acceptable Use Policy", "https://policylibrary.gatech.edu/information-technology/acceptable-use-policy" )
    , ( "Georgia Institute of Technology Cyber Security Policy", "https://policylibrary.gatech.edu/information-technology/cyber-security-policy" )
    , ( "Georgia Institute of Technology Data Privacy Policy", "https://policylibrary.gatech.edu/information-technology/data-privacy-policy" )
    ]



-- REGEX


nameRegex : Regex.Regex
nameRegex =
    withDefault Regex.never (Regex.fromString "^[a-zA-Z-'\\. ]+$")


studentCenterMailboxRegex : Regex.Regex
studentCenterMailboxRegex =
    withDefault Regex.never (Regex.fromString "^\\d{6} georgia tech station$")


graduateLivingCenterMailboxRegex : Regex.Regex
graduateLivingCenterMailboxRegex =
    withDefault Regex.never (Regex.fromString "^(apt|apartment) [1-6][0-2][0-9][a-d]$")



-- STRINGS


noBreakSpace : String
noBreakSpace =
    String.fromChar '\u{00A0}'


emailFeedbackText : String
emailFeedbackText =
    "Please enter a valid email address ending in gatech.edu or robojackets.org"


managerFeedbackText : String
managerFeedbackText =
    "Please select your manager"


managerDepartmentFeedbackText : String
managerDepartmentFeedbackText =
    "Please select a manager within your department"



-- localStorage form-state keys: written by encodeFormState, read by buildInitialModel
-- Changing a value orphans previously saved form state


firstNameLocalStorageKey : String
firstNameLocalStorageKey =
    "firstName"


lastNameLocalStorageKey : String
lastNameLocalStorageKey =
    "lastName"


emailAddressLocalStorageKey : String
emailAddressLocalStorageKey =
    "emailAddress"


managerApiaryIdLocalStorageKey : String
managerApiaryIdLocalStorageKey =
    "managerApiaryId"


managerRampIdLocalStorageKey : String
managerRampIdLocalStorageKey =
    "managerRampId"


departmentIdLocalStorageKey : String
departmentIdLocalStorageKey =
    "departmentId"


locationIdLocalStorageKey : String
locationIdLocalStorageKey =
    "locationId"


roleIdLocalStorageKey : String
roleIdLocalStorageKey =
    "roleId"


orderPhysicalCardLocalStorageKey : String
orderPhysicalCardLocalStorageKey =
    "orderPhysicalCard"


addressLineOneLocalStorageKey : String
addressLineOneLocalStorageKey =
    "addressLineOne"


addressLineTwoLocalStorageKey : String
addressLineTwoLocalStorageKey =
    "addressLineTwo"


cityLocalStorageKey : String
cityLocalStorageKey =
    "city"


stateLocalStorageKey : String
stateLocalStorageKey =
    "state"


zipCodeLocalStorageKey : String
zipCodeLocalStorageKey =
    "zip"


showAdvancedOptionsLocalStorageKey : String
showAdvancedOptionsLocalStorageKey =
    "showAdvancedOptions"



-- FIELD IDS


firstNameFieldId : String
firstNameFieldId =
    "first_name"


lastNameFieldId : String
lastNameFieldId =
    "last_name"


emailAddressFieldId : String
emailAddressFieldId =
    "email_address"


emailVerificationButtonId : String
emailVerificationButtonId =
    "email_verification_button"


managerFieldId : String
managerFieldId =
    "manager"


departmentFieldId : String
departmentFieldId =
    "department"


locationFieldId : String
locationFieldId =
    "location"


roleFieldId : String
roleFieldId =
    "role"


orderPhysicalCardFieldId : String
orderPhysicalCardFieldId =
    "order_physical_card"


addressLineOneFieldId : String
addressLineOneFieldId =
    "address_line_one"


addressLineTwoFieldId : String
addressLineTwoFieldId =
    "address_line_two"


cityFieldId : String
cityFieldId =
    "city"


stateFieldId : String
stateFieldId =
    "state"


zipCodeFieldId : String
zipCodeFieldId =
    "zip_code"


submitButtonId : String
submitButtonId =
    "submit_button"



-- ICONS


googleIcon : Svg msg
googleIcon =
    svg [ Svg.Attributes.width "16", Svg.Attributes.height "16", Svg.Attributes.viewBox "0 0 16 16", Svg.Attributes.fill "currentColor", Svg.Attributes.style "top: -0.125em; position: relative;" ] [ path [ d "M15.545 6.558a9.42 9.42 0 0 1 .139 1.626c0 2.434-.87 4.492-2.384 5.885h.002C11.978 15.292 10.158 16 8 16A8 8 0 1 1 8 0a7.689 7.689 0 0 1 5.352 2.082l-2.284 2.284A4.347 4.347 0 0 0 8 3.166c-2.087 0-3.86 1.408-4.492 3.304a4.792 4.792 0 0 0 0 3.063h.003c.635 1.893 2.405 3.301 4.492 3.301 1.078 0 2.004-.276 2.722-.764h-.003a3.702 3.702 0 0 0 1.599-2.431H8v-3.08h7.545z" ] [] ]


microsoftIcon : Svg msg
microsoftIcon =
    svg [ Svg.Attributes.width "16", Svg.Attributes.height "16", Svg.Attributes.viewBox "0 0 16 16", Svg.Attributes.fill "currentColor", Svg.Attributes.style "top: -0.125em; position: relative;" ] [ path [ d "M7.462 0H0v7.19h7.462V0zM16 0H8.538v7.19H16V0zM7.462 8.211H0V16h7.462V8.211zm8.538 0H8.538V16H16V8.211z" ] [] ]


checkIcon : Svg msg
checkIcon =
    svg [ Svg.Attributes.width "16", Svg.Attributes.height "16", Svg.Attributes.viewBox "0 0 16 16", Svg.Attributes.fill "currentColor", Svg.Attributes.style "top: -0.125em; position: relative;" ] [ path [ d "M12.736 3.97a.733.733 0 0 1 1.047 0c.286.289.29.756.01 1.05L7.88 12.01a.733.733 0 0 1-1.065.02L3.217 8.384a.757.757 0 0 1 0-1.06.733.733 0 0 1 1.047 0l3.052 3.093 5.4-6.425a.247.247 0 0 1 .02-.022Z" ] [] ]


exclamationCircleIcon : Svg msg
exclamationCircleIcon =
    svg [ Svg.Attributes.width "16", Svg.Attributes.height "16", Svg.Attributes.viewBox "0 0 16 16", Svg.Attributes.fill "currentColor", Svg.Attributes.style "top: -0.125em; position: relative;" ] [ path [ d "M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z" ] [], path [ d "M7.002 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0zM7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 4.995z" ] [] ]


checkCircleIcon : Svg msg
checkCircleIcon =
    svg
        [ Svg.Attributes.width "16"
        , Svg.Attributes.height "16"
        , Svg.Attributes.viewBox "2 2 20 20"
        , Svg.Attributes.fill "currentColor"
        , attribute "aria-hidden" "true"
        ]
        [ path [ d "M12 2C6.5 2 2 6.5 2 12S6.5 22 12 22 22 17.5 22 12 17.5 2 12 2M10 17L5 12L6.41 10.59L10 14.17L17.59 6.58L19 8L10 17Z" ] [] ]


spinner : Html msg
spinner =
    div
        [ class "spinner-border"
        , class "spinner-border-sm"
        , style "display" "inline-block"
        , attribute "aria-hidden" "true"
        ]
        []



-- MAPS


emailProviderByDomain : Dict String EmailProvider
emailProviderByDomain =
    Dict.fromList [ ( "robojackets.org", Google ), ( "gatech.edu", Microsoft ) ]


statesMap : Dict String String
statesMap =
    Dict.fromList [ ( "AK", "Alaska" ), ( "AL", "Alabama" ), ( "AR", "Arkansas" ), ( "AZ", "Arizona" ), ( "CA", "California" ), ( "CO", "Colorado" ), ( "CT", "Connecticut" ), ( "DC", "District of Columbia" ), ( "DE", "Delaware" ), ( "FL", "Florida" ), ( "GA", "Georgia" ), ( "HI", "Hawaii" ), ( "IA", "Iowa" ), ( "ID", "Idaho" ), ( "IL", "Illinois" ), ( "IN", "Indiana" ), ( "KS", "Kansas" ), ( "KY", "Kentucky" ), ( "LA", "Louisiana" ), ( "MA", "Massachusetts" ), ( "MD", "Maryland" ), ( "ME", "Maine" ), ( "MI", "Michigan" ), ( "MN", "Minnesota" ), ( "MO", "Missouri" ), ( "MS", "Mississippi" ), ( "MT", "Montana" ), ( "NC", "North Carolina" ), ( "ND", "North Dakota" ), ( "NE", "Nebraska" ), ( "NH", "New Hampshire" ), ( "NJ", "New Jersey" ), ( "NM", "New Mexico" ), ( "NV", "Nevada" ), ( "NY", "New York" ), ( "OH", "Ohio" ), ( "OK", "Oklahoma" ), ( "OR", "Oregon" ), ( "PA", "Pennsylvania" ), ( "RI", "Rhode Island" ), ( "SC", "South Carolina" ), ( "SD", "South Dakota" ), ( "TN", "Tennessee" ), ( "TX", "Texas" ), ( "UT", "Utah" ), ( "VA", "Virginia" ), ( "VT", "Vermont" ), ( "WA", "Washington" ), ( "WI", "Wisconsin" ), ( "WV", "West Virginia" ), ( "WY", "Wyoming" ) ]


rampRoleRankOrder : Dict String Int
rampRoleRankOrder =
    Dict.fromList [ ( "BUSINESS_ADMIN", 0 ), ( "IT_ADMIN", 1 ), ( "BUSINESS_BOOKKEEPER", 2 ), ( "BUSINESS_USER", 3 ) ]



-- TYPES


type EmailProvider
    = Google
    | Microsoft


type CampusAddress
    = StudentCenter
    | GraduateLivingCenter
    | ManufacturingRelatedDisciplinesComplex
    | NotCampusAddress


type ValidationResult
    = Valid
    | Invalid String


type Check
    = InFlight
    | Done


type alias SubmissionChecks =
    { manager : Check
    , address : Check
    }


type FormState
    = Editing
    | Validating SubmissionChecks
    | Error ProvisioningFailure
    | CreatingRampAccount (Maybe String)
    | RampAccountCreated
    | PhysicalCardOrdered


type ProvisioningFailure
    = CreateAccountRequestFailed String
    | CreateAccountTaskFailed
    | CreateAccountStatusCheckFailed String
    | OrderPhysicalCardFailed String


type alias AddressComponent =
    { value : String
    , types : List String
    }


type PlaceChange
    = PlaceSelected (List AddressComponent)
    | PlaceIncomplete


type ManagerValidation
    = ManagerResolved { managerApiaryId : Int, managerRampId : String }
    | ManagerRejected { managerApiaryId : Int, managerFeedbackText : String }


type alias GoogleAddressValidation =
    { addressComplete : Maybe Bool
    , missingComponentTypes : Maybe (List String)
    }


type alias AddressValidationRequest =
    { addressLineOne : String
    , addressLineTwo : String
    , city : String
    , state : Maybe String
    , zip : String
    }


type alias TaskId =
    { taskId : String }


type TaskStatus
    = TaskStarted
    | TaskInProgress
    | TaskSucceeded
    | TaskFailed


type alias RampObject =
    { label : String
    , enabled : Bool
    }


type alias RampUser =
    { label : String
    , enabled : Bool
    , departmentId : String
    }


type alias Model =
    { firstName : String
    , lastName : String
    , emailAddress : String
    , emailVerified : Bool
    , managerApiaryOptions : Dict Int String
    , managerApiaryId : Maybe Int
    , managerRampId : Maybe String
    , managerIsValid : Maybe Bool
    , managerFeedbackText : String
    , selfApiaryId : Int
    , orderPhysicalCard : Bool
    , addressLineOne : String
    , addressLineTwo : String
    , city : String
    , state : Maybe String
    , zip : String
    , addressLineTwoRequired : Bool
    , addressIsValid : Maybe Bool
    , showValidation : Bool
    , googleMapsApiKey : String
    , googleClientId : String
    , googleOneTapLoginUri : String
    , time : Time.Posix
    , zone : Time.Zone
    , formState : FormState
    , redirectingToEmailVerification : Bool
    , showAdvancedOptions : Bool
    , rampDepartmentOptions : Dict String RampObject
    , rampLocationOptions : Dict String RampObject
    , rampRoleOptions : Dict String RampObject
    , rampDepartmentId : Maybe String
    , rampLocationId : Maybe String
    , rampRoleId : Maybe String
    , studentDefaultDepartmentId : String
    , nonStudentDefaultDepartmentId : String
    , studentDefaultLocationId : String
    , nonStudentDefaultLocationId : String
    , managerRampOptions : Dict String RampUser
    , rampSignInUri : String
    , businessLegalName : String
    , slackSupportChannelDeepLink : String
    , slackSupportChannelName : String
    }


type AppModel
    = Ready Model
    | ServerDataInvalid Json.Decode.Error


type Msg
    = UrlRequest Browser.UrlRequest
    | UrlChanged Url.Url
    | FormSubmitted
    | FormChanged
    | FirstNameInput String
    | LastNameInput String
    | EmailAddressInput String
    | ApiaryManagerInput Int
    | RampManagerInput String
    | OrderPhysicalCardChecked Bool
    | AddressLineOneInput String
    | AddressLineTwoInput String
    | CityInput String
    | StateInput String
    | ZipInput String
    | NoOpMsg
    | LocalStorageSaved
    | EmailVerificationButtonClicked
    | PlaceChanged Value
    | ManagerValidationResultReceived (Result Http.Error ManagerValidation)
    | GoogleAddressValidationResultReceived AddressValidationRequest (Result Http.Error GoogleAddressValidation)
    | CreateRampAccountTaskIdReceived (Result Http.Error TaskId)
    | CreateRampAccountTaskStatusReceived (Result Http.Error TaskStatus)
    | OrderPhysicalCardResponseReceived (Result Http.Error ())
    | SetTime Time.Posix
    | SetZone Time.Zone
    | ShowAdvancedOptionsButtonClicked
    | AdvancedModeManagerPrefillReceived (Result Http.Error ManagerValidation)
    | DepartmentInput String
    | LocationInput String
    | RoleInput String



-- PLUMBING


main : Program Value AppModel Msg
main =
    Browser.application
        { init = init
        , view = view
        , update = update
        , subscriptions = subscriptions
        , onUrlChange = UrlChanged
        , onUrlRequest = UrlRequest
        }


init : Value -> Url.Url -> Nav.Key -> ( AppModel, Cmd Msg )
init flags _ _ =
    case decodeValue (field "serverData" serverDataDecoder) flags of
        Ok serverData ->
            let
                localData : Value
                localData =
                    flags
                        |> decodeValue (field "localData" string)
                        |> Result.andThen (decodeString Json.Decode.value)
                        |> Result.withDefault Json.Encode.null

                model : Model
                model =
                    buildInitialModel serverData localData
            in
            ( Ready model
            , Cmd.batch
                [ Task.perform SetTime Time.now
                , Task.perform SetZone Time.here
                , initializeAutocomplete { apiKey = model.googleMapsApiKey, fieldId = addressLineOneFieldId }
                , if showOneTap model then
                    initializeOneTap ()

                  else
                    Cmd.none
                ]
            )

        Err decodeError ->
            ( ServerDataInvalid decodeError
            , reportErrorCmd "fatal"
                (Json.Decode.errorToString decodeError)
                [ ( "step", "boot" ), ( "kind", "flags_decode" ) ]
            )


update : Msg -> AppModel -> ( AppModel, Cmd Msg )
update msg appModel =
    case appModel of
        Ready model ->
            Tuple.mapFirst Ready (updateReady msg model)

        ServerDataInvalid _ ->
            ( appModel, Cmd.none )


updateReady : Msg -> Model -> ( Model, Cmd Msg )
updateReady msg model =
    case msg of
        UrlRequest urlRequest ->
            case urlRequest of
                Browser.Internal url ->
                    ( model, Nav.load (Url.toString url) )

                Browser.External externalUrl ->
                    ( model, Nav.load externalUrl )

        UrlChanged _ ->
            ( model, Cmd.none )

        FormSubmitted ->
            if model.formState /= Editing then
                ( model, Cmd.none )

            else
                case firstInvalidFieldId model of
                    Just fieldId ->
                        ( { model | showValidation = True }
                        , Task.attempt (\_ -> NoOpMsg) (focus fieldId)
                        )

                    Nothing ->
                        let
                            checks : SubmissionChecks
                            checks =
                                submissionChecksFromModel model

                            updatedModel : Model
                            updatedModel =
                                { model
                                    | showValidation = True
                                    , formState = Validating checks
                                }

                            ( proceededModel, proceedCmd ) =
                                proceedIfReady updatedModel
                        in
                        ( proceededModel
                        , Cmd.batch
                            [ saveFormStateToLocalStorage model
                            , if needsManagerValidation model then
                                requestManagerValidation model

                              else
                                Cmd.none
                            , if needsAddressValidation model then
                                requestGoogleAddressValidation model

                              else
                                Cmd.none
                            , proceedCmd
                            ]
                        )

        FormChanged ->
            updateAndSaveToLocalStorage model

        FirstNameInput firstName ->
            ( { model | firstName = firstName }, Cmd.none )

        LastNameInput lastName ->
            ( { model | lastName = lastName }, Cmd.none )

        EmailAddressInput emailAddress ->
            ( { model
                | emailAddress = emailAddress
                , emailVerified = False
                , redirectingToEmailVerification = False
              }
            , Cmd.none
            )

        EmailVerificationButtonClicked ->
            updateAndSaveToLocalStorage { model | redirectingToEmailVerification = True }

        ApiaryManagerInput managerApiaryId ->
            updateAndSaveToLocalStorage
                { model
                    | managerApiaryId = Just managerApiaryId
                    , managerRampId = Nothing
                    , managerIsValid = Nothing
                }

        RampManagerInput managerRampId ->
            updateAndSaveToLocalStorage
                { model
                    | managerApiaryId = Nothing
                    , managerRampId = Just managerRampId
                    , managerIsValid = Just True
                }

        OrderPhysicalCardChecked orderPhysicalCard ->
            updateAndSaveToLocalStorage { model | orderPhysicalCard = orderPhysicalCard }

        AddressLineOneInput addressLineOne ->
            ( { model
                | addressLineOne = addressLineOne
                , addressLineTwoRequired = False
                , addressIsValid = Nothing
              }
            , Cmd.none
            )

        AddressLineTwoInput addressLineTwo ->
            ( { model
                | addressLineTwo = addressLineTwo
                , addressIsValid = Nothing
              }
            , Cmd.none
            )

        CityInput city ->
            ( { model
                | city = city
                , addressLineTwoRequired = False
                , addressIsValid = Nothing
              }
            , Cmd.none
            )

        StateInput state ->
            updateAndSaveToLocalStorage
                { model
                    | state = Just state
                    , addressLineTwoRequired = False
                    , addressIsValid = Nothing
                }

        ZipInput zip ->
            ( { model
                | zip = zip
                , addressLineTwoRequired = False
                , addressIsValid = Nothing
              }
            , Cmd.none
            )

        NoOpMsg ->
            ( model, Cmd.none )

        LocalStorageSaved ->
            ( model
            , if model.redirectingToEmailVerification then
                Nav.load
                    (Url.Builder.absolute
                        [ "verify-email" ]
                        [ Url.Builder.string "emailAddress" model.emailAddress ]
                    )

              else
                Cmd.none
            )

        PlaceChanged value ->
            case model.formState of
                Editing ->
                    case decodePlaceChanged value of
                        Ok (PlaceSelected addressComponents) ->
                            let
                                newModel : Model
                                newModel =
                                    { model
                                        | addressLineOne =
                                            String.trim (getAddressComponent addressComponents "street_number")
                                                ++ " "
                                                ++ String.trim (getAddressComponent addressComponents "route")
                                        , addressLineTwo = String.trim (getAddressComponent addressComponents "subpremise")
                                        , city = String.trim (getAddressComponent addressComponents "locality")
                                        , state = Just (String.trim (getAddressComponent addressComponents "administrative_area_level_1"))
                                        , zip = String.trim (getAddressComponent addressComponents "postal_code")
                                        , addressIsValid = Nothing
                                        , addressLineTwoRequired = False
                                    }
                            in
                            ( newModel
                            , Cmd.batch
                                [ Task.attempt (\_ -> NoOpMsg) (focus addressLineTwoFieldId)
                                , saveFormStateToLocalStorage newModel
                                ]
                            )

                        Ok PlaceIncomplete ->
                            ( model, Cmd.none )

                        Err decodeError ->
                            let
                                decodeErrorMessage : String
                                decodeErrorMessage =
                                    Json.Decode.errorToString decodeError
                            in
                            ( model
                            , Cmd.batch
                                [ showAlert
                                    ("There was an error parsing the selected address: "
                                        ++ decodeErrorMessage
                                    )
                                , reportErrorCmd "warning"
                                    decodeErrorMessage
                                    [ ( "step", "place_changed_decode" ), ( "kind", "decode" ) ]
                                ]
                            )

                _ ->
                    ( model, Cmd.none )

        GoogleAddressValidationResultReceived requested result ->
            case model.formState of
                Validating _ ->
                    if not (addressValidationRequestMatchesModel requested model) then
                        ( model, Cmd.none )

                    else
                        let
                            missingAddressLineTwo : Bool
                            missingAddressLineTwo =
                                case result of
                                    Ok verdict ->
                                        List.member "subpremise" (withDefault [] verdict.missingComponentTypes)

                                    Err _ ->
                                        False

                            updatedModel : Model
                            updatedModel =
                                { model
                                    | addressLineTwoRequired =
                                        case result of
                                            Ok _ ->
                                                missingAddressLineTwo

                                            Err _ ->
                                                False
                                    , addressIsValid =
                                        case result of
                                            Ok verdict ->
                                                case verdict.addressComplete of
                                                    Just addressComplete ->
                                                        Just addressComplete

                                                    Nothing ->
                                                        if missingAddressLineTwo then
                                                            Just True

                                                        else
                                                            Just False

                                            Err _ ->
                                                model.addressIsValid
                                }
                        in
                        case result of
                            Ok verdict ->
                                case verdict.addressComplete of
                                    Just True ->
                                        proceedIfReady (markAddressCheckDone updatedModel)

                                    _ ->
                                        ( { updatedModel | formState = abortValidation model.formState }
                                        , if missingAddressLineTwo then
                                            Task.attempt (\_ -> NoOpMsg) (focus addressLineTwoFieldId)

                                          else
                                            Cmd.none
                                        )

                            Err error ->
                                ( { updatedModel | formState = abortValidation model.formState }
                                , Cmd.batch
                                    [ showAlert
                                        ("There was an error verifying your mailing address: "
                                            ++ httpErrorToString error
                                            ++ "\n\nPlease check your internet connection."
                                        )
                                    , reportHttpError "address_validation" error
                                    ]
                                )

                _ ->
                    ( model, Cmd.none )

        SetTime time ->
            ( { model | time = time }, Cmd.none )

        SetZone zone ->
            ( { model | zone = zone }, Cmd.none )

        ManagerValidationResultReceived result ->
            case model.formState of
                Validating _ ->
                    case result of
                        Ok managerValidation ->
                            if Just (managerApiaryIdFromValidation managerValidation) /= model.managerApiaryId then
                                ( model, Cmd.none )

                            else
                                case managerValidation of
                                    ManagerResolved { managerRampId } ->
                                        proceedIfReady
                                            (markManagerCheckDone
                                                { model
                                                    | managerRampId = Just managerRampId
                                                    , managerFeedbackText = ""
                                                    , managerIsValid = Just True
                                                }
                                            )

                                    ManagerRejected rejected ->
                                        ( { model
                                            | managerRampId = Nothing
                                            , managerFeedbackText = rejected.managerFeedbackText
                                            , managerIsValid = Just False
                                            , formState = abortValidation model.formState
                                          }
                                        , Cmd.none
                                        )

                        Err error ->
                            let
                                updatedModel : Model
                                updatedModel =
                                    { model
                                        | managerRampId = Nothing
                                        , managerFeedbackText =
                                            "There was an error verifying your manager: "
                                                ++ httpErrorToString error
                                        , managerIsValid = Just False
                                    }
                            in
                            ( { updatedModel | formState = abortValidation model.formState }
                            , Cmd.batch
                                [ showAlert
                                    ("There was an error verifying your manager: "
                                        ++ httpErrorToString error
                                        ++ "\n\nPlease check your internet connection."
                                    )
                                , reportHttpError "manager_validation" error
                                ]
                            )

                _ ->
                    ( model, Cmd.none )

        CreateRampAccountTaskIdReceived result ->
            case result of
                Ok createRampAccountTaskId ->
                    ( { model | formState = CreatingRampAccount (Just createRampAccountTaskId.taskId) }
                    , getRampAccountTaskStatus createRampAccountTaskId.taskId
                    )

                Err error ->
                    showProvisioningFailure model (CreateAccountRequestFailed (httpErrorToString error))

        CreateRampAccountTaskStatusReceived result ->
            let
                taskId : String
                taskId =
                    case model.formState of
                        CreatingRampAccount maybeTaskId ->
                            withDefault "" maybeTaskId

                        _ ->
                            ""

                preserveCreatingRampAccount : FormState
                preserveCreatingRampAccount =
                    case model.formState of
                        CreatingRampAccount maybeTaskId ->
                            CreatingRampAccount maybeTaskId

                        _ ->
                            CreatingRampAccount Nothing
            in
            case result of
                Ok TaskSucceeded ->
                    ( { model | formState = RampAccountCreated }
                    , if model.orderPhysicalCard then
                        Http.request
                            { method = "POST"
                            , headers = []
                            , url =
                                Url.Builder.absolute
                                    [ "order-physical-card" ]
                                    []
                            , body =
                                jsonBody
                                    (Json.Encode.object
                                        [ ( "addressLineOne", Json.Encode.string (String.trim model.addressLineOne) )
                                        , ( "addressLineTwo", Json.Encode.string (String.trim model.addressLineTwo) )
                                        , ( "city", Json.Encode.string (String.trim model.city) )
                                        , ( "state"
                                          , case model.state of
                                                Just state ->
                                                    Json.Encode.string state

                                                Nothing ->
                                                    Json.Encode.null
                                          )
                                        , ( "zip", Json.Encode.string (String.trim model.zip) )
                                        ]
                                    )
                            , expect = expectWhatever OrderPhysicalCardResponseReceived
                            , timeout = Just httpRequestTimeoutMs
                            , tracker = Nothing
                            }

                      else
                        Nav.load model.rampSignInUri
                    )

                Ok TaskStarted ->
                    ( { model | formState = preserveCreatingRampAccount }
                    , getRampAccountTaskStatus taskId
                    )

                Ok TaskInProgress ->
                    ( { model | formState = preserveCreatingRampAccount }
                    , getRampAccountTaskStatus taskId
                    )

                Ok TaskFailed ->
                    showProvisioningFailure model CreateAccountTaskFailed

                Err error ->
                    showProvisioningFailure model (CreateAccountStatusCheckFailed (httpErrorToString error))

        OrderPhysicalCardResponseReceived result ->
            case result of
                Ok _ ->
                    ( { model | formState = PhysicalCardOrdered }
                    , Nav.load model.rampSignInUri
                    )

                Err error ->
                    showProvisioningFailure model (OrderPhysicalCardFailed (httpErrorToString error))

        ShowAdvancedOptionsButtonClicked ->
            let
                newModel : Model
                newModel =
                    { model
                        | showAdvancedOptions = True
                        , managerApiaryId = Nothing
                        , managerIsValid = Just True
                    }

                prefillCmd : Cmd Msg
                prefillCmd =
                    case ( model.managerRampId, model.managerApiaryId ) of
                        ( Nothing, Just managerApiaryId ) ->
                            requestManagerRampIdPrefill managerApiaryId

                        _ ->
                            Cmd.none

                focusCmd : Cmd Msg
                focusCmd =
                    if model.managerRampId /= Nothing then
                        Task.attempt (\_ -> NoOpMsg) (focus departmentFieldId)

                    else
                        Task.attempt (\_ -> NoOpMsg) (focus managerFieldId)
            in
            ( newModel
            , Cmd.batch
                [ saveFormStateToLocalStorage newModel
                , focusCmd
                , prefillCmd
                ]
            )

        AdvancedModeManagerPrefillReceived result ->
            case result of
                Ok (ManagerResolved { managerRampId }) ->
                    if model.managerRampId == Nothing && isEnabledOption model.managerRampOptions managerRampId then
                        updateAndSaveToLocalStorage { model | managerRampId = Just managerRampId }

                    else
                        ( model, Cmd.none )

                Ok (ManagerRejected _) ->
                    ( model, Cmd.none )

                Err error ->
                    ( model, reportHttpError "manager_prefill" error )

        DepartmentInput selectedDepartment ->
            updateAndSaveToLocalStorage { model | rampDepartmentId = Just selectedDepartment }

        LocationInput selectedLocation ->
            updateAndSaveToLocalStorage { model | rampLocationId = Just selectedLocation }

        RoleInput selectedRole ->
            updateAndSaveToLocalStorage { model | rampRoleId = Just selectedRole }


subscriptions : AppModel -> Sub Msg
subscriptions appModel =
    case appModel of
        Ready _ ->
            Sub.batch
                [ localStorageSaved (always LocalStorageSaved)
                , placeChanged PlaceChanged
                ]

        ServerDataInvalid _ ->
            Sub.none



-- Page shell shared by every form state. Keep in sync with layout.html.


pageChrome : List (Html Msg) -> List (Html Msg)
pageChrome children =
    [ div [ class "container", class "mt-md-4", class "mt-3", style "max-width" "48rem" ]
        (h1 []
            [ text "Ramp Onboarding"
            ]
            :: children
        )
    ]


view : AppModel -> Browser.Document Msg
view appModel =
    case appModel of
        Ready model ->
            viewReady model

        ServerDataInvalid decodeError ->
            { title = "Ramp Onboarding"
            , body =
                pageChrome
                    [ p [ class "mt-4", class "mb-4" ]
                        [ text "Something went wrong while loading page data. Please refresh to try again."
                        ]
                    , pre [ class "text-secondary" ]
                        [ text (Json.Decode.errorToString decodeError)
                        ]
                    ]
            }


viewReady : Model -> Browser.Document Msg
viewReady model =
    { title = "Ramp Onboarding"
    , body =
        case model.formState of
            Editing ->
                renderForm model

            Validating _ ->
                renderForm model

            CreatingRampAccount _ ->
                renderLoadingIndicators model

            RampAccountCreated ->
                renderLoadingIndicators model

            PhysicalCardOrdered ->
                renderLoadingIndicators model

            Error failure ->
                pageChrome
                    [ p [ class "mt-4", class "mb-4" ]
                        [ text
                            ("There was an error "
                                ++ provisioningFailureStepLabel failure
                                ++ ". Please post in "
                            )
                        , a [ href model.slackSupportChannelDeepLink ]
                            [ text ("#" ++ model.slackSupportChannelName)
                            ]
                        , text " for further assistance."
                        ]
                    , pre [ class "text-secondary" ]
                        [ text (provisioningFailureDetail failure)
                        ]
                    ]
    }


renderForm : Model -> List (Html Msg)
renderForm model =
    let
        firstNameValidationResult : ValidationResult
        firstNameValidationResult =
            validateName "first" model.firstName

        lastNameValidationResult : ValidationResult
        lastNameValidationResult =
            validateName "last" model.lastName

        emailAddressValidationResult : ValidationResult
        emailAddressValidationResult =
            validateEmailAddress model.emailAddress model.emailVerified

        maybeEmailProvider : Maybe EmailProvider
        maybeEmailProvider =
            emailProviderForAddress model.emailAddress

        managerValidationResult : ValidationResult
        managerValidationResult =
            validateManager model.showAdvancedOptions model.managerIsValid model.managerFeedbackText model.managerRampId model.managerApiaryId model.rampDepartmentId model.managerApiaryOptions model.managerRampOptions model.selfApiaryId

        departmentValidationResult : ValidationResult
        departmentValidationResult =
            validateRampObject "department" model.rampDepartmentId model.rampDepartmentOptions

        locationValidationResult : ValidationResult
        locationValidationResult =
            validateRampObject "location" model.rampLocationId model.rampLocationOptions

        roleValidationResult : ValidationResult
        roleValidationResult =
            validateRampObject "role" model.rampRoleId model.rampRoleOptions

        userRolesRampHelpCenterLink : List (Html Msg)
        userRolesRampHelpCenterLink =
            [ a [ href "https://support.ramp.com/user-roles-overview/", target "_blank", rel "noopener noreferrer", class "text-secondary" ] [ text "Ramp help center" ]
            , text "."
            ]

        addressLineOneValidationResult : ValidationResult
        addressLineOneValidationResult =
            validateAddressLineOne model.addressLineOne

        addressLineTwoValidationResult : ValidationResult
        addressLineTwoValidationResult =
            validateAddressLineTwo model.addressLineTwo model.addressLineTwoRequired (classifyCampusAddress model)

        cityValidationResult : ValidationResult
        cityValidationResult =
            validateCity model.city

        stateValidationResult : ValidationResult
        stateValidationResult =
            validateState model.state

        zipValidationResult : ValidationResult
        zipValidationResult =
            validateZipCode model.zip

        physicalCardEstimatedDeliveryDate : String
        physicalCardEstimatedDeliveryDate =
            formatDate model.zone (estimatePhysicalCardDeliveryDate model.zone model.time)
    in
    -- The markup above the <form> tag should match the server-side rendered markup in form.html, so the first contentful paint is consistent with the largest contentful paint.
    pageChrome
        [ p [ class "mt-4", class "mb-4" ]
            [ text (model.businessLegalName ++ " uses ")
            , a [ href "https://ramp.com", target "_blank", rel "noopener noreferrer" ]
                [ text "Ramp"
                ]
            , text " to issue corporate credit cards and manage reimbursements. We need some information from you to create your Ramp account."
            ]
        , Html.form
            [ class "row"
            , class "g-3"
            , novalidate True
            , autocomplete False
            , onSubmit FormSubmitted
            ]
            [ div [ class "col-6" ]
                [ label [ for firstNameFieldId, class "form-label" ]
                    [ text "First Name" ]
                , input
                    ([ id firstNameFieldId
                     , type_ "text"
                     , class "form-control"
                     , maxlength 40
                     , readonly (model.formState /= Editing)
                     , placeholder "First Name"
                     , on "change" (succeed FormChanged)
                     , onInput FirstNameInput
                     , Html.Attributes.value model.firstName
                     ]
                        ++ validationClasses model.showValidation firstNameValidationResult
                    )
                    []
                , invalidFeedback firstNameValidationResult
                ]
            , div [ class "col-6" ]
                [ label [ for lastNameFieldId, class "form-label" ]
                    [ text "Last Name" ]
                , input
                    ([ id lastNameFieldId
                     , type_ "text"
                     , class "form-control"
                     , maxlength 40
                     , readonly (model.formState /= Editing)
                     , placeholder "Last Name"
                     , on "change" (succeed FormChanged)
                     , onInput LastNameInput
                     , Html.Attributes.value model.lastName
                     ]
                        ++ validationClasses model.showValidation lastNameValidationResult
                    )
                    []
                , invalidFeedback lastNameValidationResult
                ]
            , div [ class "form-text", class "mb-3" ]
                [ text "Your name must match your government-issued identification and be a maximum of 80 characters." ]
            , div [ class "col-12" ]
                [ label [ for emailAddressFieldId, class "form-label" ]
                    [ text "Email Address" ]
                , div [ class "input-group" ]
                    [ input
                        ([ id emailAddressFieldId
                         , type_ "email"
                         , class "form-control"
                         , readonly (model.formState /= Editing)
                         , placeholder "Email Address"
                         , on "change" (succeed FormChanged)
                         , onInput EmailAddressInput
                         , Html.Attributes.value model.emailAddress
                         ]
                            ++ validationClasses model.showValidation emailAddressValidationResult
                        )
                        []
                    , button
                        [ class "btn"
                        , class "btn-primary"
                        , class "rounded-end"
                        , type_ "button"
                        , id emailVerificationButtonId
                        , disabled
                            (model.emailVerified
                                || maybeEmailProvider
                                == Nothing
                                || model.redirectingToEmailVerification
                            )
                        , onClick EmailVerificationButtonClicked
                        ]
                        [ if model.emailVerified then
                            checkIcon

                          else
                            case maybeEmailProvider of
                                Just provider ->
                                    emailProviderIcon provider

                                Nothing ->
                                    exclamationCircleIcon
                        , text
                            (noBreakSpace
                                ++ noBreakSpace
                                ++ (if model.emailVerified then
                                        "Verified"

                                    else
                                        case maybeEmailProvider of
                                            Just provider ->
                                                "Verify with " ++ emailProviderDisplayName provider

                                            Nothing ->
                                                "Verify"
                                   )
                            )
                        ]
                    , invalidFeedback emailAddressValidationResult
                    ]
                ]
            , div [ class "form-text", class "mb-3" ]
                [ text "You'll receive notifications about your credit card transactions and reimbursements to this address." ]
            , div [ class "col-12" ]
                (renderSelect
                    { fieldId = managerFieldId
                    , labelText = "Manager"
                    , placeholderSelected =
                        if model.showAdvancedOptions then
                            model.managerRampId == Nothing

                        else
                            case model.managerApiaryId of
                                Just managerApiaryId ->
                                    model.selfApiaryId == managerApiaryId

                                Nothing ->
                                    True
                    , placeholderLabel = "Select your manager..."
                    , isDisabled = model.formState /= Editing
                    , onChange =
                        if model.showAdvancedOptions then
                            Json.Decode.map RampManagerInput targetValue

                        else
                            Json.Decode.map ApiaryManagerInput targetValueIntParse
                    , validationAttributes = validationClasses model.showValidation managerValidationResult
                    , options =
                        if model.showAdvancedOptions then
                            List.map (rampObjectToHtmlOption model.managerRampId) (sortWith sortByRampObjectLabel (toList model.managerRampOptions))

                        else
                            List.map (managerTupleToHtmlOption model.managerApiaryId model.selfApiaryId) (sortBy second (toList model.managerApiaryOptions))
                    , validationResult = managerValidationResult
                    }
                    ++ [ div [ class "form-text", class "mb-3" ]
                            [ text "Your manager will be responsible for reviewing your credit card transactions and reimbursement requests. This should typically be your project manager." ]
                       ]
                )
            , div [ class "col-md-6", class "col-12", classList [ ( "d-none", not model.showAdvancedOptions ) ] ]
                (renderSelect
                    { fieldId = departmentFieldId
                    , labelText = "Department"
                    , placeholderSelected = model.rampDepartmentId == Nothing
                    , placeholderLabel = "Select your department..."
                    , isDisabled = model.formState /= Editing
                    , onChange = Json.Decode.map DepartmentInput targetValue
                    , validationAttributes = validationClasses model.showValidation departmentValidationResult
                    , options =
                        List.map (rampObjectToHtmlOption model.rampDepartmentId) (sortWith sortByRampObjectLabel (toList model.rampDepartmentOptions))
                    , validationResult = departmentValidationResult
                    }
                    ++ [ div [ class "form-text", class "mb-3" ]
                            [ text "Students should generally select "
                            , strong [] [ text (rampObjectLabel model.rampDepartmentOptions model.studentDefaultDepartmentId) ]
                            , text ", and corporation staff should generally select "
                            , strong [] [ text (rampObjectLabel model.rampDepartmentOptions model.nonStudentDefaultDepartmentId) ]
                            , text "."
                            ]
                       ]
                )
            , div [ class "col-md-6", class "col-12", classList [ ( "d-none", not model.showAdvancedOptions ) ] ]
                (renderSelect
                    { fieldId = locationFieldId
                    , labelText = "Location"
                    , placeholderSelected = model.rampLocationId == Nothing
                    , placeholderLabel = "Select your location..."
                    , isDisabled = model.formState /= Editing
                    , onChange = Json.Decode.map LocationInput targetValue
                    , validationAttributes = validationClasses model.showValidation locationValidationResult
                    , options =
                        List.map (rampObjectToHtmlOption model.rampLocationId) (sortWith sortByRampObjectLabel (toList model.rampLocationOptions))
                    , validationResult = locationValidationResult
                    }
                    ++ [ div [ class "form-text", class "mb-3" ]
                            [ text (rampObjectLabel model.rampLocationOptions model.studentDefaultLocationId ++ "-based members should select ")
                            , strong [] [ text (rampObjectLabel model.rampLocationOptions model.studentDefaultLocationId) ]
                            , text ". All other members should select "
                            , strong [] [ text (rampObjectLabel model.rampLocationOptions model.nonStudentDefaultLocationId) ]
                            , text "."
                            ]
                       ]
                )
            , div [ class "col-12", classList [ ( "d-none", not model.showAdvancedOptions ) ] ]
                (renderSelect
                    { fieldId = roleFieldId
                    , labelText = "Role"
                    , placeholderSelected = model.rampRoleId == Nothing
                    , placeholderLabel = "Select your role..."
                    , isDisabled = model.formState /= Editing
                    , onChange = Json.Decode.map RoleInput targetValue
                    , validationAttributes = validationClasses model.showValidation roleValidationResult
                    , options =
                        List.map (rampObjectToHtmlOption model.rampRoleId) (sortWith sortByRampRoleRankOrder (toList model.rampRoleOptions))
                    , validationResult = roleValidationResult
                    }
                    ++ [ div [ class "form-text", class "d-md-none", class "mb-3" ]
                            ([ text "Most members should select "
                             , strong [] [ text "Employee" ]
                             , text ", unless you have a specific need for additional access. Read more about roles in the "
                             ]
                                ++ userRolesRampHelpCenterLink
                            )
                       , div [ class "form-text", class "d-none", class "mb-3", class "d-md-block" ]
                            ([ text "Corporation staff that need to manage our Ramp account should select "
                             , strong [] [ text "Admin" ]
                             , text ". Technology staff that need to manage users within Ramp should select "
                             , strong [] [ text "IT admin" ]
                             , text ". Members that need to view all activity within Ramp should select "
                             , strong [] [ text "Accounting" ]
                             , text ". All other members should select "
                             , strong [] [ text "Employee" ]
                             , text ". Read more about roles in the "
                             ]
                                ++ userRolesRampHelpCenterLink
                            )
                       ]
                )
            , div [ class "col-12" ]
                [ div [ class "form-check" ]
                    [ input
                        [ id orderPhysicalCardFieldId
                        , type_ "checkbox"
                        , class "form-check-input"
                        , disabled (model.formState /= Editing)
                        , onCheck OrderPhysicalCardChecked
                        , checked model.orderPhysicalCard
                        ]
                        []
                    , label [ for orderPhysicalCardFieldId, class "form-check-label" ]
                        [ text "Order a physical card" ]
                    , div [ class "form-text", class "mb-3" ]
                        [ text "We recommend a physical card for everyone. You will only be able to use it once you activate it ", strong [] [ text " and " ], text " request funds within Ramp. If you choose not to order one now, you can do so later within Ramp." ]
                    ]
                ]
            , div [ class "col-12", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ label [ for addressLineOneFieldId, class "form-label" ] [ text "Mailing Address" ]
                , input
                    ([ type_ "text"
                     , class "form-control"
                     , id addressLineOneFieldId
                     , maxlength 100
                     , readonly (model.formState /= Editing)
                     , placeholder "Street Address"
                     , onInput AddressLineOneInput
                     , on "change" (succeed FormChanged)
                     , Html.Attributes.value model.addressLineOne
                     , preventDefaultOn "keydown" keyDecoder
                     ]
                        ++ addressValidationClasses model.showValidation model.addressIsValid addressLineOneValidationResult
                    )
                    []
                , invalidFeedback
                    (if isValid addressLineOneValidationResult then
                        validateAddressLineOneGoogleResult model.addressIsValid

                     else
                        addressLineOneValidationResult
                    )
                ]
            , div [ class "col-12", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ label [ for addressLineTwoFieldId, class "visually-hidden" ]
                    [ text "Apartment, suite, unit, etc." ]
                , input
                    ([ type_ "text"
                     , class "form-control"
                     , id addressLineTwoFieldId
                     , maxlength 100
                     , placeholder "Apt, Suite, Unit, etc."
                     , readonly (model.formState /= Editing)
                     , onInput AddressLineTwoInput
                     , on "change" (succeed FormChanged)
                     , Html.Attributes.value model.addressLineTwo
                     ]
                        ++ addressValidationClasses model.showValidation model.addressIsValid addressLineTwoValidationResult
                    )
                    []
                , invalidFeedback addressLineTwoValidationResult
                ]
            , div [ class "col-md-6", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ label [ for cityFieldId, class "form-label" ] [ text "City" ]
                , input
                    ([ type_ "text"
                     , class "form-control"
                     , id cityFieldId
                     , maxlength 40
                     , placeholder "City"
                     , readonly (model.formState /= Editing)
                     , onInput CityInput
                     , on "change" (succeed FormChanged)
                     , Html.Attributes.value model.city
                     ]
                        ++ addressValidationClasses model.showValidation model.addressIsValid cityValidationResult
                    )
                    []
                , invalidFeedback cityValidationResult
                ]
            , div [ class "col-md-3", class "col-8", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                (renderSelect
                    { fieldId = stateFieldId
                    , labelText = "State"
                    , placeholderSelected = model.state == Nothing
                    , placeholderLabel = "Select..."
                    , isDisabled = model.formState /= Editing
                    , onChange = Json.Decode.map StateInput targetValue
                    , validationAttributes = addressValidationClasses model.showValidation model.addressIsValid stateValidationResult
                    , options = List.map (stateTupleToHtmlOption model.state) (sortBy second (toList statesMap))
                    , validationResult = stateValidationResult
                    }
                )
            , div [ class "col-md-3", class "col-4", class "mb-2", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ label [ for zipCodeFieldId, class "form-label" ] [ text "ZIP Code" ]
                , input
                    ([ type_ "text"
                     , attribute "inputmode" "numeric"
                     , class "form-control"
                     , id zipCodeFieldId
                     , placeholder "ZIP Code"
                     , maxlength 5
                     , readonly (model.formState /= Editing)
                     , onInput ZipInput
                     , on "change" (succeed FormChanged)
                     , Html.Attributes.value model.zip
                     ]
                        ++ addressValidationClasses model.showValidation model.addressIsValid zipValidationResult
                    )
                    []
                , invalidFeedback zipValidationResult
                ]
            , div [ class "form-text", class "d-none", class "mb-3", classList [ ( "d-sm-block", model.orderPhysicalCard ) ] ]
                [ text
                    ("Your physical card should be delivered by "
                        ++ physicalCardEstimatedDeliveryDate
                        ++ "."
                    )
                ]
            , div [ class "form-text", class "d-sm-none", class "mb-3", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ text
                    ("Your card should be delivered by "
                        ++ physicalCardEstimatedDeliveryDate
                        ++ "."
                    )
                ]
            , div [ class "col-12", class "mb-2" ]
                [ button
                    [ type_ "submit"
                    , class "btn"
                    , class "btn-primary"
                    , id submitButtonId
                    , disabled (model.formState /= Editing)
                    ]
                    [ text "Create Account"
                    ]
                , button
                    [ type_ "button"
                    , class "btn"
                    , class "btn-link"
                    , classList [ ( "d-none", model.showAdvancedOptions ) ]
                    , disabled (model.formState /= Editing)
                    , onClick ShowAdvancedOptionsButtonClicked
                    ]
                    [ text "Show advanced options"
                    ]
                ]
            ]
        , div [ class "mb-4", class "mb-md-5", class "col-12", class "form-text" ]
            ([ text "By creating an account, you confirm that you have read and agree to the "
             , a [ href "https://docs.google.com/document/d/e/2PACX-1vRtmt5h8lq3Z1dgxC8eGh04-EPEc7twiYF8t4BQGr9XxCamkjlPavBcPWuMAMGLFNJeRft3Z89ITCkY/pub", class "text-secondary", target "_blank", rel "noopener noreferrer" ] [ text (model.businessLegalName ++ " Expense Policy") ]
             , text ", "
             ]
                ++ List.intersperse (text ", ") (List.map termsOfServiceItemToLink (List.take (List.length termsOfService - 1) termsOfService))
                ++ [ text ", and ", termsOfServiceItemToLink (withDefault ( "", "" ) (List.head (List.reverse termsOfService))), text "." ]
            )
        ]
        ++ [ div
                [ id "g_id_onload"
                , attribute "data-client_id" model.googleClientId
                , attribute "data-auto_prompt" "true"
                , attribute "data-auto_select" "true"
                , attribute "data-login_uri" model.googleOneTapLoginUri
                , attribute "data-cancel_on_tap_outside" "false"
                , attribute "data-context" "signin"
                , attribute "data-itp_support" "true"
                , attribute "data-login_hint" (String.trim model.emailAddress)
                , attribute "data-hd" "robojackets.org"
                , attribute "data-use_fedcm_for_prompt" "true"
                ]
                []
           ]


renderLoadingIndicators : Model -> List (Html Msg)
renderLoadingIndicators model =
    let
        accountCreated : Bool
        accountCreated =
            model.formState == RampAccountCreated || model.formState == PhysicalCardOrdered

        ssoConfigured : Bool
        ssoConfigured =
            accountCreated
                || (case model.formState of
                        CreatingRampAccount (Just _) ->
                            True

                        _ ->
                            False
                   )

        cardOrdered : Bool
        cardOrdered =
            model.formState == PhysicalCardOrdered

        allVisibleStepsComplete : Bool
        allVisibleStepsComplete =
            if model.orderPhysicalCard then
                cardOrdered

            else
                accountCreated
    in
    pageChrome
        [ div
            [ attribute "aria-live" "polite"
            , attribute "aria-atomic" "true"
            , attribute "aria-busy"
                (if allVisibleStepsComplete then
                    "false"

                 else
                    "true"
                )
            ]
            [ p [ class "mt-4", class "mb-3" ]
                [ text "Please wait a moment..."
                ]
            , loadingIndicatorRow [ class "mt-3" ] ssoConfigured "Configuring single sign-on"
            , loadingIndicatorRow [ class "mt-2" ] accountCreated "Creating your Ramp account"
            , loadingIndicatorRow [ class "mt-2", classList [ ( "d-none", not model.orderPhysicalCard ) ] ] cardOrdered "Ordering your physical card"
            ]
        ]



-- VALIDATION


validateName : String -> String -> ValidationResult
validateName whichName nameValue =
    if blankString nameValue then
        Invalid ("Please enter your " ++ whichName ++ " name")

    else if String.length (String.trim nameValue) < 2 then
        Invalid ("Your " ++ whichName ++ " name must be at least 2 characters")

    else if String.length (String.trim nameValue) > 40 then
        Invalid ("Your " ++ whichName ++ " name may be a maximum of 40 characters")

    else if not (Regex.contains nameRegex nameValue) then
        Invalid ("Your " ++ whichName ++ " name may only contain letters, spaces, dashes, apostrophes, and periods")

    else
        Valid


validateEmailAddress : String -> Bool -> ValidationResult
validateEmailAddress emailAddress verified =
    case Email.parse emailAddress of
        Ok addressParts ->
            case getSecondLevelDomain addressParts.domain of
                Just domain ->
                    case Dict.get domain emailProviderByDomain of
                        Just provider ->
                            if not verified then
                                Invalid ("Please verify your email address with " ++ emailProviderDisplayName provider)

                            else
                                Valid

                        Nothing ->
                            Invalid emailFeedbackText

                Nothing ->
                    Invalid emailFeedbackText

        Err _ ->
            Invalid emailFeedbackText


validateManager : Bool -> Maybe Bool -> String -> Maybe String -> Maybe Int -> Maybe String -> Dict Int String -> Dict String RampUser -> Int -> ValidationResult
validateManager usingRampManagerOptions selectedManagerHasRampAccount selectedManagerRampFeedbackText selectedManagerRampId selectedManagerApiaryId selectedDepartmentId managerApiaryOptions managerRampOptions selfId =
    if usingRampManagerOptions then
        case selectedManagerRampId of
            Just managerId ->
                case Dict.get managerId managerRampOptions of
                    Just manager ->
                        if not manager.enabled then
                            Invalid managerFeedbackText

                        else
                            case selectedDepartmentId of
                                Just deptId ->
                                    if manager.departmentId /= deptId then
                                        Invalid managerDepartmentFeedbackText

                                    else
                                        Valid

                                Nothing ->
                                    Valid

                    Nothing ->
                        Invalid managerFeedbackText

            Nothing ->
                Invalid managerFeedbackText

    else
        case selectedManagerApiaryId of
            Just managerId ->
                if managerId == selfId then
                    Invalid managerFeedbackText

                else if Dict.member managerId managerApiaryOptions then
                    case selectedManagerHasRampAccount of
                        Just True ->
                            Valid

                        Just False ->
                            Invalid selectedManagerRampFeedbackText

                        Nothing ->
                            Valid

                else
                    Invalid managerFeedbackText

            Nothing ->
                Invalid managerFeedbackText


validateAddressLineOne : String -> ValidationResult
validateAddressLineOne addressLineOne =
    if blankString addressLineOne then
        Invalid "Please enter your street address"

    else if String.length (String.trim addressLineOne) > 100 then
        Invalid "Your street address may be a maximum of 100 characters"

    else
        Valid


validateAddressLineOneGoogleResult : Maybe Bool -> ValidationResult
validateAddressLineOneGoogleResult maybeIsValid =
    case maybeIsValid of
        Just False ->
            Invalid "This doesn't appear to be a valid address"

        _ ->
            Valid


validateAddressLineTwo : String -> Bool -> CampusAddress -> ValidationResult
validateAddressLineTwo addressLineTwo isRequired campusAddress =
    if String.length (String.trim addressLineTwo) > 100 then
        Invalid "Your second address line may be a maximum of 100 characters"

    else if blankString addressLineTwo && (isRequired || campusAddress /= NotCampusAddress) then
        Invalid
            ("This address requires "
                ++ (case campusAddress of
                        StudentCenter ->
                            "a mailbox"

                        GraduateLivingCenter ->
                            "an apartment"

                        ManufacturingRelatedDisciplinesComplex ->
                            "a room"

                        NotCampusAddress ->
                            "an apartment or unit"
                   )
                ++ " number"
            )

    else if
        campusAddress
            == StudentCenter
            && not (Regex.contains studentCenterMailboxRegex (String.trim (String.toLower addressLineTwo)))
    then
        Invalid "This doesn't appear to be a valid mailbox number"

    else if
        campusAddress
            == GraduateLivingCenter
            && not (Regex.contains graduateLivingCenterMailboxRegex (String.trim (String.toLower addressLineTwo)))
    then
        Invalid "This doesn't appear to be a valid apartment number"

    else if
        campusAddress
            == ManufacturingRelatedDisciplinesComplex
            && String.trim (String.toLower addressLineTwo)
            /= "rm 1312"
            && String.trim (String.toLower addressLineTwo)
            /= "room 1312"
            && String.trim (String.toLower addressLineTwo)
            /= "mrdc rm 1312"
            && String.trim (String.toLower addressLineTwo)
            /= "mrdc room 1312"
    then
        Invalid "For delivery to the MRDC loading dock, use Room 1312"

    else
        Valid


validateCity : String -> ValidationResult
validateCity city =
    if blankString city then
        Invalid "Please enter your city"

    else if String.length (String.trim city) > 40 then
        Invalid "Your city may be a maximum of 40 characters"

    else
        Valid


validateState : Maybe String -> ValidationResult
validateState selectedState =
    case selectedState of
        Just _ ->
            Valid

        Nothing ->
            Invalid "Please select your state"


validateRampObject : String -> Maybe String -> Dict String RampObject -> ValidationResult
validateRampObject objectName selectedObject objectOptions =
    case selectedObject of
        Just selectedObjectId ->
            if (withDefault { label = "", enabled = False } (Dict.get selectedObjectId objectOptions)).enabled then
                Valid

            else
                Invalid ("Please select your " ++ objectName)

        Nothing ->
            Invalid ("Please select your " ++ objectName)


validateZipCode : String -> ValidationResult
validateZipCode zipCode =
    let
        trimmedZipCode : String
        trimmedZipCode =
            String.trim zipCode
    in
    if String.length trimmedZipCode == 5 && String.all isDigit trimmedZipCode then
        Valid

    else
        Invalid "Please enter exactly 5 digits"


firstInvalidFieldId : Model -> Maybe String
firstInvalidFieldId model =
    [ ( firstNameFieldId, isValid (validateName "first" model.firstName) )
    , ( lastNameFieldId, isValid (validateName "last" model.lastName) )
    , ( emailAddressFieldId, isValid (validateEmailAddress model.emailAddress True) )
    , ( emailVerificationButtonId, model.emailVerified )
    , ( managerFieldId, isValid (validateManager model.showAdvancedOptions model.managerIsValid model.managerFeedbackText model.managerRampId model.managerApiaryId model.rampDepartmentId model.managerApiaryOptions model.managerRampOptions model.selfApiaryId) )
    , ( departmentFieldId, isValid (validateRampObject "department" model.rampDepartmentId model.rampDepartmentOptions) )
    , ( locationFieldId, isValid (validateRampObject "location" model.rampLocationId model.rampLocationOptions) )
    , ( roleFieldId, isValid (validateRampObject "role" model.rampRoleId model.rampRoleOptions) )
    , ( addressLineOneFieldId
      , not model.orderPhysicalCard
            || (isValid (validateAddressLineOne model.addressLineOne)
                    && isValid (validateAddressLineOneGoogleResult model.addressIsValid)
               )
      )
    , ( addressLineTwoFieldId, not model.orderPhysicalCard || isValid (validateAddressLineTwo model.addressLineTwo model.addressLineTwoRequired (classifyCampusAddress model)) )
    , ( cityFieldId, not model.orderPhysicalCard || isValid (validateCity model.city) )
    , ( stateFieldId, not model.orderPhysicalCard || isValid (validateState model.state) )
    , ( zipCodeFieldId, not model.orderPhysicalCard || isValid (validateZipCode model.zip) )
    ]
        |> List.filterMap
            (\( fieldId, fieldIsValid ) ->
                if fieldIsValid then
                    Nothing

                else
                    Just fieldId
            )
        |> List.head



-- HELPERS


isValid : ValidationResult -> Bool
isValid validation =
    case validation of
        Valid ->
            True

        Invalid _ ->
            False


feedbackText : ValidationResult -> String
feedbackText validation =
    case validation of
        Valid ->
            ""

        Invalid feedback ->
            feedback


validationClasses : Bool -> ValidationResult -> List (Attribute msg)
validationClasses showValidation validationResult =
    let
        isInvalid : Bool
        isInvalid =
            showValidation && not (isValid validationResult)
    in
    [ classList
        [ ( "is-valid", showValidation && isValid validationResult )
        , ( "is-invalid", isInvalid )
        ]
    , attribute "aria-invalid"
        (if isInvalid then
            "true"

         else
            "false"
        )
    ]


addressValidationClasses : Bool -> Maybe Bool -> ValidationResult -> List (Attribute msg)
addressValidationClasses showValidation addressIsValid validationResult =
    let
        isInvalid : Bool
        isInvalid =
            showValidation && (not (isValid validationResult) || not (withDefault True addressIsValid))
    in
    [ classList
        [ ( "is-valid", showValidation && isValid validationResult && withDefault True addressIsValid )
        , ( "is-invalid", isInvalid )
        ]
    , attribute "aria-invalid"
        (if isInvalid then
            "true"

         else
            "false"
        )
    ]


invalidFeedback : ValidationResult -> Html msg
invalidFeedback validationResult =
    div [ class "invalid-feedback" ] [ text (feedbackText validationResult) ]


placeholderOption : Bool -> String -> Html msg
placeholderOption isSelected labelText =
    option
        [ Html.Attributes.value ""
        , disabled True
        , selected isSelected
        , style "display" "none"
        ]
        [ text labelText ]


type alias SelectFieldConfig =
    { fieldId : String
    , labelText : String
    , placeholderSelected : Bool
    , placeholderLabel : String
    , isDisabled : Bool
    , onChange : Decoder Msg
    , validationAttributes : List (Attribute Msg)
    , options : List (Html Msg)
    , validationResult : ValidationResult
    }


renderSelect : SelectFieldConfig -> List (Html Msg)
renderSelect config =
    [ label [ for config.fieldId, class "form-label" ]
        [ text config.labelText ]
    , select
        ([ class "form-select"
         , id config.fieldId
         , disabled config.isDisabled
         , on "change" config.onChange
         ]
            ++ config.validationAttributes
        )
        (placeholderOption config.placeholderSelected config.placeholderLabel
            :: config.options
        )
    , invalidFeedback config.validationResult
    ]


loadingIndicatorRow : List (Attribute msg) -> Bool -> String -> Html msg
loadingIndicatorRow extraAttributes isComplete labelText =
    div ([ class "d-flex", class "align-items-center" ] ++ extraAttributes)
        [ if isComplete then
            checkCircleIcon

          else
            spinner
        , div [ class "ms-2", style "display" "inline-block" ] [ text labelText ]
        ]


rampObjectLabel : Dict String RampObject -> String -> String
rampObjectLabel options optionId =
    Dict.get optionId options
        |> Maybe.map .label
        |> withDefault ""


httpErrorToString : Http.Error -> String
httpErrorToString error =
    case error of
        Http.BadUrl url ->
            "Invalid URL: " ++ url

        Http.Timeout ->
            "The request timed out"

        Http.NetworkError ->
            "Network error"

        Http.BadStatus status ->
            "Unexpected HTTP status code " ++ String.fromInt status

        Http.BadBody body ->
            "Unexpected response body: " ++ body


provisioningFailureStepLabel : ProvisioningFailure -> String
provisioningFailureStepLabel failure =
    case failure of
        CreateAccountRequestFailed _ ->
            "creating your Ramp account"

        CreateAccountTaskFailed ->
            "creating your Ramp account"

        CreateAccountStatusCheckFailed _ ->
            "checking account creation status"

        OrderPhysicalCardFailed _ ->
            "ordering your physical card"


provisioningFailureDetail : ProvisioningFailure -> String
provisioningFailureDetail failure =
    case failure of
        CreateAccountRequestFailed detail ->
            detail

        CreateAccountTaskFailed ->
            "Ramp reported that account creation failed."

        CreateAccountStatusCheckFailed detail ->
            detail

        OrderPhysicalCardFailed detail ->
            detail


provisioningFailureAlertText : ProvisioningFailure -> String
provisioningFailureAlertText failure =
    "There was an error "
        ++ provisioningFailureStepLabel failure
        ++ ": "
        ++ provisioningFailureDetail failure


showProvisioningFailure : Model -> ProvisioningFailure -> ( Model, Cmd Msg )
showProvisioningFailure model failure =
    ( { model | formState = Error failure }
    , Cmd.batch
        [ showAlert (provisioningFailureAlertText failure)
        , reportErrorCmd "error"
            (provisioningFailureAlertText failure)
            [ ( "step", provisioningFailureStepTag failure )
            , ( "kind", "provisioning" )
            ]
        ]
    )


reportErrorCmd : String -> String -> List ( String, String ) -> Cmd msg
reportErrorCmd level message tags =
    reportError
        (Json.Encode.object
            [ ( "message", Json.Encode.string message )
            , ( "level", Json.Encode.string level )
            , ( "tags"
              , Json.Encode.object
                    (List.map (\( key, value ) -> ( key, Json.Encode.string value )) tags)
              )
            ]
        )


reportHttpError : String -> Http.Error -> Cmd msg
reportHttpError step error =
    reportErrorCmd "warning"
        (httpErrorToString error)
        [ ( "step", step ), ( "kind", "http" ) ]


provisioningFailureStepTag : ProvisioningFailure -> String
provisioningFailureStepTag failure =
    case failure of
        CreateAccountRequestFailed _ ->
            "create_account"

        CreateAccountTaskFailed ->
            "create_account_task"

        CreateAccountStatusCheckFailed _ ->
            "create_account_status"

        OrderPhysicalCardFailed _ ->
            "order_physical_card"


emailAddressDomain : String -> Maybe String
emailAddressDomain emailAddress =
    case Email.parse emailAddress of
        Ok addressParts ->
            getSecondLevelDomain addressParts.domain

        Err _ ->
            Nothing


getSecondLevelDomain : String -> Maybe String
getSecondLevelDomain domain =
    case take 2 (List.reverse (String.split "." (String.toLower (String.trim domain)))) of
        [ tld, sld ] ->
            Just (sld ++ "." ++ tld)

        _ ->
            Nothing


emailProviderForAddress : String -> Maybe EmailProvider
emailProviderForAddress emailAddress =
    emailAddressDomain emailAddress
        |> Maybe.andThen (\domain -> Dict.get domain emailProviderByDomain)


emailProviderDisplayName : EmailProvider -> String
emailProviderDisplayName provider =
    case provider of
        Google ->
            "Google"

        Microsoft ->
            "Microsoft"


emailProviderIcon : EmailProvider -> Svg msg
emailProviderIcon provider =
    case provider of
        Google ->
            googleIcon

        Microsoft ->
            microsoftIcon


managerTupleToHtmlOption : Maybe Int -> Int -> ( Int, String ) -> Html msg
managerTupleToHtmlOption selectedManagerId selfId ( managerId, managerName ) =
    option
        [ Html.Attributes.value (String.fromInt managerId)
        , selected (selectedManagerId == Just managerId && managerId /= selfId)
        , disabled (selfId == managerId)
        ]
        [ text managerName ]


rampObjectToHtmlOption : Maybe String -> ( String, { a | label : String, enabled : Bool } ) -> Html msg
rampObjectToHtmlOption maybeSelectedId ( rampId, rampObject ) =
    option
        [ Html.Attributes.value rampId
        , selected (maybeSelectedId == Just rampId)
        , disabled (not rampObject.enabled)
        ]
        [ text rampObject.label ]


stateTupleToHtmlOption : Maybe String -> ( String, String ) -> Html msg
stateTupleToHtmlOption selectedState ( stateCode, stateName ) =
    option
        [ Html.Attributes.value stateCode
        , selected (selectedState == Just stateCode)
        ]
        [ text stateName ]



-- Encodes only the form fields that are persisted to localStorage, not the entire model.
-- Ramp fields and showAdvancedOptions are written only in advanced mode.


encodeFormState : Model -> String
encodeFormState model =
    let
        baseFields : List ( String, Json.Encode.Value )
        baseFields =
            [ ( firstNameLocalStorageKey, Json.Encode.string (String.trim model.firstName) )
            , ( lastNameLocalStorageKey, Json.Encode.string (String.trim model.lastName) )
            , ( emailAddressLocalStorageKey, Json.Encode.string (String.trim model.emailAddress) )
            , ( managerApiaryIdLocalStorageKey
              , case model.managerApiaryId of
                    Just managerApiaryId ->
                        Json.Encode.int managerApiaryId

                    Nothing ->
                        Json.Encode.null
              )
            , ( orderPhysicalCardLocalStorageKey, Json.Encode.bool model.orderPhysicalCard )
            , ( addressLineOneLocalStorageKey, Json.Encode.string (String.trim model.addressLineOne) )
            , ( addressLineTwoLocalStorageKey, Json.Encode.string (String.trim model.addressLineTwo) )
            , ( cityLocalStorageKey, Json.Encode.string (String.trim model.city) )
            , ( stateLocalStorageKey
              , case model.state of
                    Just state ->
                        Json.Encode.string (String.trim state)

                    Nothing ->
                        Json.Encode.null
              )
            , ( zipCodeLocalStorageKey, Json.Encode.string (String.trim model.zip) )
            ]
    in
    Json.Encode.encode 0
        (Json.Encode.object
            (baseFields
                ++ (if model.showAdvancedOptions then
                        [ ( showAdvancedOptionsLocalStorageKey, Json.Encode.bool True )
                        , ( managerRampIdLocalStorageKey
                          , case model.managerRampId of
                                Just managerRampId ->
                                    Json.Encode.string (String.trim managerRampId)

                                Nothing ->
                                    Json.Encode.null
                          )
                        , ( departmentIdLocalStorageKey
                          , case model.rampDepartmentId of
                                Just departmentId ->
                                    Json.Encode.string (String.trim departmentId)

                                Nothing ->
                                    Json.Encode.null
                          )
                        , ( locationIdLocalStorageKey
                          , case model.rampLocationId of
                                Just locationId ->
                                    Json.Encode.string (String.trim locationId)

                                Nothing ->
                                    Json.Encode.null
                          )
                        , ( roleIdLocalStorageKey
                          , case model.rampRoleId of
                                Just roleId ->
                                    Json.Encode.string (String.trim roleId)

                                Nothing ->
                                    Json.Encode.null
                          )
                        ]

                    else
                        []
                   )
            )
        )


saveFormStateToLocalStorage : Model -> Cmd msg
saveFormStateToLocalStorage model =
    saveToLocalStorage (encodeFormState model)


updateAndSaveToLocalStorage : Model -> ( Model, Cmd msg )
updateAndSaveToLocalStorage newModel =
    ( newModel, saveFormStateToLocalStorage newModel )



-- Stops the Enter key from submitting the form, so that selecting a Google Places autocomplete suggestion with Enter doesn't submit a half-filled form


keyDecoder : Decoder ( Msg, Bool )
keyDecoder =
    field "key" string
        |> Json.Decode.map
            (\key ->
                ( NoOpMsg, isEnterKey key )
            )


isEnterKey : String -> Bool
isEnterKey key =
    key == "Enter"


addressComponentDecoder : Decoder AddressComponent
addressComponentDecoder =
    Json.Decode.map2 AddressComponent
        (field "short_name" string)
        (field "types" (Json.Decode.list string))


decodePlaceChanged : Value -> Result Json.Decode.Error PlaceChange
decodePlaceChanged value =
    case decodeValue (maybe (field "address_components" Json.Decode.value)) value of
        Ok Nothing ->
            Ok PlaceIncomplete

        Ok (Just addressComponentsValue) ->
            case decodeValue (Json.Decode.list addressComponentDecoder) addressComponentsValue of
                Ok components ->
                    if List.isEmpty components then
                        Ok PlaceIncomplete

                    else
                        Ok (PlaceSelected components)

                Err decodeError ->
                    Err decodeError

        Err decodeError ->
            Err decodeError


getAddressComponent : List AddressComponent -> String -> String
getAddressComponent components desiredType =
    case List.head (List.filter (addressComponentTypeMatches desiredType) components) of
        Just component ->
            component.value

        Nothing ->
            ""


addressComponentTypeMatches : String -> AddressComponent -> Bool
addressComponentTypeMatches desiredType component =
    List.member desiredType component.types


googleAddressValidationResponseDecoder : Decoder GoogleAddressValidation
googleAddressValidationResponseDecoder =
    Json.Decode.map2 GoogleAddressValidation
        (maybe (at [ "result", "verdict", "addressComplete" ] bool))
        (maybe (at [ "result", "address", "missingComponentTypes" ] (Json.Decode.list string)))


managerApiaryIdFromValidation : ManagerValidation -> Int
managerApiaryIdFromValidation validation =
    case validation of
        ManagerResolved { managerApiaryId } ->
            managerApiaryId

        ManagerRejected { managerApiaryId } ->
            managerApiaryId


managerValidationApiaryIdDecoder : Decoder Int
managerValidationApiaryIdDecoder =
    field "apiaryUserId" string
        |> andThen
            (\apiaryUserId ->
                case String.toInt apiaryUserId of
                    Just managerApiaryId ->
                        succeed managerApiaryId

                    Nothing ->
                        fail ("apiaryUserId is not an integer: " ++ apiaryUserId)
            )


managerValidationResponseDecoder : Decoder ManagerValidation
managerValidationResponseDecoder =
    Json.Decode.oneOf
        [ Json.Decode.map2
            (\managerApiaryId managerRampId ->
                ManagerResolved
                    { managerApiaryId = managerApiaryId
                    , managerRampId = managerRampId
                    }
            )
            managerValidationApiaryIdDecoder
            (field "rampUserId" string)
        , Json.Decode.map2
            (\managerApiaryId feedback ->
                ManagerRejected
                    { managerApiaryId = managerApiaryId
                    , managerFeedbackText = feedback
                    }
            )
            managerValidationApiaryIdDecoder
            (field "error" string)
        ]


rampObjectDecoder : Decoder RampObject
rampObjectDecoder =
    Json.Decode.map2 RampObject
        (field "label" string)
        (field "enabled" bool)


rampUserDecoder : Decoder RampUser
rampUserDecoder =
    Json.Decode.map3 RampUser
        (field "label" string)
        (field "enabled" bool)
        (field "departmentId" string)


type alias ServerData =
    { firstName : String
    , lastName : String
    , emailAddress : String
    , emailVerified : Bool
    , managerApiaryId : Maybe Int
    , apiaryManagerOptions : Dict Int String
    , managerRampId : Maybe String
    , rampManagerOptions : Dict String RampUser
    , selfApiaryId : Int
    , addressLineOne : String
    , addressLineTwo : String
    , city : String
    , state : Maybe String
    , zip : String
    , googleMapsApiKey : String
    , googleClientId : String
    , googleOneTapLoginUri : String
    , showAdvancedOptions : Bool
    , departmentOptions : Dict String RampObject
    , departmentId : Maybe String
    , locationOptions : Dict String RampObject
    , locationId : Maybe String
    , roleOptions : Dict String RampObject
    , roleId : Maybe String
    , studentDefaultDepartmentId : String
    , nonStudentDefaultDepartmentId : String
    , studentDefaultLocationId : String
    , nonStudentDefaultLocationId : String
    , rampSignInUri : String
    , businessLegalName : String
    , slackSupportChannelDeepLink : String
    , slackSupportChannelName : String
    }


andMap : Decoder a -> Decoder (a -> b) -> Decoder b
andMap =
    Json.Decode.map2 (|>)


trimmedString : Decoder String
trimmedString =
    Json.Decode.map String.trim string


intKeyedDict : Decoder a -> Decoder (Dict Int a)
intKeyedDict valueDecoder =
    let
        toIntPair : ( String, a ) -> Maybe ( Int, a )
        toIntPair ( key, entryValue ) =
            Maybe.map (\intKey -> ( intKey, entryValue )) (String.toInt key)
    in
    keyValuePairs valueDecoder
        |> Json.Decode.andThen
            (\pairs ->
                case List.filter (\( key, _ ) -> String.toInt key == Nothing) pairs of
                    [] ->
                        succeed (Dict.fromList (List.filterMap toIntPair pairs))

                    ( badKey, _ ) :: _ ->
                        fail ("Expected an integer key, but found \"" ++ badKey ++ "\"")
            )


stringToInt : Decoder Int
stringToInt =
    string
        |> andThen
            (\raw ->
                case String.toInt (String.trim raw) of
                    Just intValue ->
                        succeed intValue

                    Nothing ->
                        fail ("Expected an integer string, but found \"" ++ raw ++ "\"")
            )


serverDataDecoder : Decoder ServerData
serverDataDecoder =
    succeed ServerData
        |> andMap (field "firstName" trimmedString)
        |> andMap (field "lastName" trimmedString)
        |> andMap (field "emailAddress" trimmedString)
        |> andMap (field "emailVerified" bool)
        |> andMap (field "managerApiaryId" (nullable stringToInt))
        |> andMap (field "apiaryManagerOptions" (intKeyedDict string))
        |> andMap (field "managerRampId" (nullable string))
        |> andMap (field "rampManagerOptions" (dict rampUserDecoder))
        |> andMap (field "selfApiaryId" stringToInt)
        |> andMap (field "addressLineOne" trimmedString)
        |> andMap (field "addressLineTwo" trimmedString)
        |> andMap (field "city" trimmedString)
        |> andMap (field "state" (nullable string))
        |> andMap (field "zip" trimmedString)
        |> andMap (field "googleMapsApiKey" trimmedString)
        |> andMap (field "googleClientId" trimmedString)
        |> andMap (field "googleOneTapLoginUri" trimmedString)
        |> andMap (field "showAdvancedOptions" bool)
        |> andMap (field "departmentOptions" (dict rampObjectDecoder))
        |> andMap (field "departmentId" (nullable string))
        |> andMap (field "locationOptions" (dict rampObjectDecoder))
        |> andMap (field "locationId" (nullable string))
        |> andMap (field "roleOptions" (dict rampObjectDecoder))
        |> andMap (field "roleId" (nullable string))
        |> andMap (field "defaultDepartmentForStudents" trimmedString)
        |> andMap (field "defaultDepartmentForNonStudents" trimmedString)
        |> andMap (field "defaultLocationForStudents" trimmedString)
        |> andMap (field "defaultLocationForNonStudents" trimmedString)
        |> andMap (field "rampSignInUri" trimmedString)
        |> andMap (field "businessLegalName" trimmedString)
        |> andMap (field "slackSupportChannelDeepLink" trimmedString)
        |> andMap (field "slackSupportChannelName" trimmedString)


createTaskResponseDecoder : Decoder TaskId
createTaskResponseDecoder =
    Json.Decode.map TaskId
        (at [ "taskId" ] Json.Decode.string)


getTaskResponseDecoder : Decoder TaskStatus
getTaskResponseDecoder =
    at [ "taskStatus" ] string
        |> Json.Decode.andThen
            (\status ->
                case status of
                    "STARTED" ->
                        succeed TaskStarted

                    "IN_PROGRESS" ->
                        succeed TaskInProgress

                    "SUCCESS" ->
                        succeed TaskSucceeded

                    "ERROR" ->
                        succeed TaskFailed

                    _ ->
                        fail ("Unknown task status: " ++ status)
            )


needsManagerValidation : Model -> Bool
needsManagerValidation model =
    model.managerRampId == Nothing


needsAddressValidation : Model -> Bool
needsAddressValidation model =
    model.orderPhysicalCard
        && classifyCampusAddress model
        == NotCampusAddress
        && model.addressIsValid
        == Nothing


submissionChecksFromModel : Model -> SubmissionChecks
submissionChecksFromModel model =
    { manager =
        if needsManagerValidation model then
            InFlight

        else
            Done
    , address =
        if needsAddressValidation model then
            InFlight

        else
            Done
    }


abortValidation : FormState -> FormState
abortValidation formState =
    case formState of
        Validating _ ->
            Editing

        _ ->
            formState


markManagerCheckDone : Model -> Model
markManagerCheckDone model =
    case model.formState of
        Validating checks ->
            { model | formState = Validating { checks | manager = Done } }

        _ ->
            model


markAddressCheckDone : Model -> Model
markAddressCheckDone model =
    case model.formState of
        Validating checks ->
            { model | formState = Validating { checks | address = Done } }

        _ ->
            model


proceedIfReady : Model -> ( Model, Cmd Msg )
proceedIfReady model =
    case model.formState of
        Validating checks ->
            case ( checks.manager, checks.address ) of
                ( Done, Done ) ->
                    if firstInvalidFieldId model == Nothing then
                        ( { model | formState = CreatingRampAccount Nothing }
                        , createRampAccountTask model
                        )

                    else
                        ( { model | formState = Editing }, Cmd.none )

                _ ->
                    ( model, Cmd.none )

        _ ->
            ( model, Cmd.none )


httpRequestTimeoutMs : Float
httpRequestTimeoutMs =
    5000


requestManagerValidation : Model -> Cmd Msg
requestManagerValidation model =
    Http.request
        { method = "GET"
        , headers = []
        , url =
            Url.Builder.absolute
                [ "get-ramp-user", String.fromInt (withDefault 0 model.managerApiaryId) ]
                []
        , body = Http.emptyBody
        , expect = expectJson ManagerValidationResultReceived managerValidationResponseDecoder
        , timeout = Just httpRequestTimeoutMs
        , tracker = Nothing
        }


requestManagerRampIdPrefill : Int -> Cmd Msg
requestManagerRampIdPrefill managerApiaryId =
    Http.request
        { method = "GET"
        , headers = []
        , url =
            Url.Builder.absolute
                [ "get-ramp-user", String.fromInt managerApiaryId ]
                []
        , body = Http.emptyBody
        , expect = expectJson AdvancedModeManagerPrefillReceived managerValidationResponseDecoder
        , timeout = Just httpRequestTimeoutMs
        , tracker = Nothing
        }


requestGoogleAddressValidation : Model -> Cmd Msg
requestGoogleAddressValidation model =
    Http.request
        { method = "POST"
        , headers = []
        , url =
            Url.Builder.crossOrigin
                "https://addressvalidation.googleapis.com/v1:validateAddress"
                []
                [ Url.Builder.string "key" model.googleMapsApiKey ]
        , body =
            jsonBody
                (Json.Encode.object
                    [ ( "enableUspsCass", Json.Encode.bool True )
                    , ( "address"
                      , Json.Encode.object
                            [ ( "regionCode", Json.Encode.string "US" )
                            , ( "postalCode", Json.Encode.string (String.trim model.zip) )
                            , ( "administrativeArea", Json.Encode.string (withDefault "" model.state) )
                            , ( "locality", Json.Encode.string (String.trim model.city) )
                            , ( "addressLines"
                              , Json.Encode.list Json.Encode.string
                                    (List.filter nonBlankString
                                        (List.map String.trim
                                            [ model.addressLineOne
                                            , model.addressLineTwo
                                            ]
                                        )
                                    )
                              )
                            ]
                      )
                    ]
                )
        , expect = expectJson (GoogleAddressValidationResultReceived (addressValidationRequestFromModel model)) googleAddressValidationResponseDecoder
        , timeout = Just httpRequestTimeoutMs
        , tracker = Nothing
        }


addressValidationRequestFromModel : Model -> AddressValidationRequest
addressValidationRequestFromModel model =
    { addressLineOne = model.addressLineOne
    , addressLineTwo = model.addressLineTwo
    , city = model.city
    , state = model.state
    , zip = model.zip
    }


addressValidationRequestMatchesModel : AddressValidationRequest -> Model -> Bool
addressValidationRequestMatchesModel requested model =
    requested.addressLineOne
        == model.addressLineOne
        && requested.addressLineTwo
        == model.addressLineTwo
        && requested.city
        == model.city
        && requested.state
        == model.state
        && requested.zip
        == model.zip


createRampAccountTask : Model -> Cmd Msg
createRampAccountTask model =
    Http.request
        { method = "POST"
        , headers = []
        , url =
            Url.Builder.absolute
                [ "create-ramp-account" ]
                []
        , body =
            jsonBody
                (Json.Encode.object
                    [ ( "firstName", Json.Encode.string (String.trim model.firstName) )
                    , ( "lastName", Json.Encode.string (String.trim model.lastName) )
                    , ( "directManagerId", Json.Encode.string (withDefault "" model.managerRampId) )
                    , ( "departmentId", Json.Encode.string (withDefault "" model.rampDepartmentId) )
                    , ( "locationId", Json.Encode.string (withDefault "" model.rampLocationId) )
                    , ( "role", Json.Encode.string (withDefault "" model.rampRoleId) )
                    , ( "orderPhysicalCard", Json.Encode.bool model.orderPhysicalCard )
                    ]
                )
        , expect = expectJson CreateRampAccountTaskIdReceived createTaskResponseDecoder
        , timeout = Just httpRequestTimeoutMs
        , tracker = Nothing
        }


getRampAccountTaskStatus : String -> Cmd Msg
getRampAccountTaskStatus taskId =
    Http.request
        { method = "GET"
        , headers = []
        , url =
            Url.Builder.absolute
                [ "create-ramp-account", taskId ]
                []
        , body = Http.emptyBody
        , expect = expectJson CreateRampAccountTaskStatusReceived getTaskResponseDecoder
        , timeout = Just httpRequestTimeoutMs
        , tracker = Nothing
        }


campusAddressStreetPrefixes : List ( String, CampusAddress )
campusAddressStreetPrefixes =
    [ ( "351 ferst", StudentCenter )
    , ( "301 10", GraduateLivingCenter )
    , ( "301 ten", GraduateLivingCenter )
    , ( "801 ferst", ManufacturingRelatedDisciplinesComplex )
    ]


matchCampusAddressByStreetPrefix : String -> CampusAddress
matchCampusAddressByStreetPrefix street =
    campusAddressStreetPrefixes
        |> List.filterMap
            (\( prefix, campusAddress ) ->
                if String.startsWith prefix street then
                    Just campusAddress

                else
                    Nothing
            )
        |> List.head
        |> withDefault NotCampusAddress


classifyCampusAddress : Model -> CampusAddress
classifyCampusAddress model =
    let
        city : String
        city =
            String.toLower (String.trim model.city)

        state : String
        state =
            withDefault "" model.state

        zipPrefix : String
        zipPrefix =
            String.left 3 (String.trim model.zip)
    in
    if city == "atlanta" && state == "GA" && zipPrefix == "303" then
        let
            street : String
            street =
                String.toLower (String.trim model.addressLineOne)
        in
        matchCampusAddressByStreetPrefix street

    else
        NotCampusAddress


buildInitialModel : ServerData -> Value -> Model
buildInitialModel serverData localData =
    let
        showAdvancedOptions : Bool
        showAdvancedOptions =
            serverData.showAdvancedOptions || localOr showAdvancedOptionsLocalStorageKey bool False localData

        managerApiaryId : Maybe Int
        managerApiaryId =
            validatedId managerApiaryIdLocalStorageKey int (\managerId -> managerId /= serverData.selfApiaryId && Dict.member managerId serverData.apiaryManagerOptions) localData serverData.managerApiaryId
    in
    { firstName = trimmedLocalOr firstNameLocalStorageKey serverData.firstName localData
    , lastName = trimmedLocalOr lastNameLocalStorageKey serverData.lastName localData
    , emailAddress =
        if serverData.emailVerified then
            serverData.emailAddress

        else
            trimmedLocalOr emailAddressLocalStorageKey serverData.emailAddress localData
    , emailVerified = serverData.emailVerified
    , managerApiaryOptions = serverData.apiaryManagerOptions
    , managerApiaryId = managerApiaryId
    , managerRampId =
        if showAdvancedOptions then
            validatedId managerRampIdLocalStorageKey string (isEnabledOption serverData.rampManagerOptions) localData serverData.managerRampId

        else if managerApiaryId == serverData.managerApiaryId then
            -- the server-resolved Ramp ID belongs to the server's Apiary manager; it is only
            -- valid while the restored selection still matches
            validServerId (isEnabledOption serverData.rampManagerOptions) serverData.managerRampId

        else
            Nothing
    , managerIsValid = Nothing
    , managerFeedbackText = ""
    , selfApiaryId = serverData.selfApiaryId
    , orderPhysicalCard = localOr orderPhysicalCardLocalStorageKey bool True localData
    , addressLineOne = trimmedLocalOr addressLineOneLocalStorageKey serverData.addressLineOne localData
    , addressLineTwo = trimmedLocalOr addressLineTwoLocalStorageKey serverData.addressLineTwo localData
    , city = trimmedLocalOr cityLocalStorageKey serverData.city localData
    , state = validatedId stateLocalStorageKey string (\stateCode -> Dict.member stateCode statesMap) localData serverData.state
    , zip = trimmedLocalOr zipCodeLocalStorageKey serverData.zip localData
    , addressLineTwoRequired = False
    , addressIsValid = Nothing
    , showValidation = False
    , googleMapsApiKey = serverData.googleMapsApiKey
    , googleClientId = serverData.googleClientId
    , googleOneTapLoginUri = serverData.googleOneTapLoginUri
    , time = millisToPosix 0
    , zone = Time.utc
    , formState = Editing
    , redirectingToEmailVerification = False
    , showAdvancedOptions = showAdvancedOptions
    , rampDepartmentOptions = serverData.departmentOptions
    , rampLocationOptions = serverData.locationOptions
    , rampRoleOptions = serverData.roleOptions
    , rampDepartmentId =
        if showAdvancedOptions then
            validatedId departmentIdLocalStorageKey string (isEnabledOption serverData.departmentOptions) localData serverData.departmentId

        else
            validServerId (isEnabledOption serverData.departmentOptions) serverData.departmentId
    , rampLocationId =
        if showAdvancedOptions then
            validatedId locationIdLocalStorageKey string (isEnabledOption serverData.locationOptions) localData serverData.locationId

        else
            validServerId (isEnabledOption serverData.locationOptions) serverData.locationId
    , rampRoleId =
        if showAdvancedOptions then
            validatedId roleIdLocalStorageKey string (isEnabledOption serverData.roleOptions) localData serverData.roleId

        else
            validServerId (isEnabledOption serverData.roleOptions) serverData.roleId
    , studentDefaultDepartmentId = serverData.studentDefaultDepartmentId
    , nonStudentDefaultDepartmentId = serverData.nonStudentDefaultDepartmentId
    , studentDefaultLocationId = serverData.studentDefaultLocationId
    , nonStudentDefaultLocationId = serverData.nonStudentDefaultLocationId
    , managerRampOptions = serverData.rampManagerOptions
    , rampSignInUri = serverData.rampSignInUri
    , businessLegalName = serverData.businessLegalName
    , slackSupportChannelDeepLink = serverData.slackSupportChannelDeepLink
    , slackSupportChannelName = serverData.slackSupportChannelName
    }


localOr : String -> Decoder a -> a -> Value -> a
localOr fieldName decoder fallback localData =
    Result.withDefault fallback (decodeValue (field fieldName decoder) localData)


trimmedLocalOr : String -> String -> Value -> String
trimmedLocalOr fieldName fallback localData =
    String.trim (localOr fieldName string fallback localData)


validatedId : String -> Decoder a -> (a -> Bool) -> Value -> Maybe a -> Maybe a
validatedId fieldName decoder isValidId localData serverValue =
    [ Result.toMaybe (decodeValue (field fieldName decoder) localData)
    , serverValue
    ]
        |> List.filterMap identity
        |> List.filter isValidId
        |> List.head


validServerId : (a -> Bool) -> Maybe a -> Maybe a
validServerId isValidId serverValue =
    Maybe.andThen
        (\value ->
            if isValidId value then
                Just value

            else
                Nothing
        )
        serverValue


isEnabledOption : Dict String { a | enabled : Bool } -> String -> Bool
isEnabledOption options optionId =
    Dict.get optionId options
        |> Maybe.map .enabled
        |> withDefault False


nonBlankString : String -> Bool
nonBlankString value =
    not (blankString value)


blankString : String -> Bool
blankString value =
    String.isEmpty (String.trim value)



-- One Tap is a Google product, so it is only shown when the email domain is hosted by Google.


showOneTap : Model -> Bool
showOneTap model =
    not model.emailVerified && emailProviderForAddress model.emailAddress == Just Google


millisPerDay : Float
millisPerDay =
    1000 * 60 * 60 * 24



-- Physical cards are shipped via USPS First Class mail, which typically takes about a week and a half to arrive. The extra half day means afternoon orders round to the next calendar day.


estimatedShippingDays : Float
estimatedShippingDays =
    9.5


addDays : Float -> Posix -> Posix
addDays days time =
    millisToPosix (posixToMillis time + ceiling (days * millisPerDay))



-- USPS delivers First Class mail Monday through Saturday, but not Sunday, so estimates that land on a Sunday are pushed to the following Monday
-- USPS delivers First Class mail on Saturday, but the Georgia Tech Post Office is closed on Saturday, so estimates that land on a Saturday are pushed to the following Monday


estimatePhysicalCardDeliveryDate : Zone -> Posix -> Posix
estimatePhysicalCardDeliveryDate zone now =
    let
        estimate : Posix
        estimate =
            addDays estimatedShippingDays now
    in
    case toWeekday zone estimate of
        Sat ->
            addDays 2 estimate

        Sun ->
            addDays 1 estimate

        _ ->
            estimate


formatDate : Zone -> Posix -> String
formatDate zone time =
    (case toWeekday zone time of
        Mon ->
            "Monday"

        Tue ->
            "Tuesday"

        Wed ->
            "Wednesday"

        Thu ->
            "Thursday"

        Fri ->
            "Friday"

        Sat ->
            "Saturday"

        Sun ->
            "Sunday"
    )
        ++ ", "
        ++ (case toMonth zone time of
                Jan ->
                    "January"

                Feb ->
                    "February"

                Mar ->
                    "March"

                Apr ->
                    "April"

                May ->
                    "May"

                Jun ->
                    "June"

                Jul ->
                    "July"

                Aug ->
                    "August"

                Sep ->
                    "September"

                Oct ->
                    "October"

                Nov ->
                    "November"

                Dec ->
                    "December"
           )
        ++ " "
        ++ String.fromInt (toDay zone time)


sortByRampObjectLabel : ( String, { a | label : String } ) -> ( String, { a | label : String } ) -> Order
sortByRampObjectLabel left right =
    compare (second left).label (second right).label


sortByRampRoleRankOrder : ( String, RampObject ) -> ( String, RampObject ) -> Order
sortByRampRoleRankOrder left right =
    compare (withDefault 0 (Dict.get (first left) rampRoleRankOrder)) (withDefault 0 (Dict.get (first right) rampRoleRankOrder))


termsOfServiceItemToLink : ( String, String ) -> Html msg
termsOfServiceItemToLink ( label, url ) =
    a
        [ href url
        , class "text-secondary"
        , target "_blank"
        , rel "noopener noreferrer"
        ]
        [ text label ]



-- PORTS


port initializeAutocomplete : { apiKey : String, fieldId : String } -> Cmd msg


port initializeOneTap : () -> Cmd msg


port saveToLocalStorage : String -> Cmd msg


port showAlert : String -> Cmd msg


port reportError : Value -> Cmd msg


port localStorageSaved : (() -> msg) -> Sub msg


port placeChanged : (Value -> msg) -> Sub msg
