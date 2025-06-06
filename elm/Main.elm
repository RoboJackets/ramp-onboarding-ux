port module Main exposing (..)

import Browser
import Browser.Dom exposing (..)
import Browser.Navigation as Nav
import Char exposing (isDigit)
import Dict exposing (..)
import Email
import Html exposing (..)
import Html.Attributes exposing (..)
import Html.Events exposing (..)
import Html.Events.Extra exposing (..)
import Http exposing (..)
import Json.Decode exposing (..)
import Json.Encode
import List exposing (..)
import Maybe exposing (..)
import Regex
import String
import Svg exposing (Svg, path, svg)
import Svg.Attributes exposing (d)
import Task
import Time exposing (..)
import Tuple exposing (..)
import Url
import Url.Builder
import W3.Html exposing (toAttribute)
import W3.Html.Attributes exposing (inputmode, numeric)



-- REGEX


nameRegex : Regex.Regex
nameRegex =
    Maybe.withDefault Regex.never (Regex.fromString "^[a-zA-Z-'\\. ]+$")


studentCenterMailboxRegex : Regex.Regex
studentCenterMailboxRegex =
    Maybe.withDefault Regex.never (Regex.fromString "^\\d{6} georgia tech station$")


graduateLivingCenterMailboxRegex : Regex.Regex
graduateLivingCenterMailboxRegex =
    Maybe.withDefault Regex.never (Regex.fromString "^(apt|apartment) [1-6][0-2][0-9][a-d]$")



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


firstNameFieldName : String
firstNameFieldName =
    "firstName"


lastNameFieldName : String
lastNameFieldName =
    "lastName"


emailAddressFieldName : String
emailAddressFieldName =
    "emailAddress"


emailVerifiedFieldName : String
emailVerifiedFieldName =
    "emailVerified"


managerApiaryIdFieldName : String
managerApiaryIdFieldName =
    "managerApiaryId"


managerRampIdFieldName : String
managerRampIdFieldName =
    "managerRampId"


departmentIdFieldName : String
departmentIdFieldName =
    "departmentId"


locationIdFieldName : String
locationIdFieldName =
    "locationId"


roleIdFieldName : String
roleIdFieldName =
    "roleId"


orderPhysicalCardFieldName : String
orderPhysicalCardFieldName =
    "orderPhysicalCard"


addressLineOneFieldName : String
addressLineOneFieldName =
    "addressLineOne"


addressLineTwoFieldName : String
addressLineTwoFieldName =
    "addressLineTwo"


cityFieldName : String
cityFieldName =
    "city"


stateFieldName : String
stateFieldName =
    "state"


zipCodeFieldName : String
zipCodeFieldName =
    "zip"


showAdvancedOptionsFieldName : String
showAdvancedOptionsFieldName =
    "showAdvancedOptions"


googleMapsApiKeyFieldName : String
googleMapsApiKeyFieldName =
    "googleMapsApiKey"


serverDataFieldName : String
serverDataFieldName =
    "serverData"


localDataFieldName : String
localDataFieldName =
    "localData"


apiaryManagerOptionsFieldName : String
apiaryManagerOptionsFieldName =
    "apiaryManagerOptions"


rampManagerOptionsFieldName : String
rampManagerOptionsFieldName =
    "rampManagerOptions"


departmentOptionsFieldName : String
departmentOptionsFieldName =
    "departmentOptions"


locationOptionsFieldName : String
locationOptionsFieldName =
    "locationOptions"


roleOptionsFieldName : String
roleOptionsFieldName =
    "roleOptions"


selfIdFieldName : String
selfIdFieldName =
    "selfApiaryId"



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
    svg [ Svg.Attributes.width "16", Svg.Attributes.height "16", Svg.Attributes.viewBox "2 2 20 20", Svg.Attributes.fill "currentColor" ] [ path [ d "M12 2C6.5 2 2 6.5 2 12S6.5 22 12 22 22 17.5 22 12 17.5 2 12 2M10 17L5 12L6.41 10.59L10 14.17L17.59 6.58L19 8L10 17Z" ] [] ]


spinner : Html msg
spinner =
    div [ class "spinner-border", class "spinner-border-sm", style "display" "inline-block" ] []



-- MAPS


emailProviderIcon : Dict String (Svg msg)
emailProviderIcon =
    Dict.fromList [ ( "robojackets.org", googleIcon ), ( "gatech.edu", microsoftIcon ) ]


emailProviderName : Dict String String
emailProviderName =
    Dict.fromList [ ( "robojackets.org", "Google" ), ( "gatech.edu", "Microsoft" ) ]


statesMap : Dict String String
statesMap =
    Dict.fromList [ ( "AK", "Alaska" ), ( "AL", "Alabama" ), ( "AR", "Arkansas" ), ( "AZ", "Arizona" ), ( "CA", "California" ), ( "CO", "Colorado" ), ( "CT", "Connecticut" ), ( "DC", "District of Columbia" ), ( "DE", "Delaware" ), ( "FL", "Florida" ), ( "GA", "Georgia" ), ( "HI", "Hawaii" ), ( "IA", "Iowa" ), ( "ID", "Idaho" ), ( "IL", "Illinois" ), ( "IN", "Indiana" ), ( "KS", "Kansas" ), ( "KY", "Kentucky" ), ( "LA", "Louisiana" ), ( "MA", "Massachusetts" ), ( "MD", "Maryland" ), ( "ME", "Maine" ), ( "MI", "Michigan" ), ( "MN", "Minnesota" ), ( "MO", "Missouri" ), ( "MS", "Mississippi" ), ( "MT", "Montana" ), ( "NC", "North Carolina" ), ( "ND", "North Dakota" ), ( "NE", "Nebraska" ), ( "NH", "New Hampshire" ), ( "NJ", "New Jersey" ), ( "NM", "New Mexico" ), ( "NV", "Nevada" ), ( "NY", "New York" ), ( "OH", "Ohio" ), ( "OK", "Oklahoma" ), ( "OR", "Oregon" ), ( "PA", "Pennsylvania" ), ( "RI", "Rhode Island" ), ( "SC", "South Carolina" ), ( "SD", "South Dakota" ), ( "TN", "Tennessee" ), ( "TX", "Texas" ), ( "UT", "Utah" ), ( "VA", "Virginia" ), ( "VT", "Vermont" ), ( "WA", "Washington" ), ( "WI", "Wisconsin" ), ( "WV", "West Virginia" ), ( "WY", "Wyoming" ) ]


rampRoleRankOrder : Dict String Int
rampRoleRankOrder =
    Dict.fromList [ ( "BUSINESS_ADMIN", 0 ), ( "IT_ADMIN", 1 ), ( "BUSINESS_BOOKKEEPER", 2 ), ( "BUSINESS_USER", 3 ) ]



-- TYPES


type NextAction
    = RedirectToEmailVerification
    | ValidateForm
    | CreateRampAccount
    | NoOpNextAction


type CampusAddress
    = StudentCenter
    | GraduateLivingCenter
    | ManufacturingRelatedDisciplinesComplex
    | NotCampusAddress


type ValidationResult
    = Valid
    | Invalid String


type FormState
    = Editing
    | Validating
    | Error
    | CreatingRampAccount
    | OrderingPhysicalCard
    | ProvisioningComplete


type alias AddressComponent =
    { value : String
    , types : List String
    }


type alias ManagerValidation =
    { managerRampId : Maybe String
    , managerFeedbackText : Maybe String
    }


type alias GoogleAddressValidation =
    { addressComplete : Maybe Bool
    , missingComponentTypes : Maybe (List String)
    }


type alias TaskId =
    { taskId : Maybe String }


type alias TaskStatus =
    { taskStatus : Maybe String }


type alias RampObject =
    { label : String
    , enabled : Bool
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
    , nextAction : NextAction
    , createRampAccountTaskId : Maybe String
    , orderPhysicalCardTaskId : Maybe String
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
    , managerRampOptions : Dict String RampObject
    , rampSingleSignOnUri : String
    , businessLegalName : String
    , slackSupportChannelDeepLink : String
    , slackSupportChannelName : String
    }


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
    | LocalStorageSaved Bool
    | EmailVerificationButtonClicked
    | PlaceChanged Value
    | ManagerValidationResultReceived (Result Http.Error ManagerValidation)
    | GoogleAddressValidationResultReceived (Result Http.Error GoogleAddressValidation)
    | CreateRampAccountTaskIdReceived (Result Http.Error TaskId)
    | CreateRampAccountTaskStatusReceived (Result Http.Error TaskStatus)
    | OrderPhysicalCardTaskIdReceived (Result Http.Error TaskId)
    | OrderPhysicalCardTaskStatusReceived (Result Http.Error TaskStatus)
    | SetTime Time.Posix
    | SetZone Time.Zone
    | ShowAdvancedOptionsButtonClicked
    | DepartmentInput String
    | LocationInput String
    | RoleInput String



-- PLUMBING


main : Program Value Model Msg
main =
    Browser.application
        { init = init
        , view = view
        , update = update
        , subscriptions = subscriptions
        , onUrlChange = UrlChanged
        , onUrlRequest = UrlRequest
        }


init : Value -> Url.Url -> Nav.Key -> ( Model, Cmd Msg )
init flags url key =
    ( buildInitialModel flags
    , Cmd.batch
        [ Task.perform SetTime Time.now
        , Task.perform SetZone Time.here
        , initializeAutocomplete (String.trim (Result.withDefault "" (decodeValue (at [ serverDataFieldName, googleMapsApiKeyFieldName ] string) flags)))
        , if showOneTap (buildInitialModel flags) then
            initializeOneTap True

          else
            Cmd.none
        ]
    )


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        UrlRequest urlRequest ->
            case urlRequest of
                Browser.Internal url ->
                    ( model, Nav.load (Url.toString url) )

                Browser.External href ->
                    ( model, Nav.load href )

        UrlChanged url ->
            ( model, Cmd.none )

        FormSubmitted ->
            ( { model
                | showValidation = True
                , formState =
                    case validateModel model of
                        Invalid _ ->
                            Editing

                        Valid ->
                            if model.managerRampId == Nothing then
                                Validating

                            else if model.orderPhysicalCard == True then
                                Validating

                            else
                                CreatingRampAccount
                , nextAction =
                    case validateModel model of
                        Invalid _ ->
                            NoOpNextAction

                        Valid ->
                            if model.managerRampId == Nothing then
                                ValidateForm

                            else if model.orderPhysicalCard == True then
                                ValidateForm

                            else
                                CreateRampAccount
              }
            , case validateModel model of
                Invalid fieldId ->
                    Task.attempt (\_ -> NoOpMsg) (focus fieldId)

                Valid ->
                    saveToLocalStorage (stringifyModel model)
            )

        FormChanged ->
            ( { model | nextAction = NoOpNextAction }, saveToLocalStorage (stringifyModel model) )

        FirstNameInput firstName ->
            ( { model
                | firstName = firstName
                , nextAction = NoOpNextAction
              }
            , Cmd.none
            )

        LastNameInput lastName ->
            ( { model
                | lastName = lastName
                , nextAction = NoOpNextAction
              }
            , Cmd.none
            )

        EmailAddressInput emailAddress ->
            ( { model
                | emailAddress = emailAddress
                , emailVerified = False
                , nextAction = NoOpNextAction
              }
            , Cmd.none
            )

        EmailVerificationButtonClicked ->
            ( { model
                | nextAction = RedirectToEmailVerification
              }
            , saveToLocalStorage (stringifyModel model)
            )

        ApiaryManagerInput managerApiaryId ->
            let
                newModel : Model
                newModel =
                    { model
                        | managerApiaryId = Just managerApiaryId
                        , managerRampId = Nothing
                        , managerIsValid = Nothing
                        , nextAction = NoOpNextAction
                    }
            in
            ( newModel
            , saveToLocalStorage (stringifyModel newModel)
            )

        RampManagerInput managerRampId ->
            let
                newModel : Model
                newModel =
                    { model
                        | managerApiaryId = Nothing
                        , managerRampId = Just managerRampId
                        , managerIsValid = Just True
                        , nextAction = NoOpNextAction
                    }
            in
            ( newModel
            , saveToLocalStorage (stringifyModel newModel)
            )

        OrderPhysicalCardChecked orderPhysicalCard ->
            let
                newModel : Model
                newModel =
                    { model
                        | orderPhysicalCard = orderPhysicalCard
                        , nextAction = NoOpNextAction
                    }
            in
            ( newModel
            , saveToLocalStorage (stringifyModel newModel)
            )

        AddressLineOneInput addressLineOne ->
            ( { model
                | addressLineOne = addressLineOne
                , nextAction = NoOpNextAction
                , addressLineTwoRequired = False
              }
            , Cmd.none
            )

        AddressLineTwoInput addressLineTwo ->
            ( { model
                | addressLineTwo = addressLineTwo
                , nextAction = NoOpNextAction
              }
            , Cmd.none
            )

        CityInput city ->
            ( { model
                | city = city
                , nextAction = NoOpNextAction
                , addressLineTwoRequired = False
              }
            , Cmd.none
            )

        StateInput state ->
            let
                newModel : Model
                newModel =
                    { model
                        | state = Just state
                        , nextAction = NoOpNextAction
                        , addressLineTwoRequired = False
                    }
            in
            ( newModel
            , saveToLocalStorage (stringifyModel newModel)
            )

        ZipInput zip ->
            ( { model
                | zip = zip
                , nextAction = NoOpNextAction
                , addressLineTwoRequired = False
              }
            , Cmd.none
            )

        NoOpMsg ->
            ( { model | nextAction = NoOpNextAction }, Cmd.none )

        LocalStorageSaved _ ->
            let
                needGoogleAddressValidation : Bool
                needGoogleAddressValidation =
                    model.orderPhysicalCard && checkCampusAddress model == NotCampusAddress
            in
            ( { model
                | nextAction = NoOpNextAction
                , formState =
                    if model.nextAction == ValidateForm then
                        if model.managerRampId == Nothing then
                            Validating

                        else if needGoogleAddressValidation then
                            Validating

                        else
                            CreatingRampAccount

                    else
                        model.formState
              }
            , case model.nextAction of
                RedirectToEmailVerification ->
                    Nav.load
                        (Url.Builder.absolute
                            [ "verify-email" ]
                            [ Url.Builder.string emailAddressFieldName model.emailAddress ]
                        )

                ValidateForm ->
                    Cmd.batch
                        [ if model.managerRampId == Nothing then
                            Http.get
                                { url =
                                    Url.Builder.absolute
                                        [ "get-ramp-user", String.fromInt (Maybe.withDefault 0 model.managerApiaryId) ]
                                        []
                                , expect = expectJson ManagerValidationResultReceived managerValidationResponseDecoder
                                }

                          else
                            Cmd.none
                        , if needGoogleAddressValidation then
                            Http.post
                                { url =
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
                                                    , ( "administrativeArea", Json.Encode.string (Maybe.withDefault "" model.state) )
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
                                , expect = expectJson GoogleAddressValidationResultReceived googleAddressValidationResponseDecoder
                                }

                          else if model.managerRampId /= Nothing then
                            createRampAccountTask model

                          else
                            Cmd.none
                        ]

                CreateRampAccount ->
                    createRampAccountTask model

                NoOpNextAction ->
                    Cmd.none
            )

        PlaceChanged value ->
            let
                addressLineOne : String
                addressLineOne =
                    String.trim (getAddressComponent (decodePlaceChanged value) "street_number")
                        ++ " "
                        ++ String.trim (getAddressComponent (decodePlaceChanged value) "route")

                addressLineTwo : String
                addressLineTwo =
                    String.trim (getAddressComponent (decodePlaceChanged value) "subpremise")

                city : String
                city =
                    String.trim (getAddressComponent (decodePlaceChanged value) "locality")

                state : Maybe String
                state =
                    Just (String.trim (getAddressComponent (decodePlaceChanged value) "administrative_area_level_1"))

                zip : String
                zip =
                    String.trim (getAddressComponent (decodePlaceChanged value) "postal_code")
            in
            ( { model
                | addressLineOne = addressLineOne
                , addressLineTwo = addressLineTwo
                , city = city
                , state = state
                , zip = zip
                , nextAction = NoOpNextAction
              }
            , Cmd.batch
                [ Task.attempt (\_ -> NoOpMsg) (focus "address_line_two")
                , saveToLocalStorage
                    (stringifyModel
                        { model
                            | addressLineOne = addressLineOne
                            , addressLineTwo = addressLineTwo
                            , city = city
                            , state = state
                            , zip = zip
                        }
                    )
                ]
            )

        GoogleAddressValidationResultReceived result ->
            let
                missingAddressLineTwo : Bool
                missingAddressLineTwo =
                    case result of
                        Ok verdict ->
                            List.member "subpremise" (Maybe.withDefault [] verdict.missingComponentTypes)

                        Err _ ->
                            False
            in
            ( { model
                | nextAction = NoOpNextAction
                , addressLineTwoRequired =
                    case result of
                        Ok verdict ->
                            if missingAddressLineTwo then
                                True

                            else
                                False

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
                            Just False
                , formState =
                    case result of
                        Ok verdict ->
                            case verdict.addressComplete of
                                Just addressComplete ->
                                    case model.managerRampId of
                                        Just _ ->
                                            CreatingRampAccount

                                        Nothing ->
                                            Validating

                                Nothing ->
                                    if missingAddressLineTwo then
                                        Editing

                                    else
                                        Editing

                        Err _ ->
                            Editing
              }
            , case result of
                Ok verdict ->
                    if Maybe.withDefault False verdict.addressComplete then
                        case model.managerRampId of
                            Just _ ->
                                createRampAccountTask model

                            Nothing ->
                                Cmd.none

                    else if missingAddressLineTwo then
                        Task.attempt (\_ -> NoOpMsg) (focus "address_line_two")

                    else
                        Cmd.none

                Err _ ->
                    Task.attempt (\_ -> NoOpMsg) (focus "address_line_one")
            )

        SetTime time ->
            ( { model
                | time = time
                , nextAction = NoOpNextAction
              }
            , Cmd.none
            )

        SetZone zone ->
            ( { model
                | zone = zone
                , nextAction = NoOpNextAction
              }
            , Cmd.none
            )

        ManagerValidationResultReceived result ->
            ( { model
                | managerRampId =
                    case result of
                        Ok managerRampInfo ->
                            managerRampInfo.managerRampId

                        Err _ ->
                            Nothing
                , managerFeedbackText =
                    case result of
                        Ok managerRampInfo ->
                            Maybe.withDefault "There was an error verifying your manager" managerRampInfo.managerFeedbackText

                        Err _ ->
                            "There was an error verifying your manager"
                , managerIsValid =
                    case result of
                        Ok managerRampInfo ->
                            if managerRampInfo.managerRampId == Nothing then
                                Just False

                            else
                                Just True

                        Err _ ->
                            Just False
                , formState =
                    case result of
                        Ok managerRampInfo ->
                            if managerRampInfo.managerRampId == Nothing then
                                Editing

                            else if model.orderPhysicalCard then
                                case model.addressIsValid of
                                    Just True ->
                                        if validateModel model == Valid then
                                            CreatingRampAccount

                                        else
                                            Editing

                                    _ ->
                                        Editing

                            else
                                CreatingRampAccount

                        Err _ ->
                            Editing
                , nextAction = NoOpNextAction
              }
            , case result of
                Ok managerRampInfo ->
                    let
                        task : Cmd Msg
                        task =
                            createRampAccountTask { model | managerRampId = managerRampInfo.managerRampId }
                    in
                    if managerRampInfo.managerRampId == Nothing then
                        Cmd.none

                    else if model.orderPhysicalCard then
                        case model.addressIsValid of
                            Just True ->
                                if validateModel model == Valid then
                                    task

                                else
                                    Cmd.none

                            Just False ->
                                Cmd.none

                            Nothing ->
                                if checkCampusAddress model /= NotCampusAddress then
                                    task

                                else
                                    Cmd.none

                    else
                        task

                Err _ ->
                    Cmd.none
            )

        CreateRampAccountTaskIdReceived result ->
            ( { model
                | createRampAccountTaskId =
                    case result of
                        Ok createRampAccountTaskId ->
                            createRampAccountTaskId.taskId

                        Err _ ->
                            Nothing
                , formState =
                    case result of
                        Ok createRampAccountTaskId ->
                            if createRampAccountTaskId.taskId == Nothing then
                                Error

                            else
                                CreatingRampAccount

                        Err _ ->
                            Error
                , nextAction = NoOpNextAction
              }
            , case result of
                Ok createRampAccountTaskId ->
                    case createRampAccountTaskId.taskId of
                        Just taskId ->
                            getRampAccountTaskStatus taskId

                        Nothing ->
                            Cmd.none

                Err _ ->
                    Cmd.none
            )

        CreateRampAccountTaskStatusReceived result ->
            ( { model
                | formState =
                    case result of
                        Ok createRampAccountTaskStatus ->
                            case createRampAccountTaskStatus.taskStatus of
                                Just "SUCCESS" ->
                                    OrderingPhysicalCard

                                Just "STARTED" ->
                                    CreatingRampAccount

                                Just "IN_PROGRESS" ->
                                    CreatingRampAccount

                                _ ->
                                    Error

                        Err _ ->
                            Error
                , nextAction = NoOpNextAction
              }
            , case result of
                Ok createRampAccountTaskStatus ->
                    case createRampAccountTaskStatus.taskStatus of
                        Just "SUCCESS" ->
                            if model.orderPhysicalCard then
                                Http.post
                                    { url =
                                        Url.Builder.absolute
                                            [ "order-physical-card" ]
                                            []
                                    , body =
                                        jsonBody
                                            (Json.Encode.object
                                                [ ( firstNameFieldName, Json.Encode.string (String.trim model.firstName) )
                                                , ( lastNameFieldName, Json.Encode.string (String.trim model.lastName) )
                                                , ( addressLineOneFieldName, Json.Encode.string (String.trim model.addressLineOne) )
                                                , ( addressLineTwoFieldName, Json.Encode.string (String.trim model.addressLineTwo) )
                                                , ( cityFieldName, Json.Encode.string (String.trim model.city) )
                                                , ( stateFieldName
                                                  , case model.state of
                                                        Just state ->
                                                            Json.Encode.string state

                                                        Nothing ->
                                                            Json.Encode.null
                                                  )
                                                , ( zipCodeFieldName, Json.Encode.string (String.trim model.zip) )
                                                ]
                                            )
                                    , expect = expectJson OrderPhysicalCardTaskIdReceived createTaskResponseDecoder
                                    }

                            else
                                Nav.load model.rampSingleSignOnUri

                        Just "STARTED" ->
                            getRampAccountTaskStatus (Maybe.withDefault "" model.createRampAccountTaskId)

                        Just "IN_PROGRESS" ->
                            getRampAccountTaskStatus (Maybe.withDefault "" model.createRampAccountTaskId)

                        _ ->
                            Cmd.none

                Err _ ->
                    Cmd.none
            )

        OrderPhysicalCardTaskIdReceived result ->
            ( { model
                | orderPhysicalCardTaskId =
                    case result of
                        Ok orderPhysicalCardTaskId ->
                            orderPhysicalCardTaskId.taskId

                        Err _ ->
                            Nothing
                , formState =
                    case result of
                        Ok orderPhysicalCardTaskId ->
                            if orderPhysicalCardTaskId.taskId == Nothing then
                                Error

                            else
                                OrderingPhysicalCard

                        Err _ ->
                            Error
                , nextAction = NoOpNextAction
              }
            , case result of
                Ok orderPhysicalCardTaskId ->
                    case orderPhysicalCardTaskId.taskId of
                        Just taskId ->
                            getPhysicalCardTaskStatus taskId

                        Nothing ->
                            Cmd.none

                Err _ ->
                    Cmd.none
            )

        OrderPhysicalCardTaskStatusReceived result ->
            ( { model
                | formState =
                    case result of
                        Ok orderPhysicalCardTaskStatus ->
                            case orderPhysicalCardTaskStatus.taskStatus of
                                Just "SUCCESS" ->
                                    ProvisioningComplete

                                Just "STARTED" ->
                                    OrderingPhysicalCard

                                Just "IN_PROGRESS" ->
                                    OrderingPhysicalCard

                                _ ->
                                    Error

                        Err _ ->
                            Error
                , nextAction = NoOpNextAction
              }
            , case result of
                Ok orderPhysicalCardTaskStatus ->
                    case orderPhysicalCardTaskStatus.taskStatus of
                        Just "SUCCESS" ->
                            Nav.load model.rampSingleSignOnUri

                        Just "STARTED" ->
                            getPhysicalCardTaskStatus (Maybe.withDefault "" model.orderPhysicalCardTaskId)

                        Just "IN_PROGRESS" ->
                            getPhysicalCardTaskStatus (Maybe.withDefault "" model.orderPhysicalCardTaskId)

                        _ ->
                            Cmd.none

                Err _ ->
                    Cmd.none
            )

        ShowAdvancedOptionsButtonClicked ->
            let
                newModel : Model
                newModel =
                    { model
                        | showAdvancedOptions = True
                        , managerApiaryId = Nothing
                        , managerRampId = getManagerRampIdFromApiaryId model
                        , managerIsValid = Just True
                        , nextAction = NoOpNextAction
                    }
            in
            ( newModel
            , Cmd.batch
                [ saveToLocalStorage (stringifyModel newModel)
                , case getManagerRampIdFromApiaryId model of
                    Just _ ->
                        Task.attempt (\_ -> NoOpMsg) (focus "department")

                    Nothing ->
                        Task.attempt (\_ -> NoOpMsg) (focus "manager")
                ]
            )

        DepartmentInput selectedDepartment ->
            let
                newModel : Model
                newModel =
                    { model
                        | rampDepartmentId = Just selectedDepartment
                        , nextAction = NoOpNextAction
                    }
            in
            ( newModel
            , saveToLocalStorage (stringifyModel newModel)
            )

        LocationInput selectedLocation ->
            let
                newModel : Model
                newModel =
                    { model
                        | rampLocationId = Just selectedLocation
                        , nextAction = NoOpNextAction
                    }
            in
            ( newModel
            , saveToLocalStorage (stringifyModel newModel)
            )

        RoleInput selectedRole ->
            let
                newModel : Model
                newModel =
                    { model
                        | rampRoleId = Just selectedRole
                        , nextAction = NoOpNextAction
                    }
            in
            ( newModel
            , saveToLocalStorage (stringifyModel newModel)
            )


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.batch
        [ localStorageSaved LocalStorageSaved
        , placeChanged PlaceChanged
        ]


view : Model -> Browser.Document Msg
view model =
    { title = "Ramp Onboarding"
    , body =
        case model.formState of
            Editing ->
                renderForm model

            Validating ->
                renderForm model

            CreatingRampAccount ->
                renderLoadingIndicators model

            OrderingPhysicalCard ->
                renderLoadingIndicators model

            ProvisioningComplete ->
                renderLoadingIndicators model

            Error ->
                [ div [ class "container", class "mt-md-4", class "mt-3", style "max-width" "48rem" ]
                    [ h1 []
                        [ text "Ramp Onboarding"
                        ]
                    , p [ class "mt-4", class "mb-4" ]
                        [ text "There was an error creating your Ramp account. Please post in "
                        , a [ href model.slackSupportChannelDeepLink ]
                            [ text ("#" ++ model.slackSupportChannelName)
                            ]
                        , text " for further assistance."
                        ]
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

        emailAddressDomainString : String
        emailAddressDomainString =
            withDefault "unknown" (emailAddressDomain model.emailAddress)

        managerValidationResult : ValidationResult
        managerValidationResult =
            validateManager model.showAdvancedOptions model.managerIsValid model.managerFeedbackText model.managerRampId model.managerApiaryId model.managerApiaryOptions model.managerRampOptions model.selfApiaryId

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
            [ a [ href "https://support.ramp.com/hc/en-us/articles/360042579734-User-roles-overview", target "_blank", class "text-secondary" ] [ text "Ramp help center" ]
            , text "."
            ]

        addressLineOneValidationResult : ValidationResult
        addressLineOneValidationResult =
            validateAddressLineOne model.addressLineOne

        addressLineTwoValidationResult : ValidationResult
        addressLineTwoValidationResult =
            validateAddressLineTwo model.addressLineTwo model.addressLineTwoRequired (checkCampusAddress model)

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
            formatTime model.zone
                (case toWeekday model.zone (millisToPosix (posixToMillis model.time + ceiling (9.5 * 1000 * 60 * 60 * 24 * 1))) of
                    Sat ->
                        millisToPosix (posixToMillis model.time + ceiling (11.5 * 1000 * 60 * 60 * 24 * 1))

                    Sun ->
                        millisToPosix (posixToMillis model.time + ceiling (10.5 * 1000 * 60 * 60 * 24 * 1))

                    _ ->
                        millisToPosix (posixToMillis model.time + ceiling (9.5 * 1000 * 60 * 60 * 24 * 1))
                )
    in
    [ div [ class "container", class "mt-md-4", class "mt-3", style "max-width" "48rem" ]
        [ h1 []
            [ text "Ramp Onboarding"
            ]
        , p [ class "mt-4", class "mb-4" ]
            [ text (model.businessLegalName ++ " uses ")
            , a [ href "https://ramp.com", target "_blank" ]
                [ text "Ramp"
                ]
            , text " to issue corporate credit cards and manage reimbursements. We need some information from you to create your Ramp account."
            ]
        , Html.form
            [ class "row"
            , class "g-3"
            , method "POST"
            , action "/"
            , novalidate True
            , onSubmit FormSubmitted
            ]
            [ div [ class "col-6" ]
                [ label [ for "first_name", class "form-label" ]
                    [ text "First Name" ]
                , input
                    [ id "first_name"
                    , type_ "text"
                    , classList
                        [ ( "form-control", True )
                        , ( "is-valid", model.showValidation && isValid firstNameValidationResult )
                        , ( "is-invalid", model.showValidation && not (isValid firstNameValidationResult) )
                        ]
                    , name "first_name"
                    , minlength 1
                    , maxlength 40
                    , required True
                    , readonly (model.formState /= Editing)
                    , placeholder "First Name"
                    , on "change" (succeed FormChanged)
                    , onInput FirstNameInput
                    , Html.Attributes.value model.firstName
                    ]
                    []
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText firstNameValidationResult) ]
                ]
            , div [ class "col-6" ]
                [ label [ for "last_name", class "form-label" ]
                    [ text "Last Name" ]
                , input
                    [ id "last_name"
                    , type_ "text"
                    , classList
                        [ ( "form-control", True )
                        , ( "is-valid", model.showValidation && isValid lastNameValidationResult )
                        , ( "is-invalid", model.showValidation && not (isValid lastNameValidationResult) )
                        ]
                    , name "last_name"
                    , minlength 1
                    , maxlength 40
                    , required True
                    , readonly (model.formState /= Editing)
                    , placeholder "Last Name"
                    , on "change" (succeed FormChanged)
                    , onInput LastNameInput
                    , Html.Attributes.value model.lastName
                    ]
                    []
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText lastNameValidationResult) ]
                ]
            , div [ class "form-text", class "mb-3" ]
                [ text "Your name must match your government-issued identification and be a maximum of 80 characters." ]
            , div [ class "col-12" ]
                [ label [ for "email_address", class "form-label" ]
                    [ text "Email Address" ]
                , div [ class "input-group" ]
                    [ input
                        [ id "email_address"
                        , name "email_address"
                        , type_ "email"
                        , classList
                            [ ( "form-control", True )
                            , ( "is-valid", model.showValidation && isValid emailAddressValidationResult )
                            , ( "is-invalid", model.showValidation && not (isValid emailAddressValidationResult) )
                            ]
                        , minlength 13
                        , required True
                        , readonly (model.formState /= Editing)
                        , placeholder "Email Address"
                        , on "change" (succeed FormChanged)
                        , onInput EmailAddressInput
                        , Html.Attributes.value model.emailAddress
                        ]
                        []
                    , button
                        [ classList
                            [ ( "btn", True )
                            , ( "btn-primary", True )
                            , ( "rounded-end", True )
                            ]
                        , type_ "button"
                        , id "email_verification_button"
                        , disabled
                            (model.emailVerified
                                || not (Dict.member emailAddressDomainString emailProviderName)
                                || (model.nextAction /= NoOpNextAction)
                            )
                        , onClick EmailVerificationButtonClicked
                        ]
                        [ if model.emailVerified then
                            checkIcon

                          else
                            case emailAddressDomain model.emailAddress of
                                Just domain ->
                                    withDefault exclamationCircleIcon (Dict.get domain emailProviderIcon)

                                Nothing ->
                                    exclamationCircleIcon
                        , text
                            (noBreakSpace
                                ++ noBreakSpace
                                ++ (if model.emailVerified then
                                        "Verified"

                                    else if Dict.member emailAddressDomainString emailProviderName then
                                        "Verify with "
                                            ++ withDefault "Unknown" (Dict.get emailAddressDomainString emailProviderName)

                                    else
                                        "Verify"
                                   )
                            )
                        ]
                    , div [ class "invalid-feedback" ]
                        [ text (feedbackText emailAddressValidationResult) ]
                    ]
                ]
            , div [ class "form-text", class "mb-3" ]
                [ text "You'll receive notifications about your credit card transactions and reimbursements to this address." ]
            , div [ class "col-12" ]
                [ label [ for "manager", class "form-label" ]
                    [ text "Manager" ]
                , select
                    [ class "form-select"
                    , name "manager"
                    , id "manager"
                    , required True
                    , readonly (model.formState /= Editing)
                    , on "change"
                        (if model.showAdvancedOptions then
                            Json.Decode.map RampManagerInput targetValue

                         else
                            Json.Decode.map ApiaryManagerInput targetValueIntParse
                        )
                    , classList
                        [ ( "is-valid", model.showValidation && isValid managerValidationResult )
                        , ( "is-invalid", model.showValidation && not (isValid managerValidationResult) )
                        ]
                    ]
                    ([ option
                        [ Html.Attributes.value ""
                        , disabled True
                        , selected
                            (if model.showAdvancedOptions then
                                case model.managerRampId of
                                    Just _ ->
                                        False

                                    Nothing ->
                                        True

                             else
                                case model.managerApiaryId of
                                    Just managerApiaryId ->
                                        model.selfApiaryId == managerApiaryId

                                    Nothing ->
                                        True
                            )
                        , style "display" "none"
                        ]
                        [ text "Select your manager..." ]
                     ]
                        ++ (if model.showAdvancedOptions then
                                List.map (rampObjectToHtmlOption model.managerRampId) (sortWith sortByRampObjectLabel (toList model.managerRampOptions))

                            else
                                List.map (managerTupleToHtmlOption model.managerApiaryId model.selfApiaryId) (sortBy second (toList model.managerApiaryOptions))
                           )
                    )
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText managerValidationResult) ]
                , div [ class "form-text", class "mb-3" ]
                    [ text "Your manager will be responsible for reviewing your credit card transactions and reimbursement requests. This should typically be your project manager." ]
                ]
            , div [ class "col-md-6", class "col-12", classList [ ( "d-none", not model.showAdvancedOptions ) ] ]
                [ label [ for "department", class "form-label" ]
                    [ text "Department" ]
                , select
                    [ class "form-select"
                    , name "department"
                    , id "department"
                    , required True
                    , readonly (model.formState /= Editing)
                    , on "change" (Json.Decode.map DepartmentInput targetValue)
                    , classList
                        [ ( "is-valid", model.showValidation && isValid departmentValidationResult )
                        , ( "is-invalid", model.showValidation && not (isValid departmentValidationResult) )
                        ]
                    ]
                    ([ option
                        [ Html.Attributes.value ""
                        , disabled True
                        , selected
                            (case model.rampDepartmentId of
                                Just rampDepartmentId ->
                                    False

                                Nothing ->
                                    True
                            )
                        , style "display" "none"
                        ]
                        [ text "Select your department..." ]
                     ]
                        ++ List.map (rampObjectToHtmlOption model.rampDepartmentId) (sortWith sortByRampObjectLabel (toList model.rampDepartmentOptions))
                    )
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText departmentValidationResult) ]
                , div [ class "form-text", class "mb-3" ]
                    [ text "Students should generally select "
                    , strong [] [ text (Maybe.withDefault { label = "", enabled = True } (Dict.get model.studentDefaultDepartmentId model.rampDepartmentOptions)).label ]
                    , text ", and corporation staff should generally select "
                    , strong [] [ text (Maybe.withDefault { label = "", enabled = True } (Dict.get model.nonStudentDefaultDepartmentId model.rampDepartmentOptions)).label ]
                    , text "."
                    ]
                ]
            , div [ class "col-md-6", class "col-12", classList [ ( "d-none", not model.showAdvancedOptions ) ] ]
                [ label [ for "location", class "form-label" ]
                    [ text "Location" ]
                , select
                    [ class "form-select"
                    , name "location"
                    , id "location"
                    , required True
                    , readonly (model.formState /= Editing)
                    , on "change" (Json.Decode.map LocationInput targetValue)
                    , classList
                        [ ( "is-valid", model.showValidation && isValid locationValidationResult )
                        , ( "is-invalid", model.showValidation && not (isValid locationValidationResult) )
                        ]
                    ]
                    ([ option
                        [ Html.Attributes.value ""
                        , disabled True
                        , selected
                            (case model.rampLocationId of
                                Just rampLocationId ->
                                    False

                                Nothing ->
                                    True
                            )
                        , style "display" "none"
                        ]
                        [ text "Select your location..." ]
                     ]
                        ++ List.map (rampObjectToHtmlOption model.rampLocationId) (sortWith sortByRampObjectLabel (toList model.rampLocationOptions))
                    )
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText locationValidationResult) ]
                , div [ class "form-text", class "mb-3" ]
                    [ text ((Maybe.withDefault { label = "", enabled = True } (Dict.get model.studentDefaultLocationId model.rampLocationOptions)).label ++ "-based members should select ")
                    , strong [] [ text (Maybe.withDefault { label = "", enabled = True } (Dict.get model.studentDefaultLocationId model.rampLocationOptions)).label ]
                    , text ". All other members should select "
                    , strong [] [ text (Maybe.withDefault { label = "", enabled = True } (Dict.get model.nonStudentDefaultLocationId model.rampLocationOptions)).label ]
                    , text "."
                    ]
                ]
            , div [ class "col-12", classList [ ( "d-none", not model.showAdvancedOptions ) ] ]
                [ label [ for "role", class "form-label" ]
                    [ text "Role" ]
                , select
                    [ class "form-select"
                    , name "role"
                    , id "role"
                    , required True
                    , readonly (model.formState /= Editing)
                    , on "change" (Json.Decode.map RoleInput targetValue)
                    , classList
                        [ ( "is-valid", model.showValidation && isValid roleValidationResult )
                        , ( "is-invalid", model.showValidation && not (isValid roleValidationResult) )
                        ]
                    ]
                    ([ option
                        [ Html.Attributes.value ""
                        , disabled True
                        , selected
                            (case model.rampRoleId of
                                Just rampRoleId ->
                                    False

                                Nothing ->
                                    True
                            )
                        , style "display" "none"
                        ]
                        [ text "Select your role..." ]
                     ]
                        ++ List.map (rampObjectToHtmlOption model.rampRoleId) (sortWith sortByRampRoleRankOrder (toList model.rampRoleOptions))
                    )
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText roleValidationResult) ]
                , div [ class "form-text", class "d-md-none", class "mb-3" ]
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
                     , strong [] [ text "Bookkeeper" ]
                     , text ". All other members should select "
                     , strong [] [ text "Employee" ]
                     , text ". Read more about roles in the "
                     ]
                        ++ userRolesRampHelpCenterLink
                    )
                ]
            , div [ class "col-12" ]
                [ div [ class "form-check" ]
                    [ input
                        [ id "order_physical_card"
                        , name "order_physical_card"
                        , type_ "checkbox"
                        , class "form-check-input"
                        , readonly (model.formState /= Editing)
                        , Html.Attributes.value "order_physical_card"
                        , onCheck OrderPhysicalCardChecked
                        , checked model.orderPhysicalCard
                        ]
                        []
                    , label [ for "order_physical_card", class "form-check-label" ]
                        [ text "Order a physical card" ]
                    , div [ class "form-text", class "mb-3" ]
                        [ text "We recommend a physical card for everyone. You will only be able to use it once you activate it ", strong [] [ text " and " ], text " request funds within Ramp. If you choose not to order one now, you can do so later within Ramp." ]
                    ]
                ]
            , div [ class "col-12", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ label [ for "address_line_one", class "form-label" ] [ text "Mailing Address" ]
                , input
                    [ type_ "text"
                    , class "form-control"
                    , classList
                        [ ( "is-valid", model.showValidation && (isValid addressLineOneValidationResult && Maybe.withDefault True model.addressIsValid) )
                        , ( "is-invalid", model.showValidation && (not (isValid addressLineOneValidationResult) || not (Maybe.withDefault True model.addressIsValid)) )
                        ]
                    , id "address_line_one"
                    , name "address_line_one"
                    , minlength 1
                    , maxlength 100
                    , required True
                    , readonly (model.formState /= Editing)
                    , placeholder "Street Address"
                    , onInput AddressLineOneInput
                    , on "change" (succeed FormChanged)
                    , Html.Attributes.value model.addressLineOne
                    , preventDefaultOn "keypress" keyDecoder
                    ]
                    []
                , div [ class "invalid-feedback" ]
                    [ text
                        (if isValid addressLineOneValidationResult then
                            feedbackText (validateAddressLineOneGoogleResult model.addressIsValid)

                         else
                            feedbackText (validateAddressLineOne model.addressLineOne)
                        )
                    ]
                ]
            , div [ class "col-12", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ input
                    [ type_ "text"
                    , class "form-control"
                    , classList
                        [ ( "is-valid", model.showValidation && isValid addressLineTwoValidationResult && Maybe.withDefault True model.addressIsValid )
                        , ( "is-invalid", model.showValidation && not (isValid addressLineTwoValidationResult) || not (Maybe.withDefault True model.addressIsValid) )
                        ]
                    , id "address_line_two"
                    , name "address_line_two"
                    , maxlength 100
                    , placeholder "Apt, Suite, Unit, etc. (optional)"
                    , readonly (model.formState /= Editing)
                    , onInput AddressLineTwoInput
                    , on "change" (succeed FormChanged)
                    , Html.Attributes.value model.addressLineTwo
                    ]
                    []
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText addressLineTwoValidationResult) ]
                ]
            , div [ class "col-md-6", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ label [ for "city", class "form-label" ] [ text "City" ]
                , input
                    [ type_ "text"
                    , class "form-control"
                    , classList
                        [ ( "is-valid", model.showValidation && isValid cityValidationResult && Maybe.withDefault True model.addressIsValid )
                        , ( "is-invalid", model.showValidation && (not (isValid cityValidationResult) || not (Maybe.withDefault True model.addressIsValid)) )
                        ]
                    , id "city"
                    , name "city"
                    , minlength 1
                    , maxlength 40
                    , placeholder "City"
                    , readonly (model.formState /= Editing)
                    , required True
                    , onInput CityInput
                    , on "change" (succeed FormChanged)
                    , Html.Attributes.value model.city
                    ]
                    []
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText cityValidationResult) ]
                ]
            , div [ class "col-md-3", class "col-8", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ label [ for "state", class "form-label" ] [ text "State" ]
                , select
                    [ class "form-select"
                    , id "state"
                    , name "state"
                    , minlength 1
                    , maxlength 40
                    , required True
                    , readonly (model.formState /= Editing)
                    , classList
                        [ ( "is-valid", model.showValidation && isValid stateValidationResult && Maybe.withDefault True model.addressIsValid )
                        , ( "is-invalid", model.showValidation && (not (isValid stateValidationResult) || not (Maybe.withDefault True model.addressIsValid)) )
                        ]
                    , on "change" (Json.Decode.map StateInput targetValue)
                    ]
                    ([ option
                        [ Html.Attributes.value ""
                        , disabled True
                        , selected
                            (case model.state of
                                Just _ ->
                                    False

                                Nothing ->
                                    True
                            )
                        , style "display" "none"
                        ]
                        [ text "Select..." ]
                     ]
                        ++ List.map (stateTupleToHtmlOption model.state) (sortBy second (toList statesMap))
                    )
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText stateValidationResult) ]
                ]
            , div [ class "col-md-3", class "col-4", class "mb-2", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ label [ for "zip_code", class "form-label" ] [ text "ZIP Code" ]
                , input
                    [ type_ "text"
                    , toAttribute (inputmode numeric)
                    , class "form-control"
                    , id "zip_code"
                    , name "zip_code"
                    , placeholder "ZIP Code"
                    , minlength 5
                    , maxlength 5
                    , required True
                    , readonly (model.formState /= Editing)
                    , onInput ZipInput
                    , on "change" (succeed FormChanged)
                    , Html.Attributes.value model.zip
                    , classList
                        [ ( "is-valid", model.showValidation && isValid zipValidationResult && Maybe.withDefault True model.addressIsValid )
                        , ( "is-invalid", model.showValidation && (not (isValid zipValidationResult) || not (Maybe.withDefault True model.addressIsValid)) )
                        ]
                    ]
                    []
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText zipValidationResult) ]
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
                    , id "submit_button"
                    , disabled (model.formState /= Editing)
                    ]
                    [ text "Create Account"
                    ]
                , button
                    [ type_ "button"
                    , class "btn"
                    , class "btn-link"
                    , classList [ ( "d-none", model.showAdvancedOptions ) ]
                    , onClick ShowAdvancedOptionsButtonClicked
                    ]
                    [ text "Show advanced options"
                    ]
                ]
            ]
        , div [ class "mb-4", class "mb-md-5", class "col-12", class "form-text" ]
            [ text "By creating an account, you confirm that you have read and agree to the "
            , a [ href "https://docs.google.com/document/d/e/2PACX-1vRtmt5h8lq3Z1dgxC8eGh04-EPEc7twiYF8t4BQGr9XxCamkjlPavBcPWuMAMGLFNJeRft3Z89ITCkY/pub", class "text-secondary", target "_blank" ] [ text (model.businessLegalName ++ " Expense Policy") ]
            , text ", "
            , a [ href "https://ramp.com/legal/platform-agreement", class "text-secondary", target "_blank" ] [ text "Ramp Platform Agreement" ]
            , text ", "
            , a [ href "https://ramp.com/legal/cookie-policy", class "text-secondary", target "_blank" ] [ text "Ramp Cookie Policy" ]
            , text ", "
            , a [ href "https://ramp.com/legal/privacy-policy", class "text-secondary", target "_blank" ] [ text "Ramp Privacy Policy" ]
            , text ", "
            , a [ href "https://ramp.com/legal/authorized-user-terms", class "text-secondary", target "_blank" ] [ text "Ramp Authorized User Agreement" ]
            , text ", "
            , a [ href "https://ramp.com/legal/authorized-user-card-addendum", class "text-secondary", target "_blank" ] [ text "Ramp Authorized User Payment Card Addendum" ]
            , text ", and "
            , a [ href "https://www.suttonbank.com/_/kcms-doc/85/49033/WK-Privacy-Disclosure-1218.pdf", class "text-secondary", target "_blank" ] [ text "Sutton Privacy Policy" ]
            , text "."
            ]
        ]
    , div
        [ id "g_id_onload"
        , attribute "data-client_id" model.googleClientId
        , attribute "data-auto_prompt" "true"
        , attribute "data-auto_select" "true"
        , attribute "data-login_uri" model.googleOneTapLoginUri
        , attribute "data-cancel_on_tap_outside" "false"
        , attribute "data-context" "signin"
        , attribute "data-itp_support" "true"
        , attribute "data-login_hint" model.emailAddress
        , attribute "data-hd" "robojackets.org"
        , attribute "data-use_fedcm_for_prompt" "true"
        ]
        []
    ]


renderLoadingIndicators : Model -> List (Html Msg)
renderLoadingIndicators model =
    [ div [ class "container", class "mt-md-4", class "mt-3", style "max-width" "48rem" ]
        [ h1 []
            [ text "Ramp Onboarding"
            ]
        , p [ class "mt-4", class "mb-3" ]
            [ text "Please wait a moment..."
            ]
        , div [ class "d-flex", class "align-items-center", class "mt-3" ]
            [ case model.formState of
                Editing ->
                    spinner

                Validating ->
                    spinner

                Error ->
                    spinner

                CreatingRampAccount ->
                    case model.createRampAccountTaskId of
                        Just _ ->
                            checkCircleIcon

                        Nothing ->
                            spinner

                OrderingPhysicalCard ->
                    checkCircleIcon

                ProvisioningComplete ->
                    checkCircleIcon
            , div [ class "ms-2", style "display" "inline-block" ] [ text "Configuring single sign-on" ]
            ]
        , div [ class "d-flex", class "align-items-center", class "mt-2" ]
            [ case model.formState of
                Editing ->
                    spinner

                Validating ->
                    spinner

                Error ->
                    spinner

                CreatingRampAccount ->
                    spinner

                OrderingPhysicalCard ->
                    checkCircleIcon

                ProvisioningComplete ->
                    checkCircleIcon
            , div [ class "ms-2", style "display" "inline-block" ] [ text "Creating your Ramp account" ]
            ]
        , div [ class "d-flex", class "align-items-center", class "mt-2", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
            [ case model.formState of
                Editing ->
                    spinner

                Validating ->
                    spinner

                Error ->
                    spinner

                CreatingRampAccount ->
                    spinner

                OrderingPhysicalCard ->
                    spinner

                ProvisioningComplete ->
                    checkCircleIcon
            , div [ class "ms-2", style "display" "inline-block" ] [ text "Ordering your physical card" ]
            ]
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
                    if not (Dict.member domain emailProviderName) then
                        Invalid emailFeedbackText

                    else if not verified then
                        Invalid ("Please verify your email address with " ++ emailProvider domain)

                    else
                        Valid

                Nothing ->
                    Invalid emailFeedbackText

        Err _ ->
            Invalid emailFeedbackText


validateManager : Bool -> Maybe Bool -> String -> Maybe String -> Maybe Int -> Dict Int String -> Dict String RampObject -> Int -> ValidationResult
validateManager usingRampManagerOptions selectedManagerHasRampAccount selectedManagerRampFeedbackText selectedManagerRampId selectedManagerApiaryId managerApiaryOptions managerRampOptions selfId =
    if usingRampManagerOptions then
        case selectedManagerRampId of
            Just managerId ->
                if (Maybe.withDefault { label = "", enabled = False } (Dict.get managerId managerRampOptions)).enabled == True then
                    Valid

                else
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
validateAddressLineTwo addressLineTwo required campusAddress =
    if String.length (String.trim addressLineTwo) > 100 then
        Invalid "Your second address line may be a maximum of 100 characters"

    else if blankString addressLineTwo && (required || campusAddress /= NotCampusAddress) then
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
            if (Maybe.withDefault { label = "", enabled = False } (Dict.get selectedObjectId objectOptions)).enabled == True then
                Valid

            else
                Invalid ("Please select your " ++ objectName)

        Nothing ->
            Invalid ("Please select your " ++ objectName)


validateZipCode : String -> ValidationResult
validateZipCode zipCode =
    if String.length zipCode == 5 && String.all isDigit zipCode then
        Valid

    else
        Invalid "Please enter exactly 5 digits"


validateModel : Model -> ValidationResult
validateModel model =
    if not (isValid (validateName "first" model.firstName)) then
        Invalid "first_name"

    else if not (isValid (validateName "last" model.lastName)) then
        Invalid "last_name"

    else if not (isValid (validateEmailAddress model.emailAddress True)) then
        Invalid "email_address"

    else if not model.emailVerified then
        Invalid "email_verification_button"

    else if not (isValid (validateManager model.showAdvancedOptions model.managerIsValid model.managerFeedbackText model.managerRampId model.managerApiaryId model.managerApiaryOptions model.managerRampOptions model.selfApiaryId)) then
        Invalid "manager"

    else if not (isValid (validateRampObject "department" model.rampDepartmentId model.rampDepartmentOptions)) then
        Invalid "department"

    else if not (isValid (validateRampObject "location" model.rampLocationId model.rampLocationOptions)) then
        Invalid "location"

    else if not (isValid (validateRampObject "role" model.rampRoleId model.rampRoleOptions)) then
        Invalid "role"

    else if model.orderPhysicalCard && not (isValid (validateAddressLineOne model.addressLineOne)) then
        Invalid "address_line_one"

    else if
        model.orderPhysicalCard
            && not
                (isValid
                    (validateAddressLineTwo
                        model.addressLineTwo
                        model.addressLineTwoRequired
                        (checkCampusAddress model)
                    )
                )
    then
        Invalid "address_line_two"

    else if model.orderPhysicalCard && not (isValid (validateCity model.city)) then
        Invalid "city"

    else if
        model.orderPhysicalCard
            && (case model.state of
                    Just _ ->
                        False

                    Nothing ->
                        True
               )
    then
        Invalid "state"

    else if model.orderPhysicalCard && not (isValid (validateZipCode model.zip)) then
        Invalid "zip_code"

    else
        Valid



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

        Invalid text ->
            text


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
        [ "edu", "gatech" ] ->
            Just "gatech.edu"

        [ "org", "robojackets" ] ->
            Just "robojackets.org"

        _ ->
            Nothing


emailProvider : String -> String
emailProvider domain =
    withDefault "unknown" (Dict.get (String.toLower (String.trim domain)) emailProviderName)


managerTupleToHtmlOption : Maybe Int -> Int -> ( Int, String ) -> Html msg
managerTupleToHtmlOption selectedManagerId selfId ( managerId, managerName ) =
    option
        [ Html.Attributes.value (String.fromInt managerId)
        , selected
            (case selectedManagerId of
                Just selectedId ->
                    selectedId == managerId && selectedId /= selfId

                Nothing ->
                    False
            )
        , disabled (selfId == managerId)
        ]
        [ text managerName ]


rampObjectToHtmlOption : Maybe String -> ( String, RampObject ) -> Html msg
rampObjectToHtmlOption maybeSelectedId ( rampId, rampObject ) =
    option
        [ Html.Attributes.value rampId
        , selected
            (case maybeSelectedId of
                Just selectedId ->
                    selectedId == rampId

                Nothing ->
                    False
            )
        , disabled (not rampObject.enabled)
        ]
        [ text rampObject.label ]


stateTupleToHtmlOption : Maybe String -> ( String, String ) -> Html msg
stateTupleToHtmlOption selectedState ( stateCode, stateName ) =
    option
        [ Html.Attributes.value stateCode
        , selected
            (case selectedState of
                Just selectedStateCode ->
                    selectedStateCode == stateCode

                Nothing ->
                    False
            )
        ]
        [ text stateName ]


stringifyModel : Model -> String
stringifyModel model =
    Json.Encode.encode 0
        (Json.Encode.object
            [ ( firstNameFieldName, Json.Encode.string (String.trim model.firstName) )
            , ( lastNameFieldName, Json.Encode.string (String.trim model.lastName) )
            , ( emailAddressFieldName, Json.Encode.string (String.trim model.emailAddress) )
            , ( managerApiaryIdFieldName
              , case model.managerApiaryId of
                    Just managerApiaryId ->
                        Json.Encode.int managerApiaryId

                    Nothing ->
                        Json.Encode.null
              )
            , ( managerRampIdFieldName
              , case model.managerRampId of
                    Just managerRampId ->
                        Json.Encode.string (String.trim managerRampId)

                    Nothing ->
                        Json.Encode.null
              )
            , ( departmentIdFieldName
              , case model.rampDepartmentId of
                    Just departmentId ->
                        Json.Encode.string (String.trim departmentId)

                    Nothing ->
                        Json.Encode.null
              )
            , ( locationIdFieldName
              , case model.rampLocationId of
                    Just locationId ->
                        Json.Encode.string (String.trim locationId)

                    Nothing ->
                        Json.Encode.null
              )
            , ( roleIdFieldName
              , case model.rampRoleId of
                    Just roleId ->
                        Json.Encode.string (String.trim roleId)

                    Nothing ->
                        Json.Encode.null
              )
            , ( showAdvancedOptionsFieldName, Json.Encode.bool model.showAdvancedOptions )
            , ( orderPhysicalCardFieldName, Json.Encode.bool model.orderPhysicalCard )
            , ( addressLineOneFieldName, Json.Encode.string (String.trim model.addressLineOne) )
            , ( addressLineTwoFieldName, Json.Encode.string (String.trim model.addressLineTwo) )
            , ( cityFieldName, Json.Encode.string (String.trim model.city) )
            , ( stateFieldName
              , case model.state of
                    Just state ->
                        Json.Encode.string (String.trim state)

                    Nothing ->
                        Json.Encode.null
              )
            , ( zipCodeFieldName, Json.Encode.string (String.trim model.zip) )
            ]
        )


keyDecoder : Decoder ( Msg, Bool )
keyDecoder =
    field "key" string
        |> Json.Decode.map
            (\key ->
                ( NoOpMsg, preventDefault key )
            )


preventDefault : String -> Bool
preventDefault key =
    key == "Enter"


decodePlaceChanged : Value -> List AddressComponent
decodePlaceChanged value =
    Result.withDefault []
        (decodeValue
            (field "address_components"
                (Json.Decode.list
                    (Json.Decode.map2 AddressComponent
                        (field "short_name" string)
                        (field "types" (Json.Decode.list string))
                    )
                )
            )
            value
        )


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


managerValidationResponseDecoder : Decoder ManagerValidation
managerValidationResponseDecoder =
    Json.Decode.map2 ManagerValidation
        (maybe (at [ "rampUserId" ] string))
        (maybe (at [ "error" ] string))


rampObjectDecoder : Decoder RampObject
rampObjectDecoder =
    Json.Decode.map2 RampObject
        (field "label" string)
        (field "enabled" bool)


createTaskResponseDecoder : Decoder TaskId
createTaskResponseDecoder =
    Json.Decode.map TaskId
        (maybe (at [ "taskId" ] Json.Decode.string))


getTaskResponseDecoder : Decoder TaskStatus
getTaskResponseDecoder =
    Json.Decode.map TaskStatus
        (maybe (at [ "taskStatus" ] Json.Decode.string))


createRampAccountTask : Model -> Cmd Msg
createRampAccountTask model =
    Http.post
        { url =
            Url.Builder.absolute
                [ "create-ramp-account" ]
                []
        , body =
            jsonBody
                (Json.Encode.object
                    [ ( "firstName", Json.Encode.string (String.trim model.firstName) )
                    , ( "lastName", Json.Encode.string (String.trim model.lastName) )
                    , ( "directManagerId", Json.Encode.string (Maybe.withDefault "" model.managerRampId) )
                    , ( "departmentId", Json.Encode.string (Maybe.withDefault "" model.rampDepartmentId) )
                    , ( "locationId", Json.Encode.string (Maybe.withDefault "" model.rampLocationId) )
                    , ( "role", Json.Encode.string (Maybe.withDefault "" model.rampRoleId) )
                    ]
                )
        , expect = expectJson CreateRampAccountTaskIdReceived createTaskResponseDecoder
        }


getRampAccountTaskStatus : String -> Cmd Msg
getRampAccountTaskStatus taskId =
    Http.get
        { url =
            Url.Builder.absolute
                [ "create-ramp-account", taskId ]
                []
        , expect = expectJson CreateRampAccountTaskStatusReceived getTaskResponseDecoder
        }


getPhysicalCardTaskStatus : String -> Cmd Msg
getPhysicalCardTaskStatus taskId =
    Http.get
        { url =
            Url.Builder.absolute
                [ "order-physical-card", taskId ]
                []
        , expect = expectJson OrderPhysicalCardTaskStatusReceived getTaskResponseDecoder
        }


checkCampusAddress : Model -> CampusAddress
checkCampusAddress model =
    if
        String.toLower (String.trim model.addressLineOne)
            == "351 ferst dr nw"
            && String.toLower (String.trim model.city)
            == "atlanta"
            && Maybe.withDefault "" model.state
            == "GA"
            && String.trim (String.left 3 model.zip)
            == "303"
    then
        StudentCenter

    else if
        String.toLower (String.trim model.addressLineOne)
            == "301 10th st nw"
            && String.toLower (String.trim model.city)
            == "atlanta"
            && Maybe.withDefault "" model.state
            == "GA"
            && String.trim (String.left 3 model.zip)
            == "303"
    then
        GraduateLivingCenter

    else if
        String.toLower (String.trim model.addressLineOne)
            == "801 ferst dr nw"
            && String.toLower (String.trim model.city)
            == "atlanta"
            && Maybe.withDefault "" model.state
            == "GA"
            && String.trim (String.left 3 model.zip)
            == "303"
    then
        ManufacturingRelatedDisciplinesComplex

    else if
        String.toLower (String.trim model.addressLineOne)
            == "801 ferst dr"
            && String.toLower (String.trim model.city)
            == "atlanta"
            && Maybe.withDefault "" model.state
            == "GA"
            && String.trim (String.left 3 model.zip)
            == "303"
    then
        ManufacturingRelatedDisciplinesComplex

    else
        NotCampusAddress


buildInitialModel : Value -> Model
buildInitialModel value =
    let
        serverDataEmailAddress : String
        serverDataEmailAddress =
            Result.withDefault "" (decodeValue (at [ serverDataFieldName, emailAddressFieldName ] string) value)

        emailAddressVerified : Bool
        emailAddressVerified =
            Result.withDefault False (decodeValue (at [ serverDataFieldName, emailVerifiedFieldName ] bool) value)

        apiaryManagerOptions : Dict Int String
        apiaryManagerOptions =
            Dict.fromList (List.filterMap stringStringTupleToMaybeIntStringTuple (Result.withDefault [] (decodeValue (at [ serverDataFieldName, apiaryManagerOptionsFieldName ] (keyValuePairs string)) value)))

        apiarySelfId : Int
        apiarySelfId =
            Result.withDefault -1 (decodeValue (at [ serverDataFieldName, selfIdFieldName ] int) value)

        rampManagerOptions : Dict String RampObject
        rampManagerOptions =
            Result.withDefault Dict.empty (decodeValue (at [ serverDataFieldName, rampManagerOptionsFieldName ] (dict rampObjectDecoder)) value)

        rampDepartmentOptions : Dict String RampObject
        rampDepartmentOptions =
            Result.withDefault Dict.empty (decodeValue (at [ serverDataFieldName, departmentOptionsFieldName ] (dict rampObjectDecoder)) value)

        rampLocationOptions : Dict String RampObject
        rampLocationOptions =
            Result.withDefault Dict.empty (decodeValue (at [ serverDataFieldName, locationOptionsFieldName ] (dict rampObjectDecoder)) value)

        rampRoleOptions : Dict String RampObject
        rampRoleOptions =
            Result.withDefault Dict.empty (decodeValue (at [ serverDataFieldName, roleOptionsFieldName ] (dict rampObjectDecoder)) value)
    in
    Model
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ serverDataFieldName, firstNameFieldName ] string) value))
                (decodeString (field firstNameFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)))
            )
        )
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ serverDataFieldName, lastNameFieldName ] string) value))
                (decodeString (field lastNameFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)))
            )
        )
        (if emailAddressVerified then
            String.trim serverDataEmailAddress

         else
            String.trim
                (Result.withDefault
                    serverDataEmailAddress
                    (decodeString (field emailAddressFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)))
                )
        )
        emailAddressVerified
        apiaryManagerOptions
        (case decodeString (field managerApiaryIdFieldName int) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)) of
            Ok managerId ->
                if apiarySelfId == managerId || not (Dict.member managerId apiaryManagerOptions) then
                    Nothing

                else
                    Just managerId

            Err _ ->
                case decodeValue (at [ serverDataFieldName, managerApiaryIdFieldName ] int) value of
                    Ok managerId ->
                        if apiarySelfId == managerId || not (Dict.member managerId apiaryManagerOptions) then
                            Nothing

                        else
                            Just managerId

                    Err _ ->
                        Nothing
        )
        (case decodeString (field managerRampIdFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)) of
            Ok managerId ->
                if (Maybe.withDefault { label = "", enabled = False } (Dict.get managerId rampManagerOptions)).enabled then
                    Just managerId

                else
                    Nothing

            Err _ ->
                case decodeValue (at [ serverDataFieldName, managerRampIdFieldName ] string) value of
                    Ok managerId ->
                        if (Maybe.withDefault { label = "", enabled = False } (Dict.get managerId rampManagerOptions)).enabled then
                            Just managerId

                        else
                            Nothing

                    Err _ ->
                        Nothing
        )
        Nothing
        ""
        apiarySelfId
        (Result.withDefault True (decodeString (field orderPhysicalCardFieldName bool) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value))))
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ serverDataFieldName, addressLineOneFieldName ] string) value))
                (decodeString (field addressLineOneFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)))
            )
        )
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ serverDataFieldName, addressLineTwoFieldName ] string) value))
                (decodeString (field addressLineTwoFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)))
            )
        )
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ serverDataFieldName, cityFieldName ] string) value))
                (decodeString (field cityFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)))
            )
        )
        (case decodeString (field stateFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)) of
            Ok state ->
                if Dict.member state statesMap then
                    Just state

                else
                    Nothing

            Err _ ->
                case decodeValue (at [ serverDataFieldName, stateFieldName ] string) value of
                    Ok state ->
                        if Dict.member state statesMap then
                            Just state

                        else
                            Nothing

                    Err _ ->
                        Nothing
        )
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ serverDataFieldName, zipCodeFieldName ] string) value))
                (decodeString (field zipCodeFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)))
            )
        )
        False
        Nothing
        False
        (String.trim (Result.withDefault "" (decodeValue (at [ serverDataFieldName, googleMapsApiKeyFieldName ] string) value)))
        (String.trim (Result.withDefault "" (decodeValue (at [ serverDataFieldName, "googleClientId" ] string) value)))
        (String.trim (Result.withDefault "" (decodeValue (at [ serverDataFieldName, "googleOneTapLoginUri" ] string) value)))
        (Time.millisToPosix 0)
        Time.utc
        Editing
        NoOpNextAction
        Nothing
        Nothing
        (Result.withDefault
            (Result.withDefault False (decodeValue (at [ serverDataFieldName, showAdvancedOptionsFieldName ] bool) value))
            (decodeString (field showAdvancedOptionsFieldName bool) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)))
        )
        rampDepartmentOptions
        rampLocationOptions
        rampRoleOptions
        (case decodeString (field departmentIdFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)) of
            Ok departmentId ->
                if (Maybe.withDefault { label = "", enabled = False } (Dict.get departmentId rampDepartmentOptions)).enabled then
                    Just departmentId

                else
                    Nothing

            Err _ ->
                case decodeValue (at [ serverDataFieldName, departmentIdFieldName ] string) value of
                    Ok departmentId ->
                        if (Maybe.withDefault { label = "", enabled = False } (Dict.get departmentId rampDepartmentOptions)).enabled then
                            Just departmentId

                        else
                            Nothing

                    Err _ ->
                        Nothing
        )
        (case decodeString (field locationIdFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)) of
            Ok locationId ->
                if Dict.member locationId rampLocationOptions then
                    Just locationId

                else
                    Nothing

            Err _ ->
                case decodeValue (at [ serverDataFieldName, locationIdFieldName ] string) value of
                    Ok locationId ->
                        if Dict.member locationId rampLocationOptions then
                            Just locationId

                        else
                            Nothing

                    Err _ ->
                        Nothing
        )
        (case decodeString (field roleIdFieldName string) (Result.withDefault "{}" (decodeValue (field localDataFieldName string) value)) of
            Ok roleId ->
                if (Maybe.withDefault { label = "", enabled = False } (Dict.get roleId rampRoleOptions)).enabled then
                    Just roleId

                else
                    Nothing

            Err _ ->
                case decodeValue (at [ serverDataFieldName, roleIdFieldName ] string) value of
                    Ok roleId ->
                        if (Maybe.withDefault { label = "", enabled = False } (Dict.get roleId rampRoleOptions)).enabled then
                            Just roleId

                        else
                            Nothing

                    Err _ ->
                        Nothing
        )
        (String.trim (Result.withDefault "" (decodeValue (at [ serverDataFieldName, "defaultDepartmentForStudents" ] string) value)))
        (String.trim (Result.withDefault "" (decodeValue (at [ serverDataFieldName, "defaultDepartmentForNonStudents" ] string) value)))
        (String.trim (Result.withDefault "" (decodeValue (at [ serverDataFieldName, "defaultLocationForStudents" ] string) value)))
        (String.trim (Result.withDefault "" (decodeValue (at [ serverDataFieldName, "defaultLocationForNonStudents" ] string) value)))
        rampManagerOptions
        (String.trim (Result.withDefault "" (decodeValue (at [ serverDataFieldName, "rampSingleSignOnUri" ] string) value)))
        (String.trim (Result.withDefault "" (decodeValue (at [ serverDataFieldName, "businessLegalName" ] string) value)))
        (String.trim (Result.withDefault "" (decodeValue (at [ serverDataFieldName, "slackSupportChannelDeepLink" ] string) value)))
        (String.trim (Result.withDefault "" (decodeValue (at [ serverDataFieldName, "slackSupportChannelName" ] string) value)))


stringStringTupleToMaybeIntStringTuple : ( String, String ) -> Maybe ( Int, String )
stringStringTupleToMaybeIntStringTuple ( first, second ) =
    case String.toInt first of
        Just intVal ->
            Just ( intVal, second )

        Nothing ->
            Nothing


nonBlankString : String -> Bool
nonBlankString value =
    not (blankString value)


blankString : String -> Bool
blankString value =
    String.isEmpty (String.trim value)


showOneTap : Model -> Bool
showOneTap model =
    case model.emailVerified of
        True ->
            False

        False ->
            case Dict.get (withDefault "unknown" (emailAddressDomain model.emailAddress)) emailProviderName of
                Just providerName ->
                    if providerName == "Google" then
                        True

                    else
                        False

                Nothing ->
                    False


formatTime : Zone -> Posix -> String
formatTime zone time =
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


sortByRampObjectLabel : ( String, RampObject ) -> ( String, RampObject ) -> Order
sortByRampObjectLabel first second =
    compare (Tuple.second first).label (Tuple.second second).label


sortByRampRoleRankOrder : ( String, RampObject ) -> ( String, RampObject ) -> Order
sortByRampRoleRankOrder first second =
    compare (Maybe.withDefault 0 (Dict.get (Tuple.first first) rampRoleRankOrder)) (Maybe.withDefault 0 (Dict.get (Tuple.first second) rampRoleRankOrder))


labelMatches : Maybe String -> String -> RampObject -> Bool
labelMatches maybeGivenLabel rampId rampObject =
    case maybeGivenLabel of
        Just givenLabel ->
            givenLabel == rampObject.label

        Nothing ->
            False


getManagerRampIdFromApiaryId : Model -> Maybe String
getManagerRampIdFromApiaryId model =
    let
        filteredOptions : Dict String RampObject
        filteredOptions =
            Dict.filter (labelMatches (Dict.get (Maybe.withDefault 0 model.managerApiaryId) model.managerApiaryOptions)) model.managerRampOptions

        matchingOption : ( String, RampObject )
        matchingOption =
            Maybe.withDefault ( "", { label = "", enabled = False } ) (List.head (Dict.toList filteredOptions))
    in
    if Dict.size filteredOptions == 1 && (Tuple.second matchingOption).enabled then
        Just (Tuple.first matchingOption)

    else
        Nothing



-- PORTS


port initializeAutocomplete : String -> Cmd msg


port initializeOneTap : Bool -> Cmd msg


port saveToLocalStorage : String -> Cmd msg


port localStorageSaved : (Bool -> msg) -> Sub msg


port placeChanged : (Value -> msg) -> Sub msg
