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
    Maybe.withDefault Regex.never (Regex.fromString "^[a-zA-Z ]+$")


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



-- TYPES


type NextAction
    = RedirectToEmailVerification
    | Validation
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


type alias Model =
    { firstName : String
    , lastName : String
    , emailAddress : String
    , emailVerified : Bool
    , managerOptions : Dict Int String
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
    }


type Msg
    = UrlRequest Browser.UrlRequest
    | UrlChanged Url.Url
    | FormSubmitted
    | FormChanged
    | FirstNameInput String
    | LastNameInput String
    | EmailAddressInput String
    | ManagerInput Int
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
        , initializeAutocomplete (String.trim (Result.withDefault "" (decodeValue (at [ "serverData", "googleMapsApiKey" ] string) flags)))
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
                                Validation

                            else if model.orderPhysicalCard == True then
                                Validation

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

        ManagerInput managerApiaryId ->
            ( { model
                | managerApiaryId = Just managerApiaryId
                , managerRampId = Nothing
                , managerIsValid = Nothing
                , nextAction = NoOpNextAction
              }
            , saveToLocalStorage (stringifyModel { model | managerApiaryId = Just managerApiaryId })
            )

        OrderPhysicalCardChecked orderPhysicalCard ->
            ( { model
                | orderPhysicalCard = orderPhysicalCard
                , nextAction = NoOpNextAction
              }
            , saveToLocalStorage (stringifyModel { model | orderPhysicalCard = orderPhysicalCard })
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
            ( { model
                | state = Just state
                , nextAction = NoOpNextAction
                , addressLineTwoRequired = False
              }
            , saveToLocalStorage (stringifyModel { model | state = Just state })
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
            ( { model
                | nextAction = NoOpNextAction
              }
            , case model.nextAction of
                RedirectToEmailVerification ->
                    Nav.load
                        (Url.Builder.absolute
                            [ "verify-email" ]
                            [ Url.Builder.string "emailAddress" model.emailAddress ]
                        )

                Validation ->
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
                        , if model.orderPhysicalCard then
                            if checkCampusAddress model == NotCampusAddress then
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

                          else
                            Cmd.none
                        ]

                CreateRampAccount ->
                    createRampAccountTask model

                NoOpNextAction ->
                    Cmd.none
            )

        PlaceChanged value ->
            ( { model
                | addressLineOne =
                    String.trim (getAddressComponent (decodePlaceChanged value) "street_number")
                        ++ " "
                        ++ String.trim (getAddressComponent (decodePlaceChanged value) "route")
                , addressLineTwo = String.trim (getAddressComponent (decodePlaceChanged value) "subpremise")
                , city = String.trim (getAddressComponent (decodePlaceChanged value) "locality")
                , state = Just (String.trim (getAddressComponent (decodePlaceChanged value) "administrative_area_level_1"))
                , zip = String.trim (getAddressComponent (decodePlaceChanged value) "postal_code")
                , nextAction = NoOpNextAction
              }
            , Cmd.batch
                [ Task.attempt (\_ -> NoOpMsg) (focus "address_line_two")
                , saveToLocalStorage
                    (stringifyModel
                        { model
                            | addressLineOne =
                                String.trim (getAddressComponent (decodePlaceChanged value) "street_number")
                                    ++ " "
                                    ++ String.trim (getAddressComponent (decodePlaceChanged value) "route")
                            , addressLineTwo = String.trim (getAddressComponent (decodePlaceChanged value) "subpremise")
                            , city = String.trim (getAddressComponent (decodePlaceChanged value) "locality")
                            , state = Just (String.trim (getAddressComponent (decodePlaceChanged value) "administrative_area_level_1"))
                            , zip = String.trim (getAddressComponent (decodePlaceChanged value) "postal_code")
                        }
                    )
                ]
            )

        GoogleAddressValidationResultReceived result ->
            ( { model
                | nextAction = NoOpNextAction
                , addressLineTwoRequired =
                    case result of
                        Ok verdict ->
                            if List.member "subpremise" (Maybe.withDefault [] verdict.missingComponentTypes) then
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
                                    if List.member "subpremise" (Maybe.withDefault [] verdict.missingComponentTypes) then
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
                                    if List.member "subpremise" (Maybe.withDefault [] verdict.missingComponentTypes) then
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

                    else if List.member "subpremise" (Maybe.withDefault [] verdict.missingComponentTypes) then
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
                    if managerRampInfo.managerRampId == Nothing then
                        Cmd.none

                    else if model.orderPhysicalCard then
                        case model.addressIsValid of
                            Just True ->
                                if validateModel model == Valid then
                                    createRampAccountTask { model | managerRampId = managerRampInfo.managerRampId }

                                else
                                    Cmd.none

                            Just False ->
                                Cmd.none

                            Nothing ->
                                if checkCampusAddress model /= NotCampusAddress then
                                    createRampAccountTask { model | managerRampId = managerRampInfo.managerRampId }

                                else
                                    Cmd.none

                    else
                        createRampAccountTask { model | managerRampId = managerRampInfo.managerRampId }

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
                                                [ ( "firstName", Json.Encode.string (String.trim model.firstName) )
                                                , ( "lastName", Json.Encode.string (String.trim model.lastName) )
                                                , ( "addressLineOne", Json.Encode.string (String.trim model.addressLineOne) )
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
                                    , expect = expectJson OrderPhysicalCardTaskIdReceived createTaskResponseDecoder
                                    }

                            else
                                Nav.load "/"

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
                            Nav.load "/"

                        Just "IN_PROGRESS" ->
                            getPhysicalCardTaskStatus (Maybe.withDefault "" model.orderPhysicalCardTaskId)

                        _ ->
                            Cmd.none

                Err _ ->
                    Cmd.none
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
                        , a [ href "slack://channel?team=T033JPZLT&id=C64F32R50" ]
                            [ text "#treasury-helpdesk"
                            ]
                        , text " for further assistance."
                        ]
                    ]
                ]
    }


renderForm : Model -> List (Html Msg)
renderForm model =
    [ div [ class "container", class "mt-md-4", class "mt-3", style "max-width" "48rem" ]
        [ h1 []
            [ text "Ramp Onboarding"
            ]
        , p [ class "mt-4", class "mb-4" ]
            [ text "RoboJackets, Inc. uses "
            , a [ href "https://ramp.com" ]
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
                        , ( "is-valid", model.showValidation && isValid (validateName "first" model.firstName) )
                        , ( "is-invalid", model.showValidation && not (isValid (validateName "first" model.firstName)) )
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
                    [ text (feedbackText (validateName "first" model.firstName)) ]
                ]
            , div [ class "col-6" ]
                [ label [ for "last_name", class "form-label" ]
                    [ text "Last Name" ]
                , input
                    [ id "last_name"
                    , type_ "text"
                    , classList
                        [ ( "form-control", True )
                        , ( "is-valid", model.showValidation && isValid (validateName "last" model.lastName) )
                        , ( "is-invalid", model.showValidation && not (isValid (validateName "last" model.lastName)) )
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
                    [ text (feedbackText (validateName "last" model.lastName)) ]
                ]
            , div [ class "form-text", class "mb-3" ]
                [ text "Your name must match your government-issued identification, only contain letters and spaces, and be a maximum of 80 characters." ]
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
                            , ( "is-valid", model.showValidation && isValid (validateEmailAddress model.emailAddress model.emailVerified) )
                            , ( "is-invalid", model.showValidation && not (isValid (validateEmailAddress model.emailAddress model.emailVerified)) )
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
                                || not (Dict.member (withDefault "unknown" (emailAddressDomain model.emailAddress)) emailProviderName)
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

                                    else if Dict.member (withDefault "unknown" (emailAddressDomain model.emailAddress)) emailProviderName then
                                        "Verify with "
                                            ++ withDefault "Unknown" (Dict.get (withDefault "unknown" (emailAddressDomain model.emailAddress)) emailProviderName)

                                    else
                                        "Verify"
                                   )
                            )
                        ]
                    , div [ class "invalid-feedback" ]
                        [ text (feedbackText (validateEmailAddress model.emailAddress model.emailVerified)) ]
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
                    , on "change" (Json.Decode.map ManagerInput targetValueIntParse)
                    , classList
                        [ ( "is-valid", model.showValidation && isValid (validateManager model.managerIsValid model.managerFeedbackText model.managerApiaryId (Dict.keys model.managerOptions) model.selfApiaryId) )
                        , ( "is-invalid", model.showValidation && not (isValid (validateManager model.managerIsValid model.managerFeedbackText model.managerApiaryId (Dict.keys model.managerOptions) model.selfApiaryId)) )
                        ]
                    ]
                    ([ option
                        [ Html.Attributes.value ""
                        , disabled True
                        , selected
                            (case model.managerApiaryId of
                                Just managerApiaryId ->
                                    model.selfApiaryId == managerApiaryId

                                Nothing ->
                                    True
                            )
                        ]
                        [ text "Select your manager..." ]
                     ]
                        ++ List.map (managerTupleToHtmlOption model.managerApiaryId model.selfApiaryId) (sortBy second (toList model.managerOptions))
                    )
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText (validateManager model.managerIsValid model.managerFeedbackText model.managerApiaryId (Dict.keys model.managerOptions) model.selfApiaryId)) ]
                , div [ class "form-text", class "mb-3" ]
                    [ text "Your manager will be responsible for reviewing your credit card transactions and reimbursement requests. This should typically be your project manager." ]
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
                        [ ( "is-valid", model.showValidation && (isValid (validateAddressLineOne model.addressLineOne) && Maybe.withDefault True model.addressIsValid) )
                        , ( "is-invalid", model.showValidation && (not (isValid (validateAddressLineOne model.addressLineOne)) || not (Maybe.withDefault True model.addressIsValid)) )
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
                        (if isValid (validateAddressLineOne model.addressLineOne) then
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
                        [ ( "is-valid", model.showValidation && isValid (validateAddressLineTwo model.addressLineTwo model.addressLineTwoRequired (checkCampusAddress model)) && Maybe.withDefault True model.addressIsValid )
                        , ( "is-invalid", model.showValidation && (not (isValid (validateAddressLineTwo model.addressLineTwo model.addressLineTwoRequired (checkCampusAddress model))) || not (Maybe.withDefault True model.addressIsValid)) )
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
                    [ text (feedbackText (validateAddressLineTwo model.addressLineTwo model.addressLineTwoRequired (checkCampusAddress model))) ]
                ]
            , div [ class "col-md-6", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ label [ for "city", class "form-label" ] [ text "City" ]
                , input
                    [ type_ "text"
                    , class "form-control"
                    , classList
                        [ ( "is-valid", model.showValidation && isValid (validateCity model.city) && Maybe.withDefault True model.addressIsValid )
                        , ( "is-invalid", model.showValidation && (not (isValid (validateCity model.city)) || not (Maybe.withDefault True model.addressIsValid)) )
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
                    [ text (feedbackText (validateCity model.city)) ]
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
                        [ ( "is-valid", model.showValidation && isValid (validateState model.state) && Maybe.withDefault True model.addressIsValid )
                        , ( "is-invalid", model.showValidation && (not (isValid (validateState model.state)) || not (Maybe.withDefault True model.addressIsValid)) )
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
                        ]
                        [ text "Select..." ]
                     ]
                        ++ List.map (stateTupleToHtmlOption model.state) (sortBy second (toList statesMap))
                    )
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText (validateState model.state)) ]
                ]
            , div [ class "col-md-3", class "col-4", class "mb-2", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ label [ for "zip", class "form-label" ] [ text "ZIP Code" ]
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
                        [ ( "is-valid", model.showValidation && isValid (validateZipCode model.zip) && Maybe.withDefault True model.addressIsValid )
                        , ( "is-invalid", model.showValidation && (not (isValid (validateZipCode model.zip)) || not (Maybe.withDefault True model.addressIsValid)) )
                        ]
                    ]
                    []
                , div [ class "invalid-feedback" ]
                    [ text (feedbackText (validateZipCode model.zip)) ]
                ]
            , div [ class "form-text", class "mb-3", classList [ ( "d-none", not model.orderPhysicalCard ) ] ]
                [ text
                    ("Your physical card should be delivered by "
                        ++ formatTime model.zone
                            (case toWeekday model.zone (millisToPosix (posixToMillis model.time + ceiling (9.5 * 1000 * 60 * 60 * 24 * 1))) of
                                Sat ->
                                    millisToPosix (posixToMillis model.time + ceiling (11.5 * 1000 * 60 * 60 * 24 * 1))

                                Sun ->
                                    millisToPosix (posixToMillis model.time + ceiling (10.5 * 1000 * 60 * 60 * 24 * 1))

                                _ ->
                                    millisToPosix (posixToMillis model.time + ceiling (9.5 * 1000 * 60 * 60 * 24 * 1))
                            )
                        ++ "."
                    )
                ]
            , div [ class "col-12", class "mb-3", class "mb-md-5" ]
                [ button
                    [ type_ "submit"
                    , class "btn"
                    , class "btn-primary"
                    , id "submit_button"
                    , disabled (model.formState /= Editing)
                    ]
                    [ text "Create Account"
                    ]
                ]
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

    else if String.length (String.trim nameValue) > 40 then
        Invalid ("Your " ++ whichName ++ " name may be a maximum of 40 characters")

    else if not (Regex.contains nameRegex nameValue) then
        Invalid ("Your " ++ whichName ++ " name may only contain letters and spaces")

    else
        Valid


validateEmailAddress : String -> Bool -> ValidationResult
validateEmailAddress emailAddress verified =
    case Email.parse emailAddress of
        Ok addressParts ->
            case getSecondLevelDomain addressParts.domain of
                Just domain ->
                    if not (List.member domain (Dict.keys emailProviderName)) then
                        Invalid emailFeedbackText

                    else if not verified then
                        Invalid ("Please verify your email address with " ++ emailProvider domain)

                    else
                        Valid

                Nothing ->
                    Invalid emailFeedbackText

        Err _ ->
            Invalid emailFeedbackText


validateManager : Maybe Bool -> String -> Maybe Int -> List Int -> Int -> ValidationResult
validateManager selectedManagerHasRampAccount selectedManagerRampFeedbackText selectedManagerId managerOptions selfId =
    case selectedManagerId of
        Just managerId ->
            if managerId == selfId then
                Invalid managerFeedbackText

            else if List.member managerId managerOptions then
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

    else if not (isValid (validateManager model.managerIsValid model.managerFeedbackText model.managerApiaryId (Dict.keys model.managerOptions) model.selfApiaryId)) then
        Invalid "manager"

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
            [ ( "firstName", Json.Encode.string (String.trim model.firstName) )
            , ( "lastName", Json.Encode.string (String.trim model.lastName) )
            , ( "emailAddress", Json.Encode.string (String.trim model.emailAddress) )
            , ( "managerId"
              , case model.managerApiaryId of
                    Just managerApiaryId ->
                        Json.Encode.int managerApiaryId

                    Nothing ->
                        Json.Encode.null
              )
            , ( "orderPhysicalCard", Json.Encode.bool model.orderPhysicalCard )
            , ( "addressLineOne", Json.Encode.string (String.trim model.addressLineOne) )
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
                    [ ( "directManagerId", Json.Encode.string (Maybe.withDefault "" model.managerRampId) )
                    , ( "firstName", Json.Encode.string (String.trim model.firstName) )
                    , ( "lastName", Json.Encode.string (String.trim model.lastName) )
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
            && String.trim model.zip
            == "30332"
    then
        StudentCenter

    else if
        String.toLower (String.trim model.addressLineOne)
            == "301 10th st nw"
            && String.toLower (String.trim model.city)
            == "atlanta"
            && Maybe.withDefault "" model.state
            == "GA"
            && String.trim model.zip
            == "30318"
    then
        GraduateLivingCenter

    else if
        String.toLower (String.trim model.addressLineOne)
            == "801 ferst dr nw"
            && String.toLower (String.trim model.city)
            == "atlanta"
            && Maybe.withDefault "" model.state
            == "GA"
            && String.trim model.zip
            == "30332"
    then
        ManufacturingRelatedDisciplinesComplex

    else if
        String.toLower (String.trim model.addressLineOne)
            == "801 ferst dr"
            && String.toLower (String.trim model.city)
            == "atlanta"
            && Maybe.withDefault "" model.state
            == "GA"
            && String.trim model.zip
            == "30332"
    then
        ManufacturingRelatedDisciplinesComplex

    else
        NotCampusAddress


buildInitialModel : Value -> Model
buildInitialModel value =
    Model
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ "serverData", "firstName" ] string) value))
                (decodeString (field "firstName" string) (Result.withDefault "{}" (decodeValue (field "localData" string) value)))
            )
        )
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ "serverData", "lastName" ] string) value))
                (decodeString (field "lastName" string) (Result.withDefault "{}" (decodeValue (field "localData" string) value)))
            )
        )
        (if Result.withDefault False (decodeValue (at [ "serverData", "emailVerified" ] bool) value) then
            String.trim
                (Result.withDefault
                    ""
                    (decodeValue (at [ "serverData", "emailAddress" ] string) value)
                )

         else
            String.trim
                (Result.withDefault
                    (Result.withDefault "" (decodeValue (at [ "serverData", "emailAddress" ] string) value))
                    (decodeString (field "emailAddress" string) (Result.withDefault "{}" (decodeValue (field "localData" string) value)))
                )
        )
        (Result.withDefault False (decodeValue (at [ "serverData", "emailVerified" ] bool) value))
        (Dict.fromList (List.filterMap stringStringTupleToMaybeIntStringTuple (Result.withDefault [] (decodeValue (at [ "serverData", "managerOptions" ] (keyValuePairs string)) value))))
        (case decodeString (field "managerId" int) (Result.withDefault "{}" (decodeValue (field "localData" string) value)) of
            Ok managerId ->
                Just managerId

            Err _ ->
                case decodeValue (at [ "serverData", "managerId" ] int) value of
                    Ok managerId ->
                        if Result.withDefault -1 (decodeValue (at [ "serverData", "selfId" ] int) value) == managerId then
                            Nothing

                        else
                            Just managerId

                    Err _ ->
                        Nothing
        )
        Nothing
        Nothing
        ""
        (Result.withDefault -1 (decodeValue (at [ "serverData", "selfId" ] int) value))
        (Result.withDefault True (decodeString (field "orderPhysicalCard" bool) (Result.withDefault "{}" (decodeValue (field "localData" string) value))))
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ "serverData", "addressLineOne" ] string) value))
                (decodeString (field "addressLineOne" string) (Result.withDefault "{}" (decodeValue (field "localData" string) value)))
            )
        )
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ "serverData", "addressLineTwo" ] string) value))
                (decodeString (field "addressLineTwo" string) (Result.withDefault "{}" (decodeValue (field "localData" string) value)))
            )
        )
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ "serverData", "city" ] string) value))
                (decodeString (field "city" string) (Result.withDefault "{}" (decodeValue (field "localData" string) value)))
            )
        )
        (case decodeString (field "state" string) (Result.withDefault "{}" (decodeValue (field "localData" string) value)) of
            Ok state ->
                if List.member state (Dict.keys statesMap) then
                    Just state

                else
                    Nothing

            Err _ ->
                case decodeValue (at [ "serverData", "state" ] string) value of
                    Ok state ->
                        if List.member state (Dict.keys statesMap) then
                            Just state

                        else
                            Nothing

                    Err _ ->
                        Nothing
        )
        (String.trim
            (Result.withDefault
                (Result.withDefault "" (decodeValue (at [ "serverData", "zip" ] string) value))
                (decodeString (field "zip" string) (Result.withDefault "{}" (decodeValue (field "localData" string) value)))
            )
        )
        False
        Nothing
        False
        (String.trim (Result.withDefault "" (decodeValue (at [ "serverData", "googleMapsApiKey" ] string) value)))
        (String.trim (Result.withDefault "" (decodeValue (at [ "serverData", "googleClientId" ] string) value)))
        (String.trim (Result.withDefault "" (decodeValue (at [ "serverData", "googleOneTapLoginUri" ] string) value)))
        (Time.millisToPosix 0)
        Time.utc
        Editing
        NoOpNextAction
        Nothing
        Nothing


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



-- PORTS


port initializeAutocomplete : String -> Cmd msg


port initializeOneTap : Bool -> Cmd msg


port saveToLocalStorage : String -> Cmd msg


port localStorageSaved : (Bool -> msg) -> Sub msg


port placeChanged : (Value -> msg) -> Sub msg
