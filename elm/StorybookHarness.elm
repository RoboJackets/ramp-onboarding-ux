module StorybookHarness exposing (main)

import Browser
import Html exposing (Html, text)
import Json.Decode
    exposing
        ( Decoder
        , Value
        , andThen
        , at
        , bool
        , decodeValue
        , fail
        , field
        , int
        , map
        , map2
        , maybe
        , nullable
        , oneOf
        , string
        , succeed
        )
import List exposing (head)
import Main
    exposing
        ( AppModel(..)
        , Check(..)
        , FormState(..)
        , Model
        , Msg
        , ProvisioningFailure(..)
        , subscriptions
        , update
        )
import Time


main : Program Value AppModel Msg
main =
    Browser.element
        { init = init
        , view = view
        , update = update
        , subscriptions = subscriptions
        }


init : Value -> ( AppModel, Cmd Msg )
init flags =
    let
        ( appModel, _ ) =
            Main.init flags
    in
    ( case appModel of
        Ready model ->
            Ready (applyStorybookState flags model)

        ServerDataInvalid _ ->
            appModel
    , Cmd.none
    )


view : AppModel -> Html Msg
view appModel =
    case head (Main.view appModel).body of
        Just container ->
            container

        Nothing ->
            text "Harness error"


applyStorybookState : Value -> Model -> Model
applyStorybookState flags model =
    { model
        | formState = storybookField "formState" formStateDecoder model.formState flags
        , managerIsValid = storybookField "managerIsValid" (nullable bool) model.managerIsValid flags
        , managerFeedbackText = storybookField "managerFeedbackText" string model.managerFeedbackText flags
        , addressLineTwoRequired = storybookField "addressLineTwoRequired" bool model.addressLineTwoRequired flags
        , addressIsValid = storybookField "addressIsValid" (nullable bool) model.addressIsValid flags
        , showValidation = storybookField "showValidation" bool model.showValidation flags
        , redirectingToEmailVerification = storybookField "redirectingToEmailVerification" bool model.redirectingToEmailVerification flags
        , time = storybookField "time" (map Time.millisToPosix int) model.time flags
    }


storybookField : String -> Decoder a -> a -> Value -> a
storybookField key decoder fallback flags =
    decodeValue (at [ "storybookState", key ] decoder) flags
        |> Result.withDefault fallback


formStateDecoder : Decoder FormState
formStateDecoder =
    oneOf
        [ string |> andThen simpleFormStateKind
        , field "kind" string |> andThen formStateKind
        ]


simpleFormStateKind : String -> Decoder FormState
simpleFormStateKind kind =
    case kind of
        "editing" ->
            succeed Editing

        "validating" ->
            succeed (Validating { manager = InFlight, address = InFlight })

        "creatingRampAccount" ->
            succeed (CreatingRampAccount False)

        "rampAccountCreated" ->
            succeed RampAccountCreated

        "physicalCardOrdered" ->
            succeed PhysicalCardOrdered

        "error" ->
            succeed (Error CreateAccountTaskFailed)

        _ ->
            fail ("Unknown formState kind \"" ++ kind ++ "\"")


formStateKind : String -> Decoder FormState
formStateKind kind =
    case kind of
        "editing" ->
            succeed Editing

        "validating" ->
            map2
                (\manager address -> Validating { manager = manager, address = address })
                (map (Maybe.withDefault InFlight) (maybe (field "manager" checkDecoder)))
                (map (Maybe.withDefault InFlight) (maybe (field "address" checkDecoder)))

        "creatingRampAccount" ->
            map CreatingRampAccount
                (map (Maybe.withDefault False) (maybe (field "requestCompleted" bool)))

        "rampAccountCreated" ->
            succeed RampAccountCreated

        "physicalCardOrdered" ->
            succeed PhysicalCardOrdered

        "error" ->
            map Error (field "failure" provisioningFailureDecoder)

        _ ->
            fail ("Unknown formState kind \"" ++ kind ++ "\"")


checkDecoder : Decoder Check
checkDecoder =
    string
        |> andThen
            (\value ->
                case value of
                    "inFlight" ->
                        succeed InFlight

                    "done" ->
                        succeed Done

                    _ ->
                        fail ("Unknown check value \"" ++ value ++ "\"")
            )


provisioningFailureDecoder : Decoder ProvisioningFailure
provisioningFailureDecoder =
    field "kind" string
        |> andThen
            (\kind ->
                case kind of
                    "createAccountRequestFailed" ->
                        map CreateAccountRequestFailed (field "detail" string)

                    "createAccountTaskFailed" ->
                        succeed CreateAccountTaskFailed

                    "createAccountStatusCheckFailed" ->
                        map CreateAccountStatusCheckFailed (field "detail" string)

                    "orderPhysicalCardFailed" ->
                        map OrderPhysicalCardFailed (field "detail" string)

                    _ ->
                        fail ("Unknown provisioning failure kind \"" ++ kind ++ "\"")
            )
