module EncodeFormStateTest exposing (suite)

import Expect
import Json.Decode
import Json.Encode
import Main
    exposing
        ( departmentIdLocalStorageKey
        , encodeFormState
        , locationIdLocalStorageKey
        , managerRampIdLocalStorageKey
        , roleIdLocalStorageKey
        , showAdvancedOptionsLocalStorageKey
        )
import Test exposing (Test, describe, test)
import TestFixtures exposing (minimalServerData, modelFrom)


advancedModeKeys : List String
advancedModeKeys =
    [ showAdvancedOptionsLocalStorageKey
    , managerRampIdLocalStorageKey
    , departmentIdLocalStorageKey
    , locationIdLocalStorageKey
    , roleIdLocalStorageKey
    ]


encodedKeys : String -> List String
encodedKeys encoded =
    case Json.Decode.decodeString (Json.Decode.keyValuePairs Json.Decode.value) encoded of
        Ok pairs ->
            List.map Tuple.first pairs

        Err _ ->
            []


suite : Test
suite =
    describe "encodeFormState"
        [ test "omits advanced-mode keys in simple mode" <|
            \_ ->
                let
                    model =
                        modelFrom minimalServerData Json.Encode.null

                    keys =
                        encodedKeys (encodeFormState model)
                in
                List.filter (\key -> List.member key keys) advancedModeKeys
                    |> Expect.equal []
        , test "includes advanced-mode keys in advanced mode" <|
            \_ ->
                let
                    model =
                        let
                            baseModel =
                                modelFrom minimalServerData Json.Encode.null
                        in
                        { baseModel | showAdvancedOptions = True }

                    keys =
                        encodedKeys (encodeFormState model)
                in
                List.filter (\key -> not (List.member key keys)) advancedModeKeys
                    |> Expect.equal []
        ]
