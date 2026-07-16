module EncodeFormStateTest exposing (suite)

import Dict
import Expect
import Json.Decode
import Json.Encode
import Main
    exposing
        ( buildInitialModel
        , departmentIdLocalStorageKey
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


decodeEncodedFormState : String -> Json.Encode.Value
decodeEncodedFormState encoded =
    Json.Decode.decodeString Json.Decode.value encoded
        |> Result.withDefault Json.Encode.null


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
        , describe "localStorage round-trip"
            [ test "restores every persisted field after encodeFormState → buildInitialModel" <|
                \_ ->
                    let
                        serverData =
                            { minimalServerData
                                | firstName = "Server"
                                , lastName = "Default"
                                , emailAddress = "server@robojackets.org"
                                , emailVerified = False
                                , managerApiaryId = Just 2
                                , addressLineOne = "Old Street"
                                , addressLineTwo = "Old Suite"
                                , city = "Old City"
                                , state = Just "FL"
                                , zip = "00000"
                                , showAdvancedOptions = False
                                , departmentId = "dept-students"
                                , locationId = "loc-campus"
                                , roleId = "BUSINESS_USER"
                                , locationOptions =
                                    Dict.fromList
                                        [ ( "loc-campus", { label = "Campus", enabled = True } )
                                        , ( "loc-remote", { label = "Remote", enabled = True } )
                                        , ( "loc-disabled", { label = "Disabled", enabled = False } )
                                        ]
                                , roleOptions =
                                    Dict.fromList
                                        [ ( "BUSINESS_USER", { label = "Employee", enabled = True } )
                                        , ( "BUSINESS_ADMIN", { label = "Admin", enabled = True } )
                                        , ( "role-disabled", { label = "Disabled", enabled = False } )
                                        ]
                                , rampManagerOptions =
                                    Dict.fromList
                                        [ ( "ramp-manager"
                                          , { label = "Manager Two"
                                            , enabled = True
                                            , departmentId = "dept-students"
                                            }
                                          )
                                        , ( "ramp-manager-3"
                                          , { label = "Manager Three"
                                            , enabled = True
                                            , departmentId = "dept-staff"
                                            }
                                          )
                                        ]
                            }

                        model =
                            let
                                baseModel =
                                    modelFrom serverData Json.Encode.null
                            in
                            { baseModel
                                | firstName = " Local "
                                , lastName = " User "
                                , emailAddress = " local@robojackets.org "
                                , managerApiaryId = Just 3
                                , orderPhysicalCard = False
                                , addressLineOne = " 123 Main St "
                                , addressLineTwo = " Apt 4 "
                                , city = " Atlanta "
                                , state = Just "GA"
                                , zip = " 30301 "
                                , showAdvancedOptions = True
                                , managerRampId = Just "ramp-manager-3"
                                , rampDepartmentId = "dept-staff"
                                , rampLocationId = "loc-remote"
                                , rampRoleId = "BUSINESS_ADMIN"
                            }

                        restored =
                            buildInitialModel serverData (decodeEncodedFormState (encodeFormState model))
                    in
                    Expect.all
                        [ .firstName >> Expect.equal "Local"
                        , .lastName >> Expect.equal "User"
                        , .emailAddress >> Expect.equal "local@robojackets.org"
                        , .managerApiaryId >> Expect.equal (Just 3)
                        , .orderPhysicalCard >> Expect.equal False
                        , .addressLineOne >> Expect.equal "123 Main St"
                        , .addressLineTwo >> Expect.equal "Apt 4"
                        , .city >> Expect.equal "Atlanta"
                        , .state >> Expect.equal (Just "GA")
                        , .zip >> Expect.equal "30301"
                        , .showAdvancedOptions >> Expect.equal True
                        , .managerRampId >> Expect.equal (Just "ramp-manager-3")
                        , .rampDepartmentId >> Expect.equal "dept-staff"
                        , .rampLocationId >> Expect.equal "loc-remote"
                        , .rampRoleId >> Expect.equal "BUSINESS_ADMIN"
                        ]
                        restored
            , test "simple-mode encode does not restore advanced Ramp fields" <|
                \_ ->
                    let
                        serverData =
                            { minimalServerData
                                | emailVerified = False
                                , emailAddress = "server@robojackets.org"
                                , managerApiaryId = Just 2
                                , departmentId = "dept-students"
                                , locationId = "loc-campus"
                                , roleId = "BUSINESS_USER"
                                , showAdvancedOptions = False
                            }

                        model =
                            let
                                baseModel =
                                    modelFrom serverData Json.Encode.null
                            in
                            { baseModel
                                | firstName = "Round"
                                , lastName = "Trip"
                                , emailAddress = "roundtrip@robojackets.org"
                                , managerApiaryId = Just 3
                                , orderPhysicalCard = False
                                , addressLineOne = "1 Peachtree St"
                                , addressLineTwo = "Floor 2"
                                , city = "Atlanta"
                                , state = Just "GA"
                                , zip = "30303"
                                , showAdvancedOptions = False
                                , managerRampId = Just "ramp-manager"
                                , rampDepartmentId = "dept-staff"
                                , rampLocationId = "loc-campus"
                                , rampRoleId = "BUSINESS_USER"
                            }

                        restored =
                            buildInitialModel serverData (decodeEncodedFormState (encodeFormState model))
                    in
                    Expect.all
                        [ .firstName >> Expect.equal "Round"
                        , .lastName >> Expect.equal "Trip"
                        , .emailAddress >> Expect.equal "roundtrip@robojackets.org"
                        , .managerApiaryId >> Expect.equal (Just 3)
                        , .orderPhysicalCard >> Expect.equal False
                        , .addressLineOne >> Expect.equal "1 Peachtree St"
                        , .addressLineTwo >> Expect.equal "Floor 2"
                        , .city >> Expect.equal "Atlanta"
                        , .state >> Expect.equal (Just "GA")
                        , .zip >> Expect.equal "30303"
                        , .showAdvancedOptions >> Expect.equal False
                        , -- Apiary manager changed, so server Ramp manager is cleared in simple mode
                          .managerRampId >> Expect.equal Nothing
                        , -- Advanced Ramp fields stay at server defaults when not encoded
                          .rampDepartmentId >> Expect.equal "dept-students"
                        , .rampLocationId >> Expect.equal "loc-campus"
                        , .rampRoleId >> Expect.equal "BUSINESS_USER"
                        ]
                        restored
            ]
        ]
