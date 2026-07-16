module BuildInitialModelTest exposing (suite)

import Expect
import Json.Encode
import Main exposing (buildInitialModel)
import Test exposing (Test, describe, test)
import TestFixtures exposing (minimalServerData)


suite : Test
suite =
    describe "buildInitialModel"
        [ test "uses localStorage values when present and valid" <|
            \_ ->
                let
                    localData =
                        Json.Encode.object
                            [ ( "firstName", Json.Encode.string "Local" )
                            , ( "lastName", Json.Encode.string "User" )
                            , ( "city", Json.Encode.string "Savannah" )
                            ]

                    model =
                        buildInitialModel minimalServerData localData
                in
                Expect.all
                    [ .firstName >> Expect.equal "Local"
                    , .lastName >> Expect.equal "User"
                    , .city >> Expect.equal "Savannah"
                    ]
                    model
        , test "falls back to server values when localStorage is empty" <|
            \_ ->
                let
                    model =
                        buildInitialModel minimalServerData Json.Encode.null
                in
                Expect.all
                    [ .firstName >> Expect.equal "Ada"
                    , .lastName >> Expect.equal "Lovelace"
                    , .emailAddress >> Expect.equal "ada@robojackets.org"
                    ]
                    model
        , test "ignores local email when the server email is verified" <|
            \_ ->
                let
                    localData =
                        Json.Encode.object
                            [ ( "emailAddress", Json.Encode.string "other@robojackets.org" )
                            ]

                    model =
                        buildInitialModel minimalServerData localData
                in
                model.emailAddress
                    |> Expect.equal "ada@robojackets.org"
        , test "uses local email when the server email is not verified" <|
            \_ ->
                let
                    serverData =
                        { minimalServerData | emailVerified = False, emailAddress = "server@robojackets.org" }

                    localData =
                        Json.Encode.object
                            [ ( "emailAddress", Json.Encode.string "local@robojackets.org" )
                            ]

                    model =
                        buildInitialModel serverData localData
                in
                model.emailAddress
                    |> Expect.equal "local@robojackets.org"
        , test "ORs showAdvancedOptions from server and localStorage" <|
            \_ ->
                let
                    serverData =
                        { minimalServerData | showAdvancedOptions = False }

                    localData =
                        Json.Encode.object
                            [ ( "showAdvancedOptions", Json.Encode.bool True )
                            ]

                    model =
                        buildInitialModel serverData localData
                in
                model.showAdvancedOptions
                    |> Expect.equal True
        , test "rejects a disabled department id from localStorage" <|
            \_ ->
                let
                    localData =
                        Json.Encode.object
                            [ ( "showAdvancedOptions", Json.Encode.bool True )
                            , ( "departmentId", Json.Encode.string "dept-disabled" )
                            ]

                    model =
                        buildInitialModel minimalServerData localData
                in
                model.rampDepartmentId
                    |> Expect.equal "dept-students"
        , test "accepts a valid local department id over the server default" <|
            \_ ->
                let
                    localData =
                        Json.Encode.object
                            [ ( "showAdvancedOptions", Json.Encode.bool True )
                            , ( "departmentId", Json.Encode.string "dept-staff" )
                            ]

                    model =
                        buildInitialModel minimalServerData localData
                in
                model.rampDepartmentId
                    |> Expect.equal "dept-staff"
        , test "rejects an invalid local state code" <|
            \_ ->
                let
                    serverData =
                        { minimalServerData | state = Just "GA" }

                    localData =
                        Json.Encode.object
                            [ ( "state", Json.Encode.string "ZZ" )
                            ]

                    model =
                        buildInitialModel serverData localData
                in
                model.state
                    |> Expect.equal (Just "GA")
        , test "clears managerRampId in simple mode when local Apiary manager differs from server" <|
            \_ ->
                let
                    localData =
                        Json.Encode.object
                            [ ( "managerApiaryId", Json.Encode.int 3 )
                            , ( "managerRampId", Json.Encode.null )
                            ]

                    model =
                        buildInitialModel minimalServerData localData
                in
                Expect.all
                    [ .managerApiaryId >> Expect.equal (Just 3)
                    , .managerRampId >> Expect.equal Nothing
                    ]
                    model
        , test "keeps server managerRampId in simple mode when local Apiary manager still matches" <|
            \_ ->
                let
                    localData =
                        Json.Encode.object
                            [ ( "managerApiaryId", Json.Encode.int 2 )
                            , ( "managerRampId", Json.Encode.null )
                            ]

                    model =
                        buildInitialModel minimalServerData localData
                in
                Expect.all
                    [ .managerApiaryId >> Expect.equal (Just 2)
                    , .managerRampId >> Expect.equal (Just "ramp-manager")
                    ]
                    model
        , test "ignores stored Ramp fields in simple mode" <|
            \_ ->
                let
                    localData =
                        Json.Encode.object
                            [ ( "managerApiaryId", Json.Encode.int 3 )
                            , ( "managerRampId", Json.Encode.string "ramp-manager" )
                            , ( "departmentId", Json.Encode.string "dept-staff" )
                            ]

                    model =
                        buildInitialModel minimalServerData localData
                in
                Expect.all
                    [ .managerRampId >> Expect.equal Nothing
                    , .rampDepartmentId >> Expect.equal "dept-students"
                    ]
                    model
        , test "restores managerRampId from localStorage in advanced mode" <|
            \_ ->
                let
                    localData =
                        Json.Encode.object
                            [ ( "showAdvancedOptions", Json.Encode.bool True )
                            , ( "managerRampId", Json.Encode.string "ramp-manager" )
                            ]

                    model =
                        buildInitialModel minimalServerData localData
                in
                model.managerRampId
                    |> Expect.equal (Just "ramp-manager")
        , test "falls back to server managerRampId in advanced mode when local is null" <|
            \_ ->
                let
                    localData =
                        Json.Encode.object
                            [ ( "showAdvancedOptions", Json.Encode.bool True )
                            , ( "managerRampId", Json.Encode.null )
                            ]

                    model =
                        buildInitialModel minimalServerData localData
                in
                model.managerRampId
                    |> Expect.equal (Just "ramp-manager")
        ]
