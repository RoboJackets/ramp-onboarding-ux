module ValidationTest exposing (suite)

import Dict
import Expect
import Main
    exposing
        ( ValidationResult(..)
        , validateAddressLineOne
        , validateAddressLineOneGoogleResult
        , validateCity
        , validateEmailAddress
        , validateManager
        , validateName
        , validateRampObject
        , validateState
        , validateZipCode
        )
import Test exposing (Test, describe, test)


suite : Test
suite =
    describe "validators"
        [ describe "validateName"
            [ test "accepts a normal name" <|
                \_ ->
                    validateName "first" "Ada"
                        |> Expect.equal Valid
            , test "rejects a blank name" <|
                \_ ->
                    validateName "first" "  "
                        |> Expect.equal (Invalid "Please enter your first name")
            , test "rejects a too-short name" <|
                \_ ->
                    validateName "last" "A"
                        |> Expect.equal (Invalid "Your last name must be at least 2 characters")
            , test "rejects disallowed characters" <|
                \_ ->
                    validateName "first" "Ada3"
                        |> Expect.equal (Invalid "Your first name may only contain letters, spaces, dashes, apostrophes, and periods")
            ]
        , describe "validateEmailAddress"
            [ test "accepts a verified known-domain address" <|
                \_ ->
                    validateEmailAddress "ada@robojackets.org" True
                        |> Expect.equal Valid
            , test "asks to verify with the provider when unverified" <|
                \_ ->
                    validateEmailAddress "ada@robojackets.org" False
                        |> Expect.equal (Invalid "Please verify your email address with Google")
            , test "rejects an unknown domain" <|
                \_ ->
                    validateEmailAddress "ada@example.com" False
                        |> Expect.equal (Invalid "Please enter a valid email address ending in gatech.edu or robojackets.org")
            ]
        , describe "validateAddressLineOne"
            [ test "accepts a street address" <|
                \_ ->
                    validateAddressLineOne "123 Main St"
                        |> Expect.equal Valid
            , test "rejects blank" <|
                \_ ->
                    validateAddressLineOne ""
                        |> Expect.equal (Invalid "Please enter your street address")
            ]
        , describe "validateAddressLineOneGoogleResult"
            [ test "treats Nothing as valid" <|
                \_ ->
                    validateAddressLineOneGoogleResult Nothing
                        |> Expect.equal Valid
            , test "treats Just False as invalid" <|
                \_ ->
                    validateAddressLineOneGoogleResult (Just False)
                        |> Expect.equal (Invalid "This doesn't appear to be a valid address")
            ]
        , describe "validateCity / validateState / validateZipCode"
            [ test "city rejects blank" <|
                \_ ->
                    validateCity ""
                        |> Expect.equal (Invalid "Please enter your city")
            , test "state requires a selection" <|
                \_ ->
                    validateState Nothing
                        |> Expect.equal (Invalid "Please select your state")
            , test "state accepts a selection" <|
                \_ ->
                    validateState (Just "GA")
                        |> Expect.equal Valid
            , test "zip accepts five digits" <|
                \_ ->
                    validateZipCode "30332"
                        |> Expect.equal Valid
            , test "zip accepts five digits with surrounding whitespace" <|
                \_ ->
                    validateZipCode " 30332 "
                        |> Expect.equal Valid
            , test "zip rejects non-digits" <|
                \_ ->
                    validateZipCode "3033a"
                        |> Expect.equal (Invalid "Please enter exactly 5 digits")
            ]
        , describe "validateRampObject"
            [ test "accepts an enabled option" <|
                \_ ->
                    validateRampObject "department"
                        "dept-1"
                        (Dict.fromList [ ( "dept-1", { label = "One", enabled = True } ) ])
                        |> Expect.equal Valid
            , test "rejects a disabled option" <|
                \_ ->
                    validateRampObject "department"
                        "dept-1"
                        (Dict.fromList [ ( "dept-1", { label = "One", enabled = False } ) ])
                        |> Expect.equal (Invalid "Please select your department")
            ]
        , describe "validateManager"
            [ test "advanced mode requires the manager department to match the selected department" <|
                \_ ->
                    validateManager True
                        Nothing
                        ""
                        (Just "mgr-1")
                        Nothing
                        "dept-a"
                        Dict.empty
                        (Dict.fromList
                            [ ( "mgr-1"
                              , { label = "Manager"
                                , enabled = True
                                , departmentId = "dept-b"
                                }
                              )
                            ]
                        )
                        1
                        |> Expect.equal (Invalid "Please select a manager within your department")
            , test "advanced mode accepts a matching department" <|
                \_ ->
                    validateManager True
                        Nothing
                        ""
                        (Just "mgr-1")
                        Nothing
                        "dept-a"
                        Dict.empty
                        (Dict.fromList
                            [ ( "mgr-1"
                              , { label = "Manager"
                                , enabled = True
                                , departmentId = "dept-a"
                                }
                              )
                            ]
                        )
                        1
                        |> Expect.equal Valid
            ]
        ]
