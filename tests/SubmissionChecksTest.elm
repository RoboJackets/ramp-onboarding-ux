module SubmissionChecksTest exposing (suite)

import Expect
import Json.Encode
import Main
    exposing
        ( Check(..)
        , FormState(..)
        , ManagerValidation(..)
        , Msg(..)
        , ProvisioningFailure(..)
        , abortValidation
        , addressValidationRequestFromModel
        , markAddressCheckDone
        , markManagerCheckDone
        , needsAddressValidation
        , needsManagerValidation
        , proceedIfReady
        , submissionChecksFromModel
        , updateReady
        )
import Test exposing (Test, describe, test)
import TestFixtures
    exposing
        ( minimalServerData
        , modelFrom
        , withAddress
        , withManagerRampId
        , withOrderPhysicalCard
        )
import Tuple


suite : Test
suite =
    describe "submission checks"
        [ describe "needsManagerValidation"
            [ test "needed when managerRampId is missing" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withManagerRampId Nothing
                        |> needsManagerValidation
                        |> Expect.equal True
            , test "not needed when managerRampId is present" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> needsManagerValidation
                        |> Expect.equal False
            ]
        , describe "needsAddressValidation"
            [ test "needed for a non-campus physical card order" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withOrderPhysicalCard True
                        |> withAddress "123 Main St" "" "Atlanta" (Just "GA") "30309"
                        |> needsAddressValidation
                        |> Expect.equal True
            , test "not needed when not ordering a physical card" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withOrderPhysicalCard False
                        |> needsAddressValidation
                        |> Expect.equal False
            , test "not needed for a campus address" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withOrderPhysicalCard True
                        |> withAddress "351 Ferst Drive" "123456 Georgia Tech Station" "Atlanta" (Just "GA") "30332"
                        |> needsAddressValidation
                        |> Expect.equal False
            , test "not needed when address already validated as complete" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withOrderPhysicalCard True
                        |> withAddress "123 Main St" "" "Atlanta" (Just "GA") "30309"
                        |> (\model -> { model | addressIsValid = Just True })
                        |> needsAddressValidation
                        |> Expect.equal False
            , test "not needed when address already validated as invalid" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withOrderPhysicalCard True
                        |> withAddress "123 Main St" "" "Atlanta" (Just "GA") "30309"
                        |> (\model -> { model | addressIsValid = Just False })
                        |> needsAddressValidation
                        |> Expect.equal False
            ]
        , describe "submissionChecksFromModel"
            [ test "marks both checks Done when neither is needed" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withOrderPhysicalCard False
                        |> submissionChecksFromModel
                        |> Expect.equal { manager = Done, address = Done }
            , test "marks manager InFlight when Ramp id is missing" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withManagerRampId Nothing
                        |> withOrderPhysicalCard False
                        |> submissionChecksFromModel
                        |> Expect.equal { manager = InFlight, address = Done }
            , test "marks address Done when a Google verdict already exists" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withOrderPhysicalCard True
                        |> withAddress "123 Main St" "" "Atlanta" (Just "GA") "30309"
                        |> (\model -> { model | addressIsValid = Just False })
                        |> submissionChecksFromModel
                        |> Expect.equal { manager = Done, address = Done }
            ]
        , describe "address field edits clear Google verdict"
            [ test "AddressLineOneInput resets addressIsValid" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null
                                |> withOrderPhysicalCard True
                                |> withAddress "123 Main St" "" "Atlanta" (Just "GA") "30309"
                                |> (\m -> { m | addressIsValid = Just False })
                    in
                    updateReady (AddressLineOneInput "456 Oak Ave") model
                        |> Tuple.first
                        |> .addressIsValid
                        |> Expect.equal Nothing
            ]
        , describe "abortValidation / mark*CheckDone"
            [ test "abortValidation returns Editing from Validating" <|
                \_ ->
                    abortValidation (Validating { manager = InFlight, address = Done })
                        |> Expect.equal Editing
            , test "abortValidation leaves non-Validating states alone" <|
                \_ ->
                    abortValidation (Error (CreateAccountRequestFailed "network error"))
                        |> Expect.equal (Error (CreateAccountRequestFailed "network error"))
            , test "markManagerCheckDone flips manager to Done" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null

                        validating =
                            { model | formState = Validating { manager = InFlight, address = Done } }
                    in
                    markManagerCheckDone validating
                        |> .formState
                        |> Expect.equal (Validating { manager = Done, address = Done })
            , test "markAddressCheckDone flips address to Done" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null

                        validating =
                            { model | formState = Validating { manager = Done, address = InFlight } }
                    in
                    markAddressCheckDone validating
                        |> .formState
                        |> Expect.equal (Validating { manager = Done, address = Done })
            ]
        , describe "proceedIfReady"
            [ test "stays put while a check is still InFlight" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null

                        validating =
                            { model | formState = Validating { manager = Done, address = InFlight } }
                    in
                    proceedIfReady validating
                        |> Tuple.first
                        |> .formState
                        |> Expect.equal (Validating { manager = Done, address = InFlight })
            , test "returns to Editing when both checks are Done but the form is invalid" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null
                                |> withManagerRampId Nothing

                        validating =
                            { model | formState = Validating { manager = Done, address = Done } }
                    in
                    proceedIfReady validating
                        |> Tuple.first
                        |> .formState
                        |> Expect.equal Editing
            , test "moves to CreatingRampAccount when both checks are Done and the form is valid" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null
                                |> withOrderPhysicalCard False

                        validating =
                            { model | formState = Validating { manager = Done, address = Done } }
                    in
                    proceedIfReady validating
                        |> Tuple.first
                        |> .formState
                        |> Expect.equal (CreatingRampAccount Nothing)
            ]
        , describe "stale validation responses"
            [ test "ignores ManagerValidationResultReceived when not Validating" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null
                                |> withManagerRampId Nothing

                        editing =
                            { model
                                | formState = Editing
                                , managerApiaryId = Just 3
                                , managerIsValid = Nothing
                            }
                    in
                    updateReady
                        (ManagerValidationResultReceived 3
                            (Ok (ManagerResolved "ramp-a"))
                        )
                        editing
                        |> Tuple.first
                        |> Expect.all
                            [ .managerRampId >> Expect.equal Nothing
                            , .managerApiaryId >> Expect.equal (Just 3)
                            , .managerIsValid >> Expect.equal Nothing
                            , .formState >> Expect.equal Editing
                            ]
            , test "ignores GoogleAddressValidationResultReceived when not Validating" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null
                                |> withAddress "123 Main St" "" "Atlanta" (Just "GA") "30309"

                        editing =
                            { model
                                | formState = Editing
                                , addressIsValid = Nothing
                                , addressLineTwoRequired = False
                            }
                    in
                    updateReady
                        (GoogleAddressValidationResultReceived
                            (addressValidationRequestFromModel editing)
                            (Ok
                                { addressComplete = Just True
                                , missingComponentTypes = Nothing
                                }
                            )
                        )
                        editing
                        |> Tuple.first
                        |> Expect.all
                            [ .addressIsValid >> Expect.equal Nothing
                            , .addressLineTwoRequired >> Expect.equal False
                            , .formState >> Expect.equal Editing
                            ]
            , test "ignores GoogleAddressValidationResultReceived for a different address" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null
                                |> withOrderPhysicalCard False
                                |> withAddress "123 Main St" "" "Atlanta" (Just "GA") "30309"

                        validating =
                            { model
                                | formState = Validating { manager = Done, address = InFlight }
                                , addressIsValid = Nothing
                            }

                        staleRequest =
                            { addressLineOne = "999 Other St"
                            , addressLineTwo = ""
                            , city = "Atlanta"
                            , state = Just "GA"
                            , zip = "30309"
                            }
                    in
                    updateReady
                        (GoogleAddressValidationResultReceived
                            staleRequest
                            (Ok
                                { addressComplete = Just True
                                , missingComponentTypes = Nothing
                                }
                            )
                        )
                        validating
                        |> Tuple.first
                        |> Expect.all
                            [ .addressIsValid >> Expect.equal Nothing
                            , .formState >> Expect.equal (Validating { manager = Done, address = InFlight })
                            ]
            , test "applies GoogleAddressValidationResultReceived while Validating for matching address" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null
                                |> withOrderPhysicalCard False
                                |> withAddress "123 Main St" "" "Atlanta" (Just "GA") "30309"

                        validating =
                            { model
                                | formState = Validating { manager = Done, address = InFlight }
                                , addressIsValid = Nothing
                            }
                    in
                    updateReady
                        (GoogleAddressValidationResultReceived
                            (addressValidationRequestFromModel validating)
                            (Ok
                                { addressComplete = Just True
                                , missingComponentTypes = Nothing
                                }
                            )
                        )
                        validating
                        |> Tuple.first
                        |> Expect.all
                            [ .addressIsValid >> Expect.equal (Just True)
                            , .formState >> Expect.equal (CreatingRampAccount Nothing)
                            ]
            , test "ignores ManagerValidationResultReceived for a different Apiary id" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null
                                |> withManagerRampId Nothing
                                |> withOrderPhysicalCard False

                        validating =
                            { model
                                | formState = Validating { manager = InFlight, address = Done }
                                , managerApiaryId = Just 3
                                , managerIsValid = Nothing
                            }
                    in
                    updateReady
                        (ManagerValidationResultReceived 2
                            (Ok (ManagerResolved "ramp-a"))
                        )
                        validating
                        |> Tuple.first
                        |> Expect.all
                            [ .managerRampId >> Expect.equal Nothing
                            , .managerApiaryId >> Expect.equal (Just 3)
                            , .managerIsValid >> Expect.equal Nothing
                            , .formState >> Expect.equal (Validating { manager = InFlight, address = Done })
                            ]
            , test "applies ManagerValidationResultReceived while Validating" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null
                                |> withManagerRampId Nothing
                                |> withOrderPhysicalCard False

                        validating =
                            { model
                                | formState = Validating { manager = InFlight, address = Done }
                                , managerApiaryId = Just 2
                                , managerIsValid = Nothing
                            }
                    in
                    updateReady
                        (ManagerValidationResultReceived 2
                            (Ok (ManagerResolved "ramp-manager"))
                        )
                        validating
                        |> Tuple.first
                        |> Expect.all
                            [ .managerRampId >> Expect.equal (Just "ramp-manager")
                            , .managerIsValid >> Expect.equal (Just True)
                            , .formState >> Expect.equal (CreatingRampAccount Nothing)
                            ]
            , test "ignores PlaceChanged when not Editing" <|
                \_ ->
                    let
                        model =
                            modelFrom minimalServerData Json.Encode.null
                                |> withAddress "123 Main St" "" "Atlanta" (Just "GA") "30309"

                        validating =
                            { model
                                | formState = Validating { manager = Done, address = InFlight }
                            }

                        placeSelected =
                            Json.Encode.object
                                [ ( "address_components"
                                  , Json.Encode.list identity
                                        [ Json.Encode.object
                                            [ ( "short_name", Json.Encode.string "999" )
                                            , ( "types", Json.Encode.list Json.Encode.string [ "street_number" ] )
                                            ]
                                        , Json.Encode.object
                                            [ ( "short_name", Json.Encode.string "Other St" )
                                            , ( "types", Json.Encode.list Json.Encode.string [ "route" ] )
                                            ]
                                        , Json.Encode.object
                                            [ ( "short_name", Json.Encode.string "Atlanta" )
                                            , ( "types", Json.Encode.list Json.Encode.string [ "locality" ] )
                                            ]
                                        , Json.Encode.object
                                            [ ( "short_name", Json.Encode.string "GA" )
                                            , ( "types", Json.Encode.list Json.Encode.string [ "administrative_area_level_1" ] )
                                            ]
                                        , Json.Encode.object
                                            [ ( "short_name", Json.Encode.string "30309" )
                                            , ( "types", Json.Encode.list Json.Encode.string [ "postal_code" ] )
                                            ]
                                        ]
                                  )
                                ]
                    in
                    updateReady (PlaceChanged placeSelected) validating
                        |> Tuple.first
                        |> Expect.all
                            [ .addressLineOne >> Expect.equal "123 Main St"
                            , .formState >> Expect.equal (Validating { manager = Done, address = InFlight })
                            ]
            ]
        ]
