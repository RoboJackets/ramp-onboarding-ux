module HelpersTest exposing (suite)

import Dict
import Expect
import Json.Decode exposing (bool, int)
import Json.Encode
import Main
    exposing
        ( AddressComponent
        , PlaceChange(..)
        , ValidationResult(..)
        , addressComponentTypeMatches
        , blankString
        , decodePlaceChanged
        , feedbackText
        , getAddressComponent
        , isEnabledOption
        , isEnterKey
        , isValid
        , localOr
        , nonBlankString
        , trimmedLocalOr
        , validatedId
        )
import Test exposing (Test, describe, test)


suite : Test
suite =
    describe "helpers"
        [ describe "blankString / nonBlankString"
            [ test "blankString treats whitespace as blank" <|
                \_ ->
                    blankString "   "
                        |> Expect.equal True
            , test "nonBlankString is the inverse" <|
                \_ ->
                    nonBlankString "ada"
                        |> Expect.equal True
            ]
        , describe "isEnterKey"
            [ test "Enter" <|
                \_ ->
                    isEnterKey "Enter"
                        |> Expect.equal True
            , test "other keys" <|
                \_ ->
                    isEnterKey "a"
                        |> Expect.equal False
            ]
        , describe "isValid / feedbackText"
            [ test "Valid is valid with empty feedback" <|
                \_ ->
                    Expect.all
                        [ isValid >> Expect.equal True
                        , feedbackText >> Expect.equal ""
                        ]
                        Valid
            , test "Invalid is invalid with its message" <|
                \_ ->
                    Expect.all
                        [ isValid >> Expect.equal False
                        , feedbackText >> Expect.equal "nope"
                        ]
                        (Invalid "nope")
            ]
        , describe "getAddressComponent / addressComponentTypeMatches"
            [ test "finds a component by type" <|
                \_ ->
                    let
                        components : List AddressComponent
                        components =
                            [ { value = "Atlanta", types = [ "locality" ] }
                            , { value = "GA", types = [ "administrative_area_level_1" ] }
                            ]
                    in
                    getAddressComponent components "locality"
                        |> Expect.equal "Atlanta"
            , test "addressComponentTypeMatches" <|
                \_ ->
                    addressComponentTypeMatches "locality" { value = "Atlanta", types = [ "locality", "political" ] }
                        |> Expect.equal True
            ]
        , describe "decodePlaceChanged"
            [ test "name-only place (Enter without selecting) is incomplete" <|
                \_ ->
                    Json.Encode.object [ ( "name", Json.Encode.string "123 Main St" ) ]
                        |> decodePlaceChanged
                        |> Expect.equal (Ok PlaceIncomplete)
            , test "empty address_components is incomplete" <|
                \_ ->
                    Json.Encode.object [ ( "address_components", Json.Encode.list identity [] ) ]
                        |> decodePlaceChanged
                        |> Expect.equal (Ok PlaceIncomplete)
            , test "valid address_components are selected" <|
                \_ ->
                    Json.Encode.object
                        [ ( "address_components"
                          , Json.Encode.list identity
                                [ Json.Encode.object
                                    [ ( "short_name", Json.Encode.string "123" )
                                    , ( "types", Json.Encode.list Json.Encode.string [ "street_number" ] )
                                    ]
                                , Json.Encode.object
                                    [ ( "short_name", Json.Encode.string "Main St" )
                                    , ( "types", Json.Encode.list Json.Encode.string [ "route" ] )
                                    ]
                                ]
                          )
                        ]
                        |> decodePlaceChanged
                        |> Expect.equal
                            (Ok
                                (PlaceSelected
                                    [ { value = "123", types = [ "street_number" ] }
                                    , { value = "Main St", types = [ "route" ] }
                                    ]
                                )
                            )
            , test "malformed address_components is an error" <|
                \_ ->
                    Json.Encode.object
                        [ ( "address_components"
                          , Json.Encode.list identity
                                [ Json.Encode.object
                                    [ ( "short_name", Json.Encode.int 123 )
                                    , ( "types", Json.Encode.list Json.Encode.string [ "street_number" ] )
                                    ]
                                ]
                          )
                        ]
                        |> decodePlaceChanged
                        |> Expect.err
            ]
        , describe "localOr / trimmedLocalOr / validatedId / isEnabledOption"
            [ test "localOr returns the decoded local value" <|
                \_ ->
                    localOr "flag" bool False (Json.Encode.object [ ( "flag", Json.Encode.bool True ) ])
                        |> Expect.equal True
            , test "localOr returns the fallback when missing" <|
                \_ ->
                    localOr "flag" bool False Json.Encode.null
                        |> Expect.equal False
            , test "trimmedLocalOr trims the local string" <|
                \_ ->
                    trimmedLocalOr "name" "fallback" (Json.Encode.object [ ( "name", Json.Encode.string "  Ada  " ) ])
                        |> Expect.equal "Ada"
            , test "validatedId prefers a valid local value" <|
                \_ ->
                    validatedId "id"
                        int
                        (\n -> n > 0)
                        (Json.Encode.object [ ( "id", Json.Encode.int 7 ) ])
                        (Just 3)
                        |> Expect.equal (Just 7)
            , test "validatedId falls back to a valid server value" <|
                \_ ->
                    validatedId "id"
                        int
                        (\n -> n > 0)
                        Json.Encode.null
                        (Just 3)
                        |> Expect.equal (Just 3)
            , test "validatedId skips invalid candidates" <|
                \_ ->
                    validatedId "id"
                        int
                        (\n -> n > 0)
                        (Json.Encode.object [ ( "id", Json.Encode.int -1 ) ])
                        (Just -2)
                        |> Expect.equal Nothing
            , test "isEnabledOption" <|
                \_ ->
                    Expect.all
                        [ \_ ->
                            isEnabledOption (Dict.fromList [ ( "a", { enabled = True } ) ]) "a"
                                |> Expect.equal True
                        , \_ ->
                            isEnabledOption (Dict.fromList [ ( "a", { enabled = False } ) ]) "a"
                                |> Expect.equal False
                        , \_ ->
                            isEnabledOption Dict.empty "missing"
                                |> Expect.equal False
                        ]
                        ()
            ]
        ]
