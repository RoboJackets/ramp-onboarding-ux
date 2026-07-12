module EmailProviderTest exposing (suite)

import Dict
import Expect
import Json.Encode
import Main
    exposing
        ( EmailProvider(..)
        , emailAddressDomain
        , emailProviderByDomain
        , emailProviderDisplayName
        , emailProviderForAddress
        , getSecondLevelDomain
        , showOneTap
        )
import Test exposing (Test, describe, test)
import TestFixtures exposing (minimalServerData, modelFrom, withEmail)


suite : Test
suite =
    describe "email provider"
        [ describe "emailProviderByDomain"
            [ test "contains the known Google and Microsoft domains" <|
                \_ ->
                    Expect.all
                        [ Dict.get "robojackets.org" >> Expect.equal (Just Google)
                        , Dict.get "gatech.edu" >> Expect.equal (Just Microsoft)
                        ]
                        emailProviderByDomain
            ]
        , describe "getSecondLevelDomain"
            [ test "extracts sld.tld from a subdomain" <|
                \_ ->
                    getSecondLevelDomain "mail.robojackets.org"
                        |> Expect.equal (Just "robojackets.org")
            , test "normalizes case and whitespace" <|
                \_ ->
                    getSecondLevelDomain "  Gatech.EDU  "
                        |> Expect.equal (Just "gatech.edu")
            , test "rejects a bare label" <|
                \_ ->
                    getSecondLevelDomain "localhost"
                        |> Expect.equal Nothing
            ]
        , describe "emailAddressDomain"
            [ test "returns the second-level domain for a valid address" <|
                \_ ->
                    emailAddressDomain "ada@robojackets.org"
                        |> Expect.equal (Just "robojackets.org")
            , test "returns Nothing for an invalid address" <|
                \_ ->
                    emailAddressDomain "not-an-email"
                        |> Expect.equal Nothing
            ]
        , describe "emailProviderForAddress"
            [ test "maps robojackets.org to Google" <|
                \_ ->
                    emailProviderForAddress "ada@robojackets.org"
                        |> Expect.equal (Just Google)
            , test "maps gatech.edu to Microsoft" <|
                \_ ->
                    emailProviderForAddress "ada@gatech.edu"
                        |> Expect.equal (Just Microsoft)
            , test "returns Nothing for an unknown domain" <|
                \_ ->
                    emailProviderForAddress "ada@example.com"
                        |> Expect.equal Nothing
            ]
        , describe "emailProviderDisplayName"
            [ test "Google" <|
                \_ ->
                    emailProviderDisplayName Google
                        |> Expect.equal "Google"
            , test "Microsoft" <|
                \_ ->
                    emailProviderDisplayName Microsoft
                        |> Expect.equal "Microsoft"
            ]
        , describe "showOneTap"
            [ test "shows One Tap for unverified Google-hosted email" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withEmail "ada@robojackets.org" False
                        |> showOneTap
                        |> Expect.equal True
            , test "hides One Tap when email is already verified" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withEmail "ada@robojackets.org" True
                        |> showOneTap
                        |> Expect.equal False
            , test "hides One Tap for Microsoft-hosted email" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withEmail "ada@gatech.edu" False
                        |> showOneTap
                        |> Expect.equal False
            , test "hides One Tap for an unknown domain" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withEmail "ada@example.com" False
                        |> showOneTap
                        |> Expect.equal False
            ]
        ]
