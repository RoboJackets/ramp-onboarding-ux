module AddressTest exposing (suite)

import Expect
import Json.Encode
import Main
    exposing
        ( CampusAddress(..)
        , ValidationResult(..)
        , classifyCampusAddress
        , matchCampusAddressByStreetPrefix
        , validateAddressLineTwo
        )
import Test exposing (Test, describe, test)
import TestFixtures exposing (minimalServerData, modelFrom, withAddress)


suite : Test
suite =
    describe "address"
        [ describe "matchCampusAddressByStreetPrefix"
            [ test "Student Center on 351 Ferst" <|
                \_ ->
                    matchCampusAddressByStreetPrefix "351 ferst drive"
                        |> Expect.equal StudentCenter
            , test "Graduate Living Center on 301 10th" <|
                \_ ->
                    matchCampusAddressByStreetPrefix "301 10th street nw"
                        |> Expect.equal GraduateLivingCenter
            , test "Graduate Living Center on 301 Ten" <|
                \_ ->
                    matchCampusAddressByStreetPrefix "301 tenth street nw"
                        |> Expect.equal GraduateLivingCenter
            , test "MRDC on 801 Ferst" <|
                \_ ->
                    matchCampusAddressByStreetPrefix "801 ferst drive"
                        |> Expect.equal ManufacturingRelatedDisciplinesComplex
            , test "unknown street is not campus" <|
                \_ ->
                    matchCampusAddressByStreetPrefix "123 main street"
                        |> Expect.equal NotCampusAddress
            ]
        , describe "classifyCampusAddress"
            [ test "classifies Student Center when city/state/zip and street match" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withAddress "351 Ferst Drive" "" "Atlanta" (Just "GA") "30332"
                        |> classifyCampusAddress
                        |> Expect.equal StudentCenter
            , test "requires Atlanta / GA / 303 zip prefix" <|
                \_ ->
                    modelFrom minimalServerData Json.Encode.null
                        |> withAddress "351 Ferst Drive" "" "Atlanta" (Just "GA") "30000"
                        |> classifyCampusAddress
                        |> Expect.equal NotCampusAddress
            ]
        , describe "validateAddressLineTwo"
            [ test "allows empty when not required and not campus" <|
                \_ ->
                    validateAddressLineTwo "" False NotCampusAddress
                        |> Expect.equal Valid
            , test "requires a value when isRequired" <|
                \_ ->
                    validateAddressLineTwo "" True NotCampusAddress
                        |> Expect.equal (Invalid "This address requires an apartment or unit number")
            , test "requires a mailbox for Student Center" <|
                \_ ->
                    validateAddressLineTwo "" False StudentCenter
                        |> Expect.equal (Invalid "This address requires a mailbox number")
            , test "accepts a Student Center mailbox" <|
                \_ ->
                    validateAddressLineTwo "123456 Georgia Tech Station" False StudentCenter
                        |> Expect.equal Valid
            , test "rejects an invalid Student Center mailbox" <|
                \_ ->
                    validateAddressLineTwo "box 1" False StudentCenter
                        |> Expect.equal (Invalid "This doesn't appear to be a valid mailbox number")
            , test "accepts a Graduate Living Center apartment" <|
                \_ ->
                    validateAddressLineTwo "Apt 610A" False GraduateLivingCenter
                        |> Expect.equal Valid
            , test "rejects an invalid Graduate Living Center apartment" <|
                \_ ->
                    validateAddressLineTwo "Apt 999Z" False GraduateLivingCenter
                        |> Expect.equal (Invalid "This doesn't appear to be a valid apartment number")
            , test "accepts MRDC Room 1312" <|
                \_ ->
                    validateAddressLineTwo "Room 1312" False ManufacturingRelatedDisciplinesComplex
                        |> Expect.equal Valid
            , test "rejects other MRDC rooms" <|
                \_ ->
                    validateAddressLineTwo "Room 1000" False ManufacturingRelatedDisciplinesComplex
                        |> Expect.equal (Invalid "For delivery to the MRDC loading dock, use Room 1312")
            , test "rejects line two longer than 100 characters" <|
                \_ ->
                    validateAddressLineTwo (String.repeat 101 "a") False NotCampusAddress
                        |> Expect.equal (Invalid "Your second address line may be a maximum of 100 characters")
            ]
        ]
