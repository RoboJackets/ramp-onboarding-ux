module DeliveryDateTest exposing (suite)

import Expect
import Main exposing (addDays, estimatePhysicalCardDeliveryDate, estimatedShippingDays, millisPerDay)
import Test exposing (Test, describe, test)
import Time exposing (Weekday(..), millisToPosix, posixToMillis, toWeekday)


suite : Test
suite =
    describe "physical card delivery date"
        [ test "estimatedShippingDays is nine and a half" <|
            \_ ->
                estimatedShippingDays
                    |> Expect.within (Expect.Absolute 0.0001) 9.5
        , test "millisPerDay is one day in milliseconds" <|
            \_ ->
                millisPerDay
                    |> Expect.within (Expect.Absolute 0.0001) (1000 * 60 * 60 * 24)
        , test "addDays advances by whole calendar days when days is integral" <|
            \_ ->
                let
                    start =
                        millisToPosix 0
                in
                addDays 2 start
                    |> posixToMillis
                    |> Expect.equal (2 * round millisPerDay)
        , describe "estimatePhysicalCardDeliveryDate"
            [ test "leaves a weekday estimate unchanged" <|
                \_ ->
                    -- Monday 1970-01-05 + 9.5 days => Wednesday
                    let
                        monday =
                            millisToPosix (4 * round millisPerDay)

                        estimate =
                            estimatePhysicalCardDeliveryDate Time.utc monday
                    in
                    toWeekday Time.utc estimate
                        |> Expect.equal Wed
            , test "leaves a Saturday estimate unchanged" <|
                \_ ->
                    -- Thursday 1970-01-01 + 9.5 days => Saturday
                    let
                        thursday =
                            millisToPosix 0

                        estimate =
                            estimatePhysicalCardDeliveryDate Time.utc thursday
                    in
                    toWeekday Time.utc estimate
                        |> Expect.equal Sat
            , test "pushes a Sunday estimate to Monday" <|
                \_ ->
                    -- Friday 1970-01-02 + 9.5 days => Sunday, then +1 => Monday
                    let
                        friday =
                            millisToPosix (round millisPerDay)

                        estimate =
                            estimatePhysicalCardDeliveryDate Time.utc friday
                    in
                    toWeekday Time.utc estimate
                        |> Expect.equal Mon
            ]
        ]
