module TestFixtures exposing
    ( minimalServerData
    , modelFrom
    , withAddress
    , withEmail
    , withManagerRampId
    , withOrderPhysicalCard
    )

import Dict
import Json.Encode
import Main exposing (Model, ServerData, buildInitialModel)


minimalServerData : ServerData
minimalServerData =
    { firstName = "Ada"
    , lastName = "Lovelace"
    , emailAddress = "ada@robojackets.org"
    , emailVerified = True
    , managerApiaryId = Just 2
    , apiaryManagerOptions = Dict.fromList [ ( 2, "Manager Two" ), ( 3, "Manager Three" ) ]
    , managerRampId = Just "ramp-manager"
    , rampManagerOptions =
        Dict.fromList
            [ ( "ramp-manager"
              , { label = "Manager Two"
                , enabled = True
                , departmentId = "dept-students"
                }
              )
            ]
    , selfApiaryId = 1
    , addressLineOne = ""
    , addressLineTwo = ""
    , city = ""
    , state = Nothing
    , zip = ""
    , googleMapsApiKey = "maps-key"
    , googleClientId = "client-id"
    , googleOneTapLoginUri = "https://example.test/onetap"
    , showAdvancedOptions = False
    , departmentOptions =
        Dict.fromList
            [ ( "dept-students", { label = "Students", enabled = True } )
            , ( "dept-staff", { label = "Staff", enabled = True } )
            , ( "dept-disabled", { label = "Disabled", enabled = False } )
            ]
    , departmentId = "dept-students"
    , locationOptions =
        Dict.fromList
            [ ( "loc-campus", { label = "Campus", enabled = True } )
            , ( "loc-disabled", { label = "Disabled", enabled = False } )
            ]
    , locationId = "loc-campus"
    , roleOptions =
        Dict.fromList
            [ ( "BUSINESS_USER", { label = "Employee", enabled = True } )
            , ( "role-disabled", { label = "Disabled", enabled = False } )
            ]
    , roleId = "BUSINESS_USER"
    , studentDefaultDepartmentId = "dept-students"
    , nonStudentDefaultDepartmentId = "dept-staff"
    , studentDefaultLocationId = "loc-campus"
    , nonStudentDefaultLocationId = "loc-campus"
    , rampSignInUri = "https://example.test/ramp"
    , businessLegalName = "RoboJackets"
    , slackSupportChannelDeepLink = "slack://channel?team=T123&id=C123"
    , slackSupportChannelName = "#support"
    }


modelFrom : ServerData -> Json.Encode.Value -> Model
modelFrom serverData localData =
    buildInitialModel serverData localData


withEmail : String -> Bool -> Model -> Model
withEmail emailAddress emailVerified model =
    { model | emailAddress = emailAddress, emailVerified = emailVerified }


withAddress : String -> String -> String -> Maybe String -> String -> Model -> Model
withAddress addressLineOne addressLineTwo city state zip model =
    { model
        | addressLineOne = addressLineOne
        , addressLineTwo = addressLineTwo
        , city = city
        , state = state
        , zip = zip
    }


withOrderPhysicalCard : Bool -> Model -> Model
withOrderPhysicalCard orderPhysicalCard model =
    { model | orderPhysicalCard = orderPhysicalCard }


withManagerRampId : Maybe String -> Model -> Model
withManagerRampId managerRampId model =
    { model | managerRampId = managerRampId }
