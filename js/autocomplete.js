function initializeAutocomplete() {
    "use strict";

    const autocomplete = new google.maps.places.Autocomplete(document.getElementById("address_line_one"), {
        "componentRestrictions": {"country": ["us"]},
        "fields": ["address_components"],
        "types": ["address"],
    })

    autocomplete.addListener("place_changed", function () { app.ports.placeChanged.send(autocomplete.getPlace()) });
};
