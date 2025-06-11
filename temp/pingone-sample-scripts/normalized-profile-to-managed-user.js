/*
 * Copyright 2021-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

/*
 * This script translates the normalized social identity profile information for the authenticating user
 * into the managed user object key/value pairs.
 *
 * Defined variables:
 * normalizedProfile - The social identity provider profile information for the authenticating user
 *                     in a standard format expected by this node.
 *                     JsonValue (1).
 * logger - The debug logger instance:
 *          https://backstage.forgerock.com/docs/am/7/scripting-guide/scripting-api-global-logger.html#scripting-api-global-logger.
 * realm - String (primitive).
 *         The name of the realm the user is authenticating to.
 * requestHeaders - TreeMap (2).
 *                  The object that provides methods for accessing headers in the login request:
 *                  https://backstage.forgerock.com/docs/am/7/authentication-guide/scripting-api-node.html#scripting-api-node-requestHeaders.
 * requestParameters - TreeMap (2).
 *                     The object that contains the authentication request parameters.
 * selectedIdp - String (primitive).
 *               The social identity provider name. For example: google.
 * sharedState - LinkedHashMap (3).
 *               The object that holds the state of the authentication tree and allows data exchange between the stateless nodes:
 *               https://backstage.forgerock.com/docs/am/7/auth-nodes/core-action.html#accessing-tree-state.
 * transientState - LinkedHashMap (3).
 *                  The object for storing sensitive information that must not leave the server unencrypted,
 *                  and that may not need to persist between authentication requests during the authentication session:
 *                  https://backstage.forgerock.com/docs/am/7/auth-nodes/core-action.html#accessing-tree-state.
 *
 * Return - a JsonValue (1).
 *          The result of the last statement in the script is returned to the server.
 *          Currently, the Immediately Invoked Function Expression (also known as Self-Executing Anonymous Function)
 *          is the last (and only) statement in this script, and its return value will become the script result.
 *          Do not use "return variable" statement outside of a function definition.
 *
 * (1) JsonValue - https://backstage.forgerock.com/docs/am/7/apidocs/org/forgerock/json/JsonValue.html.
 * (2) TreeMap - https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/util/TreeMap.html.
 * (3) LinkedHashMap - https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/util/LinkedHashMap.html.
 */

(function () {
    var frJava = JavaImporter(
        org.forgerock.json.JsonValue
    );

    var managedUserData = frJava.JsonValue.json(frJava.JsonValue.object());

    managedUserData.put('givenName', normalizedProfile.get('givenName'));
    managedUserData.put('sn', normalizedProfile.get('familyName'));
    managedUserData.put('mail', normalizedProfile.get('email'));
    managedUserData.put('userName', normalizedProfile.get('username'));

    if (normalizedProfile.get('postalAddress').isNotNull()) {
        managedUserData.put('postalAddress', normalizedProfile.get('postalAddress'));
    }
    if (normalizedProfile.get('addressLocality').isNotNull()) {
        managedUserData.put('city', normalizedProfile.get('addressLocality'));
    }
    if (normalizedProfile.get('addressRegion').isNotNull()) {
        managedUserData.put('stateProvince', normalizedProfile.get('addressRegion'));
    }
    if (normalizedProfile.get('postalCode').isNotNull()) {
        managedUserData.put('postalCode', normalizedProfile.get('postalCode'));
    }
    if (normalizedProfile.get('country').isNotNull()) {
        managedUserData.put('country', normalizedProfile.get('country'));
    }
    if (normalizedProfile.get('phone').isNotNull()) {
        managedUserData.put('telephoneNumber', normalizedProfile.get('phone'));
    }

    // if the givenName and familyName is null or empty
    // then add a boolean flag to the shared state to indicate names are not present
    // this could be used elsewhere
    // for eg. this could be used in a scripted decision node to by-pass patching
    // the user object with blank values when givenName  and familyName is not present
     var noGivenName = normalizedProfile.get('givenName').isNull()
                                      || normalizedProfile.get('givenName').asString().trim().length === 0
     var noFamilyName = normalizedProfile.get('familyName').isNull()
                                       || normalizedProfile.get('familyName').asString().trim().length === 0
     sharedState.put('nameEmptyOrNull', noGivenName && noFamilyName)

    return managedUserData;
}());
