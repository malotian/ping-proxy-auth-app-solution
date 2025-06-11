/*
 * Copyright 2021-2025 Ping Identity Corporation. All Rights Reserved
 *
 * This code is to be used exclusively in connection with Ping Identity
 * Corporation software or services. Ping Identity Corporation only offers
 * such software or services to legal entities who have entered into a
 * binding license agreement with Ping Identity Corporation.
 */

/*
 * This script returns the social identity profile information for the authenticating user
 * in a standard form expected by the Social Provider Handler Node.
 *
 * Defined variables:
 * rawProfile - The social identity provider profile information for the authenticating user.
 *              JsonValue (1).
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
 *          This script's last statement should result in a JsonValue (1) with the following keys:
 *          {
 *              {"displayName": "corresponding-social-identity-provider-value"},
 *              {"email": "corresponding-social-identity-provider-value"},
 *              {"familyName": "corresponding-social-identity-provider-value"},
 *              {"givenName": "corresponding-social-identity-provider-value"},
 *              {"id": "corresponding-social-identity-provider-value"},
 *              {"locale": "corresponding-social-identity-provider-value"},
 *              {"photoUrl": "corresponding-social-identity-provider-value"},
 *              {"username": "corresponding-social-identity-provider-value"}
 *          }
 *
 *          The consumer of this data defines which keys are required and which are optional.
 *          For example, the script associated with the Social Provider Handler Node and,
 *          ultimately, the managed object created/updated with this data
 *          will expect certain keys to be populated.
 *          In some common default configurations, the following keys are required to be not empty:
 *          username, givenName, familyName, email.
 *
 *          From RFC4517: A value of the Directory String syntax is a string of one or more
 *          arbitrary characters from the Universal Character Set (UCS).
 *          A zero-length character string is not permitted.
 *
 * (1) JsonValue - https://backstage.forgerock.com/docs/am/7/apidocs/org/forgerock/json/JsonValue.html.
 * (2) TreeMap - https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/util/TreeMap.html.
 * (3) LinkedHashMap - https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/util/LinkedHashMap.html.
 */

(function () {
    var frJava = JavaImporter(
        org.forgerock.json.JsonValue
    );

    var normalizedProfileData = frJava.JsonValue.json(frJava.JsonValue.object());

    var email = null;
    var firstName = null;
    var lastName = null;
    var username = null;
    var name;

    if(rawProfile.isDefined('email') && rawProfile.get('email').isNotNull()) { // User can elect to not share their email
        email = rawProfile.get('email').asString();
        username = email;
    } else {
        throw new Error('Email is required');
    }
    if (rawProfile.isDefined('name') && rawProfile.get('name').isNotNull()) {
        if (rawProfile.name.isDefined('firstName') && rawProfile.get('firstName').isNotNull()) {
            firstName = rawProfile.get('name').get('firstName').asString()
        }
        if (rawProfile.name.isDefined('lastName') && rawProfile.get('lastName').isNotNull()) {
            lastName = rawProfile.get('name').get('lastName').asString()
        }
    }

    var hasFirstName = firstName && firstName.trim().length > 0
    var hasLastName = lastName && lastName.trim().length > 0
    name = (hasFirstName ? firstName : '') + (hasLastName ? (hasFirstName ? ' ' : '') + lastName : '')
    name =  name ? name : ' '

    normalizedProfileData.put('id', rawProfile.sub);
    normalizedProfileData.put('displayName', name);
    normalizedProfileData.put('email', email);
    if (firstName !== null) {
        normalizedProfileData.put('givenName', firstName);
    }
    if (lastName !== null) {
        normalizedProfileData.put('familyName', lastName);
    }
    normalizedProfileData.put('username', username);

    return normalizedProfileData;
}());
