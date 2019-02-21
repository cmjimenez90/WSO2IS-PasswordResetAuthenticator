# WSO2 - Password Reset Authenticator

## Purpose

A custom authenticator to be used to redirect an **ALREADY** authenticated user in WSO2 to the password management page by using the advanced authentication configuration for the Service Provider. A 3rd-party solution is currently used for our password recovery system (Tools4Ever). This authenticator works as a secondary step in the authentication flow. If the user is authenticated then check if they have an attribute that denotes they need to reset their password. If the attribute (claim) exist then redirect the user otherwise process as normal by completing the authentication flow.

### Directions

This is an OSGI Bundle that can be added to WSO2 IS as a plug-in authenticator.

1. Copy the edu.rcgc.custom.authenticator.local-#.#.#.jar to your WSO2 server's plug in directory. 
GENERAL PATH: *WSO2 FOLDER\repository\components\dropins*
2. Start the WSO2 Server.
3. Add a custom claim to record the necessary attribute.
At this time the claim attribute is hard coded to the following claim url: http://wso2.org/claims/extensionAttribute8
4. Change the Outbound and Local Authentication Configuration on the desired Service Provider as follows:
    1. Select Advanced Authentication
    2. Add step 1 as a Basic Authenticator
    3. Add step 2 as a PasswordResetRedirect

#### Custom Properties

The redirect link and required claim url can be changed by adding properties to the following property file:

#### LOCATION *WS02 Folder\repository\conf\identity\identity-mgt.properties*

**PROPERTY NAME:** _EDU.RCGC.PASSWORD.RESET.REDIRECT.AUTHENTICATOR.REDIRECT.URL=_
**PROPERTY NAME:** _EDU.RCGC.PASSWORD.RESET.REDIRECT.AUTHENTICATOR.CLAIM.URL=_