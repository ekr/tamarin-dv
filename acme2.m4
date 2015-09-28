/*
    ACME version 2:

    See https://github.com/ietf-wg-acme/acme/pull/6

*/
theory AcmeV2
begin

include(common-setup.m4i)

/* Have the client respond to the challenge. */
rule Client_FulfillChallenge:
   let
        challengeMessage = <cClientName, cToken, cAuthkeyPub>
        responseMessage = <'Response', cClientName, cToken, cAuthkeyPub>
   in

   [ 
     StoredRequest(kCaName, kClientName, kAuthkeyPriv),
     In(<challengeMessage, signature>),
     !Pk(kCaName, kPkCA),
     !Ltk($Client, kLtkClient)
   ] 
   --[ Eq(cClientName, kClientName),
       Eq(cAuthkeyPub, pk(kAuthkeyPriv)),
       Eq(verify(signature, challengeMessage, kPkCA), true),
       AClient_FulfilledChallenge(kCaName, cToken, kClientName, pk(kAuthkeyPriv)) ]->
     [ Out( <                                       
             kClientName,                           
             sign {responseMessage} kAuthkeyPriv,   // The challenge signed by the account key
                                                    // This is what the client supplies in
                                                    // the "responses" message. This is
                                                    // delivered over an insecure channel.

             sign {responseMessage} kLtkClient      // The challenge signed by the long-eerm
                                                    // client key.
                                                    // This emulates a "secure" authorization
                                                    // check.
            >)
     ]

/* Have the CA process the response. */
rule CA_HandleChallengeResponse:
   let
       responseMessage = <'Response', cRequestedName, kToken, cAuthkeyPub>
   in

   [ StoredToken(kToken, cRequestedName, cAuthkeyPub),  // These are marked as 'c' because haven't
                                                        // verified them.
     In (<cRespondedName, authKeySignature, authenticatedSignature>),  // Read the signed challenge.
     !Pk(cRespondedName, kPkClient)                     // Recover the domain key.
   ]
   --[ Eq(cRequestedName, cRespondedName),

       // Check the signature in the client's "response".
       Eq(verify(authKeySignature, responseMessage, cAuthkeyPub), true),

       // Validate the client's fulfillment of the challenge, by
       // sending the signed response via the secure channel.
       Eq(verify(authenticatedSignature, responseMessage, kPkClient), true),
       ACA_VerifiedChallenge('CA', kToken, cRequestedName, cAuthkeyPub)]-> // Record success.
   []

include(common-rules.m4i)
include(security-lemmas.m4i)
end

