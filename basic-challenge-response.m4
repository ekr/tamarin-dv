/*
    Trivial model of challenge/response-based domain validation.

    The basic model here is as follows:

    Client                                      CA (CA)
    name  ------------------------------------------------>   [Client_RequestIssuance]
    <------------------------------------------ token, name   [CA_HandleIssuanceRequest]
    sign(token, name) ------------------------------------>   [Client_RespondToChallenge]
                                                              [CA_HandleChallengeResponse]

    The signature isn't really part of the protocol but rather is
    used to enforce the fact that only the legitimate domain-holder
    can enforce the challenge.

    The output of all this is an "action" on the CA (CA) side
    binding the name ($A) to an authkey (a standin for the account
    key).
*/
theory BasicChallengeResponse
begin

include(common-setup.m4i)

/* Have the client respond to the challenge. */
rule Client_FulfillChallenge:
   let
        challengeMessage = <cClientName, cToken, cAuthkeyPub>
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
     [ Out( <                                       // Emit a "signed" challenge.
             kClientName,
             sign{<cToken, kClientName>}kLtkClient
            >)
     ]

/* Have the CA process the response. */
rule CA_HandleChallengeResponse:
   [ StoredToken(kToken, cRequestedName, cAuthkeyPub),  // These are marked as 'c' because haven't
                                                      // verified them.
     In (<cRespondedName, signature>),                // Read the signed challenge.
     !Pk(cRespondedName, kPkClient)                   // Recover the domain key.
   ]
   --[ Eq(cRequestedName, cRespondedName),
       Eq(verify(signature,
          <kToken, cRequestedName>, kPkClient), true),
      ACA_VerifiedChallenge('CA', kToken, cRequestedName, cAuthkeyPub)]-> // Record success.
   []

include(common-rules.m4i)
include(security-lemmas.m4i)
end

