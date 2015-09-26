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

builtins: hashing, symmetric-encryption, asymmetric-encryption, signing
functions: h/1, pk/1

/* Issue the signing key for the CA */
rule CA_Setup:
   [ !Ltk('CA', ~ltkCA) ]
   -->
   []

/* Issue a request for a given name ($Client) */
rule Client_RequestIssuance:
   [ !Ltk($Client, ~ltkClient),                   // Generate the key pair we will use to authenticate (as above).
     Fr(~authkeyPriv)
   ]                     // Generate a fresh authkey
   --[ClientRequested('CA', $Client, pk(~authkeyPriv))]->  // Record that we made the request
   [ StoredRequest('CA', $Client, pk(~authkeyPriv)),       // Store the (name, state) binding locally
     RequestIssuance($Client, pk(~authkeyPriv)) ]    // Output (name, state) so that it can be consumed by the CA


/* Allow the attacker to request issuance */
rule Attacker_RequestIssuance:
   [ Fr(~authkey) ]
   --[Attacker_RequestIssuance(~authkey)]->
   [ RequestIssuance($Client, ~authkey) ]

/* Have the CA handle the request for issuance */
rule CA_HandleIssuanceRequest:
   let
        challengeMessage = <clientName, ~token, authkey>
   in
     
   [ RequestIssuance(clientName, authkey),     // Take in a the request for issuance.
     Fr(~token),                         // Generate a fresh token to use as a challenge
     !Ltk('CA', ltkCA)]
  --[ IssuedChallenge(~token, clientName, authkey) ]->  // Record that we issued the challenge
    [ StoredToken(~token, clientName, authkey),// Store the challenge we issued.
     Out(<
         challengeMessage,
         sign { challengeMessage } ltkCA
         >
     )
   ]

/* Have the client respond to the challenge. */
rule Client_RespondToChallenge:
   let
        challengeMessage = <challengeName, token, challengeAuthkey>
   in

   [ 
     StoredRequest(caName, clientName, authkeyPub),
     In(<challengeMessage, signature>),
     !Pk(caName, pkCA),
     !Ltk($Client, ltkClient)
   ] 
   --[ Eq(challengeName, clientName),
       Eq(authkeyPub, challengeAuthkey),
       Eq(verify(signature, challengeMessage, pkCA), true),
       ReceivedChallenge(caName, token, clientName, authkeyPub) ]->
     [ Out( <                                       // Emit a "signed" challenge.
             clientName,
             sign{<token, clientName>}ltkClient
            >)
     ]

/* Have the CA process the response. */
rule CA_HandleChallengeResponse:
   [ StoredToken(token, challengedName, authkeyPub),
     In (<requestedName, signature>),                // Read the signed challenge.
     !Pk(challengedName, pkClient)                                 // Recover the domain key.
   ]
   --[ Eq(requestedName, challengedName),
       Eq(verify(signature,
          <token, requestedName>, pkClient), true),
      ChallengeSucceeded('CA', token, requestedName, authkeyPub)]-> // Record success.
   []

include(common-rules.m4i)
include(security-lemmas.m4i)
end

