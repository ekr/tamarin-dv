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

/* Conventions:

   kFoo means that Foo is something we actually know
   cFoo means that Foo is something that is claimed. 
*/

/* Issue the signing key for the CA */
rule CA_Setup:
   [ !Ltk('CA', ~vLtkCA) ]
   -->
   []

/* Issue a request for a given name ($Client) */
rule Client_RequestIssuance:
   [ !Ltk($Client, kvLtkClient),                   // Generate the key pair we will use to authenticate (as above).
     Fr(~kAuthkeyPriv)
   ]                     // Generate a fresh authkey
   --[ClientRequested('CA', $Client, pk(~kAuthkeyPriv))]->  // Record that we made the request
   [ StoredRequest('CA', $Client, pk(~kAuthkeyPriv)),       // Store the (name, state) binding locally
     RequestIssuance($Client, pk(~kAuthkeyPriv)) ]    // Output (name, state) so that it can be consumed by the CA


/* Allow the attacker to request issuance */
rule Attacker_RequestIssuance:
   [ Fr(~kAuthkeyPriv) ]
   --[Attacker_RequestIssuance(pk(~kAuthkeyPriv))]->
   [ RequestIssuance($Client, pk(~kAuthkeyPriv)) ]


/* Have the CA handle the request for issuance */
rule CA_HandleIssuanceRequest:
   let
        challengeMessage = <cClientName, ~kToken, cAuthkeyPub>
   in
     
   [ RequestIssuance(cClientName, cAuthkeyPub),     // Take in a the request for issuance.
     Fr(~kToken),                                 // Generate a fresh token to use as a challenge
     !Ltk('CA', kLtkCA)]
  --[ IssuedChallenge(~kToken, cClientName, cAuthkeyPub) ]->  // Record that we issued the challenge
    [ StoredToken(~kToken, cClientName, cAuthkeyPub),// Store the challenge we issued.
     Out(<
         challengeMessage,
         sign { challengeMessage } kLtkCA
         >
     )
   ]

/* Have the client respond to the challenge. */
rule Client_RespondToChallenge:
   let
        challengeMessage = <cClientName, cToken, cAuthkeyPub>
   in

   [ 
     StoredRequest(kCaName, kClientName, kAuthkeyPub),
     In(<challengeMessage, signature>),
     !Pk(kCaName, kPkCA),
     !Ltk($Client, kLtkClient)
   ] 
   --[ Eq(cClientName, kClientName),
       Eq(cAuthkeyPub, kAuthkeyPub),
       Eq(verify(signature, challengeMessage, kPkCA), true),
       ReceivedChallenge(kCaName, cToken, kClientName, kAuthkeyPub) ]->
     [ Out( <                                       // Emit a "signed" challenge.
             kClientName,
             sign{<cToken, kClientName>}kLtkClient
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

