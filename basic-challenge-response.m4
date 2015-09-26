/*
    Trivial model of challenge/response-based domain validation.

    The basic model here is as follows:

    Client                                      CA (CA)
>    name  ------------------------------------------------>   [Client_RequestIssuance]
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

/* Issue a request for a given name ($A) */
rule Client_RequestIssuance:
   [ !Ltk($A, ~ltkA),                   // Generate the key pair we will use to authenticate (as above).
     Fr(~authkeyPriv)
   ]                     // Generate a fresh authkey
   --[ClientRequested('CA', $A, pk(~authkeyPriv))]->  // Record that we made the request
   [ StoredRequest('CA', $A, pk(~authkeyPriv)),       // Store the (name, state) binding locally
     RequestIssuance($A, pk(~authkeyPriv)) ]    // Output (name, state) so that it can be consumed by the CA

/* Allow the attacker to request issuance */
rule Attacker_RequestIssuance:
   [ Fr(~authkey) ]
   --[Attacker_RequestIssuance(~authkey)]->
   [ RequestIssuance($A, ~authkey) ]

/* Have the CA handle the request for issuance */
rule CA_HandleIssuanceRequest:
   let
        challengemessage = <name, ~token, authkey>
   in
     
   [ RequestIssuance(name, authkey),     // Take in a the request for issuance.
     Fr(~token),                         // Generate a fresh token to use as a challenge
     !Ltk('CA', ltkCA)]
  --[ IssuedChallenge(~token, name, authkey) ]->  // Record that we issued the challenge
    [ StoredToken(~token, name, authkey),// Store the challenge we issued.
     Out(<
         challengemessage,
         sign { challengemessage } ltkCA
         >
     )
   ]

/* Have the client respond to the challenge. */
rule Client_RespondToChallenge:
   let
        challengemessage = <name, token, authkey>
   in

   [ 
     StoredRequest(ca, expectedname, authkeyPub),
     In(<challengemessage, signature>),
     !Pk(ca, pkCA),
     !Ltk($A, ltkA)
   ] 
   --[ Eq(expectedname, name),
       Eq(authkeyPub, authkey),
       Eq(verify(signature, challengemessage, pkCA), true),
       ReceivedChallenge(ca, token, name, authkeyPub) ]->
     [ Out( <                                       // Emit a "signed" challenge.
             name,
             sign{<token, name>}ltkA
            >)
     ]

/* Have the CA process the response. */
rule CA_HandleChallengeResponse:
   [ StoredToken(challenge, name, authkey),
     In (<claimed_name, signature>),                // Read the signed challenge.
     !Pk(name, pkA)                                 // Recover the domain key.
   ]
   --[ Eq(claimed_name, name),
       Eq(verify(signature,
          <challenge, name>, pkA), true),
      ChallengeSucceeded('CA', challenge, name, authkey)]-> // Record success.
   []

include(common-rules.m4i)
include(security-lemmas.m4i)
end

