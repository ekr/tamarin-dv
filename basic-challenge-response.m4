/*
    Trivial model of challenge/response-based domain validation.

    The basic model here is as follows:

    Client                                      Server (CA)
>    name  ------------------------------------------------>   [Client_RequestIssuance]
    <------------------------------------------ token, name   [Server_HandleIssuanceRequest]
    sign(token, name) ------------------------------------>   [Client_RespondToChallenge]
                                                              [Server_HandleChallengeResponse]

    The signature isn't really part of the protocol but rather is
    used to enforce the fact that only the legitimate domain-holder
    can enforce the challenge.

    The output of all this is an "action" on the server (CA) side
    binding the name ($A) to an authkey (a standin for the account
    key).
*/
theory BasicChallengeResponse
begin

builtins: hashing, symmetric-encryption, asymmetric-encryption, signing
functions: h/1, pk/1

/* Issue a request for a given name ($A) */
rule Client_RequestIssuance:
   [ !Ltk($A, ~ltkA),                   // Generate the key pair we will use to authenticate (as above).
     Fr(~authkeyPriv)
   ]                     // Generate a fresh authkey
   --[ClientRequested($A, pk(~authkeyPriv))]->  // Record that we made the request
   [ StoredRequest($A, pk(~authkeyPriv)),       // Store the (name, state) binding locally
     RequestIssuance($A, pk(~authkeyPriv)) ]    // Output (name, state) so that it can be consumed by the server

/* Allow the attacker to request issuance */
rule Attacker_RequestIssuance:
   [ Fr(~authkey) ]
   -->
   [ RequestIssuance($A, ~authkey) ]

/* Have the server handle the request for issuance */
rule Server_HandleIssuanceRequest:
   [ RequestIssuance(name, authkey),     // Take in a the request for issuance.
     Fr(~token)]                         // Generate a fresh token to use as a challenge
  --[ IssuedChallenge(~token, name, authkey) ]->  // Record that we issued the challenge
    [ StoredToken(~token, name, authkey),// Store the challenge we issued.
     AuthenticMessage(<~token, name, authkey>), // Send out the challenge
     Out(<~token, name>)                        // publish the challenge so it is known
   ]

/* Have the client respond to the challenge. */
rule Client_RespondToChallenge:
   [ !Ltk($A, ltkA),                    
     StoredRequest(expectedname, authkeyPub),
     AuthenticMessage(<challenge, name, authkey2>)  // Read in server request
   ] 
   --[ Eq(expectedname, name),
       Eq(authkeyPub, authkey2),
       ReceivedChallenge(challenge, name, authkeyPub) ]->
     [ Out( <                                       // Emit a "signed" challenge.
             name,
             sign{<challenge, name>}ltkA
            >)
     ]

/* Have the server process the response. */
rule Server_HandleChallengeResponse:
   [ StoredToken(challenge, name, authkey),
     In (<claimed_name, signature>),                // Read the signed challenge.
     !Pk(name, pkA)                                 // Recover the doamain key.
   ]
   --[ Eq(claimed_name, name),
       Eq(verify(signature,
          <challenge, name>, pkA), true),
      ChallengeSucceeded(challenge, name, authkey)]-> // Record success.
   []

include(common-rules.m4i)
include(security-lemmas.m4i)
end

