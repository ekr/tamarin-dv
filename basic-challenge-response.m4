/*
    Trivial model of challenge/response-based domain validation.

    The basic model here is as follows:

    Client                                      Server (CA)
    
    name  ------------------------------------------------>   [Client_RequestIssuance]
    <------------------------------------------ token, name   [Server_HandleIssuanceRequest]
    sign(token, name) ------------------------------------>   [Client_RespondToChallenge]
                                                              [Server_HandleChallengeResponse]

    The signature isn't really part of the protocol but rather is
    used to enforce the fact that only the legitimate domain-holder
    can enforce the challenge.
 */
theory BasicChallengeResponse
begin

builtins: hashing, symmetric-encryption, asymmetric-encryption, signing
functions: h/1, pk/1

rule Client_RequestIssuance:
   [ !Ltk($A, ~ltkA) ]
   --[ClientRequested($A)]->
   [ StoredRequest($A), RequestIssuance($A) ]

rule Attacker_RequestIssuance:
   [ ]
   -->
   [ RequestIssuance($A) ]

rule Server_HandleIssuanceRequest:
   [ RequestIssuance(name), Fr(~token)]
   --[ IssuedChallenge(~token, name) ]->
   [ StoredToken(~token, name),
     AuthenticMessage(<~token, name>),
     Out(~token)
   ]

rule Client_RespondToChallenge:
   [ !Ltk($A, ltkA),
     StoredRequest(expectedname),
     AuthenticMessage(<challenge, name>) ]
   --[ Eq(expectedname, name),
       ReceivedChallenge(challenge, name) ]->
     [ Out( <
             name,
             sign{<challenge, name>}ltkA
            >)
     ]

rule Server_HandleChallengeResponse:
   [ StoredToken(challenge, name),
     In (<claimed_name, signature>),
     !Pk(name, pkA)
   ]
   --[ Eq(claimed_name, name),
       Eq(verify(signature,
          <challenge, name>, pkA), true),
      ChallengeSucceeded(challenge, name)]->
   []

include(common-rules.m4i)
include(security-lemmas.m4i)
end

