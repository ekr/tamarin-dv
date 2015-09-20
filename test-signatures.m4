theory Signatures
begin

builtins: hashing, symmetric-encryption, asymmetric-encryption, signing
functions: h/1, pk/1, fakekey/2
equations:
     verify(sig, msg, fakekey(msg, sig)) = true

rule Send_Signature:
     [!Ltk($A, ~ltkA),
      Fr(~value) ]
   --[Signed(~value)]->
     [ Out(<
         pk(~ltkA),
         ~value,
         sign{~value}~ltkA
       >) ]

rule Verify_Signature:
     [ In( < pubkey, message, signature > ) ]
     --[
         Eq( verify(signature, message, pubkey), true),
         Verified(message, signature)
       ]->
     []

lemma Exists:
   exists-trace
   "Ex M S #i.
    Verified(M, S) @i"

lemma No_Duplicates:
   "All M1 M2 S #i #j.
     Verified(M1, S) @i &
     Verified(M2, S) @j ==>
     M1 = M2"


include(common-rules.m4i)
     
end
