# Tamarin DV Certificate Model

This repo contains Tamarin (https://github.com/tamarin-prover/tamarin-prover)
models for a variety of Domain Validated (DV) certificate authorization
protocols. 


# DISCLAIMER

These are my first significant Tamarin models, so they are still pretty
clunky and I don't make any promises that they are even right, let alone
that they capture all the relevant security properties.


# Overview

The basic setup common to all the protocols is as follows. The Client
is trying to get a certificate for a given name (ClientName). In
order to do so, he contacts the CA and provides:

* The name he wants (ClientName)
* His public authorization key (AuthKeyPub)

The CA responds with a challenge that consists of a randomly generated
token. The client then proves that he actually owns the name by
"displaying" the token on his site somehow. 


## Challenge Verification

In a real DV protocol, the client proves control of the domain by
displaying the token on some resource he controls, such as the
/.well-known directory of his Web site. The security is then provided
by the routing infrastructure. In this model, we emulate this by
having each client generate a key pair (LtkClient), and then storing
(ClientName, LtkClientPub) in a public directory. This directory is
trusted. When the client fulfills the challenge, it signs the respons
with KtkClientPriv, thus preventing an attacker from forging the
response.


## Client/CA Communication

In real ACME, the client and server communicate over HTTPS. I probably
should have done this, but as an interim measure, I adopted some stopgaps:

* The client requests issuance by generating a RequestIssuance fact,
  which contains the client name and the public key. This fact can't
  be tampered with, but there's a rule that lets the attacker generate
  such a fact himself.

* The server's challenge to the client is signed by the server's
  long-term key. This provides integrity for the server's challenge,
  but not confidentiality.

Taken together, these provide an approximation of a secure channel. In
future, I'll probably improve this by having the client send a traffic
key to the server.


# File Structure

The repo contains a set of files which are generally common to all the
protocols:

* common-setup.m4i: the common code to set up the keys, have the
  client/attacker make the initial request, and the server present
  the challenge.

* common-rules.m4i: some basic security primitives and rules such
  as "only one long-term key per actor"

* security-lemmas.m4i: the security properties we would like to
  prove about the system.


The basic protocol theories are written in m4 and use macros to pull
in these common dependencies. The Makefile does this automatically.
There is also a Foo.proof target which actually runs the proofs as
well.


# Protocols/Theories

This directory currently contains two theories:

* basic-challenge-response: a "typical" challenge/response protocol
  where the CA provides a random token and the client just echoes
  it. [Status: proofs succeed]

* acme1: the SimpleHTTP challenge type from draft-barnes-acme-01.
  [Status: proofs fail because of the issue raised by Andrew Ayer
  https://mailarchive.ietf.org/arch/msg/acme/F71iz6qq1o_QPVhJCV4dqWf-4Yc].
  The rule that tells Tamarin about duplicate signatures is in
  common-setup.m4i:
  ````
equations:
    verify(sig, msg, pk(fakekey(sig))) = true
  ````
  Removing this rule will make the proofs go through.
  








