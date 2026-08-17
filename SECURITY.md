# Security

This is a transport library with cryptography in it, so a flaw here can be a
flaw in everything built on top. Reports are welcome and taken seriously.

## Reporting a vulnerability

Please do not open a public issue for a security problem. A public report tells
everyone how to attack every deployment before there is a fix.

Two private channels, either is fine:

- GitHub private vulnerability reporting, through the "Report a vulnerability"
  button on the Security tab. This is the easiest route if you already have a
  GitHub account, and it keeps the whole conversation attached to the repo.
- Email, at social@binariigames.com

Useful things to include, as far as you have them: what the flaw is, which
commit you saw it on, how to reproduce it, and what an attacker gets out of it.
A rough report beats a delayed one, so send what you have and we can dig into
the rest together.

## What to expect

Flux is pre-1.0 and maintained by one person, so no acknowledgement clock is
promised that cannot be kept. In practice, expect a reply within about a week,
an assessment once the report is understood, and honest updates if a fix takes
longer than that.

Credit is given to reporters who want it, and withheld from those who do not.
Anyone who reports privately and gives us a reasonable window before going
public will be treated as having done the right thing, because they have.

## Supported versions

Pre-1.0, only the latest commit on the default branch is supported. There are
no maintenance branches and no backports. The wire format and API may still
change between versions, and a security fix is allowed to break either.

## Scope

In scope, and most useful to hear about:

- Anything that breaks the cryptography: key agreement, the AEAD seal, nonce
  reuse, the handshake transcript or its key confirmation.
- Bypassing authentication, meaning being accepted as an established peer
  without completing a handshake, or impersonating a certificate holder.
- Accepting replayed or forged packets that should have been rejected.
- Memory safety: out-of-bounds access, use-after-free, or anything reachable
  from a packet an attacker controls. This is C++ and the packet path is the
  attack surface.
- Amplification or asymmetric denial of service, where a cheap packet costs the
  receiver much more than it cost the sender.
- Privacy leaks on the wire: anything letting an observer link a peer across an
  address change, or identify a peer it should not be able to.

Out of scope:

- Flooding a host with traffic. Any UDP service can be flooded, which is a
  capacity problem rather than a protocol flaw. Amplification is a different
  matter and is in scope above.
- Attacks that assume the attacker already runs code on the host, or already
  holds the private identity or session keys.
- Misuse by the embedding application, such as ignoring an error return or
  handing the library a buffer it does not own.
- Third-party code vendored in `external/`, which today means
  `external/monocypher`. Report those upstream, and tell us too if Flux needs to
  update or work around it. `external/common` is not third-party. It is ours,
  vendored the same way, and flaws in it are in scope.

## Known limitations

These are known and are not vulnerabilities:

- `Unsecured()` sends plaintext. It is an explicit opt-out from encryption and
  authentication, and packets sent that way are readable and forgeable by anyone
  on the path. That is the documented contract.
- Anonymous peers are not authenticated. Without a loaded certificate, a session
  is encrypted but the peer's identity is unverified. Use `SendSecured` when
  identity matters.
- First-flight data has weaker forward secrecy than the rest of a session. The
  interim key that carries a knock is derived without any contribution from the
  receiver, so a later theft of the receiver's long-term key opens a recorded
  first flight. Everything from the handshake's completion onward mixes both
  ephemerals and is unaffected. This is inherent to sending data before the
  other end has spoken.
- A replayed first flight can be delivered twice. Three things bound it. The
  clock stamp is inside the authenticated header, so a captured opener cannot
  be refreshed and stops being accepted once it falls outside the window. A
  peer that exists refuses a repeat through its own replay window. And a peer
  elsewhere holding the same identity refuses the registration, so a copy sent
  from a second address cannot land beside the original. What is left is a copy
  arriving inside the clock window while no peer anywhere holds that identity,
  which means a receiver that restarted, or a peer that `RemovePeer` or a
  failed handshake took away. Nothing in a transport can close that: a first
  flight is by definition judged before there is a session to judge it against.
  `IsKnock` reports which delivered messages rode one, so an application can
  keep anything it must not do twice out of the first flight.
