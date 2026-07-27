# Security

This is a transport library with cryptography in it, so a flaw here can be a
flaw in everything built on top. Reports are welcome and taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** A public report
tells everyone how to attack every deployment before there is a fix.

Two private channels, either is fine:

- **GitHub private vulnerability reporting** — use the *Report a vulnerability*
  button on the Security tab. This is the easiest route if you already have a
  GitHub account, and it keeps the whole conversation attached to the repo.
- **Email** — social@binariigames.com

Useful things to include, as far as you have them: what the flaw is, which
commit you saw it on, how to reproduce it, and what an attacker gets out of it.
A rough report beats a delayed one — send what you have and we can dig into the
rest together.

## What to expect

openbcp is pre-1.0 and maintained by a small team, so no acknowledgement clock
is promised that cannot be kept. In practice, expect a reply within about a
week, an assessment once the report is understood, and honest updates if a fix
takes longer than that.

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
- Bypassing authentication — being accepted as an established peer without
  completing a handshake, or impersonating a certificate holder.
- Accepting replayed or forged packets that should have been rejected.
- Memory safety: out-of-bounds access, use-after-free, or anything reachable
  from a packet an attacker controls. This is C++ and the packet path is the
  attack surface.
- Amplification or asymmetric denial of service, where a cheap packet costs the
  receiver much more than it cost the sender.
- Privacy leaks on the wire: anything letting an observer link a peer across an
  address change, or identify a peer it should not be able to.

Out of scope:

- Flooding a host with traffic. Any UDP service can be flooded; that is a
  capacity problem, not a protocol flaw. Amplification is a different matter
  and is in scope above.
- Attacks that assume the attacker already runs code on the host, or already
  holds the private identity or session keys.
- Misuse by the embedding application, such as ignoring an error return or
  handing the library a buffer it does not own.
- Anything in `external/`, which is vendored third-party code. Report those
  upstream; tell us too if openbcp needs to update or work around it.

## Known limitations

Not vulnerabilities, but worth knowing before you report them:

- **`Unsecured()` sends plaintext, by design.** It is an explicit opt-out from
  encryption and authentication, and packets sent that way are readable and
  forgeable by anyone on the path. That is the documented contract.
- **Anonymous peers are not authenticated.** Without a loaded certificate, a
  session is encrypted but the peer's identity is unverified. Use
  `SendSecured` when identity matters.
- **The session key is not rotated.** It is derived once per handshake and kept
  for the life of the session, so a compromised key exposes that session's
  whole history. Known, tracked, not yet addressed.
