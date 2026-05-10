# Legion — Design Decisions

This document records features that were deliberately **not implemented** and explains why.
It exists so that contributors and curious users understand that these omissions are
intentional — not oversights — and the reasoning behind each decision.

---

## Why there is no online / presence indicator

**The feature:** A green dot or "last seen" timestamp next to contacts, showing whether
someone is currently online or recently active.

**Why it was rejected:**

The only technically viable implementation requires Legion to periodically connect to each
contact's `.onion` address through Tor and check whether it responds. This creates a
serious privacy problem:

1. **Traffic analysis.** If Legion pings 10 contacts every 30 seconds, your node
   produces a regular, predictable pattern of Tor connections. A network observer —
   an ISP, a Tor relay operator, or a government monitoring system — does not need to
   decrypt anything to observe: *"this node repeatedly connects to these specific
   .onion addresses."* That is your contact list, leaked through timing alone.

2. **Social graph reconstruction.** The pattern of which addresses you ping maps your
   social connections without touching the encrypted content of any message.

3. **Asymmetric exposure.** When you check whether Alice is online, your node connects
   to her `.onion`. Alice's node sees an incoming connection attempt. Anyone monitoring
   Alice's traffic knows that *someone* was interested in her availability at that exact
   moment — even if the connection is rejected.

4. **Behavioral fingerprinting.** Regular pings create an identifiable traffic rhythm
   even when the content is encrypted.

A passive "last seen" (derived from the timestamp of the last received message, no extra
network traffic) avoids points 1–3 but still leaks metadata: *"Alice was active at 14:32
yesterday."* For Legion's target users — journalists, activists, lawyers — even that
single data point has operational value to an adversary.

**The principle:** Legion is built to produce no metadata. A presence indicator adds it
back at the application layer after Tor removed it at the network layer. The user
experience benefit does not justify the privacy cost for the people Legion is designed
to protect.

---

## Why there are no voice messages

**The feature:** Record an audio clip inside Legion and send it as an encrypted
attachment, like a voice note in WhatsApp or Telegram.

**Why it was rejected:**

Audio recordings contain **voice biometrics** — unique characteristics of a speaker's
vocal tract that allow forensic identification even under adverse conditions. A naive
implementation (record → encrypt → send) protects the content from interception but
does nothing to protect the *speaker's identity* if the recipient's device is
compromised, seized, or if the recipient is coerced into producing the recording.

The only technically credible solution to voice biometrics is to run the audio through
a full **Speech-to-Text → Text-to-Speech** pipeline using local, offline models (no
cloud). This converts the speech to text, then re-synthesises it with a neutral
synthetic voice. The result contains none of the original speaker's vocal characteristics.

The required dependencies — a fast offline STT engine (e.g. `faster-whisper`) plus a
TTS synthesiser (e.g. `piper-tts`) — weigh approximately 200 MB in models alone and
add significant CPU overhead on every send. This conflicts with Legion's explicit
design constraint of minimal dependencies and offline-first simplicity.

A middle path (pitch shifting, formant shifting) was also considered and rejected. These
transformations are not resistant to modern speaker recognition systems. An adversary
with a reference recording of the speaker can often re-identify them after simple pitch
or formant modification. This would give users a false sense of security — which is
more dangerous than offering no voice message feature at all.

**The principle:** A half-secure feature is worse than no feature. Voice messages without
forensically credible anonymisation create a false sense of protection for users whose
safety depends on the opposite assumption.

---

## Why there are no safety numbers / key fingerprints

**The feature:** A short numeric or alphanumeric code (like Signal's "Safety Numbers")
that both parties can compare out-of-band to verify they are communicating with the
correct person and not an impostor.

**Why it was rejected:**

Safety numbers solve a specific problem: a **centralised key server** could substitute
an attacker's public key for a user's real key without the user's knowledge. Comparing
safety numbers out-of-band detects this substitution.

Legion has no centralised key server. There is no infrastructure that handles or
distributes public keys on anyone's behalf. Adding a contact requires:

1. The contact physically shares their **signed contact card** (JSON or QR code)
   with you through a channel you choose.
2. You verify and import it locally.
3. Messages are accepted **only** from senders whose contact card you have imported.
   All other senders are silently dropped.

The contact card itself — signed with the sender's Ed25519 private key — is the
verification step. The cryptographic signature proves that the card was produced by
the holder of the corresponding private key. No central authority can substitute a
different key because no central authority is involved in the exchange.

The only remaining attack vector is: an attacker intercepts the contact card during
exchange over an insecure channel and substitutes their own. The correct mitigation
for this is to exchange contact cards over a trusted channel — not to add a UI layer
that verifies a key that was potentially already compromised during exchange.

**The principle:** Safety numbers add value when a trusted third party handles key
distribution and could be compromised. In a system where keys are exchanged directly,
the exchange channel is the trust boundary. Duplicating the verification in-app solves
a problem that does not exist in this architecture.

---

## Why there is no duress / decoy password

**The feature:** A second password that opens a clean, empty Legion instance — so that
under coercion the user can "unlock" the app without revealing real data.

**Why it was rejected:**

Plausible deniability only works when the adversary does not know the feature exists.
Legion is open source. Anyone — including border agents, investigators, and government
agencies — can read the source code and verify that a second password mechanism is
present. An empty UI after unlocking is therefore not evidence of innocence; it is
evidence that the emergency password was used.

VeraCrypt's hidden volumes face the same problem: in several jurisdictions courts
already routinely demand "the second password" precisely because they know the feature
exists in widely audited open-source software.

Legion already has the correct solution for this threat: the **panic button**
(`Settings → Danger zone`). Two confirmations, then all data is deleted and the
database file is rewritten with `VACUUM` to overwrite freed pages. There is no second
database to find because there is no data left at all.

The distinction matters:
- Duress password: *pretend* the data does not exist (fails when adversary knows the tool)
- Panic button: *actually destroy* the data (no pretence required)

**The principle:** Security through actual destruction is more reliable than security
through deniability in a system whose source code is publicly auditable.

---

## How to propose a feature

If you believe a feature was rejected incorrectly, or if circumstances have changed
(e.g. a lightweight offline TTS library now exists that meets the dependency
constraints), open an issue and reference this document. The goal is not to refuse
change, but to make sure every decision is made deliberately.
