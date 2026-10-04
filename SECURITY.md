# Security Policy

## What this repository is

`ep-aec-conformance` is an independent Python conformance verifier for the IETF EP-AEC draft (`draft-schrock-ep-authorization-evidence-chain`), built from the specification text alone, with 64 conformance vectors and 4 adversarial probes.

## Reporting a vulnerability

**Preferred: GitHub private vulnerability reporting.** Open the **Security** tab on this repository and
choose **Report a vulnerability**. That channel is private between you and the maintainer, requires no
email, and nothing is posted publicly. Private reporting is enabled on this repository.

If you cannot use that channel, open a **minimal public issue** stating only that you have a security
report and how to reach you. Please do **not** include exploit details, proof-of-concept code, or
affected-version specifics in a public issue.

## Scope

**In scope:** A vector that the verifier accepts when it should reject, or rejects when it should accept; any input that makes the verifier **fail open**; divergence between the documented spec revision (`-02` default vs `-07` opt-in) and actual behaviour; and any use of the verifier's output that could mislead a relying party about the chain being verified.

**Out of scope / stated plainly:** The draft specification itself is authored by others. Defects in the specification text are **findings this project reports**, not vulnerabilities we can patch — see the published report. This verifier is an independent research artifact, not a certified or audited implementation.

## What to expect

| Stage | Commitment |
|---|---|
| Acknowledgement of your report | within 7 days |
| Initial assessment and severity call | within 14 days |
| Fix, or an agreed public disclosure | coordinated with you |

You will be credited in the fix or advisory unless you ask to remain anonymous.

## What this policy does NOT offer

There is **no bug bounty**, and no monetary reward is offered or implied. This is an independent
research project maintained by one person. What it can offer is a fast, honest response and public
credit.

## Related

- Our agent-systems threat posture and the method behind these reviews: see the `adversarial-seat`
  repository for the review method, and `hermes-refuse` for the fail-closed execution posture.
