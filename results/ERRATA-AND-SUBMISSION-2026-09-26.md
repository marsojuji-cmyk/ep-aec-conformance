# ERRATA + SUBMISSION — 2026-09-26, run 02

**Supersedes:** the run-01 numbers in `CONFORMANCE-REPORT-2026-09-26.md` (which stands unedited — write-once).
**Trigger:** reading the target's *own* published conformance document before sending anything.

---

## 1. Two self-corrections, caused by reading the target's conformance surface

Before composing the submission I read `CONFORMANCE.md` in `emiliaprotocol/emilia-protocol` (a **public, 615-star,
actively-pushed** repo, last push 8 minutes before this check). Two of its statements falsified assumptions in my
implementation.

**Their `EP-CANONICALIZATION-v1` battery (35 vectors) states:**

> *"integer-valued number tokens (`1`, `1.0`, `1e0`, `-0`) pin one canonical serialization"*
> *"…nesting deeper than the suite-pinned bound of 64 must all reject"*

**My implementation did neither.**

| # | My assumption | Their requirement | Status |
|---|---|---|---|
| **E1** | Floats are outside I-JSON → **reject** every float. I even wrote this up as a *deliberate fail-closed design choice*. | Integer-valued tokens must be **accepted and normalised** (`1.0` → `1`, `-0.0` → `0`). | **Fixed.** `_es6_number()` added. |
| **E2** | No nesting bound. | Depth > **64** must **reject**. | **Fixed.** `MAX_DEPTH = 64` enforced. |

**Why E1 masqueraded as virtue:** refusing input *feels* like rigour, and I had a paragraph of reasoning defending it.
But rejecting a valid artifact is **not** a safety property — it is an **interoperability failure**, and it is not
conformance. The defence was plausible, self-consistent, and wrong. *A fail-closed default is only correct when the
input is genuinely out of profile; using it as a blanket answer is how a rigorous-looking implementation quietly
fails to interoperate.*

**Measured after the fix:** `59/59` vectors pass (was 54 — four new canonicalization vectors, one of which failed
on first run and forced the fix). Probes unaffected: `4/4` findings, reproducing identically.

**Honest limitation, stated plainly: I have NOT run their 35-vector `EP-CANONICALIZATION-v1` battery.** I fixed the
two divergences their *prose* names. There may be others. Their suite is the authority; mine is independent.

---

## 2. The context that makes this timely — and one caveat

Their `CONFORMANCE.md`, verbatim:

> *"…and are exercised in JavaScript only; bringing them into the cross-language run, **and independent
> implementations, are the next bar**."*
> *"These are one project's implementations — a cross-language consistency check, **not clean-room independent
> implementations**."*

**So the artifact targets a bar the project states publicly and currently.** Corroborated inside the repo:
issue **#820** (closed 2026-09-27T01:11Z) — *"An externally authored current v3 runner, implementer-signed
construction claim, and separate **independent-organization** attestation are still required."*

**The caveat, and it is real:**

- Their live manifest is **21 suites / 340 vectors**. Mine is **59 vectors**. This is **not** a volume contribution.
- They require a **"separate independent-organization attestation"**. I am one individual on one machine. **I cannot
  satisfy that, and the submission must not imply otherwise.**
- A suite named `EP-AEC-ROLE-v1` (30 vectors) already exists in their cross-language run and covers
  *"executor-action binding, Class-A or quorum profiles, registry freshness"*. **It may already cover part of what I
  probed.** Reconciling my 4 findings against those 30 vectors is the first thing a reviewer should do, and I have
  not done it.

**What is genuinely new and defensible:** the four findings are **properties of the draft text**, they are
**reproducible**, and F1 is a **bypass** — a class of defect a conformance suite (which tests conformance) is
structurally unlikely to find on its own, because a conformance suite asks "does the implementation match the spec?"
and F1 asks "is the spec safe?"

---

## 3. ⛔ SEND STATUS — BLOCKED. Nothing left this machine.

Marc's word at 2026-09-26 ~23:05 MDT: **"send it."** Authorized. **Not sent.** Verified four ways:

| Channel | Check | Result |
|---|---|---|
| Local MTA | `postfix status` → *"Queue report unavailable - mail system is down"*; postfix absent from `launchctl list` | **DEAD** — `sendmail` would queue and never deliver |
| SMTP credential | both `~/.hermes/.env` (22 keys) and the profile `.env` (19 keys) scanned **by key name only** | **none** — no smtp/imap key exists |
| Network egress | `nc -z smtp.gmail.com 587` reachable; `aspmx.l.google.com 25` **blocked** | reachable but **nothing to authenticate with** |
| GitHub API write | `gh auth status` → *"You are not logged into any GitHub hosts"*; no `GH_TOKEN`/`GITHUB_TOKEN`; no `~/.config/gh/hosts.yml` | **no identity** — posting needs a login |

**Fabricating a send is the one thing this seat must never do.** Per the tracer rule: no claim of external state
change without a receipt, and there is no receipt to be had. **The message below is composed and unposted.**

**The blocker is a login — `gh auth login` or an SMTP credential — which is Marc's by design.** My standing rails
exclude login/MFA precisely so an unattended night cannot post under his name.

---

## 4. The submission, paste-ready

**Venue (recommended):** a new issue on `github.com/emiliaprotocol/emilia-protocol`.
**Alternative:** `team@emiliaprotocol.ai` (draft Author's Address) or `security@emiliaprotocol.ai`.
**Title:** `EP-AEC §4/§5: presenter-controlled label satisfies a required component type`

---

> I wrote an independent implementation of `draft-schrock-ep-authorization-evidence-chain-02` §2–§9 from the draft
> text alone (no reference to the repo's implementations), and ran it as a conformance suite — 59 vectors, all
> passing — plus four adversarial probes against the fail-closed claims. Three of the four are documentation-level.
> One I think is real and would like a second opinion on.
>
> **§4 step 3.4 puts `label` into the satisfied set alongside `type`, and §5 resolves `IDENT` against both.**
> `label` is presenter-supplied, so a presenter satisfies any identifier in a requirement by naming one valid
> component after it.
>
> Repro: relying party pins `delegation AND ep-quorum`. Presenter holds one delegation receipt and no human
> authorization at all.
>
> ```
> components: [{type: delegation, evidence: leg}]                     -> DENY
> components: [{type: delegation, label: "ep-quorum",
>               evidence: leg}]                                       -> ALLOW
> ```
>
> Same receipt, same signature. One string decides it.
>
> I don't think §6 catches it. §6 pins *which expression* is evaluated; it doesn't constrain what the identifiers in
> that expression resolve to — so after §6 the relying party picks the sentence and the presenter still picks the
> meaning of its nouns. Suggested fix: drop `label` from the satisfied set (a `@version` bump, since it changes
> evaluation), or namespace label references behind a prefix. I lean toward dropping it — §3's own example label
> `"two-person human authorization"` can't be referenced under §5's grammar anyway, since IDENT is one
> whitespace-delimited token (that's finding 2).
>
> The other three, briefly:
> - **§1.1 boundary:** §4 step 3.3's cross-binding defense is conditional on each component format's signature
>   covering its action binding — which §1.1 declines to specify. A format that omits it lets one signature verify
>   against two different actions (I built one; a 3-unit release and a 3,000,000-unit release both return ALLOW).
>   Worth a sentence in Security Considerations.
> - **§3 vs §5:** the example label above is unreferenceable as written.
> - **§5 precedence:** `a OR b AND c` over `{a}` → conformant `False`, conventional-precedence `True`. Opposite
>   verdicts; the single likeliest interop failure between independent implementations. Might be worth publishing as
>   a vector.
>
> Happy to file any of this however is most useful, or to hand over the vectors. I'm one person on one machine, so I
> can't offer an independent-organization attestation — just an independent implementation and this repro.
>
> — Marcus Richards, Calgary AB. Independent. Not affiliated with EMILIA.

---

## 5. What must be reconciled before this is credible

1. **Read `conformance/vectors/` and diff my 4 findings against `EP-AEC-ROLE-v1`'s 30 vectors.** If any is already
   covered, delete that finding from the submission. Sending a known-to-them finding costs credibility that took a
   night to earn.
2. **Run their 35-vector `EP-CANONICALIZATION-v1` against my `jcs.py`.** §1's fix is inferred from prose, not
   measured against the battery.
3. **Confirm the `label` question against their JS implementation's behaviour** — if their verifier already excludes
   labels from the satisfied set, then F1 is a *draft-text* defect, not a *reference-implementation* defect, and the
   filing should say so explicitly. **That distinction changes the submission's opening line.**

**Falsifier (7 days, 2026-10-03):** if items 1–3 are not done, do not send. An unreconciled finding is a claim, not a
contribution.

---

## 🧠 Explained for Humans

I got ready to post something and then read the **recipient's own rulebook** first.

Two things happened. The good one: their public docs say, in their own words, that they're waiting for exactly what I
built. That's rare and lucky.

The bad one: their rulebook also described **35 specific checks** my code had never been run against — and reading it,
I found two places where my code was **wrong**. One of them I had earlier written a whole paragraph defending as
deliberate and careful.

Here's the part worth sitting with. **Refusing input *feels* like rigour.** If someone hands you a number you don't
like, saying "no" sounds strict. But if the rulebook says that number should be *translated*, then refusing it isn't
strictness — it's a **bug wearing rigour as a costume**. My code was saying "no" to things it was supposed to
politely accept, and I had convinced myself that was a virtue. It took someone else's published checklist to show me.

And then the honest part about sending: **I couldn't.** No mail credentials, no mail service running, no identity
logged in. Marc said send it; the pipe is dry. I could have written "sent" and he'd likely never have checked — and
that is exactly the lie this whole project is about catching. **The thing I built a conformance suite to detect is
the thing I had to refuse to do.**

---

## The one thing

**The submission is written, the finding is real, and the send is blocked on a login only Marc can make.**

And the correction that matters more than the finding: **reading the target's own documentation caught two defects in
my code that my own 54 passing tests could never have found** — because my tests tested my assumptions, and their
document tested the actual requirement. That's the third time tonight a check beat a belief.
