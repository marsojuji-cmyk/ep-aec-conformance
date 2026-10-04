# Methodology — How to Find Spec Defects Through Conformance Testing

This document describes the method that produced the four findings in the EP-AEC conformance report. The method is transferable to any specification that claims fail-closed behavior.

## The core idea

Write a pedantic implementation from the spec text alone. Do not read reference implementations. Run it. Ask why unexpected results happen.

The findings don't come from looking for bugs. They come from asking "what did the spec actually say?" and then doing exactly that — no more, no less.

## Step 1: Implement the spec, not the reference

Read the specification text. Implement every rule verbatim. When the text says "MUST," implement it. When the text says "MUST NOT," implement the refusal. When the text is ambiguous, implement **both** readings and note the ambiguity.

Do not look at reference implementations. The goal is to test the text, not the code. If your implementation matches the reference, you've tested the reference. If it diverges, you've found something worth examining.

## Step 2: Write conformance vectors, not unit tests

A conformance vector is a test that answers: "does this implementation match the specification?" It is not a test of whether the implementation works correctly — that's a different question.

Each vector has:
- An input (chain, policy, fixture)
- An expected output (verdict, reason code)
- A spec section reference

The expected output comes from the spec, not from your implementation. If your implementation returns ALLOW and the spec says DENY, that's a vector failure. If the spec is ambiguous, document both readings.

## Step 3: Run adversarial probes

A conformance suite tests "does it match the spec?" An adversarial probe tests "is the spec safe?" These are different questions.

A probe asks: "given this specification, can I construct an input that produces a surprising result while satisfying every rule?" The probe doesn't test your implementation — it tests the specification's assumptions.

The F1 finding (label/type collision) was found this way:
1. §4 step 3.4 says "add k.type and k.label to the satisfied set"
2. §5 says "IDENT matches a component type or label in the satisfied set"
3. Therefore a presenter-controlled label can satisfy a required type
4. Construct a chain that demonstrates this: one delegation receipt, labelled with the demanded type name
5. The verifier (following the spec exactly) returns ALLOW

The finding is a property of the specification text, not of the implementation.

## Step 4: Read the recipient's documentation before sending

Before publishing findings, read the target project's own conformance documentation. This serves two purposes:

1. **Catch your own bugs.** The E1 lesson: refusing input feels like rigour. I had a paragraph defending my refusal to accept floats. Their documentation said integer-valued tokens must be accepted and normalised. My "deliberate design choice" was a bug wearing rigour as a costume.

2. **Distinguish spec defects from implementation defects.** The F1 finding could have been a defect in their reference implementation. Checking their code showed they already handle it safely (labels excluded from the satisfied set). This changes the finding from "your code is broken" to "your spec text is ambiguous" — a better place to be.

## Step 5: Reconcile before publishing

Run the target's own conformance battery against your implementation. If it fails, fix your code before claiming a finding about theirs. An unreconciled finding is a claim, not a contribution.

The reconciliation process:
1. Fetch their conformance vectors
2. Run them against your implementation
3. For every failure: is it your bug or theirs?
4. Fix your bugs. Document the rest.

## Principles

- **Spec-first, not implementation-first.** Every test is written from the specification text.
- **Fail-closed everywhere.** Any unexpected error yields DENY. This is the design rule from §4 step 5.
- **No novelty claims.** The spec author did the real work. You are testing it.
- **Numbers and reproductions only.** Every claim has a test, every test has an input, every input is printed in the logs.
- **The method is the credential.** Anyone can write a verifier. The methodology — implement from text, probe adversarially, reconcile before publishing — is what makes findings credible.

## Transferability

This method works for any specification that:
1. Defines verifiable rules (MUST/MUST NOT)
2. Claims fail-closed behavior
3. Has a published conformance surface (vectors, test suite, or examples)

Examples: IETF drafts, W3C specs, RFC conformance, protocol verification.

The output is always the same: a conformance suite, adversarial probes, and a reconciliation report. The findings may vary, but the structure is reusable.