# Security Policy

## Reporting a vulnerability

If you find a security vulnerability in ai-pen-test itself, report it privately.
Do not open a public issue for an unpatched vulnerability.

Use GitHub's private vulnerability reporting for this repository
(the "Report a vulnerability" button under the Security tab), or email
ian@arcana-research.com.

Please include:

- the version or commit you tested,
- a description of the issue and its impact,
- steps to reproduce, and
- any proof-of-concept input, kept to the minimum needed to demonstrate the
  problem.

You will get an acknowledgement of the report. Once the issue is confirmed and a
fix is available, the fix will be released and the reporter credited unless they
ask otherwise.

## Supported versions

This project is at an early version. Fixes are applied to the latest release on
the default branch. There is no long-term support branch.

## Authorized use

ai-pen-test is a defensive static-analysis tool. It reads source code and reports
likely weaknesses. It does not execute the code under review, send traffic to
running systems, or attempt exploitation.

Run it only against code you own or have explicit written permission to assess.
Using it to analyze systems or code you do not control may be illegal and is not
a supported use of this project.
