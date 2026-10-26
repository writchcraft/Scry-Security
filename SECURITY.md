# Security policy

This project is under active development for authorised local defensive use.
See [the security model](docs/security_model.md) and [verification](docs/verification.md)
for current boundaries and tested capabilities.

Do not put credentials, real logs, incident evidence or exploit details in public
issues. Use GitHub private vulnerability reporting if enabled for this repository.
Otherwise request a private contact method without including sensitive details.
No response-time guarantee or paid support service is offered.

Known package advisories can be checked using the optional `audit` extra and
`python -m pip_audit --local --skip-editable`. A clean scan is a dated check of
known package advisories, not a substitute for code and deployment review.
