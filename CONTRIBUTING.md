# Contributing

- Keep the tool non-invasive: no exploitation, brute force, fuzzing, stealth, or evasion.
- Preserve strict scope validation and the public-IP DNS guard.
- Add tests for new behavior.
- Never commit credentials, private targets, customer data, or unredacted reports.

Run tests with `python -m unittest discover -s tests -v` and syntax validation with
`python -m compileall -q grevora_recon tests`.

Pull requests should explain the change, test evidence, and security implications.
Only submit data you are permitted to share.
