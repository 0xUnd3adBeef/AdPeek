# Contributing to AdPeek

AdPeek is a lightweight tool for authorized Active Directory security assessment.  
Contributions are welcome as long as they align with the project's goals and scope.

---

## Scope of Contributions

Accepted contributions include:

- Bug fixes
- Code improvements
- New features that directly support legitimate AD enumeration or analysis
- Documentation improvements
- Performance and reliability enhancements

This project does not accept contributions intended for unauthorized exploitation or unrelated functionality.

---

## Legal and Ethical Requirements

By contributing, you confirm:

1. You have the right to submit the code (no proprietary or copied material).
2. Your contribution is intended for legal, authorized security testing.
3. Your work complies with all relevant laws and regulations in your jurisdiction.
4. You understand that AdPeek is strictly for use where explicit permission has been granted.

Any contribution that clearly promotes illegal activity will be rejected.

---

## Development Setup

Clone the repository:

```bash
git clone https://github.com/0xUnd3adBeef/AdPeek.git
cd AdPeek
````

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
```

Install in editable mode:

```bash
pip install -e .
```

Run the tool from source:

```bash
python AdPeek.py --help
```

---

## Coding Standards

Keep contributions consistent with the existing codebase:

* Write Python 3 code that follows PEP 8 where practical.
* Use type hints when they add clarity.
* Keep imports organized and minimal.
* Avoid adding heavy dependencies unless absolutely necessary.
* Do not hardcode credentials or environment-specific values.
* Maintain the simple, operator-focused output style.

---

## Documentation

If your changes modify user-facing behavior:

* Update `README.md`
* Add or adjust usage examples if applicable
* Ensure the documentation matches the actual behavior of the tool

---

## Submitting Changes

1. Create a branch:

   ```bash
   git checkout -b feature/my-change
   ```

2. Make your changes in focused, logical commits.

3. Test your changes to ensure core functionality still works.

4. Open a Pull Request with:

   * A clear description of the change
   * The reason for the change
   * Any related issues (e.g., "Fixes #7")

Large features should be discussed in an issue before implementation to avoid unnecessary work.

---

## Reporting Bugs

Include the following when reporting issues:

* The command you executed (with sensitive data redacted)
* Expected behavior vs actual behavior
* Error messages or stack traces
* Environment details:

  * Operating system
  * Python version
  * How AdPeek was installed

Do not include real domain data, usernames, SIDs, or credentials.

---

## License

AdPeek is licensed under the **Mozilla Public License 2.0 (MPL-2.0)**.
By contributing, you agree that your contribution will be released under the same license.
