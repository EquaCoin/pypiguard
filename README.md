# PyPIGuard

**PyPI supply-chain protection against .pth auto-execution and credential theft attacks** (LiteLLM 1.82.7/1.82.8 style).

- Runs GuardDog + custom .pth/credential scanner
- Fail-fast on suspicious packages
- Ready for CI (GitHub Actions) and pre-commit

## Usage in GitHub Actions

```yaml
- uses: EquaCoin/pypiguard@v1
  with:
    requirements-file: 'requirements.txt'
    extra-packages: 'litellm openai'

## Local usage
```bash

pip install guarddog
python pyguard.py --requirements requirements.txt litellm==1.82.6

## Rotate keys immediately if you installed litellm==1.82.7 or 1.82.8.

