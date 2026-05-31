# Deployment Environment Validation

## Purpose

Prevents deployment failures due to missing or malformed environment variables.

## Usage

```bash
cargo run --bin deployment-validator validate --env-file .env
```

## Required Variables

| Var | Description | Format/Example |
|-----|-------------|---------------|
| `SOROBAN_RPC_URL` | Soroban RPC endpoint | `https://soroban-testnet.stellar.org:443` |
| `STELLAR_SECRET_KEY` | Deployer secret key | `SCPUX7DFAO5...` (56 chars, starts G/A/B) |
| `STELLAR_NETWORK_PASSPHRASE` | Network passphrase | `Test SDF Network ; September 2015` |
| `CONTRACT_ADMIN_KEY` | Admin public/secret key | `SDE5US5H...` |

## Optional

- `SOROBAN_FEE_ACCOUNT`
- `SOROBAN_FEE_SECRET_KEY`

## Security

- Never commit `.env`
- Use `.env.example` as template
- Validate before every deploy

