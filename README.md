# Auth0 OAuth Client

A Django-focused Auth0 integration providing automated OIDC flows, account linking, and connected account (My Account API). It's been created to support the [Auth0 Token Vault](https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault) feature, which requires Connected Accounts flow.

It's an opinionated library focused on the needs of our own products. Feel free to fork it and adapt it to your needs.

## Read this before using it

This library uses `uuid7` for the ID columns when the Python version is 3.14 or higher. If you're using Python 3.12 or 3.13, it will use `uuid4` instead. If your project updates to Python 3.14, it will break. We know this behavior is unacceptable for a library. That's why we are letting you know in advance. Again, fork this library and adapt it to your needs. 

## Rules

The [`sample_app`](./samples) demonstrates how to use the library. It implements the following rules:

- Only required scopes are requested for social connections.
- Additional scopes are requested during the [connected account request flow](https://auth0.com/docs/api/myaccount/create-connected-account-request) (progressive consent).
- When the user creates a connected account, that connected account is eligible for automatic account linking.
  - Consider the following scenario:
    - If a user logs in with `xpto@acme.com` and adds `qwerty@gmail.com` as a connected account, logging in later with the Gmail address will link both, with `xpto@acme.com` remaining the primary account. No confirmation is required.
    - The same is true when the connected account matches the primary account.
- If a user signs up with an email/password, logs out, and later logs back in using a social connection with that same email, the accounts are automatically linked. The original email/password account is used as the primary account.
- If a user signs up via social, logs out, and later tries to log in with a password using the same email, they'll need to re-authenticate with the original social provider to link the accounts. The primary account is the social one.

## Why did we build this?

Auth0 used to be the 'Stripe of Identity' sort of thing, known for its great developer experience. Lately, I’m not so sure. I almost gave up on it, but after finding some workarounds, I decided to build this library. I’m sharing it because seeing these issues go unaddressed hurts my software developer soul. 😬

Read the following Auth0 Community Questions for more details:

- [Auth0 Fails to Store Refresh Tokens for Linked Accounts](https://community.auth0.com/t/auth0-fails-to-store-refresh-tokens-for-linked-accounts/196953?u=tinuvi.solutions).
- [I had built an integration using Token Vault, and it stopped. Understand why](https://community.auth0.com/t/ms-agent-framework-and-python-use-the-auth0-token-vault-to-call-third-party-apis/193959/4?u=tinuvi.solutions).

At the time of writing this README (2026-02-13), [My Account API is not GA yet](https://auth0.com/docs/api/myaccount/). It means this library might eventually break if Auth0 changes its API, again. 😐 