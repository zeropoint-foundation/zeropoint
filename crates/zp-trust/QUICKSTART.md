# zp-trust Quick Start Guide

## Basic Usage Patterns

### 1. Initialize Vault and Store Credentials

```rust
use zp_trust::CredentialVault;

// Create vault with 32-byte master key
let master_key = [0x42u8; 32];
let mut vault = CredentialVault::new(&master_key);

// Store encrypted credentials
vault.store("database-password", b"my-secret-password")?;
vault.store("api-key", b"sk-1234567890")?;

// List stored credentials (names only)
let credentials = vault.list();
println!("Stored: {:?}", credentials);

// Retrieve decrypted credential
let password = vault.retrieve("database-password")?;
assert_eq!(password, b"my-secret-password".to_vec());

// Clean up
vault.remove("database-password")?;
```

### 2. Inject Credentials with Policy

```rust
use zp_trust::{CredentialInjector, PolicyContext, InjectorError, InjectorResult};

// Define access policy
fn access_policy(skill_id: &str, credential: &str, _context: &PolicyContext) -> InjectorResult<()> {
    // Allow only "data-processor" skill to access database credentials
    if skill_id == "data-processor" && credential.contains("db") {
        Ok(())
    } else {
        Err(InjectorError::PolicyDenied("Access denied".to_string()))
    }
}

// Create injector
let injector = CredentialInjector::new(&vault, access_policy);

// Create context
let context = PolicyContext::new("production-boundary".to_string())
    .with_environment("prod".to_string());

// Inject single credential
let password = injector.inject_single("data-processor", "db-password", &context)?;

// Inject multiple credentials
let creds = injector.inject(
    "data-processor",
    &["db-password".to_string(), "db-username".to_string()],
    &context,
)?;

// Credentials are used and automatically dropped
for (name, value) in creds {
    println!("Using credential: {}", name);
    // value is automatically zeroized when dropped
}
```

### 3. Sign and Verify Data

```rust
use zp_trust::Signer;

// Generate new signing key
let signer = Signer::generate();
let public_key = signer.public_key();

// Sign data
let data = b"Important message";
let signature = signer.sign(data);
println!("Signature: {}", signature);

// Verify signature
let is_valid = Signer::verify(&public_key, data, &signature)?;
assert!(is_valid);

// Verify fails with different data
let is_valid = Signer::verify(&public_key, b"Different message", &signature)?;
assert!(!is_valid);
```

### 4. Recover Signer from Secret Key

```rust
use zp_trust::Signer;

// Store the secret key safely (use PKCS#8 in production)
let secret = signer.secret_key();

// Later, recover the signer
let recovered_signer = Signer::from_secret(&secret)?;

// Same secret produces same public key
assert_eq!(
    recovered_signer.public_key(),
    signer.public_key()
);

// Same data produces same signature (deterministic)
let sig1 = signer.sign(b"data");
let sig2 = recovered_signer.sign(b"data");
assert_eq!(sig1, sig2);
```

## Common Patterns

### Pattern: Policy with Environment Check

```rust
fn environment_policy(
    skill_id: &str,
    credential: &str,
    context: &PolicyContext,
) -> InjectorResult<()> {
    // Prod skills only in prod environment
    if skill_id.starts_with("prod-") {
        match &context.environment {
            Some(env) if env == "production" => Ok(()),
            _ => Err(InjectorError::PolicyDenied("Not in production".to_string())),
        }
    } else {
        Ok(())
    }
}
```

### Pattern: Hierarchical Credential Names

```rust
fn hierarchical_policy(
    skill_id: &str,
    credential: &str,
    context: &PolicyContext,
) -> InjectorResult<()> {
    let parts: Vec<&str> = credential.split('/').collect();
    
    if parts.len() < 2 {
        return Err(InjectorError::PolicyDenied("Invalid credential format".to_string()));
    }
    
    let service = parts[0];
    let _resource = parts[1];
    
    // Check if skill is authorized for this service
    if skill_id.contains(service) {
        Ok(())
    } else {
        Err(InjectorError::PolicyDenied("Service not authorized".to_string()))
    }
}
```

### Pattern: Audit Trail with Metadata

```rust
let context = PolicyContext::new("host-1".to_string())
    .with_environment("staging".to_string())
    .with_metadata("request_id".to_string(), "req-12345".to_string())
    .with_metadata("user".to_string(), "operator@example.com".to_string());

// Policy has access to all metadata
let creds = injector.inject("skill-id", &["cred"], &context)?;
// Access is logged with: skill_id, credential_name, boundary, and context in tracing
```

## Error Handling

```rust
use zp_trust::{VaultError, SignerError, InjectorError};

// Vault errors
match vault.retrieve("missing") {
    Err(VaultError::CredentialNotFound(name)) => {
        println!("Credential not found: {}", name);
    }
    Err(e) => println!("Vault error: {}", e),
    Ok(cred) => { /* use cred */ }
}

// Signer errors
match Signer::verify(&key, data, "invalid-hex") {
    Err(SignerError::InvalidSignatureFormat(e)) => {
        println!("Bad signature format: {}", e);
    }
    Ok(valid) => println!("Valid: {}", valid),
    Err(e) => println!("Error: {}", e),
}

// Injector errors
match injector.inject("skill", &creds, &context) {
    Err(InjectorError::PolicyDenied(reason)) => {
        println!("Access denied: {}", reason);
    }
    Err(e) => println!("Injection error: {}", e),
    Ok(credentials) => { /* use */ }
}
```

## Memory Safety Notes

1. **Credential Vault**: All stored credentials are automatically zeroized on drop
2. **Signer**: Secret keys are automatically zeroized on drop
3. **Injector**: Credentials returned from injection are zeroized when dropped
4. **PolicyContext**: No sensitive data held; safe to reuse

Always ensure credentials are dropped promptly after use:

```rust
{
    let cred = vault.retrieve("password")?;
    // Use credential
    // cred is zeroized when this scope ends
}
```

## Performance Considerations

- **Vault.list()**: O(n) where n is number of credentials (returns vec of names)
- **Vault.store()**: O(m) where m is credential size (encryption + random nonce)
- **Vault.retrieve()**: O(m) where m is credential size (decryption)
- **Signer.sign()**: O(n) where n is data size
- **Signer.verify()**: O(n) where n is data size
- **Injector.inject()**: O(k*m) where k is credential count, m is avg size

For large credential values, consider streaming encryption in future versions.

## Debugging

Enable tracing to see access logs:

```rust
use tracing::{info, debug};
use tracing_subscriber;

// Initialize subscriber
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();

// Now injector access logs will appear
let creds = injector.inject("skill", &["cred"], &context)?;
// [DEBUG] Credential injected for skill: skill_id="skill", credential="cred", boundary="prod"
```

## Testing Your Policies

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_policy() {
        let context = PolicyContext::new("test".to_string());
        
        // Allowed case
        assert!(my_policy("skill1", "cred1", &context).is_ok());
        
        // Denied case
        assert!(my_policy("skill2", "cred2", &context).is_err());
    }
}
```
