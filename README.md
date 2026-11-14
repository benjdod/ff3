# FF3

> **Warning:** [NIST's February 2025 Draft 2 withdraws FF3 from the NIST
> standard in light of published vulnerabilities](https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd).
> This crate implements FF3 as of [Draft 1](https://csrc.nist.gov/pubs/sp/800/38/g/r1/ipd)
> and is intended for educational and experimental use. It comes with no
> warranty and is intended for developers and researchers familiar with
> cryptographic standards. Do not use it in production or for compliance-sensitive
> purposes without independently evaluating the risks and requirements.

Standard implementation of FF3 and FF3-1 format-preserving encryption.

<https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf>

## Usage

Add the crate to your project with `cargo add ff3`.

Create a cipher with an AES key and an ordered alphabet. A 7-byte tweak selects
FF3-1; an 8-byte tweak selects FF3. The alphabet order determines the digit
value of each symbol. The examples below show a decimal round trip, Unicode
symbols, and reusing an output buffer.

```rust
use ff3::Ff3;

fn main() -> Result<(), ff3::Error> {
    // Example values only. Use a securely generated key in real applications.
    let key = [0u8; 16]; // AES-128
    let tweak = [0u8; 7]; // FF3-1
    let cipher = Ff3::new(&key, "0123456789")?;

    // Encrypt/decrypt over a custom alphabet
    let ciphertext = cipher.encrypt(&tweak, "1234567890")?;
    assert_eq!(ciphertext, "4908574168");

    let plaintext = cipher.decrypt(&tweak, &ciphertext)?;
    assert_eq!(plaintext, "1234567890");

    // Unicode characters are supported
    let alphabet = "⁰¹²³⁴⁵⁶⁷⁸⁹";
    let unicode_cipher = Ff3::new(&key, alphabet)?;
    let plaintext = "¹²³⁴⁵⁶⁷⁸⁹⁰";

    let ciphertext = unicode_cipher.encrypt(&tweak, plaintext)?;
    assert_eq!(ciphertext, "⁴⁹⁰⁸⁵⁷⁴¹⁶⁸");
    assert_eq!(
        unicode_cipher.decrypt(&tweak, &ciphertext)?,
        plaintext
    );

    // Encrypt into a String buffer for reuse
    let mut output = String::new();
    cipher.encrypt_into(&tweak, "1234567890", &mut output)?;
    assert_eq!(output, "4908574168");

    Ok(())
}
```

## Related

GitHub user [Mysto](https://github.com/mysto) publishes and maintains FF3 and
FF3-1 implementations in other languages, which inspired this crate:
- C: https://github.com/mysto/clang-fpe
- Java: https://github.com/mysto/java-fpe
- Node.js: https://github.com/mysto/node-fpe
- Python: https://github.com/mysto/python-fpe

As noted above, NIST withdrew FF3 and FF3-1 from SP 800-38G in February 2025.
These independent projects are linked for reference only; we do not maintain
them or make any warranty regarding them.

## License

Licensed under the [MIT License](https://opensource.org/license/mit/).
