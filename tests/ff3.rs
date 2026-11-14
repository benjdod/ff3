// Known-answer tests based on the NIST FF3 samples and FF3-1 vectors attributed below.
use ff3::{Error, Ff3};

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn nist_ff3_known_answer_vectors() {
    // NIST SP 800-38G FF3 sample vectors.
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF3samples.pdf
    let vectors: &[(&str, &str, &str, &str, &str)] = &[
        (
            "EF4359D8D580AA4F7F036D6F04FC6A94",
            "D8E7920AFA330A73",
            "0123456789",
            "890121234567890000",
            "750918814058654607",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A94",
            "9A768A92F60E12D8",
            "0123456789",
            "890121234567890000",
            "018989839189395384",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A94",
            "D8E7920AFA330A73",
            "0123456789",
            "89012123456789000000789000000",
            "48598367162252569629397416226",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A94",
            "0000000000000000",
            "0123456789",
            "89012123456789000000789000000",
            "34695224821734535122613701434",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A94",
            "9A768A92F60E12D8",
            "0123456789abcdefghijklmnop",
            "0123456789abcdefghi",
            "g2pk40i992fn20cjakb",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
            "D8E7920AFA330A73",
            "0123456789",
            "890121234567890000",
            "646965393875028755",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
            "9A768A92F60E12D8",
            "0123456789",
            "890121234567890000",
            "961610514491424446",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
            "D8E7920AFA330A73",
            "0123456789",
            "89012123456789000000789000000",
            "53048884065350204541786380807",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
            "0000000000000000",
            "0123456789",
            "89012123456789000000789000000",
            "98083802678820389295041483512",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6",
            "9A768A92F60E12D8",
            "0123456789abcdefghijklmnop",
            "0123456789abcdefghi",
            "i0ihe2jfj7a9opf9p88",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
            "D8E7920AFA330A73",
            "0123456789",
            "890121234567890000",
            "922011205562777495",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
            "9A768A92F60E12D8",
            "0123456789",
            "890121234567890000",
            "504149865578056140",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
            "D8E7920AFA330A73",
            "0123456789",
            "89012123456789000000789000000",
            "04344343235792599165734622699",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
            "0000000000000000",
            "0123456789",
            "89012123456789000000789000000",
            "30859239999374053872365555822",
        ),
        (
            "EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C",
            "9A768A92F60E12D8",
            "0123456789abcdefghijklmnop",
            "0123456789abcdefghi",
            "p0b2godfja9bhb7bk38",
        ),
    ];
    for (key, tweak, alphabet, plaintext, expected) in vectors {
        let cipher = Ff3::new(&unhex(key), alphabet).unwrap();
        let tweak = unhex(tweak);
        let ciphertext = cipher.encrypt(&tweak, plaintext).unwrap();
        assert_eq!(
            ciphertext,
            *expected,
            "key size {} bits, radix {}",
            key.len() * 4,
            alphabet.len()
        );
        assert_eq!(cipher.decrypt(&tweak, &ciphertext).unwrap(), *plaintext);
    }
}

#[test]
fn acvp_ff3_1_known_answer_vectors() {
    // FF3-1 vectors from Mysto's public Python FPE implementation, including
    // AES-128/192/256 and radices 10/26/64.
    // https://github.com/mysto/python-fpe/blob/1.0.0/tests/ff3_test.py
    let vectors: &[(&str, &str, &str, &str, &str)] = &[
        (
            "2DE79D232DF5585D68CE47882AE256D6",
            "CBD09280979564",
            "0123456789",
            "3992520240",
            "8901801106",
        ),
        (
            "01C63017111438F7FC8E24EB16C71AB5",
            "C4E822DCD09F27",
            "0123456789",
            "60761757463116869318437658042297305934914824457484538562",
            "35637144092473838892796702739628394376915177448290847293",
        ),
        (
            "718385E6542534604419E83CE387A437",
            "B6F35084FA90E1",
            "abcdefghijklmnopqrstuvwxyz",
            "wfmwlrorcd",
            "ywowehycyd",
        ),
        (
            "DB602DFF22ED7E84C8D8C865A941A238",
            "EBEFD63BCC2083",
            "abcdefghijklmnopqrstuvwxyz",
            "kkuomenbzqvggfbteqdyanwpmhzdmoicekiihkrm",
            "belcfahcwwytwrckieymthabgjjfkxtxauipmjja",
        ),
        (
            "AEE87D0D485B3AFD12BD1E0B9D03D50D",
            "5F9140601D224B",
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
            "ixvuuIHr0e",
            "GR90R1q838",
        ),
        (
            "7B6C88324732F7F4AD435DA9AD77F917",
            "3F42102C0BAB39",
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
            "21q1kbbIVSrAFtdFWzdMeIDpRqpo",
            "cvQ/4aGUV4wRnyO3CHmgEKW5hk8H",
        ),
        (
            "F62EDB777A671075D47563F3A1E9AC797AA706A2D8E02FC8",
            "493B8451BF6716",
            "0123456789",
            "4406616808",
            "1807744762",
        ),
        (
            "0951B475D1A327C52756F2624AF224C80E9BE85F09B2D44F",
            "D679E2EA3054E1",
            "0123456789",
            "99980459818278359406199791971849884432821321826358606310",
            "84359031857952748660483617398396641079558152339419110919",
        ),
        (
            "49CCB8F62D941E5684599ECA0300937B5C766D053E109777",
            "0BFCF75CDC2FC1",
            "abcdefghijklmnopqrstuvwxyz",
            "jaxlrchjjx",
            "kjdbfqyahd",
        ),
        (
            "03D253674A9309FF07ED0E71B24CBFE769025E09FCE544D7",
            "B33176B1DA0F6C",
            "abcdefghijklmnopqrstuvwxyz",
            "tafzrybuvhiqvcyztuxfnwfprmqlwpayphxbawpl",
            "loaemzbgqkywkdhmncrijzildzleoqibtthdiliv",
        ),
        (
            "1C24B74B7C1B9969314CB53E92F98EFD620D5520017FB076",
            "0380341C425A6F",
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
            "6np8r2t8zo",
            "HgpCXoA1Rt",
        ),
        (
            "C0ABADFC071379824A070E8C3FD40DD9BFD7A3C99A0D5FE3",
            "6C2926C705DDAF",
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
            "GKB6sa9g56BSJ09iJ4dsaxRdsMvo",
            "gC0tTSdDPxM79QOWi+z+SNL9C4V+",
        ),
        (
            "1FAA03EFF55A06F8FAB3F1DC57127D493E2F8F5C365540467A3A055BDBE6481D",
            "4D67130C030445",
            "0123456789",
            "3679409436",
            "1735794859",
        ),
        (
            "9CE16E125BD422A011408EB083355E7089E70A4CD2F59E141D0B94A74BCC5967",
            "4684635BD2C821",
            "0123456789",
            "85783290820098255530464619643265070052870796363685134012",
            "75104723514036464144839960480545848044718729603261409917",
        ),
        (
            "6187F8BDE99F7DAF9E3EE8A8654308E7E51D31FA88AFFAEB5592041C033B736B",
            "5820812B3D5DD1",
            "abcdefghijklmnopqrstuvwxyz",
            "mkblaoiyfd",
            "ifpyiihvvq",
        ),
        (
            "F6807FB9688937E4D4956006C8F0CB2394148A5F4B14666CF353F4941428FFD7",
            "30C87B99890096",
            "abcdefghijklmnopqrstuvwxyz",
            "wrammvhudopmaazlsxevzwzwpezzmghwfnmkitnk",
            "nzftnfkliuctlmtdfrxfhwgevrbcbgljurnytxkj",
        ),
        (
            "9C2B69F7DDF181C54398E345BE04C2F6B00B9DD1679200E1E04C4FF961AE0F09",
            "103C238B4B1E44",
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
            "H2/c6FblSA",
            "EOg4H1bE+8",
        ),
        (
            "C58BCBD08B90006CEC7E82B2D987D79F6A21111DEF0CEBB273CBAEB2D6CD4044",
            "7036604882667B",
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
            "bz5TcS1krnD8IOLdrQeKzXkLAa6h",
            "Z6x3/9LPW8SZunRezRM8J68Q4J03",
        ),
    ];
    for (key, tweak, alphabet, plaintext, expected) in vectors {
        let cipher = Ff3::new(&unhex(key), alphabet).unwrap();
        let tweak = unhex(tweak);
        let ciphertext = cipher.encrypt(&tweak, plaintext).unwrap();
        assert_eq!(
            ciphertext,
            *expected,
            "key size {} bits, radix {}",
            key.len() * 4,
            alphabet.len()
        );
        assert_eq!(cipher.decrypt(&tweak, &ciphertext).unwrap(), *plaintext);
    }
}

#[test]
fn unicode_superscript_digit_alphabet_vector() {
    let alphabet = "⁰¹²³⁴⁵⁶⁷⁸⁹";
    let plaintext = "⁸⁹⁰¹²¹²³⁴⁵⁶⁷⁸⁹⁰⁰⁰⁰";
    let expected = "⁷⁵⁰⁹¹⁸⁸¹⁴⁰⁵⁸⁶⁵⁴⁶⁰⁷";
    let cipher = Ff3::new(&unhex("EF4359D8D580AA4F7F036D6F04FC6A94"), alphabet).unwrap();
    let tweak = unhex("D8E7920AFA330A73");

    assert_eq!(cipher.encrypt(&tweak, plaintext).unwrap(), expected);
    assert_eq!(cipher.decrypt(&tweak, expected).unwrap(), plaintext);
}

#[test]
fn unicode_german_alphabet_vector() {
    let alphabet = concat!(
        "0123456789",
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "ÄäÖöÜüẞß"
    );
    let cipher = Ff3::new(&unhex("EF4359D8D580AA4F7F036D6F04FC6A94"), alphabet).unwrap();
    let tweak = unhex("D8E7920AFA330A73");
    let plaintext = "liebeGrüße";
    let expected = "5kÖQbairXo";

    assert_eq!(cipher.radix(), 70);
    assert_eq!(cipher.encrypt(&tweak, plaintext).unwrap(), expected);
    assert_eq!(cipher.decrypt(&tweak, expected).unwrap(), plaintext);
}

#[test]
fn unicode_alphabet_validation() {
    assert!(matches!(
        Ff3::new(&[0; 16], "aa"),
        Err(Error::DuplicateUnicodeSymbol { symbol: 'a' })
    ));
    assert!(matches!(
        Ff3::new(&[0; 16], "a"),
        Err(Error::InvalidAlphabetLength { actual: 1 })
    ));

    let cipher = Ff3::new(&[0; 16], "0123456789").unwrap();
    assert_eq!(cipher.encrypt(&[0; 7], "12345x"), Err(Error::InvalidSymbol));
}

#[test]
#[ignore = "20,000 generated vectors; run with --ignored extended_mysto_vectors"]
fn extended_mysto_vectors() {
    check_mysto_vectors("Mysto C", include_str!("vectors/mysto_clang_fpe.csv"));
    check_mysto_vectors("Mysto Python", include_str!("vectors/mysto_python_fpe.csv"));
}

fn check_mysto_vectors(corpus: &str, vectors: &str) {
    const ALPHABET: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut checked = 0;

    for (line_number, line) in vectors.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(
            fields.len(),
            6,
            "{corpus}: malformed vector at line {}",
            line_number + 1
        );
        let (variant, key_hex, tweak_hex, radix, plaintext, expected) = (
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
        );
        let key = unhex(key_hex);
        let tweak = unhex(tweak_hex);
        let radix: usize = radix
            .parse()
            .unwrap_or_else(|_| panic!("{corpus}: invalid radix at line {}", line_number + 1));
        assert!(
            radix <= ALPHABET.len(),
            "{corpus}: radix out of range at line {}",
            line_number + 1
        );
        assert_eq!(
            (variant, tweak.len()),
            match variant {
                "ff3-1" => ("ff3-1", 7),
                "ff3" => ("ff3", 8),
                _ => panic!("{corpus}: unknown variant at line {}", line_number + 1),
            },
            "{corpus}: variant/tweak mismatch at line {}",
            line_number + 1
        );

        let cipher = Ff3::new(&key, &ALPHABET[..radix]).unwrap();
        let ciphertext = cipher.encrypt(&tweak, plaintext).unwrap_or_else(|error| {
            panic!(
                "{corpus}: encrypt failed at line {}: {error}",
                line_number + 1
            )
        });
        assert_eq!(
            ciphertext,
            expected,
            "{corpus}: encryption mismatch at line {}",
            line_number + 1
        );
        let decrypted = cipher.decrypt(&tweak, expected).unwrap_or_else(|error| {
            panic!(
                "{corpus}: decrypt failed at line {}: {error}",
                line_number + 1
            )
        });
        assert_eq!(
            decrypted,
            plaintext,
            "{corpus}: decryption mismatch at line {}",
            line_number + 1
        );
        checked += 1;
    }

    assert_eq!(checked, 10_000, "{corpus}: unexpected vector count");
}
