extern crate openssl;
use openssl::rsa::Padding;

#[cfg(test)]
use openssl::rsa::Rsa;

use clap::{App, Arg};
use openssl::symm::Cipher;

extern crate base64;
extern crate clap;
extern crate json;
extern crate rand;

extern crate ansi_colours;
extern crate ansi_term;

use rand::Rng;
use rand_os::rand_core::OsRng;

use std::fmt;
use std::fs;
use std::fs::OpenOptions;

use std::io::Write;

type ErrBox = Box<dyn std::error::Error>;
type EsigmaFn = dyn Fn(&[u8]) -> Result<Vec<u8>, ErrBox>;

/// Ring Signatures. Implementation of a signature scheme from the paper:
/// "How to Leak a Secret" by Ronald L. Rivest, Adi Shamir, Yael Tauman, 2001
/// ASIACRYPT 2001, LNCS 2248 [RST01]
/// [https://people.csail.mit.edu/rivest/pubs/RST01.pdf]

/**
 * "Group signatures are useful when the members want to cooperate, while
 * ring signatures are useful when the members do not want to cooperate."
 * (explanation from [RST01])
 */

/// note: since RSA is so broadly used, we implement only the RSA based version,
/// not the Rabin cryptosystem based version.

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref THE_CIPHER: openssl::symm::Cipher = Cipher::aes_256_cbc();
}

/// RSA version of the "extended trapdoor permutation"
fn extended_trapdoor_permutation_g(
    ni: &openssl::bn::BigNumRef,
    b_bits: usize,
    m: &openssl::bn::BigNumRef,
    crypt_function: &dyn Fn(&openssl::bn::BigNumRef) -> Result<openssl::bn::BigNum, ErrBox>,
) -> Result<openssl::bn::BigNum, ErrBox> {
    let mut qi = openssl::bn::BigNum::new()?;
    let mut ri = openssl::bn::BigNum::new()?;

    // probably not optimal to create ctx every time, but let's not optimize prematurely.
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    qi.div_rem(&mut ri, m, ni, &mut ctx)?;

    // 2^b, that is:
    let mut b2 = openssl::bn::BigNum::new()?;
    b2.set_bit(b_bits as i32)?;
    let b2 = b2;

    let one = openssl::bn::BigNum::from_u32(1)?;

    if (qi.as_ref() + one.as_ref()).as_ref() * ni <= b2 {
        let x = crypt_function(&ri)?;
        Ok((qi.as_ref() * ni).as_ref() + x.as_ref())
    } else {
        // the probability of this happening is negligible.
        Ok(m.to_owned()?)
    }
}

fn extended_trapdoor_permutation_g_encrypt(
    pk: &openssl::rsa::Rsa<openssl::pkey::Public>,
    b: usize,
    xi: &openssl::bn::BigNumRef,
) -> Result<openssl::bn::BigNum, ErrBox> {
    extended_trapdoor_permutation_g(pk.n(), b, &xi, &|ri: &openssl::bn::BigNumRef| {
        let mut output = vec![];
        let ni = pk.size() as usize;
        output.resize(ni, 0);
        let ri_bytes = msb_zero_padded_tovec(ri, ni);
        pk.public_encrypt(&ri_bytes[..], &mut output[..], Padding::NONE)?;
        Ok(openssl::bn::BigNum::from_slice(&output[..])?)
    })
}

fn extended_trapdoor_permutation_g_decrypt(
    pk: &openssl::rsa::Rsa<openssl::pkey::Private>,
    b: usize,
    xi: &openssl::bn::BigNumRef,
) -> Result<openssl::bn::BigNum, ErrBox> {
    extended_trapdoor_permutation_g(pk.n(), b, &xi, &|ri: &openssl::bn::BigNumRef| {
        let mut output = vec![];
        let ni = pk.size() as usize;
        output.resize(ni, 0);
        let ri_bytes = msb_zero_padded_tovec(ri, ni);
        pk.private_decrypt(&ri_bytes[..], &mut output[..], Padding::NONE)?;
        Ok(openssl::bn::BigNum::from_slice(&output[..])?)
    })
}

fn make_esigma(message_hash: Vec<u8>, iv_bytes: Vec<u8>) -> Result<Box<EsigmaFn>, ErrBox> {
    let esigma = move |input: &[u8]| -> Result<Vec<u8>, ErrBox> {
        let cipher_result = openssl::symm::encrypt(
            *THE_CIPHER,
            &message_hash[0..THE_CIPHER.key_len()],
            Some(&iv_bytes),
            input,
        )?;

        // Truncate it. While the real output is one block longer than the input, but we really don't need the reverse direction.
        Ok(cipher_result[0..input.len()].to_vec())
    };

    Ok(Box::new(esigma))
}

#[derive(Debug)]
pub struct RingSignature {
    /// The public keys, in portable format
    public_keys: Vec<Vec<u8>>,
    /// The starting value ("glue")
    v: openssl::bn::BigNum,
    /// All the xi nonces
    nonces: Vec<openssl::bn::BigNum>,
    /// length of unit: bits, not bytes!
    b: usize,
    /// IV for block cipher based E_{\sigma}
    iv: Option<Vec<u8>>,
    /// and finally,
    message_hash: Option<Vec<u8>>,
}

// More specific errors?
#[derive(Debug, Clone)]
struct DeserializeError;

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "deserialization error")
    }
}

impl std::error::Error for DeserializeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // "Generic error, underlying cause isn't tracked."
        None
    }
}

impl RingSignature {
    pub fn to_json_str(self: &Self) -> Result<String, ErrBox> {
        let obj = json::object! {
            "description" => "RSA-based ring signature",
            "version" => "0.0.0alpha",
            "public_keys" => {
                let mut data = json::JsonValue::new_array();
                for pem in self.public_keys.iter() {
                    data.push(base64::encode(pem))?;
                }
                data },
            "v" => base64::encode(&self.v.to_vec()),
            "nonces" => {
                let mut data = json::JsonValue::new_array();
                for nonce in self.nonces.iter() {
                    data.push(base64::encode(&nonce.to_vec()))?;
                }
                data },
            "b" => self.b,
            "esigma_iv" => self.iv.as_ref().map(|vec| base64::encode(&vec)),
            "message_hash" => self.message_hash.as_ref().map(|vec| base64::encode(&vec)),
        };
        Ok(obj.dump())
    }

    pub fn from_json(str: &str) -> Result<RingSignature, ErrBox> {
        let json_obj = json::parse(str)?;

        match json_obj {
            json::JsonValue::Object(obj) => {
                let mut public_keys = vec![];
                for x in obj["public_keys"].members() {
                    match x {
                        json::JsonValue::String(x) => {
                            let x = base64::decode(&x)?;
                            public_keys.push(x)
                        }
                        _ => return Err(Box::new(DeserializeError)),
                    }
                }

                let mut nonces = vec![];
                for x in obj["nonces"].members() {
                    match x {
                        json::JsonValue::String(x) => {
                            let x = openssl::bn::BigNum::from_slice(&base64::decode(&x)?)?;
                            nonces.push(x)
                        }
                        _ => return Err(Box::new(DeserializeError)),
                    }
                }

                let v = openssl::bn::BigNum::from_slice(&base64::decode(
                    &obj["v"]
                        .as_str()
                        .ok_or_else(|| Box::new(DeserializeError))?,
                )?)?;

                let b = obj["b"]
                    .as_usize()
                    .ok_or_else(|| Box::new(DeserializeError))?;

                let iv = match obj["esigma_iv"].as_str() {
                    Some(s) => Some(base64::decode(s)?),
                    None => None,
                };
                let message_hash = match obj["message_hash"].as_str() {
                    Some(s) => Some(base64::decode(s)?),
                    None => None,
                };

                Ok(RingSignature {
                    public_keys,
                    v,
                    nonces,
                    b,
                    iv,
                    message_hash,
                })
            }
            _ => Err(Box::new(DeserializeError)),
        }
    }
}

pub fn xor_inplace(block1: &mut [u8], block2: &[u8]) {
    block2.iter().enumerate().for_each(|(i, x2)| {
        block1[i] ^= x2;
    });
}

pub fn xor_blocks(block1: &[u8], block2: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(block1.len());
    block1.iter().zip(block2.iter()).for_each(|(x1, x2)| {
        out.push(x1 ^ x2);
    });
    out
}

// Unfortunate, though only of minor impact here: why doesn't OpenSSL offer fixed size bignum calculations?
fn msb_zero_padded_tovec(number: &openssl::bn::BigNumRef, desired_len: usize) -> Vec<u8> {
    let mut bytes = number.to_vec();

    if bytes.len() < desired_len {
        let mut prefix = vec![0; desired_len - bytes.len()];
        prefix.append(&mut bytes);
        prefix
    } else {
        bytes
    }
}

pub fn ring_sign(
    keys: Vec<openssl::rsa::Rsa<openssl::pkey::Public>>,
    key: openssl::rsa::Rsa<openssl::pkey::Private>,
    esigma: &dyn Fn(&[u8]) -> Result<Vec<u8>, ErrBox>,
) -> Result<RingSignature, ErrBox> {
    let mut moduli_sizes: Vec<u32> = keys.iter().map({ |x| x.size() }).collect();
    moduli_sizes.push(key.size());
    let moduli_sizes = moduli_sizes;

    let max_size_bytes = moduli_sizes
        .iter()
        .fold(0 as u32, |max, val| if max > *val { max } else { *val });

    // According to the paper, this should be plenty to avoid ill effects:
    let b_bytes: usize = max_size_bytes as usize + 20;

    let r = b_bytes % THE_CIPHER.block_size();
    let q = b_bytes / THE_CIPHER.block_size();
    let b_bytes = if r > 0 {
        (q + 1) * THE_CIPHER.block_size()
    } else {
        b_bytes
    };

    let b = b_bytes * 8;

    // Generate the random "glue" value
    let mut v0 = openssl::bn::BigNum::new()?;
    v0.rand(
        b as i32,
        openssl::bn::MsbOption::MAYBE_ZERO,
        /* arbitrary value for MSB */
        false /* do not require v to be odd */
    )?;

    let mut vs = vec![];

    let c_bytes = msb_zero_padded_tovec(&v0, b / 8);
    let v = esigma(&c_bytes)?;

    vs.push(openssl::bn::BigNum::from_slice(&v[..])?.to_owned()?);

    let mut xi_values = vec![];

    for pk in keys.iter() {
        // generate the random value associated with the i-th key:
        let mut xi = openssl::bn::BigNum::new()?;
        xi.rand(b as i32, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
        xi_values.push(xi.to_owned()?);

        let yi = extended_trapdoor_permutation_g_encrypt(pk, b, &xi)?;

        let v_last = vs.last().unwrap();

        let mut c_bytes = msb_zero_padded_tovec(v_last, b_bytes);
        let yi_bytes = msb_zero_padded_tovec(&yi, b_bytes);

        xor_inplace(&mut c_bytes[..], &yi_bytes[..]);
        let v_next: Vec<u8> = esigma(&c_bytes)?;

        assert!(v_next.len() == c_bytes.len());
        vs.push(openssl::bn::BigNum::from_slice(&v_next[..])?.to_owned()?);
    }

    let a = v0;
    let z = vs.last().unwrap();

    let a_bytes = msb_zero_padded_tovec(&a, b_bytes);
    let z_bytes = msb_zero_padded_tovec(z, b_bytes);
    let capstone = xor_blocks(&a_bytes[..], &z_bytes[..]);

    let c = openssl::bn::BigNum::from_slice(&capstone[..])?;

    let x0 = extended_trapdoor_permutation_g_decrypt(&key, b, &c)?;

    let mut pems: Vec<Vec<u8>> = vec![];
    for pk in keys.iter() {
        pems.push(pk.public_key_to_pem()?);
    }
    pems.push(key.public_key_to_pem()?);

    // finally, add the "random value" we just computed for the secret key to the list.
    xi_values.push(x0);

    // Make the random cut - of course it's *absolutely* crucial to get this part right.
    // An off-by-one here would destroy security.
    let i = {
        let mut rng = OsRng;
        rng.gen_range(0, pems.len())
    };

    // println!("choice {}", i);

    let mut nonces = xi_values.split_off(i);
    nonces.append(&mut xi_values);

    let mut pemsc = pems.split_off(i);
    pemsc.append(&mut pems);

    let v = vs.remove(i);

    Ok(RingSignature {
        public_keys: pemsc,
        v,
        nonces,
        b,
        iv: None,
        message_hash: None,
    })
}

/// Verify a ring signature
pub fn ring_check(ringsig: RingSignature) -> Result<bool, ErrBox> {
    if let (Some(message_hash), Some(iv)) = (ringsig.message_hash, ringsig.iv) {

        // Reconstruct the message-induced permutation E_{\sigma}:
        let esigma = make_esigma(message_hash, iv)?;

        let b = ringsig.b; // given in bits

        let v0 = ringsig.v.to_owned()?;
        let mut v_accum = ringsig.v.to_owned()?;

        let v_ref = &mut v_accum;

        // Now check the ring
        for (pk_pem, xi) in ringsig.public_keys.iter().zip(ringsig.nonces.iter()) {
            let pk = openssl::rsa::Rsa::public_key_from_pem(pk_pem)?;

            let yi = extended_trapdoor_permutation_g_encrypt(&pk, b, &xi)?;

            let mut c_value = msb_zero_padded_tovec(&*v_ref, b / 8);
            let yi_bytes = msb_zero_padded_tovec(&yi, b / 8);

            xor_inplace(&mut c_value[..], &yi_bytes[..]);
            let v_next: Vec<u8> = esigma(&c_value)?;
            *v_ref = openssl::bn::BigNum::from_slice(&v_next[..])?.to_owned()?;
        }

        // Success criterion: the result obtained in the end must match the starting value.
        Ok(*v_ref == v0)
    } else {
        Ok(false)
    }
}

#[test]
fn test_prot() -> Result<(), ErrBox> {
    for i in [0, 1, 1, 1, 2, 4].iter() {
        println!("running test with {} public key(s)", i);
        test_prot_parameterized(*i)?;
        println!();
    }
    Ok(())
}

#[cfg(test)]
fn test_prot_parameterized(num_public_keys: usize) -> Result<(), ErrBox> {
    let one = openssl::bn::BigNum::from_u32(1)?;
    let v = msb_zero_padded_tovec(&one, 12);
    assert_eq!(v, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let message_to_sign = b"interesting message".to_vec();

    let (esigma, message_hash, iv) =
        hash_message_and_make_esigma_with_fresh_iv(&message_to_sign.to_vec())?;
    let iv_bytes = msb_zero_padded_tovec(&iv, THE_CIPHER.block_size());

    let rsa = Rsa::generate(1024)?;
    let mut rsas = vec![];

    for _i in 0..num_public_keys {
        let rsai = Rsa::generate(1024)?;
        let pemi = rsai.public_key_to_pem()?;
        rsas.push(Rsa::public_key_from_pem(&pemi[..])?);
    }

    let mut ring_sig = ring_sign(rsas, rsa, &esigma)?;

    ring_sig.iv = Some(iv_bytes);
    ring_sig.message_hash = Some(message_hash.to_vec());

    let serialized = ring_sig.to_json_str()?;
    let ring_sig = RingSignature::from_json(&serialized)?;
    let check_result = ring_check(ring_sig)?;

    assert!(check_result);

    Ok(())
}

fn hash_message(message: &[u8]) -> Result<Vec<u8>, ErrBox> {
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha384())?;
    hasher.update(&message)?;
    Ok(hasher.finish()?.to_vec())
}

fn hash_message_and_make_esigma_with_fresh_iv(
    message: &[u8],
) -> Result<(Box<EsigmaFn>, Vec<u8>, Box<openssl::bn::BigNum>), ErrBox> {
    let mut iv = openssl::bn::BigNum::new()?;
    iv.rand(
        8 * THE_CIPHER.block_size() as i32,
        openssl::bn::MsbOption::MAYBE_ZERO,
        false,
    )?;
    let iv_bytes = msb_zero_padded_tovec(&iv, THE_CIPHER.block_size());

    // Hash of message to sign, to be used as key for the permutation E_{\sigma}
    let message_hash = hash_message(&message[..])?;
    let esigma = make_esigma(message_hash.to_vec(), iv_bytes.to_vec())?;

    Ok((esigma, message_hash, Box::new(iv)))
}

fn check_signature_from_file(
    sig_filename: &str,
    maybe_input_filename: Option<&str>,
) -> Result<bool, ErrBox> {
    println!("reading {}", sig_filename);
    let sigdata = fs::read(sig_filename)?;
    let ring_sig = RingSignature::from_json(std::str::from_utf8(&sigdata)?)?;

    match maybe_input_filename {
        Some(input_filename) => {
            println!("reading {}", input_filename);
            let message = fs::read(input_filename)?;
            if let Some(message_hash) = ring_sig.message_hash.clone() {
                if hash_message(&message[..])? == message_hash {
                    println!("input file matches hash.");
                } else {
                    println!("input file does not match hash.");
                    return Ok(false);
                }
            } else {
                println!("signature incomplete, no hash present.");
                return Ok(false);
            }
        }
        None => {
            println!("no input file to (re-)hash, checking only internal consistency of signature");
        }
    }

    ring_check(ring_sig)
}

fn create_signature_from_files(
    input_filename: &str,
    skey_filename: &str,
    pkey_filenames: Vec<&str>,
) -> Result<RingSignature, ErrBox> {
    println!("reading {}", input_filename);
    let inputdata = fs::read(input_filename)?;

    println!("reading {}", skey_filename);
    let skeydata = fs::read(skey_filename)?;
    let mut pkeys = vec![];

    for filename in pkey_filenames {
        println!("reading {}", filename);
        let pkey_pem = fs::read(filename)?;
        pkeys.push(openssl::rsa::Rsa::public_key_from_pem(&pkey_pem)?)
    }

    let skey = openssl::rsa::Rsa::private_key_from_pem(&skeydata)?;

    let (esigma, message_hash, iv) = hash_message_and_make_esigma_with_fresh_iv(&inputdata[..])?;

    let mut ring_sig = ring_sign(pkeys, skey, &esigma)?;
    let iv_bytes = msb_zero_padded_tovec(&iv, THE_CIPHER.block_size());
    ring_sig.iv = Some(iv_bytes);
    ring_sig.message_hash = Some(message_hash.to_vec());
    Ok(ring_sig)
}

fn main() {

    let matches = App::new("ringsig")
        .version("0.0.1")
        .author("fnordomat <GPG:46D46D1246803312401472B5A7427E237B7908CA>")
        .about("Computes and checks ring signatures")
        .arg(
            Arg::with_name("check")
                .short("c")
                .long("check")
                .takes_value(true)
                .conflicts_with("secret_key")
                .help("Signature (JSON file) to check/verify"),
        )
        .arg(
            Arg::with_name("public_key")
                .short("p")
                .long("public-key")
                .takes_value(true)
                .multiple(true)
                .help("Add public key (file)"),
        )
        .arg(
            Arg::with_name("secret_key")
                .short("k")
                .long("secret-key")
                .takes_value(true)
                .multiple(false)
                .required_unless("check")
                .help("Use this secret key (file)"),
        )
        .arg(
            Arg::with_name("input_file")
                .short("i")
                .long("input")
                .takes_value(true)
                .multiple(false)
                .required_unless("check")
                .help("Sign the content of this file"),
        )
        .arg(
            Arg::with_name("output_file")
                .short("o")
                .long("output")
                .takes_value(true)
                .multiple(false)
                .required_unless("check")
                .help("Name for the signature file"),
        )
        .get_matches();

    if matches.is_present("check") {
        println!("Signature check");

        let sig_filename = matches.value_of("check").unwrap();

        // if input file is given, check whether hash matches too! otherwise, check internal consistency and show a different message
        let maybe_input_filename = matches.value_of("input_file");

        match check_signature_from_file(sig_filename, maybe_input_filename) {
            Ok(true) => {
                println!(
                    "check result: {} ring signature",
                    ansi_term::Colour::Fixed(ansi_colours::ansi256_from_rgb((0, 255, 0)))
                        .paint("valid")
                );
            }
            // could not be successfully checked because numbers did not match
            Ok(false) => {
                println!(
                    "check result: {} ring signature",
                    ansi_term::Colour::Fixed(ansi_colours::ansi256_from_rgb((255, 0, 0)))
                        .paint("invalid")
                );
            }
            // could not be successfully checked because of error, e.g. key format
            Err(e) => {
                println!(
                    "{}: {}",
                    ansi_term::Colour::Fixed(ansi_colours::ansi256_from_rgb((255, 0, 0)))
                        .paint("error"),
                    e
                );
            }
        }
    } else {
        println!("Ring signature creation");
        println!("              ");
        println!("     xoox     ");
        println!("   xox  xox   ");
        println!("  oo      oo  ");
        println!("  oo      oo  ");
        println!("   xox  xox   ");
        println!("     xoox     ");
        println!("              ");

        // actually we don't know whether they are well formed yet, but if they aren't, we'll throw an error.
        println!(
            "number of keys: {} public + 1 secret",
            matches.occurrences_of("public_key")
        );

        // Ask: "Are you sure you want to do this?"

        let output_filename = matches.value_of("output_file").unwrap();
        let mut output_file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_filename)
        {
            Ok(file) => file,
            Err(e) => {
                eprintln!("error creating {}: {}", output_filename, e);
                std::process::exit(1);
            }
        };

        let input_filename = matches.value_of("input_file").unwrap();
        let skey_filename = matches.value_of("secret_key").unwrap();
        let pkey_filenames: Vec<&str> = matches
            .values_of("public_key")
            .map_or([].to_vec(), |x| x.collect());

        match create_signature_from_files(input_filename, skey_filename, pkey_filenames).and_then(
            |ring_sig| {
                let serialized = ring_sig.to_json_str()?;
                println!("writing {}", output_filename);
                write!(output_file, "{}", serialized)?;
                Ok(())
            },
        ) {
            Ok(_) => {}
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}
