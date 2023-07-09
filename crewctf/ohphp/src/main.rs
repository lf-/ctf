use aes::cipher::{BlockDecryptMut, KeyIvInit};
use std::fmt;

#[inline]
fn is_printable(buf: &[u8]) -> bool {
    buf.iter().all(|&c| c > 32 && c < 127)
}

/// Displays a binary value as an escaped ascii string.
pub struct Show<'a>(pub &'a [u8]);
impl<'a> fmt::Display for Show<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"")?;
        for &ch in self.0 {
            for part in std::ascii::escape_default(ch) {
                fmt::Write::write_char(f, part as char)?;
            }
        }
        write!(f, "\"")
    }
}

impl<'a> fmt::Debug for Show<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

fn main() {
    let mut key = *b"crew{php_1s_4ijk";
    let data = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        "wCX3NcMho0BZO0SxG2kHxA==",
    )
    .unwrap();
    let iv = hex_literal::hex!("5ba6655c0f8dbd670b55b47b7eceba29");

    for a in 0..=u8::MAX {
        for b in 0..=u8::MAX {
            for c in 0..=u8::MAX {
                key[13] = a;
                key[14] = b;
                key[15] = c;

                let mut buf = [0u8; 48];
                buf[..data.len()].copy_from_slice(&data);

                let pt = cbc::Decryptor::<aes::Aes128>::new(&key.into(), &iv.into())
                    .decrypt_padded_mut::<aes::cipher::block_padding::ZeroPadding>(&mut buf)
                    .unwrap();

                if is_printable(&pt[..data.len()]) {
                    println!(
                        "candidate? {} {} {} {}",
                        a as char,
                        b as char,
                        c as char,
                        Show(&pt[..data.len()])
                    );
                }
            }
        }
    }
}
