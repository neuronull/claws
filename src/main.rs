use core_affinity;
use hex::FromHex;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::Instant;
use wagyu_ethereum::{
    wordlist::*, EthereumDerivationPath, EthereumFormat, EthereumMnemonic, EthereumNetwork,
    Mainnet as EthereumMainnet,
};
use wagyu_model::{ExtendedPrivateKey, ExtendedPublicKey, Mnemonic, MnemonicExtended, PublicKey};

mod words;
use words::{WORDLIST, WORDS_BOTH, WORDS_POST, WORDS_POST_ONLY, WORDS_VIDEO, WORDS_VIDEO_ONLY};

fn get_checksum(data: &[u8]) -> u8 {
    let mut hasher = Sha256::new();
    hasher.input(data);
    let hash = hasher.result();
    hash[0] >> 4
}

fn to_hex(val: &str, len: usize) -> String {
    let n: u64 = u64::from_str_radix(val, 2).unwrap();
    format!("{:01$x}", n, len * 2)
}

fn is_mnemonic_valid(mnemonic_v: &Vec<&str>) -> bool {
    let mut binary_strs: Vec<String> = vec![];
    for idx in 0..12 {
        let pos = WORDLIST.iter().position(|&x| x == mnemonic_v[idx]).unwrap();
        let t = format!("{:0>11b}", pos);
        binary_strs.push(t);
    }
    let entropy_str = binary_strs.concat();
    let entropy_minus_checksum = &entropy_str[..=127];
    let entropy_checksum = &entropy_str[128..];
    let entropy_str_first = &entropy_minus_checksum[0..64];
    let entropy_str_second = &entropy_minus_checksum[64..128];
    let mut entropy_hex_first = to_hex(&entropy_str_first, 8);
    let entropy_hex_second = to_hex(&entropy_str_second, 8);
    entropy_hex_first.push_str(&entropy_hex_second);

    let bytes: Vec<u8> = Vec::from_hex(entropy_hex_first).unwrap();

    let checksum = get_checksum(&bytes);
    let checksum_str = format!("{:0>4b}", checksum);

    checksum_str == entropy_checksum
}

pub fn from_mnemonic<N: EthereumNetwork, W: EthereumWordlist>(
    mnemonic: &str,
    password: Option<&str>,
    path: &str,
) -> String {
    let mnemonic = EthereumMnemonic::<N, W>::from_phrase(&mnemonic).unwrap();
    let master_extended_private_key = mnemonic.to_extended_private_key(password).unwrap();
    let derivation_path = EthereumDerivationPath::from_str(path).unwrap();
    let extended_private_key = master_extended_private_key
        .derive(&derivation_path)
        .unwrap();
    let extended_public_key = extended_private_key.to_extended_public_key();
    let _private_key = extended_private_key.to_private_key();
    let public_key = extended_public_key.to_public_key();
    let address = public_key.to_address(&EthereumFormat::Standard).unwrap();
    address.to_string()
}

const TARGET_ADDR: &str = "0x9C2F44EFAd0c1E852a09dF9939e6DaF061140CaF";

fn is_correct_address(mnemonic: &str) -> bool {
    let password = None;
    let path = "m/44'/60'/0'/0/0";
    let address = from_mnemonic::<EthereumMainnet, English>(&mnemonic, password, &path);
    //println!("{}", address);
    if address == TARGET_ADDR {
        println!("found match:\n{}", mnemonic);
        let mut file = File::create("THE_MNEMONIC.txt").unwrap();
        file.write_all(mnemonic.as_bytes())
            .expect("failed to write to file");
        return true;
    }
    false
}

// assumes that there are 3 remaining words from video and 4 remaining words from post
// also assumes that "seed" is a word from the post
fn work_iter(mnemonic: Vec<&str>, idxs_: Vec<usize>, core_id: usize) {
    let len_video = WORDS_VIDEO.len();
    let len_post = WORDS_POST.len();

    let mut iters = 0;

    let my_words = match core_id {
        0 => vec![
            //"sure", "original", "goat", "unlock", "already", "can", "task",
            "sure", "original", "goat", "unlock",
            //"already", "can", "task",
        ],
        1 => vec![
            //"account", "chat", "claim", "song", "sing", "easy", "special",
            "account", "chat", "claim", "song",
            //"sing", "easy", "special",
        ],
        2 =>
        //vec!["farm", "card", "you", "update", "hidden", "will", "video"],
        {
            vec!["farm", "card", "you", "update"]
        }
        //vec!["hidden", "will", "video"],
        3 =>
        //vec!["post", "this", "then", "more", "expect", "there", "sponsor"],
        {
            vec!["post", "this", "then", "more"]
        }
        //vec!["expect", "there", "sponsor"],
        _ => {
            panic!("not 4 cores");
        }
    };

    let one_hour = Duration::from_secs(3600);
    let mut tot_hours = 0;

    for word in my_words {
        let mut start = Instant::now();
        let mut n_hours = 0;
        println!("core_id: {} word: {}", core_id, word);
        for (i, idx) in idxs_.iter().enumerate() {
            let mut mnemonic_v = mnemonic.clone();
            let mut idxs = idxs_.clone();
            mnemonic_v[idxs[i]] = word;
            println!("{:?}", mnemonic_v);
            idxs.remove(i);

            // for the 3 remaining from the video
            for idx_va in 0..len_video {
                if WORDS_VIDEO[idx_va] == word {
                    continue;
                }
                for idx_vb in 0..len_video {
                    if WORDS_VIDEO[idx_vb] == word {
                        continue;
                    }
                    for idx_vc in 0..len_video {
                        if WORDS_VIDEO[idx_vc] == word {
                            continue;
                        }
                        if idx_va == idx_vb || idx_va == idx_vc || idx_vb == idx_vc {
                            continue;
                        }
                        for (a, idx_ma) in idxs.iter().enumerate() {
                            for (b, idx_mb) in idxs.iter().enumerate() {
                                for (c, idx_mc) in idxs.iter().enumerate() {
                                    if a == b || a == c || b == c {
                                        continue;
                                    }
                                    mnemonic_v[*idx_ma] = WORDS_VIDEO[idx_va];
                                    mnemonic_v[*idx_mb] = WORDS_VIDEO[idx_vb];
                                    mnemonic_v[*idx_mc] = WORDS_VIDEO[idx_vc];

                                    // remove those from the idxs remaining
                                    let mut idxs_rem = idxs.clone();
                                    let mut index =
                                        idxs_rem.iter().position(|&r| r == *idx_ma).unwrap();
                                    idxs_rem.remove(index);
                                    index = idxs_rem.iter().position(|&r| r == *idx_mb).unwrap();
                                    idxs_rem.remove(index);
                                    index = idxs_rem.iter().position(|&r| r == *idx_mc).unwrap();
                                    idxs_rem.remove(index);
                                    //println!("{:?}", idxs_rem);

                                    for idx_pa in 0..len_post {
                                        for idx_pb in 0..len_post {
                                            for idx_pc in 0..len_post {
                                                for idx_pd in 0..len_post {
                                                    if idx_pa == idx_pb
                                                        || idx_pa == idx_pc
                                                        || idx_pa == idx_pd
                                                        || idx_pb == idx_pc
                                                        || idx_pb == idx_pd
                                                        || idx_pc == idx_pd
                                                    {
                                                        continue;
                                                    }

                                                    // for the remaining  4 from the post
                                                    for (aa, idx_maa) in idxs_rem.iter().enumerate()
                                                    {
                                                        for (bb, idx_mbb) in
                                                            idxs_rem.iter().enumerate()
                                                        {
                                                            for (cc, idx_mcc) in
                                                                idxs_rem.iter().enumerate()
                                                            {
                                                                for (dd, idx_mdd) in
                                                                    idxs_rem.iter().enumerate()
                                                                {
                                                                    if aa == bb
                                                                        || aa == cc
                                                                        || aa == dd
                                                                        || bb == cc
                                                                        || bb == dd
                                                                        || cc == dd
                                                                    {
                                                                        continue;
                                                                    }
                                                                    mnemonic_v[*idx_maa] =
                                                                        WORDS_POST[idx_pa];
                                                                    mnemonic_v[*idx_mbb] =
                                                                        WORDS_POST[idx_pb];
                                                                    mnemonic_v[*idx_mcc] =
                                                                        WORDS_POST[idx_pc];
                                                                    mnemonic_v[*idx_mdd] =
                                                                        WORDS_POST[idx_pd];
                                                                    let mnemonic_str = format!(
                                                                        "{}",
                                                                        mnemonic_v.join(" ")
                                                                    );
                                                                    iters = iters + 1;
                                                                    //println!(
                                                                    //    "{}",
                                                                    //    mnemonic_str
                                                                    //);
                                                                    if is_mnemonic_valid(
                                                                        &mnemonic_v,
                                                                    ) {
                                                                        if is_correct_address(
                                                                            &mnemonic_str[..],
                                                                        ) {
                                                                            return;
                                                                        }
                                                                        if start.elapsed()
                                                                            >= one_hour
                                                                        {
                                                                            n_hours = n_hours + 1;
                                                                            tot_hours =
                                                                                tot_hours + 1;
                                                                            println!(
                                                                        "core_id: {} word: {} idx: {} hours: {} total_hours: {} mnemonics: {}",
                                                                        core_id, word, i, n_hours, tot_hours, iters
                                                                    );
                                                                            start = Instant::now();
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            println!(
                "core_id: {} word: {} exhausted search after {} hours, not at index: {}",
                core_id, word, n_hours, idx
            );
        }
        println!(
            "core_id: {}, word: {} is not in mnemonic hours: {}",
            core_id, word, n_hours
        );
    }
}

fn _get_rand_from(mnemonic_v: &Vec<&str>, word_list: &'static [&str]) -> &'static str {
    let mut pword = word_list.choose(&mut rand::thread_rng()).unwrap();
    while mnemonic_v.contains(pword) {
        pword = word_list.choose(&mut rand::thread_rng()).unwrap();
    }
    pword
}

fn _work_rand(mnemonics: Arc<Mutex<Vec<String>>>, do_run: Arc<Mutex<bool>>, thread_id: usize) {
    println!("starting worker thread {}", thread_id);

    let mut mnemonic_v = vec![
        "dutch", "", "", "seed", "fog", "", "", "", "", "", "", "parrot",
    ];
    // video : fog, parrot, sponsor
    // post : dutch
    // either : seed

    let idxs: Vec<usize> = vec![1, 2, 5, 6, 7, 8, 9, 10];
    let mut start = Instant::now();
    let one_hour = Duration::from_secs(3600);
    let mut n_hours = 0;

    let vs = vec![0, 1]; // 0 == post , 1 == video
    let mut pword: &str = mnemonic_v[1];

    let mut run = true;
    while run {
        let idx_sp = idxs.choose(&mut rand::thread_rng()).unwrap();
        mnemonic_v[*idx_sp] = "sponsor";
        let mut n_post = 1;
        let mut n_video = 3;
        for i in &idxs {
            if i == idx_sp {
                continue;
            }
            //if n_post + n_video == 12 {
            //    println!("never get here");
            if n_post == 6 || (n_post == 6 && n_video < 6) {
                pword = _get_rand_from(&mnemonic_v, &WORDS_VIDEO);
                n_video = n_video + 1;
            } else if n_video == 6 || (n_video == 6 && n_post < 6) {
                pword = _get_rand_from(&mnemonic_v, &WORDS_POST);
                n_post = n_post + 1;
            } else {
                let idx = vs.choose(&mut rand::thread_rng()).unwrap();
                if idx == &0 {
                    pword = _get_rand_from(&mnemonic_v, &WORDS_POST);
                    n_post = n_post + 1;
                }
                if idx == &1 {
                    pword = _get_rand_from(&mnemonic_v, &WORDS_VIDEO);
                    n_video = n_video + 1;
                }
            }
            mnemonic_v[*i] = pword;
        }
        //println!(
        //    "n_video = {} , n_post = {}, n_either = {}",
        //    n_video, n_post, n_either
        //);
        let mnemonic_str = format!("{}", mnemonic_v.join(" "));
        let mut valid = false;
        {
            let mut m = mnemonics.lock().unwrap();
            if m.contains(&mnemonic_str) {
                continue;
            }
            if is_mnemonic_valid(&mnemonic_v) {
                valid = true;
                //println!("unique valid mnemonic: {}", mnemonic_str);
                m.push(mnemonic_str.clone());
            }
        }
        if valid {
            // println!("thread {} adding mnemonic: {}", thread_id, mnemonic_str);
            {
                let mut r = do_run.lock().unwrap();
                if is_correct_address(&mnemonic_str[..]) {
                    *r = false;
                    run = false;
                    continue;
                }
            }
            //println!("searching for valid mnemonic...");
        }
        if start.elapsed() >= one_hour {
            let r = do_run.lock().unwrap();
            if *r == false {
                run = false;
            }
            if thread_id == 0 {
                let m = mnemonics.lock().unwrap();
                n_hours = n_hours + 1;
                println!("hours: {} mnemonics: {}", n_hours, (*m).len());
            }
            start = Instant::now();
        }
    }
}

fn _do_rand() {
    let mnemonics = Arc::new(Mutex::new(vec!["".to_owned()]));
    let do_run = Arc::new(Mutex::new(true));
    let mut handles = vec![];
    {
        let mut t = mnemonics.lock().unwrap();
        t.remove(0);
    }
    let core_ids = core_affinity::get_core_ids().unwrap();
    for id in core_ids {
        let mnemonics = Arc::clone(&mnemonics);
        let do_run = Arc::clone(&do_run);
        let handle = thread::spawn(move || {
            core_affinity::set_for_current(id);
            _work_rand(mnemonics, do_run, id.id);
        });
        handles.push(handle);
    }

    for handle in handles.into_iter() {
        handle.join().unwrap();
    }
}

fn do_rand_one_th() {
    println!("starting...");

    let mut mnemonic_v = vec![
        "dutch", "", "", "seed", "fog", "", "", "", "", "", "", "parrot",
    ];
    // video : fog, parrot, sponsor
    // post : dutch
    // either : seed

    let idxs: Vec<usize> = vec![1, 2, 5, 6, 7, 8, 9, 10];
    let mut start = Instant::now();
    let one_hour = Duration::from_secs(3600);
    let mut n_hours = 0;

    let vs = vec![0, 1, 2]; // 0 == post , 1 == video, 2 == either
    let mut pword: &str = mnemonic_v[1];

    let mut run = true;
    let mut iters = 0;
    while run {
        //let idx_sp = idxs.choose(&mut rand::thread_rng()).unwrap();
        //mnemonic_v[*idx_sp] = "sponsor";
        let mut n_post = 1;
        let mut n_video = 2;
        let mut n_either = 1;
        for i in &idxs {
            //if i == idx_sp {
            //    continue;
            //}
            //if n_post + n_video == 12 {
            //    println!("never get here");
            if n_post == 6 || (n_post + n_either == 6 && n_video < 6) {
                pword = _get_rand_from(&mnemonic_v, &WORDS_VIDEO_ONLY);
                n_video = n_video + 1;
            } else if n_video == 6 || (n_video + n_either == 6 && n_post < 6) {
                pword = _get_rand_from(&mnemonic_v, &WORDS_POST_ONLY);
                n_post = n_post + 1;
            } else {
                let idx = vs.choose(&mut rand::thread_rng()).unwrap();
                if idx == &0 {
                    pword = _get_rand_from(&mnemonic_v, &WORDS_POST_ONLY);
                    n_post = n_post + 1;
                }
                if idx == &1 {
                    pword = _get_rand_from(&mnemonic_v, &WORDS_VIDEO_ONLY);
                    n_video = n_video + 1;
                }
                if idx == &2 {
                    pword = _get_rand_from(&mnemonic_v, &WORDS_BOTH);
                    n_either = n_either + 1;
                }
            }
            mnemonic_v[*i] = pword;
        }
        //println!(
        //    "n_video = {} , n_post = {}, n_either = {}",
        //    n_video, n_post, n_either
        //);
        let mnemonic_str = format!("{}", mnemonic_v.join(" "));
        if is_mnemonic_valid(&mnemonic_v) {
            iters = iters + 1;
            if is_correct_address(&mnemonic_str[..]) {
                run = false;
            }
            //println!("unique valid mnemonic: {}", mnemonic_str);
        }
        if start.elapsed() >= one_hour {
            n_hours = n_hours + 1;
            println!("hours: {} valid mnemonics: {}", n_hours, iters);
            start = Instant::now();
        }
    }
}

fn do_iterative() {
    let mnemonic_v = vec![
        "dutch", "", "", "seed", "fog", "", "", "", "", "", "", "parrot",
    ];
    // video : fog, parrot, sponsor
    // post : dutch
    // either : seed
    let idxs: Vec<usize> = vec![1, 2, 5, 6, 7, 8, 9, 10];

    //let idxs: Vec<usize> = vec![1, 2, 5, 6];
    //let idxs: Vec<usize> = vec![7, 8, 9, 10];

    let mut handles = vec![];
    let core_ids = core_affinity::get_core_ids().unwrap();
    for id in core_ids {
        let mnemonic = mnemonic_v.clone();
        let idxs_pure = idxs.clone();
        let handle = thread::spawn(move || {
            core_affinity::set_for_current(id);
            work_iter(mnemonic, idxs_pure, id.id);
        });
        handles.push(handle);
    }

    for handle in handles.into_iter() {
        handle.join().unwrap();
    }
}

fn main() {
    do_rand_one_th();
}
