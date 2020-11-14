use core_affinity;
use hex::FromHex;
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
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
        return true;
    }
    false
}

fn get_rand_from(mnemonic_v: &Vec<&str>, word_list: &'static [&str]) -> &'static str {
    let mut pword = word_list.choose(&mut rand::thread_rng()).unwrap();
    while mnemonic_v.contains(pword) {
        pword = word_list.choose(&mut rand::thread_rng()).unwrap();
    }
    pword
}

fn work(mnemonics: Arc<Mutex<Vec<String>>>, do_run: Arc<Mutex<bool>>, thread_id: usize) {
    let mut mnemonic_v = vec![
        "dutch", "", "", "seed", "fog", "", "", "", "", "", "", "parrot",
    ];
    // video : fog, parrot, sponsor
    // post : dutch
    // both : seed
    println!("starting worker thread {}", thread_id);

    let idxs: Vec<usize> = vec![1, 2, 5, 6, 7, 8, 9, 10];
    let mut run = true;
    let mut start = Instant::now();
    let five_min = Duration::from_secs(300);

    let vs = vec![0, 1, 2]; // 0 == post , 1 == video , 2 == either
    let mut pword: &str = mnemonic_v[1];

    while run {
        let idx_sp = idxs.choose(&mut rand::thread_rng()).unwrap();
        mnemonic_v[*idx_sp] = "sponsor";
        let mut n_post = 1;
        let mut n_video = 3;
        let mut n_either = 1;
        for i in &idxs {
            if i == idx_sp {
                continue;
            }
            if n_post + n_video + n_either == 12 {
                println!("never get here");
            } else if n_post == 6 || (n_post + n_either == 6 && n_video < 6) {
                pword = get_rand_from(&mnemonic_v, &WORDS_VIDEO_ONLY);
                n_video = n_video + 1;
            } else if n_video == 6 || (n_video + n_either == 6 && n_post < 6) {
                pword = get_rand_from(&mnemonic_v, &WORDS_POST_ONLY);
                n_post = n_post + 1;
            } else {
                let idx = vs.choose(&mut rand::thread_rng()).unwrap();
                if idx == &0 {
                    pword = get_rand_from(&mnemonic_v, &WORDS_POST_ONLY);
                    n_post = n_post + 1;
                }
                if idx == &1 {
                    pword = get_rand_from(&mnemonic_v, &WORDS_VIDEO_ONLY);
                    n_video = n_video + 1;
                }
                if idx == &2 {
                    pword = get_rand_from(&mnemonic_v, &WORDS_BOTH);
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
        if start.elapsed() >= five_min {
            let r = do_run.lock().unwrap();
            if *r == false {
                run = false;
            }
            start = Instant::now();
        }
    }
}

fn main() {
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
            work(mnemonics, do_run, id.id);
        });
        handles.push(handle);
    }

    for handle in handles.into_iter() {
        handle.join().unwrap();
    }
}

const WORDLIST: [&str; 2048] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address",
    "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid",
    "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst",
    "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual",
    "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear",
    "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed",
    "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt",
    "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome",
    "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony",
    "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin",
    "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better",
    "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter",
    "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom",
    "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus",
    "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy",
    "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle",
    "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz",
    "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
    "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital",
    "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash",
    "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught",
    "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal",
    "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase",
    "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon",
    "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean",
    "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog",
    "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast",
    "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come",
    "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress",
    "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral",
    "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin",
    "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl",
    "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
    "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry",
    "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve",
    "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring",
    "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide",
    "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay",
    "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit",
    "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy",
    "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary",
    "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur",
    "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display",
    "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll",
    "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
    "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip",
    "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty",
    "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy",
    "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either",
    "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else",
    "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable",
    "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine",
    "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire",
    "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error",
    "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
    "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse",
    "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand",
    "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow",
    "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family",
    "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue",
    "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
    "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file",
    "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first",
    "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee",
    "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam",
    "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork",
    "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame",
    "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit",
    "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery",
    "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate",
    "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture",
    "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance",
    "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
    "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown",
    "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid",
    "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt",
    "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
    "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health",
    "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden",
    "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday",
    "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host",
    "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry",
    "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify",
    "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune",
    "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index",
    "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit",
    "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane",
    "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite",
    "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar",
    "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge",
    "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup",
    "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten",
    "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake",
    "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
    "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left",
    "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson",
    "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like",
    "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan",
    "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge",
    "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine",
    "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
    "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine",
    "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix",
    "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media",
    "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry",
    "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
    "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed",
    "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster",
    "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor",
    "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum",
    "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
    "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect",
    "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next",
    "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable",
    "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak",
    "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
    "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic",
    "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose",
    "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original",
    "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
    "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace",
    "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot",
    "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment",
    "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people",
    "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
    "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer",
    "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please",
    "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police",
    "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato",
    "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
    "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison",
    "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote",
    "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull",
    "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose",
    "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question",
    "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio",
    "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate",
    "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall",
    "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region",
    "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember",
    "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace",
    "report", "require", "rescue", "resemble", "resist", "resource", "response", "result",
    "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
    "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple",
    "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance",
    "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber",
    "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail",
    "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi",
    "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme",
    "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub",
    "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek",
    "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service",
    "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell",
    "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop",
    "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since",
    "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin",
    "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim",
    "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack",
    "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar",
    "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul",
    "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
    "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split",
    "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square",
    "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand",
    "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still",
    "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
    "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit",
    "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun",
    "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise",
    "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear",
    "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system",
    "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste",
    "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test",
    "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this",
    "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt",
    "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today",
    "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue",
    "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss",
    "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
    "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial",
    "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly",
    "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey",
    "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
    "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair",
    "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until",
    "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge",
    "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague",
    "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
    "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel",
    "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage",
    "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice",
    "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall",
    "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
    "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird",
    "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip",
    "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink",
    "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder",
    "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist",
    "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone",
    "zoo",
];

//const POSSIBLE_WORDS: [&str; 85] = [
//    "word", "parrot", "time", "song", "when", "because", "fog", "know", "initial", "original",
//    "cattle", "goat", "seed", "roast", "claim", "left", "only", "high", "dutch", "address",
//    "there", "that", "dinner", "all", "wait", "now", "round", "bring", "then", "coin", "very",
//    "possible", "hidden", "video", "rib", "like", "man", "unlock", "soon", "have", "mind", "they",
//    "ten", "sponsor", "sing", "more", "capital", "idea", "chat", "what", "market", "total", "good",
//    "sure", "post", "gain", "great", "task", "expect", "year", "stay", "one", "best", "already",
//    "update", "come", "forest", "act", "hard", "profit", "you", "easy", "will", "account", "chase",
//    "top", "head", "current", "this", "phrase", "spend", "make", "can", "month", "trade",
//];

const _POSSIBLE_WORDS: [&str; 81] = [
    "word", "time", "song", "when", "because", "know", "initial", "original", "cattle", "goat",
    "roast", "claim", "left", "only", "high", "address", "there", "that", "dinner", "all", "wait",
    "now", "round", "bring", "then", "coin", "very", "possible", "hidden", "video", "rib", "like",
    "man", "unlock", "soon", "have", "mind", "they", "ten", "sponsor", "sing", "more", "capital",
    "idea", "chat", "what", "market", "total", "good", "sure", "post", "gain", "great", "task",
    "expect", "year", "stay", "one", "best", "already", "update", "come", "forest", "act", "hard",
    "profit", "you", "easy", "will", "account", "chase", "top", "head", "current", "this",
    "phrase", "spend", "make", "can", "month", "trade",
];

const _WORDS_VIDEO: [&str; 28] = [
    "sure", "original", "goat", "you", "post", "unlock", "hidden", "will", "then", "fog", "more",
    "already", "can", "there", "task", "account", "this", "seed", "update", "chat", "sponsor",
    "claim", "song", "video", "expect", "sing", "parrot", "easy",
];

const _WORDS_POST: [&str; 69] = [
    "what", "chase", "very", "good", "man", "capital", "you", "high", "best", "only", "gain",
    "round", "possible", "post", "phrase", "mind", "month", "roast", "great", "hidden", "will",
    "then", "year", "idea", "head", "more", "stay", "spend", "now", "current", "there", "all",
    "bring", "have", "wait", "when", "this", "come", "act", "seed", "they", "dinner", "update",
    "top", "word", "address", "hard", "market", "know", "make", "rib", "because", "expect",
    "video", "trade", "one", "time", "soon", "initial", "dutch", "ten", "like", "left", "cattle",
    "profit", "that", "forest", "coin", "total",
];

const WORDS_VIDEO_ONLY: [&str; 13] = [
    "sure", "original", "goat", "unlock", "already", "can", "task", "account", "chat", "claim",
    "song", "sing", "easy",
];

const WORDS_POST_ONLY: [&str; 56] = [
    "what", "chase", "very", "good", "man", "capital", "high", "best", "only", "gain", "round",
    "possible", "phrase", "mind", "month", "roast", "great", "year", "idea", "head", "stay",
    "spend", "now", "current", "all", "bring", "have", "wait", "when", "come", "act", "they",
    "dinner", "top", "word", "address", "hard", "market", "know", "make", "rib", "because",
    "trade", "one", "time", "soon", "initial", "ten", "like", "left", "cattle", "profit", "that",
    "forest", "coin", "total",
];

const WORDS_BOTH: [&str; 11] = [
    "you", "update", "hidden", "will", "video", "post", "this", "then", "more", "expect", "there",
];
