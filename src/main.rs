use clap::{Parser, Subcommand, CommandFactory};
use clap_complete::{generate, shells::PowerShell};

use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use aes::Aes256;
use aes::cipher::{
    KeyIvInit,
    block_padding::Pkcs7,
    BlockEncryptMut,
    BlockDecryptMut,
};

use base64::{engine::general_purpose, Engine};
use cbc::{Encryptor, Decryptor};
use chrono::Utc;
use colored::*;
use cron::Schedule;
use data_encoding::BASE32;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use hmac::{Hmac, Mac};
use lipsum::lipsum_words;
use rand::{Rng, rngs::OsRng};
use ratatui::{prelude::*, widgets::*};
use regex::Regex;
use serde_json::Value;
use sha2::{Sha256, Digest};
use similar::TextDiff;
use urlencoding::{encode, decode};
use uuid::Uuid;
use atty;

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser)]
#[command(name = "toolbox", version, about = "Advanced CLI Toolbox")]
#[command(arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    JsonPretty { input: String },
    JsonMinify { input: String },

    JwtSign { payload: String, secret: String },
    JwtDecode { token: String },

    Base64Encode { input: Option<String> },
    Base64Decode { input: String },

    Base32Encode { input: String },
    Base32Decode { input: String },

    UrlEncode { input: String },
    UrlDecode { input: String },

    RegexTest { pattern: String, text: String },

    Uuid,
    Timestamp,

    Hash { input: Option<String> },
    Hmac { key: String, message: String },

    AesEncrypt { key: String, text: String },
    AesDecrypt { key: String, data: String },

    Diff { a: String, b: String },
    Lorem { words: usize },
    Random { min: i32, max: i32 },
    Password { length: usize },

    Upper { input: String },
    Lower { input: String },
    Ascii { input: String },

    GzipCompress { file: PathBuf },
    GzipDecompress { file: PathBuf },

    CronNext { expr: String },

    Tui,
    Completions,
}

fn read_stdin() -> Option<String> {
    if atty::is(atty::Stream::Stdin) {
        None
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).ok()?;
        Some(buf)
    }
}

fn main() {
    let cli = Cli::parse();

    // Match commands normally; for full case-insensitive support, you could lowercase strings manually
    match cli.command {
        Commands::JsonPretty { input } => {
            let v: Value = serde_json::from_str(&input).unwrap();
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }

        Commands::JsonMinify { input } => {
            let v: Value = serde_json::from_str(&input).unwrap();
            println!("{}", serde_json::to_string(&v).unwrap());
        }

        Commands::JwtSign { payload, secret } => {
            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::default(),
                &serde_json::from_str::<Value>(&payload).unwrap(),
                &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
            )
            .unwrap();
            println!("{token}");
        }

        Commands::JwtDecode { token } => {
            let data = jsonwebtoken::decode::<Value>(
                &token,
                &jsonwebtoken::DecodingKey::from_secret(&[]),
                &jsonwebtoken::Validation::default(),
            )
            .unwrap();
            println!("{}", serde_json::to_string_pretty(&data.claims).unwrap());
        }

        Commands::Base64Encode { input } => {
            let data = input.or_else(read_stdin).unwrap();
            println!("{}", general_purpose::STANDARD.encode(data));
        }

        Commands::Base64Decode { input } => {
            let bytes = general_purpose::STANDARD.decode(input).unwrap();
            println!("{}", String::from_utf8_lossy(&bytes));
        }

        Commands::Base32Encode { input } => println!("{}", BASE32.encode(input.as_bytes())),
        Commands::Base32Decode { input } => {
            let bytes = BASE32.decode(input.as_bytes()).unwrap();
            println!("{}", String::from_utf8_lossy(&bytes));
        }

        Commands::UrlEncode { input } => println!("{}", encode(&input)),
        Commands::UrlDecode { input } => println!("{}", decode(&input).unwrap()),

        Commands::RegexTest { pattern, text } => {
            println!("{}", Regex::new(&pattern).unwrap().is_match(&text));
        }

        Commands::Uuid => println!("{}", Uuid::new_v4().to_string().bright_cyan()),

        Commands::Timestamp => {
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            println!("{}", ts.to_string().yellow());
        }

        Commands::Hash { input } => {
            let data = input.or_else(read_stdin).unwrap();
            let mut h = Sha256::new();
            h.update(data);
            println!("{}", format!("{:x}", h.finalize()).bright_green());
        }

        Commands::Hmac { key, message } => {
            let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
            mac.update(message.as_bytes());
            let out = format!("{:x}", mac.finalize().into_bytes());
            println!("{}", out.bright_green());
        }

        Commands::AesEncrypt { key, text } => {
            let mut iv = [0u8; 16];
            OsRng.fill(&mut iv);

            let cipher = Encryptor::<Aes256>::new_from_slices(key.as_bytes(), &iv).unwrap();
            let mut buf = text.into_bytes();
            let buf_len = buf.len();
            let ct = cipher.encrypt_padded_mut::<Pkcs7>(&mut buf, buf_len).unwrap();

            println!("{}:{}", hex::encode(iv), hex::encode(ct));
        }

        Commands::AesDecrypt { key, data } => {
            let parts: Vec<_> = data.split(':').collect();
            let iv = hex::decode(parts[0]).unwrap();
            let mut buf = hex::decode(parts[1]).unwrap();

            let cipher = Decryptor::<Aes256>::new_from_slices(key.as_bytes(), &iv).unwrap();
            let pt = cipher.decrypt_padded_mut::<Pkcs7>(&mut buf).unwrap();
            println!("{}", String::from_utf8_lossy(pt));
        }

        Commands::Diff { a, b } => {
            let diff = TextDiff::from_lines(&a, &b);
            println!("{}", diff.unified_diff().to_string().blue());
        }

        Commands::Lorem { words } => println!("{}", lipsum_words(words)),

        Commands::Random { min, max } => {
            println!("{}", rand::thread_rng().gen_range(min..=max));
        }

        Commands::Password { length } => {
            let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            let mut rng = rand::thread_rng();
            let pwd: String = (0..length)
                .map(|_| chars[rng.gen_range(0..chars.len())] as char)
                .collect();
            println!("{pwd}");
        }

        Commands::Upper { input } => println!("{}", input.to_uppercase()),
        Commands::Lower { input } => println!("{}", input.to_lowercase()),

        Commands::Ascii { input } => {
            input.bytes().for_each(|b| print!("{b} "));
            println!();
        }

        Commands::GzipCompress { file } => {
            let data = fs::read(&file).unwrap();
            let mut enc = GzEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&data).unwrap();
            fs::write(file.with_extension("gz"), enc.finish().unwrap()).unwrap();
        }

        Commands::GzipDecompress { file } => {
            let data = fs::read(&file).unwrap();
            let mut dec = GzDecoder::new(&data[..]);
            let mut out = Vec::new();
            dec.read_to_end(&mut out).unwrap();
            fs::write(file.with_extension("out"), out).unwrap();
        }

        Commands::CronNext { expr } => {
            let schedule: Schedule = expr.parse().unwrap();
            let next = schedule.upcoming(Utc).next().unwrap();
            println!("{next}");
        }

        Commands::Completions => {
            generate(PowerShell, &mut Cli::command(), "toolbox", &mut io::stdout());
        }

        Commands::Tui => run_tui(),
    }
}

fn run_tui() {
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout())).unwrap();
    terminal.draw(|f| {
        let block = Block::default()
            .title("Toolbox TUI")
            .borders(Borders::ALL);
        f.render_widget(block, f.size());
    }).unwrap();
}
