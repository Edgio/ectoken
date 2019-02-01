
use std::env;
use std::process;

fn main() {
    let usage = "Usage:
 To Encrypt:
     ectoken <key> <text>
 or:
     ectoken encrypt <key> <text>
 To Decrypt:
     ectoken decrypt <key> <text>
";
    let args: Vec<String> = env::args().collect();

    let config = Config::new(&args).unwrap_or_else(|err| {
        println!("Problem parsing arguments: {}", err);
        println!("{}", usage);
        process::exit(1);
    });

    let result = match config.action.as_str() {
        "encrypt" => ectoken::encrypt_v3(config.key.as_str(), config.text.as_str()),
        "decrypt" => ectoken::decrypt_v3(config.key.as_str(), config.text.as_str()).unwrap_or_else(|err| {
            println!("error: {}", err);
            process::exit(-1);
        }),
        _ => {
            println!("Unknown action: it must be one of (encrypt or decrypt)");
            println!("{}", usage);
            process::exit(0);
        }
    };

    println!("{}", result);
}

#[derive(Debug)]
struct Config {
    action: String,
    key: String,
    text: String,
}

impl Config {
    fn new(args: &[String]) -> Result<Config, &'static str> {
        match args.len() {
            3 => Ok(Config {
                action: String::from("encrypt"),
                key: args[1].clone(),
                text: args[2].clone(),
            }),
            4 => Ok(Config {
                action: args[1].clone(),
                key: args[2].clone(),
                text: args[3].clone(),
            }),
            _ => Err("Invalid number of arguments"),
        }
    }
}