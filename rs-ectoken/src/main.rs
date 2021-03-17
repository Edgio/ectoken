/**
* Copyright (C) 2021 Verizon. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
use clap::{crate_version, App, Arg};
use std::process;

fn main() {
    let matches = App::new("ectoken")
        .version(crate_version!())
        .author("Derek Shiell <derek@vdms.com>")
        .about("Verizon EdgeCast CDN ectoken cli.")
        .arg(
            Arg::with_name("key")
                .short("k")
                .long("key")
                .value_name("[KEY]")
                .help("Encryption key.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("token")
                .short("t")
                .long("token")
                .value_name("[TOKEN]")
                .help("Plaintext or ciphertext.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("decrypt")
                .short("d")
                .long("decrypt")
                .help("Decrypt token with provided key.")
                .takes_value(false),
        )
        .get_matches();

    let key = match matches.value_of("key") {
        Some(key) => key,
        None => {
            eprintln!("Error: 'key' must be specified.");
            process::exit(1);
        }
    };

    let token = match matches.value_of("token") {
        Some(token) => token,
        None => {
            eprintln!("Error: 'token' must be specified.");
            process::exit(1);
        }
    };

    let decrypt = matches.is_present("decrypt");

    let token = match decrypt {
        false => ectoken::encrypt(key, token),
        true => ectoken::decrypt(&key, &token),
    };

    println!("{}", token);
}
