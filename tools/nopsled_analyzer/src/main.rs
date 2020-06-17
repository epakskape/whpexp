extern crate clap;
extern crate futures;
extern crate hex;
extern crate redis;

use std::time::Duration;

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::{prelude::*, BufReader};

use async_std::future;

use std::cell::RefCell;
use std::rc::Rc;

use clap::{App, Arg};

use redis::AsyncCommands;
use redis::RedisFuture;

struct ByteChain {
    pub byte_value: u8,
    pub occurrences: u64,
    pub valid_precede: Box<HashMap<u8, Rc<RefCell<ByteChain>>>>,
}

impl ByteChain {
    pub fn new(byte_value_arg: u8) -> ByteChain {
        ByteChain {
            byte_value: byte_value_arg,
            occurrences: 1,
            valid_precede: Box::new(HashMap::<u8, Rc<RefCell<ByteChain>>>::new()),
        }
    }
}

#[tokio::main]
async fn main() {
    let matches = App::new("nopanalyzer")
        .arg(
            Arg::with_name("file_path")
                .short("f")
                .long("file_path")
                .takes_value(true)
                .help("The file containing the nops to analyze"),
        )
        .arg(
            Arg::with_name("depth")
                .short("d")
                .long("depth")
                .takes_value(true)
                .help("The maximum depth to dispaly the tree"),
        )
        .arg(
            Arg::with_name("command")
                .short("c")
                .long("command")
                .takes_value(true)
                .help("The command to execute (graph, tree)"),
        )
        .arg(
            Arg::with_name("redis")
                .short("r")
                .long("redis")
                .takes_value(false)
                .help("Use the local redis server to acquire valid byte chains"),
        )
        .get_matches();

    let nop_file_path: String = matches.value_of("file_path").unwrap_or("").to_string();
    let depth: u32 = matches.value_of("depth").unwrap_or("3").parse().unwrap();
    let command = matches.value_of("command").unwrap_or("tree").to_string();
    let use_redis = matches.is_present("redis");

    let byte_chain_root: Rc<RefCell<ByteChain>> = Rc::new(RefCell::new(ByteChain::new(0)));
    let mut predecessor_map: HashMap<u8, u8> = HashMap::new();

    if nop_file_path.len() > 0 {
        // If a file was specified, then populate the byte chain from a file containing
        // hex strings representing each valid byte chain.
        let nop_file = File::open(nop_file_path).unwrap();
        let reader = BufReader::new(nop_file);

        for line in reader.lines() {
            let line_str = line.unwrap();
            let payload: Vec<u8> = hex::decode(&line_str).unwrap();

            update_byte_chain(&mut predecessor_map, byte_chain_root.clone(), &payload);
        }
    } else if use_redis == true {
        // If redis should be used, then extract the valid byte chains from the redis server.
        redis_populate_byte_chain(&mut predecessor_map, byte_chain_root.clone()).await;
    } else {
        panic!("invalid mode");
    }

    match command.as_ref() {
        "graph" => {
            // Generate a graph describing describing "X is a valid predecessor
            // for Y" as X -> Y.
            println!("digraph {{");
            for pair in predecessor_map.into_iter() {
                println!("b_{:#02X} -> b_{:#02X};", pair.0, pair.1);
            }
            println!("}}");
        }
        "tree" => {
            println!("Displaying successor tree to a depth of {}", depth);
            if depth > 0 {
                dump_byte_chain(byte_chain_root.clone(), depth, depth);
            }
        }
        _ => {
            panic!("unexpected command");
        }
    }
}

async fn redis_populate_byte_chain(
    predecessor_map: &mut HashMap<u8, u8>,
    byte_chain_root: Rc<RefCell<ByteChain>>,
) {
    let redis_client =
        redis::Client::open("redis://127.0.0.1").expect("failed to initialize redis client");
    let mut redis_con = redis_client
        .get_async_connection()
        .await
        .expect("failed to connect to redis server at 127.0.0.1");

    let dur = Duration::from_secs(2);
    let members_fut: RedisFuture<HashSet<String>> = redis_con.smembers("valid");
    let members_res = future::timeout(dur, members_fut).await.unwrap();

    if members_res.is_err() {
        panic!("unable to query valid payloads");
    }

    let members: HashSet<String> = members_res.unwrap();

    for member in members {
        let member_raw = hex::decode(member).unwrap();
        update_byte_chain(predecessor_map, byte_chain_root.clone(), &member_raw);
    }
}

fn dump_byte_chain(byte_chain_root: Rc<RefCell<ByteChain>>, depth: u32, max_depth: u32) {
    for kv in byte_chain_root.borrow().valid_precede.values() {
        let bc = kv.borrow();

        for _i in depth..max_depth {
            print!("   ");
        }

        println!(
            "{:X} - occurrences {} valid preds {}",
            bc.byte_value,
            bc.occurrences,
            bc.valid_precede.len()
        );

        if depth > 0 {
            dump_byte_chain(kv.clone(), depth - 1, max_depth);
        }
    }
}

fn update_byte_chain(
    predecessor_map: &mut HashMap<u8, u8>,
    byte_chain_root: Rc<RefCell<ByteChain>>,
    payload: &[u8],
) {
    let mut current_byte_chain_ref = byte_chain_root;
    let mut iteration = 0;
    let mut last_byte_value = 0;

    for byte_value in payload.iter().rev() {
        if iteration > 1 {
            predecessor_map.insert(*byte_value, last_byte_value);
        }

        let next_byte_chain;
        {
            let mut current_byte_chain_mut = current_byte_chain_ref.borrow_mut();

            if let Some(nbc) = current_byte_chain_mut.valid_precede.get(byte_value) {
                nbc.borrow_mut().occurrences += 1;
                next_byte_chain = nbc.clone();
            } else {
                next_byte_chain = Rc::new(RefCell::new(ByteChain::new(*byte_value)));
                next_byte_chain.borrow_mut().byte_value = *byte_value;
                current_byte_chain_mut
                    .valid_precede
                    .insert(*byte_value, next_byte_chain.clone());
            }
        }

        current_byte_chain_ref = next_byte_chain.clone();
        last_byte_value = *byte_value;
        iteration += 1;
    }
}
