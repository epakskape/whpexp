/*
 * PayloadFuzz leverages the Windows Hypervisor Platform to test the execution
 * of arbitrary payloads using a supported payload generator.
 */
extern crate clap;
extern crate futures;
extern crate libwhp;
extern crate redis;
extern crate tokio;
extern crate url;
extern crate x86asm;

pub mod generator;
pub mod vmm;

use crate::generator::*;
use crate::vmm::*;

use std::io::Write;
use std::panic;
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use async_std::future;

use clap::{App, Arg};

use libwhp::*;

use rand::prelude::*;

use redis::AsyncCommands;
use redis::RedisFuture;
use redis::RedisResult;

use std::io::Cursor;
use x86asm::{InstructionReader, Mnemonic, Mode};

const CODE_VIRTUAL_BASE_ADDRESS: u64 = 0x20000000;
const CODE_REGION_SIZE: u64 = 4096;

#[tokio::main]
async fn main() {
    let matches = App::new("cpufuzz")
        .arg(
            Arg::with_name("vm_count")
                .short("v")
                .long("vm_count")
                .takes_value(true)
                .help("The number of VMs to run concurrently"),
        )
        .arg(
            Arg::with_name("instance")
                .short("i")
                .long("instance")
                .takes_value(true)
                .help("The instance identifier"),
        )
        .arg(
            Arg::with_name("generator")
                .short("g")
                .long("generator")
                .takes_value(true)
                .help("The generator use for the payload (options: default, reverse_nop)"),
        )
        .get_matches();

    let vm_count: u32 = matches.value_of("vm_count").unwrap_or("1").parse().unwrap();
    let instance_id: u32 = matches.value_of("instance").unwrap_or("0").parse().unwrap();
    let generator_name: String = matches
        .value_of("generator")
        .unwrap_or("default")
        .to_string();

    if instance_id == 0 {
        let mut children = Vec::new();

        for child_instance_id in 0..vm_count {
            let instance_str = (child_instance_id + 1).to_string();

            let child = Command::new(std::env::current_exe().unwrap())
                .args(&["-i", &instance_str])
                .args(&["-g", &generator_name])
                .spawn()
                .expect("failed to execute child");

            children.push(child);
        }

        for mut child in children {
            child.wait().unwrap();
        }
    } else {
        let mut generator = match generator_name.as_str() {
            "default" => ReverseNopGenerator::new(),
            "reverse_nop" => ReverseNopGenerator::new(),
            _ => panic!("unknown generator"),
        };

        worker(instance_id, &mut generator).await;
    }
}

async fn worker<T: PayloadGenerator + ?Sized>(vm_num: u32, generator: &mut T) {
    println!("Worker {} spawned", vm_num);

    let redis_client =
        redis::Client::open("redis://127.0.0.1").expect("failed to initialize redis client");
    let mut redis_con = redis_client
        .get_async_connection()
        .await
        .expect("failed to connect to redis server at 127.0.0.1");

    let mut rng = rand::thread_rng();

    let mut num: usize = 0;
    let mut num_valid: usize = 0;

    loop {
        // Ideally we would only set up the VM once to avoid initializatio and
        // teardown costs, but to ensure consistent execution we need to ensure
        // that the entire VM state has been reinitialized.
        let mut vm = VirtualMachine::new(
            vm_num as usize,
            VirtualMachineConfig {
                processor_count: 1,
                memory_layout: MemoryLayout {
                    physical_layout: vec! [
                        PhysicalMemoryRange {
                            base_address: 0x10000000,
                            region_size: 0x400000,
                            region_type: MemoryRegionType::PageTables,
                            ept_protection: MemoryProtection::ReadWrite
                        },
                        PhysicalMemoryRange {
                            base_address: 0x20000000,
                            region_size: CODE_REGION_SIZE as usize,
                            region_type: MemoryRegionType::Code,
                            ept_protection: MemoryProtection::ReadWriteExecute
                        },
                        PhysicalMemoryRange {
                            base_address: 0x30000000,
                            region_size: 0x1000,
                            region_type: MemoryRegionType::Stack,
                            ept_protection: MemoryProtection::ReadWrite
                        }
                    ],
                    virtual_layout: vec! [
                        // Code virtual mapping
                        VirtualMemoryDescriptor {
                            base_address: CODE_VIRTUAL_BASE_ADDRESS,
                            region_type: MemoryRegionType::Code,
                            memory_descriptors: vec! [
                                MemoryDescriptor {
                                    physical_address: 0x20000000,
                                    virtual_protection: MemoryProtection::ReadWriteExecute
                                }
                            ]
                        },

                        // Stack virtual mapping
                        VirtualMemoryDescriptor {
                            base_address: 0x30000000,
                            region_type: MemoryRegionType::Stack,
                            memory_descriptors: vec! [
                                MemoryDescriptor {
                                    physical_address: 0x30000000,
                                    virtual_protection: MemoryProtection::ReadWrite
                                }
                            ]
                        },
                    ]
                },
            },
        );

        vm.setup();

        num += 1;

        if (num % 100) == 0 {
            println!(
                "Worker {} [valid={} / invalid={} = {} valid ratio]",
                vm.vm_id,
                num_valid,
                num,
                (num_valid as f32) / (num as f32)
            );
            std::io::stdout().flush().ok();
        }

        let mut buf: Vec<u8> = vec![0xcc; CODE_REGION_SIZE as usize];

        let mut previous_payload: Vec<u8>;

        // Randomly select an existing key to determine if we can execute from within a random
        // offset into it
        let mut new_payload: Vec<u8>;

        loop {
            previous_payload = Vec::new();

            if rng.gen_bool(0.50) == true {
                let res: RedisResult<String> = redis_con.srandmember("valid").await;

                match res {
                    Ok(rkey) => {
                        previous_payload = hex::decode(rkey).unwrap();
                    }
                    _ => {}
                };
            }

            new_payload = generator.generate(&previous_payload);

            // Has the new payload we're about to test already been tested? If so, generate another
            // payload.
            let dur = Duration::from_secs(2);
            let get_fut: RedisFuture<u32> = redis_con.sismember("valid", hex::encode(&new_payload));
            let get_res = future::timeout(dur, get_fut).await.unwrap();

            if get_res.is_err() || get_res.unwrap() == 0 {
                break;
            }
        }

        // Copy the new payload into the staging buffer.
        let buf_slice = &mut buf[0..new_payload.len()];

        buf_slice.copy_from_slice(&new_payload);

        let initial_rip = (CODE_VIRTUAL_BASE_ADDRESS + CODE_REGION_SIZE) as usize - new_payload.len();

        // Copy the staging buffer into physical memory for the VM at the end of
        // the mapping to ensure that any attempt to execute beyond the mapping
        // will fault.
        {
            let mem = vm.get_physical_memory_slice_mut(initial_rip, new_payload.len());
            mem.copy_from_slice(buf_slice);
        }

        let initial_rsp: usize;
        {
            let mut vpe0 = vm.virtual_processors.get(0).unwrap().write().unwrap();

            // Set the general purpose registers to a high value to increase the likelihood of
            // generating a memory access fault if they are used to access memory.
            vm.set_initial_registers(&mut vpe0.vp, 0xf1f1f1f1_f1f1f1f1, initial_rip as u64);

            // Get the initial stack pointer for later comparison.
            let mut reg_names: [WHV_REGISTER_NAME; 1 as usize] = Default::default();
            let mut reg_values: [WHV_REGISTER_VALUE; 1 as usize] = Default::default();

            reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterRsp;
            reg_values[0].Reg64 = 0;

            // Create stack with stack base at high end of mapped payload
            vpe0.vp.get_registers(&reg_names, &mut reg_values).unwrap();

            initial_rsp = unsafe { reg_values[0].Reg64 as usize };
        }

        // Execute the VM.
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let pair2 = pair.clone();

        vm.execute(pair2);

        let mut cancelled = false;
        {
            let (lock, cvar) = &*pair;
            let mut done = lock.lock().unwrap();

            let result = cvar.wait_timeout(done, Duration::from_micros(1)).unwrap();

            done = result.0;

            // If execution timed out, then cancel execution of the virtual processors.
            if *done == false {
                let vpe0 = vm.virtual_processors.get(0).unwrap().read().unwrap();
                vpe0.vp.cancel_run().unwrap();
                cancelled = true;
            }
        }

        // If we cancelled the VM, then wait for the thread managing the VM to cleanly exit.
        if cancelled {
            let (lock, cvar) = &*pair;
            let mut done = lock.lock().unwrap();

            loop {
                let result = cvar.wait_timeout(done, Duration::from_millis(10)).unwrap();

                done = result.0;

                if *done == true {
                    break;
                }
            }
        }

        // Check to see if the payload that was executed is valid or not.
        {
            let vpe0 = vm.virtual_processors.get(0).unwrap().read().unwrap();

            let rip = vpe0.last_exit_context.VpContext.Rip as usize;

            // Query the current stack pointer for use when checking if the payload is valid.
            let mut reg_names: [WHV_REGISTER_NAME; 1 as usize] = Default::default();
            let mut reg_values: [WHV_REGISTER_VALUE; 1 as usize] = Default::default();

            reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterRsp;
            reg_values[0].Reg64 = 0;

            vpe0.vp.get_registers(&reg_names, &mut reg_values).unwrap();

            let final_rsp = unsafe { reg_values[0].Reg64 };

            // If the instruction pointer is equal to the start of the code
            // mapping (meaning the instruction didn't execute), then continue
            // to the next payload as this one is invalid.
            if rip <= CODE_VIRTUAL_BASE_ADDRESS as usize 
                || rip > CODE_VIRTUAL_BASE_ADDRESS as usize + 0x1000 {
                continue;
            }

            let current_payload = vm.get_physical_memory_slice(initial_rip as usize, new_payload.len());
            let starting_payload_slice = &buf[0..new_payload.len()];

            // Test to see if the payload is generally valid and that the specific generator we are using
            // considers it to be valid. If it is valid, then we'll add the payload to the valid set
            // in redis, otherwise we'll add it to the invalid set.
            if is_generally_valid(current_payload, starting_payload_slice)
                && generator.is_valid(
                    &previous_payload,
                    &new_payload,
                    initial_rip,
                    rip,
                    initial_rsp,
                    final_rsp as usize,
                )
            {
                num_valid += 1;

                let payload_hex = hex::encode(&current_payload);

                let dur = Duration::from_secs(2);
                let set_fut: RedisFuture<()> = redis_con.sadd("valid", &payload_hex);

                let _ = future::timeout(dur, set_fut).await;
            } else {
                let new_payload_hex = hex::encode(new_payload);

                let dur = Duration::from_secs(2);
                let set_fut: RedisFuture<()> = redis_con.sadd("invalid", &new_payload_hex);

                let _ = future::timeout(dur, set_fut).await;
            }
        }
    }

    // Checks to see if the current payload is generally valid using the following logic:
    //   - the payload does not exceed the maximum payload size.
    //   - the current payload in memory matches the initial version that was stored in memory (e.g. not corrupted).
    //   - the current payload does not contain a branch instruction
    fn is_generally_valid(current_payload: &[u8], starting_payload: &[u8]) -> bool {
        // Check to see if the payload itself was modified in memory.
        if current_payload != starting_payload {
            return false;
        }

        // Analyze the payload to determine if it should be treated as valid and stored
        // in the database. Treat payloads with branch instructions as invalid.
        let valid = panic::catch_unwind(|| {
            let instr_cursor = Cursor::new(current_payload);
            let mut instr_reader = InstructionReader::new(instr_cursor, Mode::Protected);

            let mut valid = true;
            loop {
                let instr_res = instr_reader.read();

                if instr_res.is_err() {
                    break;
                }

                let instr = instr_res.unwrap();

                match instr.mnemonic {
                    // Ignore conditional branch instructions
                    Mnemonic::JA
                    | Mnemonic::JAE
                    | Mnemonic::JB
                    | Mnemonic::JBE
                    | Mnemonic::JC
                    | Mnemonic::JCXZ
                    | Mnemonic::JE
                    | Mnemonic::JECXZ
                    | Mnemonic::JG
                    | Mnemonic::JGE
                    | Mnemonic::JL
                    | Mnemonic::JLE
                    | Mnemonic::JNA
                    | Mnemonic::JNAE
                    | Mnemonic::JNB
                    | Mnemonic::JNBE
                    | Mnemonic::JNC
                    | Mnemonic::JNE
                    | Mnemonic::JNG
                    | Mnemonic::JNGE
                    | Mnemonic::JNL
                    | Mnemonic::JNLE
                    | Mnemonic::JNO
                    | Mnemonic::JNP
                    | Mnemonic::JNS
                    | Mnemonic::JNZ
                    | Mnemonic::JO
                    | Mnemonic::JP
                    | Mnemonic::JPE
                    | Mnemonic::JPO
                    | Mnemonic::JRCXZ
                    | Mnemonic::JS
                    | Mnemonic::JZ
                    | Mnemonic::LOOP
                    | Mnemonic::LOOPE
                    | Mnemonic::LOOPNE => {
                        valid = false;
                        break;
                    }

                    // Ignore unconditional branch instructions
                    Mnemonic::CALL | Mnemonic::JMP | Mnemonic::RET => {
                        valid = false;
                        break;
                    }

                    _ => {}
                };
            }

            valid
        });

        if valid.is_err() || valid.unwrap() == false {
            return false;
        }

        true
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {

    use crate::vmm::*;

    use std::sync::Arc;
    use std::sync::Condvar;
    use std::sync::Mutex;

    const CODE_VIRTUAL_BASE_ADDRESS: u64 = 0x20000000;
    const CODE_REGION_SIZE: u64 = 4096;

    #[test]
    pub fn test_vm_create() {
        let mut vm = VirtualMachine::new(
            1,
            VirtualMachineConfig {
                processor_count: 1,
                memory_layout: MemoryLayout {
                    physical_layout: vec! [
                        PhysicalMemoryRange {
                            base_address: 0x10000000,
                            region_size: 0x400000,
                            region_type: MemoryRegionType::PageTables,
                            ept_protection: MemoryProtection::ReadWrite
                        },
                        PhysicalMemoryRange {
                            base_address: 0x20000000,
                            region_size: CODE_REGION_SIZE as usize,
                            region_type: MemoryRegionType::Code,
                            ept_protection: MemoryProtection::ReadWriteExecute
                        },
                        PhysicalMemoryRange {
                            base_address: 0x30000000,
                            region_size: 0x1000,
                            region_type: MemoryRegionType::Stack,
                            ept_protection: MemoryProtection::ReadWrite
                        }
                    ],
                    virtual_layout: vec! [
                        // Code virtual mapping
                        VirtualMemoryDescriptor {
                            base_address: CODE_VIRTUAL_BASE_ADDRESS,
                            region_type: MemoryRegionType::Code,
                            memory_descriptors: vec! [
                                MemoryDescriptor {
                                    physical_address: 0x20000000,
                                    virtual_protection: MemoryProtection::ReadWriteExecute
                                }
                            ]
                        },

                        // Stack virtual mapping
                        VirtualMemoryDescriptor {
                            base_address: 0x30000000,
                            region_type: MemoryRegionType::Stack,
                            memory_descriptors: vec! [
                                MemoryDescriptor {
                                    physical_address: 0x30000000,
                                    virtual_protection: MemoryProtection::ReadWrite
                                }
                            ]
                        },
                    ]
                },
            },
        );

        vm.setup();

        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let pair2 = pair.clone();

        vm.execute(pair2);

        let (lock, cvar) = &*pair;
        let done = lock.lock().unwrap();

        let _ = cvar.wait(done);
    }
}
