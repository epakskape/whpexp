use rand::prelude::*;

pub trait PayloadGenerator {
    fn generate(&mut self, previous_payload: &[u8]) -> Vec<u8>;
    fn is_valid(
        &self,
        previous_payload: &[u8],
        new_payload: &[u8],
        rip: usize,
        initial_rsp: usize,
        final_rsp: usize,
    ) -> bool;
}

pub struct ReverseNopGenerator {
    rng: ThreadRng,
}

impl ReverseNopGenerator {
    pub fn new() -> ReverseNopGenerator {
        ReverseNopGenerator {
            rng: rand::thread_rng(),
        }
    }
}

//
// The ReverseNopGenerator generates nop sleds backwards similar to nop sled
// generators like Opty2 in Metasploit.
//
// The generate method prepends a random byte to the provided payload (if one
// was provided) and returns this as the new payload.
//
impl PayloadGenerator for ReverseNopGenerator {
    fn generate(&mut self, previous_payload: &[u8]) -> Vec<u8> {
        let new_payload_len = previous_payload.len() + 1;
        let mut new_payload = vec![0; new_payload_len];

        if previous_payload.len() > 0 {
            let new_slice = &mut new_payload[1..new_payload_len];

            new_slice.copy_from_slice(&previous_payload);
        }

        new_payload[0] = self.rng.gen();

        new_payload
    }

    fn is_valid(
        &self,
        _previous_payload: &[u8],
        new_payload: &[u8],
        rip: usize,
        initial_rsp: usize,
        final_rsp: usize,
    ) -> bool {
        // Do not allow stack pointer manipulation
        if initial_rsp != final_rsp {
            return false;
        }

        // Require the payload to have executed all of the instructions in it.
        if rip as usize == new_payload.len() {
            return true;
        } else {
            return false;
        }
    }
}
