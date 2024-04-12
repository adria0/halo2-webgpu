use wasm_bindgen::prelude::*;
use web_sys::console;

mod prover;
mod circuit;

// When the `wee_alloc` feature is enabled, this uses `wee_alloc` as the global
// allocator.
//
// If you don't want to use `wee_alloc`, you can safely delete this.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

pub use wasm_bindgen_rayon::init_thread_pool;

// This is like the `main` function, except for JavaScript.
#[wasm_bindgen(start)]
pub fn main_js() -> Result<(), JsValue> {
    // This provides better error messages in debug mode.
    // It's disabled in release mode so it doesn't bloat up the file size.
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();


    // Your code goes here!
    console::log_1(&JsValue::from_str("Hello world!"));

    Ok(())
}

type CIRCUIT = circuit::WasmCircuit<16, 11, prover::F>;

#[wasm_bindgen]
pub fn gen_keys() -> String {
    match prover::gen_keys::<CIRCUIT>() {
        Ok(keys) => keys,
        Err(e) => format!("Error: {}", e),
    }
}

#[wasm_bindgen]
pub fn prove(keys: &str) -> String {
    match prover::prove::<CIRCUIT>(keys) {
        Ok(proof) => proof,
        Err(e) => format!("Error: {}", e),
    }
}

#[wasm_bindgen]
pub fn verify(keys: &str, proof: &str) -> String {
    match prover::verify::<CIRCUIT>(keys, proof) {
        Ok(success) => format!("{}", success),
        Err(e) => format!("Error: {}", e),
    }
}

#[wasm_bindgen]
pub fn mock_prover() -> String {
    prover::mock_prover::<CIRCUIT>()
}
