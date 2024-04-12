use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::Field, circuit::{Layouter, Region, SimpleFloorPlanner, Value}, halo2curves::bn256::Fr, plonk::{Advice, Circuit, Column, ConstraintSystem, ErrorFront, Selector}, poly::Rotation
};

#[derive(Clone, Debug)]
pub struct WasmCircuitConfig {
    sel: Selector,
    advices: Vec<Column<Advice>>,    
}

#[derive(Default)]
pub struct WasmCircuit<const COLS: usize, const K: u32, F: Field>{
    _marker: PhantomData<F>,
}
impl<const COLS: usize, const K: u32, F: Field + From<u64>>  Circuit<F> for WasmCircuit<COLS, K, F> {
    type Config = WasmCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advices = vec![meta.advice_column(); COLS];

        let sel = meta.selector();
        meta.create_gate("rows are equal", |meta| {
            (0..COLS-1).map(|i| {
                let lhs = meta.query_advice(advices[i], Rotation::cur());
                let rhs = meta.query_advice(advices[i+1], Rotation::cur());
                sel.expr() * (lhs - rhs) 
            }).collect::<Vec<_>>()
        });

        WasmCircuitConfig {
            sel,
            advices
        }

    }
    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), ErrorFront> {
        layouter.assign_region(
            || "all",
            |mut region: Region<'_, F>| {
                for r in 0..(2usize.pow(K) - 10) {
                    config.sel.enable(&mut region, r)?;
                    for c in 0..COLS {
                        region.assign_advice(|| "", config.advices[c], r, || Value::known(F::from(r as u64)))?;
                    }
                }
                Ok(())                
            }
        )?;
        Ok(())
    }

}

impl<const COLS: usize, const K: u32>  super::prover::TestCircuit for WasmCircuit<COLS, K, Fr> {
    type CIRCUIT = WasmCircuit<COLS, K, Fr>;
    fn public_inputs() -> Vec<Vec<Fr>> {
        vec![]
    }
    fn circuit_with_witness() -> Self::CIRCUIT {
        WasmCircuit::default()
    }
    fn k() -> u32 {
        K
    }
}
