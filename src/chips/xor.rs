use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

mod table;
use table::*;

// Table size is BITS**4
// In this example BITS=4, so table size is 256
#[derive(Clone, Debug)]
pub struct XorChip<F, const BITS: usize>
where
    F: FieldExt,
{
    q_lookup: Selector, // do we need this?
    xor_table: XorTableConfig<F, BITS>,
    left_advice: Column<Advice>,
    right_advice: Column<Advice>,
    result_advice: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const BITS: usize> XorChip<F, BITS> {
    pub fn construct(meta: &mut ConstraintSystem<F>) -> Self {
        let q_lookup = meta.complex_selector();

        // creates 3 table columns
        let xor_table = XorTableConfig::configure(meta);

        // so these have to be 3 seperate columns which are not reused (hence not taken from input)
        let left_advice = meta.advice_column();
        let right_advice = meta.advice_column();
        let result_advice = meta.advice_column();

        // in case the result needs to be copied somewhere
        meta.enable_equality(result_advice);

        meta.lookup("lookup", |meta| {
            let q = meta.query_selector(q_lookup);
            let left_cur = meta.query_advice(left_advice, Rotation::cur());
            let right_cur = meta.query_advice(right_advice, Rotation::cur());
            let result_cur = meta.query_advice(result_advice, Rotation::cur());

            vec![
                (q.clone() * left_cur, xor_table.left),
                (q.clone() * right_cur, xor_table.right),
                (q * result_cur, xor_table.result),
            ]
        });

        Self {
            q_lookup,
            xor_table,
            left_advice,
            right_advice,
            result_advice,
            _marker: PhantomData,
        }
    }

    pub fn synthesize_sub(&self, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        self.xor_table.load(&mut layouter.namespace(|| "xor table"))
    }

    pub fn calculate_xor(
        &self,
        mut layouter: impl Layouter<F>,
        left: u64,
        right: u64,
    ) -> Result<AssignedCell<F, F>, Error> {
        if left >= 1 << BITS {
            panic!(
                "left must be less than 2**BITS, left={}, BITS={}",
                left, BITS
            );
        }
        if right >= 1 << BITS {
            panic!(
                "left must be less than 2**BITS, right={}, BITS={}",
                right, BITS
            );
        }

        // convert to values
        let left_val = Value::known(F::from(left));
        let right_val = Value::known(F::from(right));
        let result_val = Value::known(F::from(left ^ right));

        // assign xor calculation to the advice columns so they are checked in lookups
        let result_cell = layouter.assign_region(
            || "Assign value for lookup XOR check",
            |mut region| {
                let offset = 0;

                // Enable q_lookup
                self.q_lookup.enable(&mut region, offset)?;

                // Assign value
                region.assign_advice(|| "left", self.left_advice, offset, || left_val)?;
                region.assign_advice(|| "right", self.right_advice, offset, || right_val)?;
                region.assign_advice(|| "result", self.result_advice, offset, || result_val)
            },
        )?;

        Ok(result_cell)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::pasta::Fp,
        plonk::{Circuit, Instance},
    };

    use super::*;

    const K: u32 = 9;

    #[derive(Default)]
    struct TestCircuit<F: FieldExt, const BITS: usize> {
        left: u64,
        right: u64,
        _marker: PhantomData<F>,
    }

    #[derive(Clone, Debug)]
    struct TestCircuitConfig<F: FieldExt, const BITS: usize> {
        xor_chip: XorChip<F, BITS>,
        result_instance: Column<Instance>,
    }

    impl<F: FieldExt, const BITS: usize> Circuit<F> for TestCircuit<F, BITS> {
        type Config = TestCircuitConfig<F, BITS>;

        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
            let result_instance = meta.instance_column();

            // meta.enable_equality(value);
            // meta.enable_equality(value_inverse);
            meta.enable_equality(result_instance);

            TestCircuitConfig::<F, BITS> {
                xor_chip: XorChip::<F, BITS>::construct(meta),
                result_instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2_proofs::circuit::Layouter<F>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            let chip = config.xor_chip;

            chip.synthesize_sub(layouter.namespace(|| "chip synthesize_sub"))?;

            let result_cell =
                chip.calculate_xor(layouter.namespace(|| "load value"), self.left, self.right)?;

            layouter.constrain_instance(result_cell.cell(), config.result_instance, 0)?;

            Ok(())
        }
    }

    #[test]
    fn test_circuit_0_pass() {
        let prover = MockProver::run(
            K,
            &TestCircuit::<Fp, 4> {
                left: 3,
                right: 1,
                _marker: Default::default(),
            },
            vec![vec![Fp::from(2)]],
        )
        .unwrap();

        // Should success.
        assert_eq!(prover.verify(), Ok(()));
    }
}
