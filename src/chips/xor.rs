use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
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
    pub xor_table: XorTableConfig<F, BITS>,
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
        meta.enable_equality(left_advice);
        meta.enable_equality(right_advice);
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

    pub fn calculate_xor(
        &self,
        mut layouter: impl Layouter<F>,
        left_cell_advice: AssignedCell<F, F>,
        right_cell_advice: AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        // assign xor calculation to the advice columns so they are checked in lookups
        let result_cell = layouter.assign_region(
            || "Assign value for lookup XOR check",
            |mut region| {
                let offset = 0;

                // Enable q_lookup
                self.q_lookup.enable(&mut region, offset)?;

                // Copy advice to lookup columns, this also performs the range check on the advice inputs
                let left_cell = left_cell_advice.copy_advice(
                    || "copy left",
                    &mut region,
                    self.left_advice,
                    offset,
                )?;
                let right_cell = right_cell_advice.copy_advice(
                    || "copy left",
                    &mut region,
                    self.right_advice,
                    offset,
                )?;

                // Assign value
                let xor_result = left_cell
                    .value()
                    .zip(right_cell.value())
                    .map(|(left, right)| left.get_lower_128() ^ right.get_lower_128())
                    .map(|v| F::from_u128(v));
                region.assign_advice(|| "result", self.result_advice, offset, || xor_result)
            },
        )?;

        Ok(result_cell)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::pasta::Fp,
        plonk::{Circuit, Instance},
    };

    use super::*;

    const K: u32 = 9;

    #[derive(Default)]
    struct TestCircuit<F: FieldExt, const BITS: usize> {
        left: F,
        right: F,
        _marker: PhantomData<F>,
    }

    #[derive(Clone, Debug)]
    struct TestCircuitConfig<F: FieldExt, const BITS: usize> {
        advice: Column<Advice>,
        xor_chip: XorChip<F, BITS>,
        result_instance: Column<Instance>,
    }

    impl<F: FieldExt, const BITS: usize> TestCircuit<F, BITS> {
        fn load_advice(
            &self,
            config: TestCircuitConfig<F, BITS>,
            mut layouter: impl halo2_proofs::circuit::Layouter<F>,
            val: F,
        ) -> Result<AssignedCell<F, F>, halo2_proofs::plonk::Error> {
            layouter.assign_region(
                || "load advice",
                |mut region| {
                    region.assign_advice(|| "assign advice", config.advice, 0, || Value::known(val))
                },
            )
        }
    }

    impl<F: FieldExt, const BITS: usize> Circuit<F> for TestCircuit<F, BITS> {
        type Config = TestCircuitConfig<F, BITS>;

        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
            let advice = meta.advice_column();
            let result_instance = meta.instance_column();

            // meta.enable_equality(value);
            // meta.enable_equality(value_inverse);
            meta.enable_equality(advice);
            meta.enable_equality(result_instance);

            TestCircuitConfig::<F, BITS> {
                advice,
                xor_chip: XorChip::<F, BITS>::construct(meta),
                result_instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2_proofs::circuit::Layouter<F>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            let xor_chip = config.xor_chip.clone();

            xor_chip
                .xor_table
                .load(&mut layouter.namespace(|| "xor table"))?;

            let left_cell = self.load_advice(
                config.clone(),
                layouter.namespace(|| "assign left"),
                self.left,
            )?;
            let right_cell = self.load_advice(
                config.clone(),
                layouter.namespace(|| "assign right"),
                self.right,
            )?;

            let result_cell = xor_chip.calculate_xor(
                layouter.namespace(|| "load value"),
                left_cell,
                right_cell,
            )?;

            layouter.constrain_instance(result_cell.cell(), config.result_instance, 0)?;

            Ok(())
        }
    }

    #[test]
    fn test_circuit_pass_1() {
        let prover = MockProver::run(
            K,
            &TestCircuit::<Fp, 4> {
                left: Fp::from(3),
                right: Fp::from(1),
                _marker: Default::default(),
            },
            vec![vec![Fp::from(2)]],
        )
        .unwrap();

        // Should success.
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_circuit_pass_2() {
        let prover = MockProver::run(
            K,
            &TestCircuit::<Fp, 4> {
                left: Fp::from(3),
                right: Fp::from(3),
                _marker: Default::default(),
            },
            vec![vec![Fp::zero()]],
        )
        .unwrap();

        // Should success.
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_circuit_fail_1() {
        let prover = MockProver::run(
            K,
            &TestCircuit::<Fp, 4> {
                left: Fp::from(3),
                right: Fp::from(3),
                _marker: Default::default(),
            },
            vec![vec![Fp::from(3)]],
        )
        .unwrap();

        // Should error.
        assert!(prover.verify().is_err());
    }
}
