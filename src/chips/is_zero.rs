use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Value},
    halo2curves::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct IsZeroConfig<F: FieldExt> {
    value: Column<Advice>,
    value_inverse: Column<Advice>,
    result: Column<Advice>,
    selector: Selector,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct IsZeroChip<F: FieldExt> {
    is_zero_config: IsZeroConfig<F>,
}

impl<F: FieldExt> Chip<F> for IsZeroChip<F> {
    type Config = IsZeroConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.is_zero_config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> IsZeroChip<F> {
    pub fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            is_zero_config: config,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        value: Column<Advice>,
        value_inverse: Column<Advice>,
        result: Column<Advice>,
    ) -> <IsZeroChip<F> as Chip<F>>::Config {
        let selector = meta.selector();

        meta.create_gate("is zero gate", |meta| {
            let s = meta.query_selector(selector);
            let v = meta.query_advice(value, Rotation::cur());
            let v_inv = meta.query_advice(value_inverse, Rotation::cur());
            let is_zero = meta.query_advice(result, Rotation::cur());
            let one = Expression::Constant(F::from(1));
            vec![
                s.clone() * is_zero.clone() * (is_zero.clone() - one.clone()), // ensure is_zero is 0 or 1
                // ensure v_inv is calculated correctly
                s.clone()
                    * ((one.clone() - is_zero.clone()) * (v.clone() * v_inv.clone() - one) // v * v_inv == 1
                        + is_zero.clone() * (v.clone() - v_inv)), // v == v_inv == 0
                s * v * is_zero, // ensure v is 0 if is_zero
            ]
        });

        IsZeroConfig {
            value,
            value_inverse,
            result,
            selector,
            _marker: PhantomData,
        }
    }
}

pub struct ValueIZ<F: FieldExt>(AssignedCell<F, F>, AssignedCell<F, F>);

impl<F: FieldExt> IsZeroChip<F> {
    pub fn load_value(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
    ) -> Result<ValueIZ<F>, Error> {
        let config = self.config();

        let value_cell = layouter.assign_region(
            || "load private",
            |mut region| region.assign_advice(|| "value", config.value, 0, || value),
        )?;
        let value_inverse_cell = layouter.assign_region(
            || "load private",
            |mut region| {
                region.assign_advice(
                    || "value inverse",
                    config.value,
                    0,
                    || value.map(|v| v.invert().unwrap_or(F::zero())),
                )
            },
        )?;
        Ok(ValueIZ::<F>(value_cell, value_inverse_cell))
    }

    pub fn is_zero(
        &self,
        mut layouter: impl Layouter<F>,
        value: ValueIZ<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let config = self.config();
        layouter.assign_region(
            || "region",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                value
                    .0
                    .copy_advice(|| "copy value", &mut region, config.value, 0)?;
                value.1.copy_advice(
                    || "copy value inverse",
                    &mut region,
                    config.value_inverse,
                    0,
                )?;

                let mul = value.0.value().copied() * value.1.value();

                let result = Value::known(F::from(1)) - mul;

                region.assign_advice(|| "result", config.result, 0, || result)
            },
        )
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

    const K: u32 = 4;

    #[derive(Default)]
    struct TestCircuit<F: FieldExt> {
        number: Value<F>,
    }

    #[derive(Clone, Debug)]
    struct TestCircuitConfig<F: FieldExt> {
        is_zero_config: IsZeroConfig<F>,
        instance: Column<Instance>,
    }

    impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig<F>;

        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
            let value = meta.advice_column();
            let value_inverse = meta.advice_column();
            let result = meta.advice_column();
            let instance = meta.instance_column();

            meta.enable_equality(value);
            meta.enable_equality(value_inverse);
            meta.enable_equality(result);
            meta.enable_equality(instance);

            TestCircuitConfig::<F> {
                is_zero_config: IsZeroChip::<F>::configure(meta, value, value_inverse, result),
                instance,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2_proofs::circuit::Layouter<F>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            let chip = IsZeroChip::<F>::construct(config.is_zero_config);
            let value = chip.load_value(layouter.namespace(|| "load value"), self.number)?;
            let result_cell = chip.is_zero(layouter.namespace(|| "load value"), value)?;

            layouter.constrain_instance(result_cell.cell(), config.instance, 0)?;

            Ok(())
        }
    }

    #[test]
    fn test_circuit_0_pass() {
        // Number is 0, hence is_zero should be true or 1.
        let prover = MockProver::run(
            K,
            &TestCircuit::<Fp> {
                number: Value::known(Fp::from(0)), // private input number
            },
            vec![vec![Fp::from(1)]], // public input is_zero
        )
        .unwrap();

        // Should success.
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_circuit_0_fail() {
        // Number is 0, hence is_zero should be true or 1. But is_zero = 0 should fail.
        let prover = MockProver::run(
            K,
            &TestCircuit::<Fp> {
                number: Value::known(Fp::from(0)), // private input number
            },
            vec![vec![Fp::from(0)]], // public input is_zero
        )
        .unwrap();

        // Should fail since is_zero should be true or 1 but it is passed as 0.
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_circuit_123_pass() {
        // Number is 123, hence is_zero should be false or 0.
        let prover = MockProver::run(
            K,
            &TestCircuit::<Fp> {
                number: Value::known(Fp::from(9)), // private input number
            },
            vec![vec![Fp::from(0)]], // public input is_zero
        )
        .unwrap();

        // Should success.
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_circuit_123_fail() {
        // Number is 123, hence is_zero should be false or 0. But is_zero = 1 should fail.
        let prover = MockProver::run(
            K,
            &TestCircuit::<Fp> {
                number: Value::known(Fp::from(123)), // private input number
            },
            vec![vec![Fp::from(1)]], // public input is_zero
        )
        .unwrap();

        // Should fail since is_zero should be false or 0 but it is passed as 1.
        assert!(prover.verify().is_err());
    }
}
