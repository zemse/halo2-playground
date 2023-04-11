use halo2_playground::chips::is_zero::{IsZeroChip, IsZeroConfig};
use halo2_proofs::{
    circuit::{SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::{pasta::Fp, FieldExt},
    plonk::{Circuit, Column, Instance},
};

/// This example shows how to use the `IsZeroChip` gadget using a circuit
/// which takes in a number as private input and public output 0 or 1 for
/// is_zero value. This basically proves that the prover knows a non-zero
/// number, though not practically useful, but just to play aroung with
/// halo2 gadgets.

#[derive(Default)]
struct MyCircuit<F: FieldExt> {
    number: Value<F>,
}

#[derive(Clone, Debug)]
struct MyCircuitConfig<F: FieldExt> {
    is_zero_config: IsZeroConfig<F>,
    instance: Column<Instance>,
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    type Config = MyCircuitConfig<F>;

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

        MyCircuitConfig::<F> {
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

fn main() {
    let k = 4;

    // Circuit with input 0, then is_zero result should be true or 1.
    let circuit = MyCircuit::<Fp> {
        number: Value::known(Fp::from(0)),
    };
    let mut public_inputs = vec![Fp::one()];

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // If we try some other public input, the proof will fail!
    public_inputs[0] = Fp::zero();
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert!(prover.verify().is_err());
}
