use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::FieldExt,
    plonk::{ConstraintSystem, Error, TableColumn},
};

// Table size is BITS**4
// use BITS as 4 so that there are 16 unique elements and table size is 256

#[derive(Debug, Clone)]
pub struct XorTableConfig<F, const BITS: usize>
where
    F: FieldExt,
{
    pub left: TableColumn,
    pub right: TableColumn,
    pub result: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const BITS: usize> XorTableConfig<F, BITS> {
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let left = meta.lookup_table_column();
        let right = meta.lookup_table_column();
        let result = meta.lookup_table_column();

        Self {
            left,
            right,
            result,
            _marker: PhantomData,
        }
    }

    // fill all possibilities of 4 BIT string XORs
    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "load xor table",
            |mut table| {
                let mut offset = 0;
                for left_value in 0..(1 << BITS) {
                    for right_value in 0..(1 << BITS) {
                        table.assign_cell(
                            || "left value",
                            self.left,
                            offset,
                            || Value::known(F::from(left_value as u64)),
                        )?;
                        table.assign_cell(
                            || "right value",
                            self.right,
                            offset,
                            || Value::known(F::from(right_value as u64)),
                        )?;
                        table.assign_cell(
                            || "output",
                            self.result,
                            offset,
                            || Value::known(F::from((left_value ^ right_value) as u64)),
                        )?;
                        offset += 1;
                    }
                }

                Ok(())
            },
        )
    }
}
