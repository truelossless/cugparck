use std::ops::Deref;

use bitvec::{order::Lsb0, prelude::BitVec, slice::BitSlice, view::BitView};
use bytecheck::CheckBytes;
use rkyv::{
    from_archived, out_field,
    ser::{ScratchSpace, Serializer},
    vec::{ArchivedVec, VecResolver},
    with::{ArchiveWith, DeserializeWith, SerializeWith},
    Archive, Archived, Deserialize, Fallible, Serialize,
};

pub struct BitVecWrapper;

#[derive(CheckBytes)]
pub struct ArchivedBitVec {
    inner: ArchivedVec<Archived<usize>>,
    bit_len: Archived<usize>,
}

impl ArchivedBitVec {
    pub fn len(&self) -> usize {
        from_archived!(self.bit_len) as usize
    }
}

impl Deref for ArchivedBitVec {
    type Target = BitSlice<u64, Lsb0>;

    fn deref(&self) -> &Self::Target {
        &self.inner.view_bits::<Lsb0>()[..self.bit_len as usize]
    }
}

impl ArchiveWith<BitVec> for BitVecWrapper {
    type Archived = ArchivedBitVec;
    type Resolver = VecResolver;

    unsafe fn resolve_with(
        field: &BitVec,
        pos: usize,
        resolver: Self::Resolver,
        out: *mut Self::Archived,
    ) {
        let (fp, fo) = out_field!(out.inner);
        ArchivedVec::resolve_from_slice(field.as_raw_slice(), pos + fp, resolver, fo);
        let (fp, fo) = out_field!(out.bit_len);
        usize::resolve(&field.len(), pos + fp, (), fo);
    }
}

impl<S: Fallible + ?Sized + ScratchSpace + Serializer> SerializeWith<BitVec, S> for BitVecWrapper {
    fn serialize_with(
        field: &BitVec,
        serializer: &mut S,
    ) -> Result<Self::Resolver, <S as Fallible>::Error> {
        let resolver = ArchivedVec::serialize_from_slice(field.as_raw_slice(), serializer)?;
        usize::serialize(&field.len(), serializer)?;

        Ok(resolver)
    }
}

impl<D: Fallible + ?Sized> DeserializeWith<ArchivedBitVec, BitVec, D> for BitVecWrapper {
    fn deserialize_with(
        field: &ArchivedBitVec,
        deserializer: &mut D,
    ) -> Result<BitVec, <D as Fallible>::Error> {
        let vec = ArchivedVec::deserialize(&field.inner, deserializer)?;
        let bit_len = u64::deserialize(&field.bit_len, deserializer)?;

        let mut bitvec = BitVec::from_vec(vec);
        bitvec.truncate(bit_len);

        Ok(bitvec)
    }
}
