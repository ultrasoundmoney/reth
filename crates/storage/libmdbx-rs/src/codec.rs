use crate::{Error, TransactionKind};
use derive_more::*;
use std::{borrow::Cow, slice};

/// Implement this to be able to decode data values
pub trait TableObject<'tx> {
    /// Decodes the object from the given bytes.
    fn decode(data_val: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;

    /// Decodes the value directly from the given MDBX_val pointer.
    ///
    /// # Safety
    ///
    /// This should only in the context of an MDBX transaction.
    #[doc(hidden)]
    unsafe fn decode_val<K: TransactionKind>(
        _: *const ffi::MDBX_txn,
        data_val: &ffi::MDBX_val,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let s = slice::from_raw_parts(data_val.iov_base as *const u8, data_val.iov_len);

        TableObject::decode(s)
    }
}

impl<'tx> TableObject<'tx> for Cow<'tx, [u8]> {
    fn decode(_: &[u8]) -> Result<Self, Error> {
        unreachable!()
    }

    #[doc(hidden)]
    unsafe fn decode_val<K: TransactionKind>(
        _txn: *const ffi::MDBX_txn,
        data_val: &ffi::MDBX_val,
    ) -> Result<Self, Error> {
        let s = slice::from_raw_parts(data_val.iov_base as *const u8, data_val.iov_len);

        #[cfg(feature = "return-borrowed")]
        {
            Ok(Cow::Borrowed(s))
        }

        #[cfg(not(feature = "return-borrowed"))]
        {
            let is_dirty = (!K::ONLY_CLEAN) &&
                crate::error::mdbx_result(ffi::mdbx_is_dirty(_txn, data_val.iov_base))?;

            Ok(if is_dirty { Cow::Owned(s.to_vec()) } else { Cow::Borrowed(s) })
        }
    }
}

#[cfg(feature = "lifetimed-bytes")]
impl<'tx> TableObject<'tx> for lifetimed_bytes::Bytes<'tx> {
    fn decode(_: &[u8]) -> Result<Self, Error> {
        unreachable!()
    }

    #[doc(hidden)]
    unsafe fn decode_val<K: TransactionKind>(
        txn: *const ffi::MDBX_txn,
        data_val: &ffi::MDBX_val,
    ) -> Result<Self, Error> {
        Cow::<'tx, [u8]>::decode_val::<K>(txn, data_val).map(From::from)
    }
}

impl<'tx> TableObject<'tx> for Vec<u8> {
    fn decode(data_val: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(data_val.to_vec())
    }
}

impl<'tx> TableObject<'tx> for () {
    fn decode(_: &[u8]) -> Result<Self, Error> {
        Ok(())
    }

    unsafe fn decode_val<K: TransactionKind>(
        _: *const ffi::MDBX_txn,
        _: &ffi::MDBX_val,
    ) -> Result<Self, Error> {
        Ok(())
    }
}

/// If you don't need the data itself, just its length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Deref, DerefMut)]
pub struct ObjectLength(pub usize);

impl<'tx> TableObject<'tx> for ObjectLength {
    fn decode(data_val: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(Self(data_val.len()))
    }
}

impl<'tx, const LEN: usize> TableObject<'tx> for [u8; LEN] {
    fn decode(data_val: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if data_val.len() != LEN {
            return Err(Error::DecodeErrorLenDiff)
        }
        let mut a = [0; LEN];
        a[..].copy_from_slice(data_val);
        Ok(a)
    }
}
