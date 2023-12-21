use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::RuntimeDebug;

#[derive(PartialEq, Clone, Encode, Decode, TypeInfo, MaxEncodedLen, RuntimeDebug)]
pub enum AmclError {
    AggregateEmptyPoints,
    HashToFieldError,
    InvalidSecretKeySize,
    InvalidSecretKeyRange,
    InvalidPoint,
    InvalidG1Size,
    InvalidG2Size,
    InvalidYFlag,
}
