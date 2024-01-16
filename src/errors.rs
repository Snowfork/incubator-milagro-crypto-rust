use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

#[derive(Copy, Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "std", derive(PartialEq, Debug))]
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
