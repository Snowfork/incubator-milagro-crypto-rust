use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

#[derive(Copy, Clone, Debug, PartialEq, Encode, Decode, TypeInfo, MaxEncodedLen)]
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
