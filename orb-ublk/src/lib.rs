pub mod runtime;
mod ublk;

pub use ublk::*;

/// Size or offset in unit of sectors (512bytes).
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    derive_more::Add,
    derive_more::AddAssign,
    derive_more::Sub,
    derive_more::SubAssign,
)]
pub struct Sector(pub u64);

impl Sector {
    pub const SHIFT: u32 = 9;
    pub const SIZE: u32 = 1 << Self::SHIFT;

    #[must_use]
    pub const fn from_bytes(bytes: u64) -> Self {
        match Self::try_from_bytes(bytes) {
            Some(sec) => sec,
            None => panic!("bytes is not multiples of sectors"),
        }
    }

    #[must_use]
    pub const fn try_from_bytes(bytes: u64) -> Option<Self> {
        if bytes % Self::SIZE as u64 == 0 {
            Some(Self(bytes >> Self::SHIFT))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn bytes(self) -> u64 {
        match self.0.checked_mul(Self::SIZE as u64) {
            Some(bytes) => bytes,
            None => panic!("overflow"),
        }
    }

    #[must_use]
    pub const fn wrapping_bytes(self) -> u64 {
        self.0.wrapping_mul(Self::SIZE as u64)
    }
}

impl std::ops::Mul<u64> for Sector {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl std::ops::Div<Sector> for Sector {
    type Output = u64;

    fn div(self, rhs: Self) -> Self::Output {
        self.0 / rhs.0
    }
}
