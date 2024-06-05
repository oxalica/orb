pub mod runtime;
mod ublk;

#[allow(warnings)]
#[rustfmt::skip]
mod sys;

use std::{fmt, ops};

pub use ublk::*;

/// Size or offset in unit of sectors (512bytes).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sector(pub u64);

impl fmt::Display for Sector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)?;
        "s".fmt(f)
    }
}

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

impl ops::Add for Sector {
    type Output = Sector;

    fn add(self, rhs: Sector) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl ops::AddAssign for Sector {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl ops::Sub for Sector {
    type Output = Sector;

    fn sub(self, rhs: Sector) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl ops::SubAssign for Sector {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl ops::Mul<u64> for Sector {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl ops::Div<Sector> for Sector {
    type Output = u64;

    fn div(self, rhs: Self) -> Self::Output {
        self.0 / rhs.0
    }
}

impl ops::Rem<Sector> for Sector {
    type Output = Sector;

    fn rem(self, rhs: Sector) -> Self::Output {
        Sector(self.0 % rhs.0)
    }
}
