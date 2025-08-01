/* automatically generated by rust-bindgen 0.72.0 */

pub const UBLK_CMD_GET_QUEUE_AFFINITY: u32 = 1;
pub const UBLK_CMD_GET_DEV_INFO: u32 = 2;
pub const UBLK_CMD_ADD_DEV: u32 = 4;
pub const UBLK_CMD_DEL_DEV: u32 = 5;
pub const UBLK_CMD_START_DEV: u32 = 6;
pub const UBLK_CMD_STOP_DEV: u32 = 7;
pub const UBLK_CMD_SET_PARAMS: u32 = 8;
pub const UBLK_CMD_GET_PARAMS: u32 = 9;
pub const UBLK_CMD_START_USER_RECOVERY: u32 = 16;
pub const UBLK_CMD_END_USER_RECOVERY: u32 = 17;
pub const UBLK_CMD_GET_DEV_INFO2: u32 = 18;
pub const UBLK_FEATURES_LEN: u32 = 8;
pub const UBLK_IO_FETCH_REQ: u32 = 32;
pub const UBLK_IO_COMMIT_AND_FETCH_REQ: u32 = 33;
pub const UBLK_IO_NEED_GET_DATA: u32 = 34;
pub const UBLK_IO_RES_OK: u32 = 0;
pub const UBLK_IO_RES_NEED_GET_DATA: u32 = 1;
pub const UBLKSRV_CMD_BUF_OFFSET: u32 = 0;
pub const UBLKSRV_IO_BUF_OFFSET: u32 = 2147483648;
pub const UBLK_MAX_QUEUE_DEPTH: u32 = 4096;
pub const UBLK_IO_BUF_OFF: u32 = 0;
pub const UBLK_IO_BUF_BITS: u32 = 25;
pub const UBLK_IO_BUF_BITS_MASK: u32 = 33554431;
pub const UBLK_TAG_OFF: u32 = 25;
pub const UBLK_TAG_BITS: u32 = 16;
pub const UBLK_TAG_BITS_MASK: u32 = 65535;
pub const UBLK_QID_OFF: u32 = 41;
pub const UBLK_QID_BITS: u32 = 12;
pub const UBLK_QID_BITS_MASK: u32 = 4095;
pub const UBLK_MAX_NR_QUEUES: u32 = 4096;
pub const UBLKSRV_IO_BUF_TOTAL_BITS: u32 = 53;
pub const UBLKSRV_IO_BUF_TOTAL_SIZE: u64 = 9007199254740992;
pub const UBLK_F_SUPPORT_ZERO_COPY: u32 = 1;
pub const UBLK_F_URING_CMD_COMP_IN_TASK: u32 = 2;
pub const UBLK_F_NEED_GET_DATA: u32 = 4;
pub const UBLK_F_USER_RECOVERY: u32 = 8;
pub const UBLK_F_USER_RECOVERY_REISSUE: u32 = 16;
pub const UBLK_F_UNPRIVILEGED_DEV: u32 = 32;
pub const UBLK_F_CMD_IOCTL_ENCODE: u32 = 64;
pub const UBLK_F_USER_COPY: u32 = 128;
pub const UBLK_F_ZONED: u32 = 256;
pub const UBLK_S_DEV_DEAD: u32 = 0;
pub const UBLK_S_DEV_LIVE: u32 = 1;
pub const UBLK_S_DEV_QUIESCED: u32 = 2;
pub const UBLK_IO_OP_READ: u32 = 0;
pub const UBLK_IO_OP_WRITE: u32 = 1;
pub const UBLK_IO_OP_FLUSH: u32 = 2;
pub const UBLK_IO_OP_DISCARD: u32 = 3;
pub const UBLK_IO_OP_WRITE_SAME: u32 = 4;
pub const UBLK_IO_OP_WRITE_ZEROES: u32 = 5;
pub const UBLK_IO_OP_ZONE_OPEN: u32 = 10;
pub const UBLK_IO_OP_ZONE_CLOSE: u32 = 11;
pub const UBLK_IO_OP_ZONE_FINISH: u32 = 12;
pub const UBLK_IO_OP_ZONE_APPEND: u32 = 13;
pub const UBLK_IO_OP_ZONE_RESET_ALL: u32 = 14;
pub const UBLK_IO_OP_ZONE_RESET: u32 = 15;
pub const UBLK_IO_OP_REPORT_ZONES: u32 = 18;
pub const UBLK_IO_F_FAILFAST_DEV: u32 = 256;
pub const UBLK_IO_F_FAILFAST_TRANSPORT: u32 = 512;
pub const UBLK_IO_F_FAILFAST_DRIVER: u32 = 1024;
pub const UBLK_IO_F_META: u32 = 2048;
pub const UBLK_IO_F_FUA: u32 = 8192;
pub const UBLK_IO_F_NOUNMAP: u32 = 32768;
pub const UBLK_IO_F_SWAP: u32 = 65536;
pub const UBLK_ATTR_READ_ONLY: u32 = 1;
pub const UBLK_ATTR_ROTATIONAL: u32 = 2;
pub const UBLK_ATTR_VOLATILE_CACHE: u32 = 4;
pub const UBLK_ATTR_FUA: u32 = 8;
pub const UBLK_PARAM_TYPE_BASIC: u32 = 1;
pub const UBLK_PARAM_TYPE_DISCARD: u32 = 2;
pub const UBLK_PARAM_TYPE_DEVT: u32 = 4;
pub const UBLK_PARAM_TYPE_ZONED: u32 = 8;
pub type __u8 = ::core::ffi::c_uchar;
pub type __u16 = ::core::ffi::c_ushort;
pub type __s32 = ::core::ffi::c_int;
pub type __u32 = ::core::ffi::c_uint;
pub type __u64 = ::core::ffi::c_ulonglong;
pub const BLK_ZONE_TYPE_CONVENTIONAL: blk_zone_type = 1;
pub const BLK_ZONE_TYPE_SEQWRITE_REQ: blk_zone_type = 2;
pub const BLK_ZONE_TYPE_SEQWRITE_PREF: blk_zone_type = 3;
pub type blk_zone_type = ::core::ffi::c_uint;
pub const BLK_ZONE_COND_NOT_WP: blk_zone_cond = 0;
pub const BLK_ZONE_COND_EMPTY: blk_zone_cond = 1;
pub const BLK_ZONE_COND_IMP_OPEN: blk_zone_cond = 2;
pub const BLK_ZONE_COND_EXP_OPEN: blk_zone_cond = 3;
pub const BLK_ZONE_COND_CLOSED: blk_zone_cond = 4;
pub const BLK_ZONE_COND_READONLY: blk_zone_cond = 13;
pub const BLK_ZONE_COND_FULL: blk_zone_cond = 14;
pub const BLK_ZONE_COND_OFFLINE: blk_zone_cond = 15;
pub type blk_zone_cond = ::core::ffi::c_uint;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct blk_zone {
    pub start: __u64,
    pub len: __u64,
    pub wp: __u64,
    pub type_: __u8,
    pub cond: __u8,
    pub non_seq: __u8,
    pub reset: __u8,
    pub resv: [__u8; 4usize],
    pub capacity: __u64,
    pub reserved: [__u8; 24usize],
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ublksrv_ctrl_cmd {
    pub dev_id: __u32,
    pub queue_id: __u16,
    pub len: __u16,
    pub addr: __u64,
    pub data: [__u64; 1usize],
    pub dev_path_len: __u16,
    pub pad: __u16,
    pub reserved: __u32,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ublksrv_ctrl_dev_info {
    pub nr_hw_queues: __u16,
    pub queue_depth: __u16,
    pub state: __u16,
    pub pad0: __u16,
    pub max_io_buf_bytes: __u32,
    pub dev_id: __u32,
    pub ublksrv_pid: __s32,
    pub pad1: __u32,
    pub flags: __u64,
    pub ublksrv_flags: __u64,
    pub owner_uid: __u32,
    pub owner_gid: __u32,
    pub reserved1: __u64,
    pub reserved2: __u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ublksrv_io_desc {
    pub op_flags: __u32,
    pub __bindgen_anon_1: ublksrv_io_desc__bindgen_ty_1,
    pub start_sector: __u64,
    pub addr: __u64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union ublksrv_io_desc__bindgen_ty_1 {
    pub nr_sectors: __u32,
    pub nr_zones: __u32,
}
impl Default for ublksrv_io_desc__bindgen_ty_1 {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
impl Default for ublksrv_io_desc {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ublksrv_io_cmd {
    pub q_id: __u16,
    pub tag: __u16,
    pub result: __s32,
    pub __bindgen_anon_1: ublksrv_io_cmd__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union ublksrv_io_cmd__bindgen_ty_1 {
    pub addr: __u64,
    pub zone_append_lba: __u64,
}
impl Default for ublksrv_io_cmd__bindgen_ty_1 {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
impl Default for ublksrv_io_cmd {
    fn default() -> Self {
        let mut s = ::core::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ublk_param_basic {
    pub attrs: __u32,
    pub logical_bs_shift: __u8,
    pub physical_bs_shift: __u8,
    pub io_opt_shift: __u8,
    pub io_min_shift: __u8,
    pub max_sectors: __u32,
    pub chunk_sectors: __u32,
    pub dev_sectors: __u64,
    pub virt_boundary_mask: __u64,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ublk_param_discard {
    pub discard_alignment: __u32,
    pub discard_granularity: __u32,
    pub max_discard_sectors: __u32,
    pub max_write_zeroes_sectors: __u32,
    pub max_discard_segments: __u16,
    pub reserved0: __u16,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ublk_param_devt {
    pub char_major: __u32,
    pub char_minor: __u32,
    pub disk_major: __u32,
    pub disk_minor: __u32,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ublk_param_zoned {
    pub max_open_zones: __u32,
    pub max_active_zones: __u32,
    pub max_zone_append_sectors: __u32,
    pub reserved: [__u8; 20usize],
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ublk_params {
    pub len: __u32,
    pub types: __u32,
    pub basic: ublk_param_basic,
    pub discard: ublk_param_discard,
    pub devt: ublk_param_devt,
    pub zoned: ublk_param_zoned,
}
pub const UBLK_U_CMD_GET_QUEUE_AFFINITY: __u32 = 2149610753;
pub const UBLK_U_CMD_GET_DEV_INFO: __u32 = 2149610754;
pub const UBLK_U_CMD_ADD_DEV: __u32 = 3223352580;
pub const UBLK_U_CMD_DEL_DEV: __u32 = 3223352581;
pub const UBLK_U_CMD_START_DEV: __u32 = 3223352582;
pub const UBLK_U_CMD_STOP_DEV: __u32 = 3223352583;
pub const UBLK_U_CMD_SET_PARAMS: __u32 = 3223352584;
pub const UBLK_U_CMD_GET_PARAMS: __u32 = 2149610761;
pub const UBLK_U_CMD_START_USER_RECOVERY: __u32 = 3223352592;
pub const UBLK_U_CMD_END_USER_RECOVERY: __u32 = 3223352593;
pub const UBLK_U_CMD_GET_DEV_INFO2: __u32 = 2149610770;
pub const UBLK_U_CMD_GET_FEATURES: __u32 = 2149610771;
pub const UBLK_U_IO_FETCH_REQ: __u32 = 3222304032;
pub const UBLK_U_IO_COMMIT_AND_FETCH_REQ: __u32 = 3222304033;
pub const UBLK_U_IO_NEED_GET_DATA: __u32 = 3222304034;
