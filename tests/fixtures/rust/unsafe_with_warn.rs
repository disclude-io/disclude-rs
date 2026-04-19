// Fixture: file has both an `unsafe` block and a Warn-level finding
// (base64 blob). The scorer should elevate the Warn to Critical per the
// SPEC elevation rule.
pub const PAYLOAD: &str = "dGhpc2lzYWxvbmdlbm91Z2hiYXNlNjRibG9idGhhdHRyaXBzdGhlaGV1cmlzdGljY2hlY2s=";

pub unsafe fn deref_raw(p: *const u8) -> u8 {
    unsafe { *p }
}
