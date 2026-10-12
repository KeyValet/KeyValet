use crate::remote::native::{NativeBridge, RawDialog};

#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {
    fn kv_remote_dialog(
        input: *const u8,
        length: usize,
        output: *mut u8,
        output_length: *mut usize,
        preview_path: *const u8,
        preview_length: usize,
    ) -> i32;
}

#[derive(Default)]
pub struct AppKit;
impl RawDialog for AppKit {
    fn call(&self, input: &[u8], output: &mut [u8], length: &mut usize, preview: &[u8]) -> i32 {
        unsafe {
            kv_remote_dialog(
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                length,
                preview.as_ptr(),
                preview.len(),
            )
        }
    }
}

pub type NativeDialog = crate::remote::native::NativeDialog<NativeBridge<AppKit>>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_bridge_rejects_invalid_input_without_creating_a_window() {
        let mut output = [0; 8192];
        let mut length = output.len();
        assert_ne!(AppKit.call(b"{}", &mut output, &mut length, b""), 0);
    }
}
