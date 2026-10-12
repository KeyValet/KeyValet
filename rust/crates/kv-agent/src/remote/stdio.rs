use super::{
    native::PreviewDialog, view::PairingView, ApprovalView, DisplayContext, Error, Platform, Result,
};
use std::io::{Read, Write};
use std::path::Path;

pub enum Mode<'a> {
    Dialog,
    Preview(&'a Path),
}

pub fn run(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    mode: Mode<'_>,
    platform: Platform,
    dialog: &mut dyn PreviewDialog,
) -> Result<()> {
    let mut bytes = Vec::new();
    reader
        .take(kv_ipc::agent::MAX_LINE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidRequest)?;
    if bytes.len() > kv_ipc::agent::MAX_LINE_BYTES {
        return Err(Error::InvalidRequest);
    }
    let input: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| Error::InvalidRequest)?;
    if let Mode::Preview(path) = mode {
        if input["op"] == "remote_pair" {
            let view = PairingView::new(&input["peer"], super::text(&input, "sas")?, platform)?;
            return dialog.preview_pairing(&view, path);
        }
        let view = ApprovalView::new(
            &input["request"],
            DisplayContext::from_json(&input["context"])?,
            platform,
        )?;
        return dialog.preview(&view, path);
    }
    let result = super::handle_dialog(&input, dialog, platform)?;
    serde_json::to_writer(&mut *writer, &result).map_err(|_| Error::UiUnavailable)?;
    writer.flush().map_err(|_| Error::UiUnavailable)
}
