//! Emit PAN-OS XML and set-commands from IR; IR transforms.

mod set;
mod transform;
mod validate;
mod xml;

pub use set::emit_set_commands;
pub use transform::{apply_zone_map, dedup_objects, parse_zone_map, DedupReport};
pub use validate::validate_document;
pub use xml::emit_panos_xml;
