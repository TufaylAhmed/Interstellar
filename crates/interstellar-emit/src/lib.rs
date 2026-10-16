//! Emit PAN-OS XML and set-commands from IR.

mod set;
mod validate;
mod xml;

pub use set::emit_set_commands;
pub use validate::validate_document;
pub use xml::emit_panos_xml;
