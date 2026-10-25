//! Internal library surface for the `archive` CLI.
//!
//! The `archive` binary is a thin wrapper around these modules. The
//! benchmark helper binary reuses the same adapters so that performance
//! measurements exercise the production dispatch code instead of a
//! separate, drift-prone copy.

pub mod adapters;
pub mod args;
pub mod commands;
pub mod detect;
pub mod error;
pub mod output;
pub mod pager;
