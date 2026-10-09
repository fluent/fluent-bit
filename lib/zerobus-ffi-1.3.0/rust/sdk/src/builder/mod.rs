//! Builder API for creating Zerobus SDK instances and ingestion streams.
//!
//! This module provides fluent builder patterns for configuring and creating
//! SDK instances and streams.
//!
//! # Examples
//!
//! ## SDK Builder
//!
//! ```no_run
//! use databricks_zerobus_ingest_sdk::ZerobusSdkBuilder;
//!
//! let sdk = ZerobusSdkBuilder::new()
//!     .endpoint("https://workspace.zerobus.databricks.com")
//!     .unity_catalog_url("https://workspace.cloud.databricks.com")
//!     .build()?;
//! # Ok::<(), databricks_zerobus_ingest_sdk::ZerobusError>(())
//! ```
//!
//! ## Stream Builder
//!
//! ```rust,ignore
//! let stream = sdk
//!     .stream_builder()
//!     .table("catalog.schema.table")
//!     .oauth("client-id", "client-secret")
//!     .json()
//!     .build()
//!     .await?;
//! ```

mod sdk_builder;
mod stream_builder;

pub use sdk_builder::ZerobusSdkBuilder;
pub use stream_builder::StreamBuilder;
