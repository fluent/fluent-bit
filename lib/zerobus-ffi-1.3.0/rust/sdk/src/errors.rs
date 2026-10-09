use thiserror::Error;

/// Represents all possible errors that can occur when using Zerobus.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum ZerobusError {
    /// Returned when the client failed to open a gRPC channel to the Zerobus endpoint.
    #[error("Failed to open a channel: {0}.")]
    ChannelCreationError(String),
    /// Returned when the client failed to create a stream.
    #[error("Failed to create stream: {0}.")]
    CreateStreamError(tonic::Status),
    /// Returned when TLS handshake failed during connection setup.
    #[error("Failed to establish TLS connection.")]
    FailedToEstablishTlsConnectionError,
    /// Returned when the specified Zerobus endpoint is in invalid format.
    #[error("The specified Zerobus endpoint is in invalid format: {0}.")]
    InvalidZerobusEndpointError(String),
    /// Returned when the specified Unity Catalog table name is invalid.
    #[error("Specified UC table name is invalid: {0}.")]
    InvalidTableName(String),
    /// Returned when the specified Unity Catalog endpoint is in invalid format.
    #[error("Specified UC endpoint is in invalid format: {0}.")]
    InvalidUCEndpointError(String),
    /// Returned when the specified Unity Catalog token is invalid.
    #[error("Specified UC token is in invalid format: {0}.")]
    InvalidUCTokenError(String),
    /// Returned when the stream is closed.
    #[error("Stream is closed: {0}")]
    StreamClosedError(tonic::Status),
    /// Returned when the client provided an invalid argument.
    #[error("Invalid argument: {0}.")]
    InvalidArgument(String),
    /// Returned when the server returned an unexpected response.
    #[error("Unexpected response from server. Response: {0}")]
    UnexpectedStreamResponseError(String),
    /// Returned when the stream is in an invalid state for a requested operation.
    #[error("Stream is in invalid state: {0}")]
    InvalidStateError(String),
    /// Returned when a connection or setup operation times out.
    #[error("Connection timeout: {0}")]
    ConnectionTimeout(String),
    /// Returned when OAuth token fetching fails due to network or server errors.
    #[error("Token fetch failed: {0}")]
    TokenFetchError(String),
}

/// List of gRPC status codes that indicate unretriable errors.
const UNRETRIABLE_STATUS_CODES: &[tonic::Code] = &[
    tonic::Code::InvalidArgument,
    tonic::Code::Unauthenticated,
    tonic::Code::PermissionDenied,
    tonic::Code::OutOfRange,
    tonic::Code::Unimplemented,
    tonic::Code::NotFound,
];

impl ZerobusError {
    /// Determines whether this error can be automatically recovered through stream recovery.
    ///
    /// Retryable errors typically indicate transient issues like network failures or
    /// temporary server problems. Non-retryable errors indicate permanent issues like
    /// authentication failures or invalid configurations that require manual intervention.
    ///
    /// # Returns
    ///
    /// `true` if the SDK should attempt automatic recovery, `false` otherwise.
    pub fn is_retryable(&self) -> bool {
        match self {
            ZerobusError::InvalidArgument(_) => false,
            ZerobusError::StreamClosedError(status) => {
                !UNRETRIABLE_STATUS_CODES.contains(&status.code())
            }
            ZerobusError::CreateStreamError(status) => {
                !UNRETRIABLE_STATUS_CODES.contains(&status.code())
            }
            ZerobusError::ChannelCreationError(_) => true,
            ZerobusError::FailedToEstablishTlsConnectionError => true,
            ZerobusError::InvalidZerobusEndpointError(_) => false,
            ZerobusError::InvalidTableName(_) => false,
            ZerobusError::InvalidUCEndpointError(_) => false,
            ZerobusError::InvalidUCTokenError(_) => false,
            ZerobusError::UnexpectedStreamResponseError(_) => true,
            ZerobusError::InvalidStateError(_) => false,
            ZerobusError::ConnectionTimeout(_) => true,
            ZerobusError::TokenFetchError(_) => true,
        }
    }

    /// Reports whether this is a server-side authentication/authorization
    /// rejection (as opposed to a transient or unrelated failure). Used to
    /// decide when to invalidate cached credentials so the next attempt
    /// re-derives them.
    pub(crate) fn is_auth_rejection(&self) -> bool {
        matches!(
            self,
            ZerobusError::CreateStreamError(status) | ZerobusError::StreamClosedError(status)
                if matches!(
                    status.code(),
                    tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
                )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_rejection_classification() {
        assert!(
            ZerobusError::CreateStreamError(tonic::Status::unauthenticated("x"))
                .is_auth_rejection()
        );
        assert!(
            ZerobusError::CreateStreamError(tonic::Status::permission_denied("x"))
                .is_auth_rejection()
        );
        assert!(
            ZerobusError::StreamClosedError(tonic::Status::unauthenticated("x"))
                .is_auth_rejection()
        );
        // Non-auth gRPC codes are not rejections.
        assert!(!ZerobusError::CreateStreamError(tonic::Status::internal("x")).is_auth_rejection());
        assert!(
            !ZerobusError::CreateStreamError(tonic::Status::unavailable("x")).is_auth_rejection()
        );
        // Other variants are never auth rejections.
        assert!(!ZerobusError::TokenFetchError("x".to_string()).is_auth_rejection());
    }

    /// Pins the cross-crate invariant the Arrow path relies on: `FlightError ->
    /// tonic::Status` via `From` preserves the inner gRPC code (unlike
    /// `Status::from_error`, which flattens it to `Unknown`). A future
    /// `arrow-flight` change to that `From` impl fails here instead of silently
    /// disabling Arrow auth-rejection detection.
    #[cfg(feature = "arrow-flight")]
    #[test]
    fn auth_rejection_survives_flight_error_conversion() {
        use arrow_flight::error::FlightError;

        let auth: tonic::Status =
            FlightError::Tonic(Box::new(tonic::Status::permission_denied("denied"))).into();
        assert!(ZerobusError::CreateStreamError(auth).is_auth_rejection());

        let non_auth: tonic::Status =
            FlightError::Tonic(Box::new(tonic::Status::unavailable("blip"))).into();
        assert!(!ZerobusError::CreateStreamError(non_auth).is_auth_rejection());
    }
}
