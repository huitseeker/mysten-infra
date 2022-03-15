use super::wire_msg::WireMsg;

use quinn::ConnectionError;

use thiserror::Error;

/// Errors that can occur when sending messages.
#[derive(Debug, Error)]
pub enum SendError {
    /// This likely indicates a bug in the library, since serializing to bytes should be infallible.
    /// Limitations in the serde API mean we cannot verify this statically, and we don't want to
    /// introduce potential panics.
    #[error("Failed to serialize message")]
    Serialization(#[from] SerializationError),

    #[error("Connection was lost when trying to send a message")]
    ConnectionLost(#[from] ConnectionError),

    #[error("Stream was lost when trying to send a message")]
    StreamLost(#[source] StreamError),
}

impl From<bincode::Error> for SendError {
    fn from(error: bincode::Error) -> Self {
        Self::Serialization(SerializationError(error))
    }
}

impl From<quinn::WriteError> for SendError {
    fn from(error: quinn::WriteError) -> Self {
        match error {
            quinn::WriteError::Stopped(code) => Self::StreamLost(StreamError::Stopped(code.into())),
            quinn::WriteError::ConnectionLost(error) => Self::ConnectionLost(error),
            quinn::WriteError::UnknownStream => Self::StreamLost(StreamError::Gone),
            quinn::WriteError::ZeroRttRejected => Self::StreamLost(StreamError::Unsupported(
                UnsupportedStreamOperation(error.into()),
            )),
        }
    }
}

/// Errors that can occur when receiving messages.
#[derive(Debug, Error)]
pub enum RecvError {
    #[error("Failed to deserialize message")]
    Serialization(#[from] SerializationError),

    #[error("Connection was lost when trying to receive a message")]
    ConnectionLost(#[from] ConnectionError),

    #[error("Stream was lost when trying to receive a message")]
    StreamLost(#[source] StreamError),
}

impl From<bincode::Error> for RecvError {
    fn from(error: bincode::Error) -> Self {
        Self::Serialization(SerializationError(error))
    }
}

impl From<quinn::ReadError> for RecvError {
    fn from(error: quinn::ReadError) -> Self {
        use quinn::ReadError;

        match error {
            ReadError::Reset(code) => Self::StreamLost(StreamError::Stopped(code.into())),
            ReadError::ConnectionLost(error) => Self::ConnectionLost(error),
            ReadError::UnknownStream => Self::StreamLost(StreamError::Gone),
            ReadError::IllegalOrderedRead | ReadError::ZeroRttRejected => Self::StreamLost(
                StreamError::Unsupported(UnsupportedStreamOperation(error.into())),
            ),
        }
    }
}

impl From<quinn::ReadExactError> for RecvError {
    fn from(error: quinn::ReadExactError) -> Self {
        match error {
            quinn::ReadExactError::FinishedEarly => Self::Serialization(SerializationError::new(
                "Received too few bytes for message",
            )),
            quinn::ReadExactError::ReadError(error) => error.into(),
        }
    }
}

/// Failed to (de)serialize message.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct SerializationError(bincode::Error);

impl SerializationError {
    /// Construct a `SerializationError` with an arbitrary message.
    pub(crate) fn new(message: impl ToString) -> Self {
        Self(bincode::ErrorKind::Custom(message.to_string()).into())
    }

    /// Construct a `SerializationError` for an unexpected message.
    pub(crate) fn unexpected(actual: &Option<WireMsg>) -> Self {
        if let Some(actual) = actual {
            Self::new(format!(
                "The message received was not the expected one: {}",
                actual
            ))
        } else {
            Self::new("Unexpected end of stream")
        }
    }
}

/// Errors that can occur when interacting with streams.
#[derive(Debug, Error)]
pub enum StreamError {
    #[error("The peer abandoned the stream (error code: {0})")]
    Stopped(u64),

    #[error("The stream was already stopped, finished, or reset")]
    Gone,

    /// Additional stream errors can arise from the use of 0-RTT connections or unordered reads,
    /// neither of which we support.
    #[error("An error was caused by an unsupported operation")]
    Unsupported(#[source] UnsupportedStreamOperation),
}

/// An error caused by an unsupported operation.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct UnsupportedStreamOperation(Box<dyn std::error::Error + Send + Sync>);
