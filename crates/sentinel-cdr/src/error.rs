use thiserror::Error;

#[derive(Error, Debug)]
pub enum CdrError {
    #[error("Unsupported file format: {0}")]
    UnsupportedFormat(String),

    #[error("Parser error during deconstruction: {0}")]
    ParserCorruption(String),

    #[error("Disarm failure: {0}")]
    DisarmFailure(String),

    #[error("Reconstruction error: {0}")]
    ReconstructionFailure(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("ZIP archive error: {0}")]
    ZipError(#[from] zip::result::ZipError),

    #[error("Image processing error: {0}")]
    ImageError(#[from] image::ImageError),

    #[error("XML parsing error: {0}")]
    XmlError(String),

    #[error("Security violation: resource limit exceeded ({0})")]
    ResourceLimitExceeded(String),
}

pub type Result<T> = std::result::Result<T, CdrError>;
