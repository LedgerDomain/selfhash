use std::borrow::Cow;

#[derive(Debug)]
pub struct Error(Cow<'static, str>);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Deref for Error {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::error::Error for Error {}

#[cfg(feature = "mbx")]
impl From<mbx::Error> for Error {
    fn from(e: mbx::Error) -> Self {
        Self(Cow::Owned(e.to_string()))
    }
}

#[cfg(feature = "self-hashable-json")]
impl From<jsonpath_lib::JsonPathError> for Error {
    fn from(e: jsonpath_lib::JsonPathError) -> Self {
        Self(Cow::Owned(e.to_string()))
    }
}

#[cfg(feature = "self-hashable-json")]
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self(Cow::Owned(e.to_string()))
    }
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Self(Cow::Owned(s))
    }
}

impl Into<Cow<'static, str>> for Error {
    fn into(self) -> Cow<'static, str> {
        self.0
    }
}

/// This will construct a formatted Error.
#[macro_export]
macro_rules! error {
    ($msg: literal) => {
        $crate::Error::from($msg)
    };
    ($format_str: literal, $($arg:tt)*) => {
        $crate::Error::from(format!($format_str, $($arg)*))
    };
}

/// This will unconditionally return with the formatted error.
#[macro_export]
macro_rules! bail {
    ($msg: literal) => {
        { return Err($crate::Error::from($msg)); }
    };
    ($format_str: literal, $($arg:tt)*) => {
        { return Err($crate::Error::from(format!($format_str, $($arg)*))); }
    };
}

/// This will return with the formatted error if the condition is not met.
#[macro_export]
macro_rules! ensure {
    ($condition: expr, $msg: literal) => {
        if !$condition {
            return Err($crate::Error::from($msg));
        }
    };
    ($condition: expr, $format_str: literal, $($arg:tt)*) => {
        if !$condition {
            return Err($crate::Error::from(format!($format_str, $($arg)*)));
        }
    };
}
