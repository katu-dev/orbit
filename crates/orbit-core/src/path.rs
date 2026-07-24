use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::UnicodeNormalization;

const MAX_COMPONENT_BYTES: usize = 255;
const MAX_PATH_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct RelativePath {
    display: String,
    comparison_key: String,
}

impl RelativePath {
    pub fn new(value: impl AsRef<str>) -> Result<Self, PathError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(PathError::Empty);
        }
        if value.starts_with('/') || value.ends_with('/') {
            return Err(PathError::NotRelative);
        }

        let mut display_components = Vec::new();
        let mut comparison_components = Vec::new();

        for component in value.split('/') {
            let normalized: String = component.nfc().collect();
            validate_component(&normalized)?;

            comparison_components.push(normalized.as_str().case_fold().nfc().collect::<String>());
            display_components.push(normalized);
        }

        let display = display_components.join("/");
        if display.len() > MAX_PATH_BYTES {
            return Err(PathError::PathTooLong {
                actual: display.len(),
                maximum: MAX_PATH_BYTES,
            });
        }

        Ok(Self {
            display,
            comparison_key: comparison_components.join("/"),
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.display
    }

    #[must_use]
    pub fn comparison_key(&self) -> &str {
        &self.comparison_key
    }

    #[must_use]
    pub fn file_name(&self) -> &str {
        self.display
            .rsplit_once('/')
            .map_or(self.display.as_str(), |(_, file_name)| file_name)
    }
}

impl AsRef<str> for RelativePath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RelativePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.display.fmt(formatter)
    }
}

impl From<RelativePath> for String {
    fn from(value: RelativePath) -> Self {
        value.display
    }
}

impl FromStr for RelativePath {
    type Err = PathError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for RelativePath {
    type Error = PathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PathError {
    #[error("path cannot be empty")]
    Empty,
    #[error("path must be relative and cannot start or end with a separator")]
    NotRelative,
    #[error("path contains an empty component")]
    EmptyComponent,
    #[error("path component '{component}' is not allowed")]
    TraversalComponent { component: String },
    #[error("path component '{component}' contains forbidden character {character:?}")]
    ForbiddenCharacter { component: String, character: char },
    #[error("path component '{component}' cannot end with a dot or space")]
    TrailingDotOrSpace { component: String },
    #[error("path component '{component}' is a reserved Windows device name")]
    ReservedName { component: String },
    #[error("path component is {actual} bytes; maximum is {maximum}")]
    ComponentTooLong { actual: usize, maximum: usize },
    #[error("path is {actual} bytes; maximum is {maximum}")]
    PathTooLong { actual: usize, maximum: usize },
}

fn validate_component(component: &str) -> Result<(), PathError> {
    if component.is_empty() {
        return Err(PathError::EmptyComponent);
    }
    if component == "." || component == ".." {
        return Err(PathError::TraversalComponent {
            component: component.to_owned(),
        });
    }
    if component.len() > MAX_COMPONENT_BYTES {
        return Err(PathError::ComponentTooLong {
            actual: component.len(),
            maximum: MAX_COMPONENT_BYTES,
        });
    }
    if component.ends_with(['.', ' ']) {
        return Err(PathError::TrailingDotOrSpace {
            component: component.to_owned(),
        });
    }
    if is_windows_reserved(component) {
        return Err(PathError::ReservedName {
            component: component.to_owned(),
        });
    }
    if let Some(character) = component
        .chars()
        .find(|character| character.is_control() || r#"<>:"\|?*"#.contains(*character))
    {
        return Err(PathError::ForbiddenCharacter {
            component: component.to_owned(),
            character,
        });
    }

    Ok(())
}

fn is_windows_reserved(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem)
        .to_ascii_uppercase();

    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || has_reserved_numbered_prefix(&stem, "COM")
        || has_reserved_numbered_prefix(&stem, "LPT")
}

fn has_reserved_numbered_prefix(stem: &str, prefix: &str) -> bool {
    stem.strip_prefix(prefix)
        .is_some_and(|suffix| matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_display_path_to_nfc() {
        let path = RelativePath::new("notes/cafe\u{301}.txt").unwrap();

        assert_eq!(path.as_str(), "notes/café.txt");
    }

    #[test]
    fn creates_full_unicode_case_fold_key() {
        let left = RelativePath::new("Straße/FILE.txt").unwrap();
        let right = RelativePath::new("STRASSE/file.txt").unwrap();

        assert_eq!(left.comparison_key(), right.comparison_key());
        assert_ne!(left, right);
    }

    #[test]
    fn rejects_ambiguous_or_non_portable_components() {
        let invalid = [
            "../secret.txt",
            "folder//file.txt",
            "folder\\file.txt",
            "CON.txt",
            "folder/trailing. ",
            "/absolute.txt",
        ];

        for value in invalid {
            assert!(RelativePath::new(value).is_err(), "accepted {value}");
        }
    }
}
