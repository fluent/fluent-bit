//! Message registry and descriptor caching.

use std::collections::HashMap;

use prost_types::{field_descriptor_proto, DescriptorProto};

use super::sparse_field_map::{SparseFieldMap, MAX_INLINE_CAPACITY};

/// LABEL_REPEATED = 3 in protobuf.
const LABEL_REPEATED: i32 = 3;

/// Empty prefix for root-level type names.
const ROOT_PREFIX: &str = "";

/// Cached field information - owns its strings for lifetime independence.
///
/// Layout tuned: hot fields (read on every parse iteration) are placed first so
/// they fit in the first 32 bytes / single cache line; cold fields (name/type_name)
/// go after.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct FieldInfo {
    /// Index into the appropriate storage array (scalars if is_scalar, complex otherwise).
    pub storage_index: usize,
    /// Index into the message's oneof groups for user-declared oneofs;
    /// `None` for regular fields and proto3 `optional` synthetic oneofs.
    pub oneof_index: Option<i32>,
    pub field_type: field_descriptor_proto::Type,
    /// True if this is a scalar field (non-repeated, non-message).
    pub is_scalar: bool,
    pub is_repeated: bool,
    /// Stored as `Box<str>` rather than `String` to keep `FieldInfo` small.
    pub name: Box<str>,
    /// For message types.
    pub type_name: Option<String>,
}

/// A member of a oneof group, referencing its storage location.
#[derive(Clone, Debug)]
pub struct OneofMember {
    pub is_scalar: bool,
    pub storage_index: usize,
}

/// Descriptor with pre-computed field cache for fast lookup.
#[derive(Debug)]
pub struct DescriptorWithFieldCache {
    /// Field lookup map using sparse array optimization.
    fields: SparseFieldMap<FieldInfo>,
    /// Whether this message type is a map entry (has options.map_entry = true).
    pub is_map_entry: bool,
    /// Number of scalar fields (for scalars array preallocation).
    pub scalar_count: usize,
    /// Number of complex fields (for complex array preallocation).
    pub complex_count: usize,
    /// Oneof groups indexed by oneof_index. Each group contains all members.
    oneof_groups: Vec<Vec<OneofMember>>,
}

impl DescriptorWithFieldCache {
    #[inline(always)]
    pub fn from_descriptor(desc: &DescriptorProto) -> Self {
        // Max field number in inline range only; larger fields use the overflow map.
        let max_inline_field_num = desc
            .field
            .iter()
            .filter_map(|f| f.number)
            .filter(|&n| n < MAX_INLINE_CAPACITY as i32)
            .max()
            .unwrap_or(0);

        let mut fields = SparseFieldMap::new(max_inline_field_num);
        let mut scalar_count = 0usize;
        let mut complex_count = 0usize;

        // Count the number of real oneof declarations to size the groups array.
        let oneof_count = desc.oneof_decl.len();
        let mut oneof_groups: Vec<Vec<OneofMember>> = vec![Vec::new(); oneof_count];

        for field in desc.field.iter() {
            if let Some(num) = field.number {
                let field_type = field.r#type();
                let is_repeated = field.label == Some(LABEL_REPEATED);

                // Singular non-message fields are scalars; everything else is complex.
                let is_scalar = !is_repeated && field_type != field_descriptor_proto::Type::Message;
                let storage_index = if is_scalar {
                    let idx = scalar_count;
                    scalar_count += 1;
                    idx
                } else {
                    let idx = complex_count;
                    complex_count += 1;
                    idx
                };

                // Capture oneof_index, excluding proto3 synthetic oneofs.
                let oneof_index = field
                    .oneof_index
                    .filter(|_| field.proto3_optional != Some(true));

                // Register in the oneof group if applicable.
                if let Some(idx) = oneof_index {
                    if let Some(group) = oneof_groups.get_mut(idx as usize) {
                        group.push(OneofMember {
                            is_scalar,
                            storage_index,
                        });
                    }
                }

                let info = FieldInfo {
                    name: Box::from(field.name.as_deref().unwrap_or("")),
                    field_type,
                    type_name: field.type_name.clone(),
                    is_repeated,
                    is_scalar,
                    storage_index,
                    oneof_index,
                };

                fields.insert(num, info);
            }
        }

        let is_map_entry = desc
            .options
            .as_ref()
            .and_then(|o| o.map_entry)
            .unwrap_or(false);

        DescriptorWithFieldCache {
            fields,
            is_map_entry,
            scalar_count,
            complex_count,
            oneof_groups,
        }
    }

    #[inline(always)]
    pub fn get_field(&self, field_num: i32) -> Option<&FieldInfo> {
        self.fields.get(field_num)
    }

    /// Returns the members of a oneof group by index.
    #[inline(always)]
    pub fn get_oneof_group(&self, oneof_index: i32) -> &[OneofMember] {
        self.oneof_groups
            .get(oneof_index as usize)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns all oneof groups. Synthetic proto3-`optional` groups appear as empty slots.
    #[inline(always)]
    pub fn oneof_groups(&self) -> &[Vec<OneofMember>] {
        &self.oneof_groups
    }
}

/// A registry that holds all message descriptors by their full type name.
/// Supports arbitrary nesting levels. Owns all data (no lifetime parameters).
#[derive(Debug)]
pub struct MessageRegistry {
    /// Map from full type name (e.g., ".MessageNested.MyNestedMessage") to descriptor cache.
    messages: HashMap<String, DescriptorWithFieldCache>,
    /// Cached descriptor for the root message type.
    pub(crate) root_descriptor: DescriptorWithFieldCache,
}

impl MessageRegistry {
    /// Build a registry from a root descriptor, recursively collecting all nested types.
    /// Clones the necessary data from the descriptor so the registry owns everything.
    #[inline(always)]
    pub fn from_descriptor(root: &DescriptorProto) -> Self {
        let mut messages = HashMap::new();
        Self::collect_messages(root, &mut messages);

        let root_descriptor = DescriptorWithFieldCache::from_descriptor(root);

        MessageRegistry {
            messages,
            root_descriptor,
        }
    }

    /// Iteratively collect all message descriptors using an explicit stack.
    /// This avoids stack overflow for deeply nested message types.
    #[inline(always)]
    fn collect_messages(
        root: &DescriptorProto,
        acc: &mut HashMap<String, DescriptorWithFieldCache>,
    ) {
        // Use an explicit stack: (descriptor, prefix)
        let mut stack: Vec<(&DescriptorProto, String)> = vec![(root, ROOT_PREFIX.to_string())];

        while let Some((desc, current_prefix)) = stack.pop() {
            let name = desc.name.as_deref().unwrap_or("");
            let full_name = if current_prefix.is_empty() {
                format!(".{name}")
            } else {
                format!("{current_prefix}.{name}")
            };

            acc.insert(
                full_name.clone(),
                DescriptorWithFieldCache::from_descriptor(desc),
            );

            // Push nested types onto the stack (in reverse order to maintain processing order).
            for nested in desc.nested_type.iter().rev() {
                stack.push((nested, full_name.clone()));
            }
        }
    }

    pub fn get(&self, type_name: &str) -> Option<&DescriptorWithFieldCache> {
        self.messages.get(type_name)
    }

    /// Get the type name for a field in the root message (for nested message/array/map types).
    /// Returns None if the field doesn't exist or has no type name.
    pub fn get_field_type_name(&self, field_num: i32) -> Option<&str> {
        self.root_descriptor
            .get_field(field_num)?
            .type_name
            .as_deref()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::zeroparser::parser::tests::{make_descriptor, make_field};

    impl MessageRegistry {
        pub fn get_field_name(&self, field_num: i32) -> Option<&str> {
            self.root_descriptor.get_field(field_num).map(|f| &*f.name)
        }
    }

    #[test]
    fn descriptor_cache_field_lookup() {
        let fields = vec![
            make_field(1, "id", field_descriptor_proto::Type::Int32, false, None),
            make_field(2, "name", field_descriptor_proto::Type::String, false, None),
            make_field(
                200,
                "large",
                field_descriptor_proto::Type::String,
                false,
                None,
            ),
            make_field(3, "items", field_descriptor_proto::Type::Int32, true, None),
        ];
        let desc = make_descriptor("TestMessage", fields);
        let cache = DescriptorWithFieldCache::from_descriptor(&desc);

        // Small field numbers in sparse array (0-127).
        let field1 = cache.get_field(1).unwrap();
        assert_eq!(&*field1.name, "id");
        assert_eq!(field1.field_type, field_descriptor_proto::Type::Int32);
        assert!(!field1.is_repeated);

        let field2 = cache.get_field(2).unwrap();
        assert_eq!(&*field2.name, "name");

        let field200 = cache.get_field(200).unwrap();
        assert_eq!(&*field200.name, "large");

        let field3 = cache.get_field(3).unwrap();
        assert!(field3.is_repeated);

        assert!(cache.get_field(99).is_none());
        assert!(cache.get_field(0).is_none());
    }

    #[test]
    fn descriptor_cache_map_entry() {
        let desc = make_descriptor("TestMessage", vec![]);
        assert!(!DescriptorWithFieldCache::from_descriptor(&desc).is_map_entry);

        let mut map_desc = make_descriptor(
            "MapEntry",
            vec![
                make_field(1, "key", field_descriptor_proto::Type::String, false, None),
                make_field(2, "value", field_descriptor_proto::Type::Int32, false, None),
            ],
        );
        map_desc.options = Some(prost_types::MessageOptions {
            map_entry: Some(true),
            ..Default::default()
        });
        assert!(DescriptorWithFieldCache::from_descriptor(&map_desc).is_map_entry);
    }

    #[test]
    fn message_registry_lookup() {
        let fields = vec![make_field(
            1,
            "id",
            field_descriptor_proto::Type::Int32,
            false,
            None,
        )];
        let desc = make_descriptor("RootMessage", fields);
        let registry = MessageRegistry::from_descriptor(&desc);

        assert_eq!(&*registry.root_descriptor.get_field(1).unwrap().name, "id");
        assert!(registry.get(".RootMessage").is_some());
        assert!(registry.get(".NonExistent").is_none());
    }

    #[test]
    fn message_registry_nested() {
        let level3 = make_descriptor(
            "Level3",
            vec![make_field(
                1,
                "field3",
                field_descriptor_proto::Type::Bool,
                false,
                None,
            )],
        );
        let mut level2 = make_descriptor("Level2", vec![]);
        level2.nested_type.push(level3);
        let mut level1 = make_descriptor(
            "Level1",
            vec![
                make_field(1, "id", field_descriptor_proto::Type::Int32, false, None),
                make_field(
                    2,
                    "nested",
                    field_descriptor_proto::Type::Message,
                    false,
                    Some(".Level1.Level2"),
                ),
            ],
        );
        level1.nested_type.push(level2);

        let registry = MessageRegistry::from_descriptor(&level1);

        assert!(registry.get(".Level1").is_some());
        assert!(registry.get(".Level1.Level2").is_some());
        assert!(registry.get(".Level1.Level2.Level3").is_some());

        let level3_cache = registry.get(".Level1.Level2.Level3").unwrap();
        assert_eq!(&*level3_cache.get_field(1).unwrap().name, "field3");

        // Test get_field_type_name: scalar returns None, message returns type name.
        assert_eq!(registry.get_field_type_name(1), None);
        assert_eq!(registry.get_field_type_name(2), Some(".Level1.Level2"));
        assert_eq!(registry.get_field_type_name(99), None);
    }
}
