//! Wireshark dissector plugin for MAC Privacy Protection (MPP) protocol (802.1AEdk).
//!
//! This plugin is built as a dynamic library which can be added to existing installs
//! of Wireshark and tshark. If you don't know where the correct directory is run
//! ```sh
//! tshark -G folders
//! ```
//! and look for the `Personal Plugins` directory.
use std::{
    cell::{LazyCell, RefCell},
    hash::{DefaultHasher, Hash, Hasher},
    os::raw::c_void,
    sync::atomic::{AtomicU32, Ordering},
};

use wsdf::{
    epan_sys::{self, gsize},
    plugin,
    wireshark::{
        Address, Column, Dissector, DissectorDecodeFrom, DissectorTrait, Encoding, EthertypeData,
        EthertypeDissector, ExpertGroup, ExpertSeverity, FieldBuilder, FieldConvert, FieldDisplay,
        FieldType, FragmentItemsNames, Plugin, Protocol, ProtocolBuilder, ReassemblyTable,
        RegistrationError, Tree, TreeItem, TrueFalseString, TvbRange,
    },
};

use crate::mac_addr::MacAddr;

mod mac_addr;

//-----------------------------------------------------------------------------
/// Bit mask to check the frame fragment bit
const FRAME_FRAGMENT_MASK: u8 = 0b1000_0000;

/// Number of octets (bytes) in a MAC address
const MAC_LENGTH_BYTES: i32 = 6;

/// MAC Privacy ethertype
const MAC_PRIVACY_ETHERTYPE: u32 = 0xe23b;

/// Bit mask to isolate the MPPDU type
const MPPDU_TYPE_MASK: u8 = 0xc0;

/// Bit mas to isolated the MPPDU following length
const MPPDU_FOLLOWING_LENGTH_MASK: u16 = 0x3f_ff;

// Frame fragment flags

/// Initial frame fragment bit mask
const INITIAL_FRAME: u8 = 0b0100_0000;

/// Final frame fragment bit mask
const FINAL_FRAME: u8 = 0b0010_0000;

/// Express frame fragment bit mask
const EXPRESS_FRAME: u8 = 0b0001_0000;

/// Maps `true` to `Set` and `false` to `Not set` when printing flags values
const SET_NOT_SET: FieldConvert = FieldConvert::TrueFalseString(TrueFalseString {
    true_string: "Set",
    false_string: "Not set",
});

/// Sequence ID of the initial frame fragment in the current fragment sequence
/// on the express channel
static EXPRESS_SEQUENCE_FIRST_ID: AtomicU32 = AtomicU32::new(0);

/// Sequence ID of the initial frame fragment in the current fragment sequence
/// on the preemptable channel
static PREEMPTABLE_SEQUENCE_FIRST_ID: AtomicU32 = AtomicU32::new(0);

//-----------------------------------------------------------------------------
thread_local! {
    /// Thread local static reassembly table.
    ///
    /// Stores tables for reassembling fragmented frames as well as pointers to
    /// functions to assist in proper reassembly of fragmented frames.
    ///
    // TODO: This uses the same function to create persistent and temporary keys.
    // Using shallow copies in the temporary_key_function might be a more efficient.
    static REASSEMBLY_TABLE: LazyCell<RefCell<ReassemblyTable<FragmentKey>>> = LazyCell::new(|| {
        let functions = epan_sys::reassembly_table_functions {
            equal_func: Some(FragmentKey::key_equal),
            hash_func: Some(FragmentKey::key_hash),
            temporary_key_func: Some(FragmentKey::persistent_key),
            persistent_key_func: Some(FragmentKey::persistent_key),
            free_temporary_key_func: Some(FragmentKey::free_persistent_key),
            free_persistent_key_func: Some(FragmentKey::free_persistent_key),
        };

        RefCell::new(ReassemblyTable::init(&functions))
    });
}

//-----------------------------------------------------------------------------
/// Frame type or priority.
///
/// 802.1AEdk-2023 20.13 identifies 2 priority levels for frames: Express and
/// Preemptable.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
enum FrameType {
    /// Preemptable frame.
    #[default]
    Preemptable = 0,

    /// Express frame.
    Express = 1 << 31,
}

impl From<FrameType> for u32 {
    fn from(value: FrameType) -> Self {
        value as u32
    }
}

//-----------------------------------------------------------------------------
/// Fragment metadata used by Wireshark when reassembling frames.
///
/// This type replaces Wireshark's built-in type `fragment_addresses_key`. While
/// very similar, that type references `pinfo->src` and `pinfo->dst` for source
/// and destination addresses but those addresses may be affected by processing
/// of MPPDU mpp_state.components. This struct uses link-layer addresses, which
/// shouldn't change during processing.
#[derive(Clone, Debug, Hash, PartialEq)]
struct FragmentKey {
    /// `true` if this frame is an express frame; otherwise `false`.
    express: bool,

    /// Sequence ID of the initial frame fragment in the current fragment sequence.
    sequence_id: u32,

    /// Link-layer source address.
    source_address: Address,

    /// Link-layer destination address.
    destination_address: Address,
}

impl FragmentKey {
    //-----------------------------------------------------------------------------
    /// C-friendly wrapper function for checking if two `FragmentKey`s are equal.
    /// Returns true if the `FragmentKey`s at the given pointers are equal;
    /// otherwise `false`.
    unsafe extern "C" fn key_equal(
        a: epan_sys::gconstpointer,
        b: epan_sys::gconstpointer,
    ) -> epan_sys::gboolean {
        if a.is_null() || b.is_null() {
            false as epan_sys::gboolean
        } else {
            let a = a as *const FragmentKey;
            let b = b as *const FragmentKey;

            let equal = unsafe { *a == *b };
            equal as epan_sys::gboolean
        }
    }

    //-----------------------------------------------------------------------------
    /// C-friendly wrapper function for computing the hash of a `FragmentKey`.
    ///
    /// Note: This function truncates the `u64` value returned by [`Hasher::finish`]
    /// to a `u32`, which is what Wireshark requires.
    unsafe extern "C" fn key_hash(key: epan_sys::gconstpointer) -> epan_sys::guint {
        let key = key as *const FragmentKey;
        let mut hasher = DefaultHasher::new();

        unsafe {
            (*key).hash(&mut hasher);
        }

        let hash_value = hasher.finish();
        // NOTE: This will cause the u64 value to be truncated
        hash_value as u32
    }

    //-----------------------------------------------------------------------------
    /// C-friendly function which allocates new memory using Wireshark's allocator
    /// and copies the given `FragmentKey` into it.
    ///
    /// Returns `nullptr` if the given `FragmentKey` pointer is `null`.
    unsafe extern "C" fn persistent_key(
        _pinfo: *const epan_sys::packet_info,
        _id: u32,
        data: *const c_void,
    ) -> *mut c_void {
        if data.is_null() {
            return std::ptr::null_mut();
        }

        let data = data as *const FragmentKey;

        unsafe {
            let fragment_key =
                epan_sys::g_slice_alloc(size_of::<FragmentKey>() as gsize) as *mut FragmentKey;
            std::ptr::copy(data, fragment_key, 1);
            fragment_key as *mut c_void
        }
    }

    //-----------------------------------------------------------------------------
    /// C-friendly function for freeing a `FragmentKey` object allocated by
    /// Wireshark's allocator.
    unsafe extern "C" fn free_persistent_key(data: epan_sys::gpointer) {
        if !data.is_null() {
            unsafe {
                epan_sys::g_slice_free1(size_of::<FragmentKey>() as gsize, data);
            }
        }
    }
}

//-----------------------------------------------------------------------------
/// Stores and tracks values during dissection
struct MppduState<'a> {
    /// Collection of MPPDU components found in the current MacPrivacy frame.
    components: Vec<&'a str>,

    /// The next TVB to dissect.
    next_tvb: TvbRange,

    /// If `true`, indicates data was passed to a subdissector for further
    /// processing; otherwise, `false`.
    subdissector_called: bool,
}

impl<'a> MppduState<'a> {
    //-----------------------------------------------------------------------------
    /// Creates a new `MppduState` object using the given [`TvbRange`].
    fn new(next_tvb: TvbRange) -> Self {
        Self {
            components: Vec::default(),
            next_tvb,
            subdissector_called: false,
        }
    }

    //-----------------------------------------------------------------------------
    /// Checks if all bytes in the given [`TvbRange`] are equal to zero.
    ///
    /// 802.1AEdk-2023 19.6.e states "All pad octets in a Trailing Pad or an
    /// Explicit Pad shall have the value zero." This function checks that rule.
    /// If the given [`TvbRange`] has non-zero values, this function uses expert
    /// info to add a warning to the dissection details.
    fn check_padding_bytes(
        tree: &mut Tree,
        pad_range: TvbRange,
        mut pad: TreeItem,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if pad_range.bytes().iter().any(|value| *value != 0) {
            tree.add_expert_info(
                &mut pad,
                "expert_nonzero_pad",
                Some("Padding bytes must be zero"),
            )?;
        }

        Ok(())
    }

    //-----------------------------------------------------------------------------
    /// Dissects an encapsulated frame MPPDU component.
    ///
    /// If successful, returns the number of bytes dissected; otherwise returns an
    /// error.
    fn dissect_encapsulated_frame(
        &mut self,
        tree: &mut Tree,
        component_tree: &mut Tree,
        mppdu_type_item: &mut TreeItem,
        mppdu_length_range: TvbRange,
        payload_range: TvbRange,
    ) -> Result<i32, Box<dyn std::error::Error>> {
        component_tree.append_text(", Type: Encapsulated Frame");
        mppdu_type_item.append_text(" (Encapsulated Frame)");
        self.components.push("Encapsulated Frame");
        component_tree.add("component.following_length", mppdu_length_range)?;

        let mut frame_subtree = tree.add("encapsulated_frame", payload_range)?;

        // Parse destination then source MAC addresses
        let da_range = payload_range.range(0, MAC_LENGTH_BYTES)?;
        frame_subtree.add_item("encapsulated_frame.destination_address", da_range)?;
        let sa_range = payload_range.range(MAC_LENGTH_BYTES, MAC_LENGTH_BYTES)?;
        frame_subtree.add_item("encapsulated_frame.source_address", sa_range)?;

        // Append parsed source and destination MAC addresses in that order--
        // consistent with handling of Ethernet II frames
        component_tree.append_text(&format!(", Src: {}", MacAddr::try_from(sa_range.bytes())?));
        component_tree.append_text(&format!(", Dst: {}", MacAddr::try_from(da_range.bytes())?));

        let msdu_range = payload_range.range(MAC_LENGTH_BYTES * 2, -1)?;

        // Pass MAC Service Data Unit (MSDU) to the ethertype dissector
        call_ethertype_dissector(msdu_range, tree, &frame_subtree)?;
        self.subdissector_called = true;

        Ok(payload_range.length())
    }

    //-----------------------------------------------------------------------------
    /// Dissects an explicit pad MPPDU component.
    ///
    /// If successful, returns the number of bytes dissected; otherwise returns an
    /// error.
    fn dissect_explicit_pad(
        &mut self,
        tree: &mut Tree,
        component_tree: &mut Tree,
        mppdu_type_item: &mut TreeItem,
        mppdu_length_range: TvbRange,
        payload_range: TvbRange,
    ) -> Result<i32, Box<dyn std::error::Error>> {
        // An Explicit Pad component can be encoded with a following length that
        // exceeds the number of octets remaining in the MPPDU. See
        // 802.1AEdk-2023 19.9.d
        // The following lines set the end of the pad to the end of the MPPDU if
        // the specified following length exceeds that index.

        component_tree.append_text(&format!(
            ", Type: Explicit Pad, Length: {}",
            payload_range.length()
        ));
        mppdu_type_item.append_text(" (Explicit Pad)");
        self.components.push("Explicit Pad");
        component_tree.add_item("component.following_length", mppdu_length_range)?;

        let pad = component_tree.add_item("explicit_pad", payload_range)?;
        Self::check_padding_bytes(tree, payload_range, pad)?;
        Ok(payload_range.length())
    }

    //-----------------------------------------------------------------------------
    /// Dissects a frame fragment MPPDU component.
    ///
    /// If successful, returns the number of bytes dissected; otherwise returns an
    /// error.
    fn dissect_frame_fragment(
        &mut self,
        tree: &mut Tree,
        component_tree: &mut Tree,
        mppdu_type_item: &mut TreeItem,
        mppdu_length_range: TvbRange,
        payload_range: TvbRange,
    ) -> Result<i32, Box<dyn std::error::Error>> {
        let frame_fragment_header_range = payload_range.range(0, 4)?;
        let flags_range = frame_fragment_header_range.range(0, 1)?;
        let flags_value = flags_range.uint8()?;

        component_tree.append_text(", Type: Frame Fragment");
        mppdu_type_item.append_text(" (Frame Fragment)");
        self.components.push("Frame Fragment");
        component_tree.add("component.following_length", mppdu_length_range)?;

        let mut frame_fragment_subtree = tree.add("frame_fragment", payload_range)?;

        // Dissect and decode frame fragment flags
        let flags_range = frame_fragment_header_range.range(0, 1)?;
        let mut flags_subtree = frame_fragment_subtree.add("frame_fragment.flags", flags_range)?;

        flags_subtree.add_item("frame_fragment.flags.initial_frame", flags_range)?;
        flags_subtree.add_item("frame_fragment.flags.final_frame", flags_range)?;
        flags_subtree.add_item("frame_fragment.flags.express_frame", flags_range)?;

        let mut set_flags_names = Vec::new();
        if flags_value & INITIAL_FRAME == INITIAL_FRAME {
            set_flags_names.push("Initial");
        }

        if flags_value & FINAL_FRAME == FINAL_FRAME {
            set_flags_names.push("Final");
        }

        if flags_value & EXPRESS_FRAME == EXPRESS_FRAME {
            set_flags_names.push("Express");
        }
        flags_subtree.append_text(&format!(" ({})", set_flags_names.join(", ")));
        component_tree.append_text(&format!(
            ", Flags: {}",
            if set_flags_names.is_empty() {
                "(None)".to_string()
            } else {
                set_flags_names.join(", ")
            }
        ));

        let frame_sequence_number_range = frame_fragment_header_range.range(1, 3)?;
        frame_fragment_subtree.add_item(
            "frame_fragment.sequence_number",
            frame_sequence_number_range,
        )?;

        let frame_sequence_number = frame_sequence_number_range.uint24(Encoding::BigEndian)?;

        // Reassembled data should processed the same as an encapsulated frame
        // The remaining data in the MPPDU is user data
        // TODO: Reassemble fragmented data across packets before continuing dissection
        let frame_fragment = payload_range.range(frame_fragment_header_range.length(), -1)?;

        tree.pinfo.set_fragmented(true);

        let is_express_frame = flags_value & EXPRESS_FRAME == EXPRESS_FRAME;
        let is_initial_frame = flags_value & INITIAL_FRAME == INITIAL_FRAME;
        let is_final_frame = flags_value & FINAL_FRAME == FINAL_FRAME;

        let frame_type = if is_express_frame {
            FrameType::Express
        } else {
            FrameType::Preemptable
        };

        // If this is an initial frame fragment, wireshark expects it's number to be zero.
        let fragment_number = if is_initial_frame {
            0
        } else {
            frame_sequence_number
        };

        let sequence_id = sequence_id(is_initial_frame, is_express_frame, frame_sequence_number);

        let fragment_head = REASSEMBLY_TABLE.with(|reassembly_table| {
            let mut table = reassembly_table.borrow_mut();

            let key = FragmentKey {
                express: is_express_frame,
                sequence_id,
                source_address: tree.pinfo.dl_src(),
                destination_address: tree.pinfo.dl_dst(),
            };

            let fragment_head = table.fragment_add_seq_check(
                &frame_fragment,
                frame_fragment.offset(),
                &tree.pinfo,
                u32::from(frame_type) + sequence_id,
                Some(&key),
                fragment_number,
                !is_final_frame,
            );

            // If this is an initial frame fragment, tell wireshark to update the sequence offset.
            // This way, we avoid renumbering every frame fragment.
            // If this adjustment is not made, the fragments won't be properly reassembled because
            // wireshark would expect the fragment IDs to be contiguous.
            if is_initial_frame {
                table.fragment_add_seq_offset(
                    &tree.pinfo,
                    frame_type.into(),
                    Some(&key),
                    frame_sequence_number,
                );
            }

            fragment_head
        });

        match tree.process_reassembled_data(payload_range, "Reassembled Frame", fragment_head, None)
        {
            Some(new_tvb) => {
                eprintln!("completed reassembling fragmented frame");

                let new_tvb_range = new_tvb.range_all();
                let mut reassembled_frame_subtree =
                    component_tree.add("reassembled_frame", new_tvb_range)?;

                // Parse destination then source MAC addresses
                let da_range = new_tvb_range.range(0, MAC_LENGTH_BYTES)?;
                reassembled_frame_subtree
                    .add_item("reassembled_frame.destination_address", da_range)?;
                let sa_range = new_tvb_range.range(MAC_LENGTH_BYTES, MAC_LENGTH_BYTES)?;
                reassembled_frame_subtree.add_item("reassembled_frame.source_address", sa_range)?;

                // Append parsed source and destination MAC addresses in that
                // order--consistent with handling of Ethernet II frames
                component_tree
                    .append_text(&format!(", Src: {}", MacAddr::try_from(sa_range.bytes())?));
                component_tree
                    .append_text(&format!(", Dst: {}", MacAddr::try_from(da_range.bytes())?));

                let msdu_range = new_tvb_range.range(MAC_LENGTH_BYTES * 2, -1)?;
                reassembled_frame_subtree.add_item("reassembled_frame.msdu", msdu_range)?;

                // Pass MAC Service Data Unit (MSDU) to the ethertype dissector
                call_ethertype_dissector(msdu_range, tree, &reassembled_frame_subtree)?;
                self.subdissector_called = true;
            }
            None => eprintln!("failed to assemble new TVB"),
        }

        Ok(payload_range.length())
    }

    //-----------------------------------------------------------------------------
    /// Dissects a trailing pad MPPDU component.
    ///
    /// If successful, returns the number of bytes dissected; otherwise returns an
    /// error.
    fn dissect_trailing_pad(
        &mut self,
        tree: &mut Tree,
        component_tree: &mut Tree,
        mppdu_type_item: &mut TreeItem,
        offset: i32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        component_tree.append_text(", Type: Trailing Pad");
        mppdu_type_item.append_text(" (Trailing Pad)");

        component_tree.set_length(self.next_tvb.length());

        // For a trailing pad, the "payload" extends to the end of the MPPDU
        // which should be the same as the end of the original buffer passed to
        // this dissector.
        let trailing_pad_range = self.next_tvb.range(offset, -1)?;

        // Don't add trailing pad bytes for special one- and two-byte trailing pads.
        if trailing_pad_range.length() > 0 {
            let pad = tree.add_item("trailing_pad", trailing_pad_range)?;
            Self::check_padding_bytes(tree, trailing_pad_range, pad)?;
        }

        self.components.push("Trailing Pad");

        Ok(())
    }

    //-----------------------------------------------------------------------------
    /// Checks if bit 8 of the third octet is zero.
    ///
    /// A frame fragment MPPDU component must have this bit clear set to zero.
    ///
    /// Returns `true` if the value is zero or `false` if the value is 1. Returns
    /// an error if the give [`TvbRange`] is not long enough.
    fn frame_fragment_flag_clear(
        &self,
        payload_range: TvbRange,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let frame_fragment_header_range = payload_range.range(0, 4)?;
        let flags_range = frame_fragment_header_range.range(0, 1)?;
        let flags_value = flags_range.uint8()?;

        Ok(flags_value & FRAME_FRAGMENT_MASK != FRAME_FRAGMENT_MASK)
    }
}

//-----------------------------------------------------------------------------
plugin!(build_mac_privacy_protocol);

//-----------------------------------------------------------------------------
/// Constructs the MAC Privacy Protection protocol dissector.
pub fn build_mac_privacy_protocol() -> Result<Protocol, RegistrationError> {
    const NAME: &str = "MAC Privacy protection Protocol Data Unit (MPPDU)";
    const ABBREVIATION: &str = "MACPrivacy";
    const FILTER: &str = "macprivacy";

    let protocol = ProtocolBuilder::new(NAME, ABBREVIATION, FILTER)
        .dissector(Dissector::new(
            |tree, tvb| -> Result<i32, Box<dyn std::error::Error>> {
                tree.pinfo.set_column_text(Column::Protocol, ABBREVIATION);

                // Set the initial value of `next_tvb` to the entire range of `tvb`
                let mut mppdu_state = MppduState::new(tvb.range(0, -1)?);

                // Dissect MPPDUs until reaching the end of the `tvb`
                // We don't know ahead of time how many MPPDUs are in a single packet
                while mppdu_state.next_tvb.length() > 0 {
                    // Determine the MPPDU type
                    let mppdu_type_range = mppdu_state.next_tvb.range(0, 1)?;
                    let mut component_tree = tree.add("component", mppdu_type_range)?;

                    let mut mppdu_type_item =
                        component_tree.add_item("component.type", mppdu_type_range)?;
                    let mppdu_type_value = mppdu_type_range.uint8()? >> 6;

                    // If there is only 1 byte remaining and its value is zero,
                    // it's a valid trailing pad
                    if mppdu_state.next_tvb.length() == 1 && mppdu_type_value == 0 {
                        mppdu_state.dissect_trailing_pad(
                            tree,
                            &mut component_tree,
                            &mut mppdu_type_item,
                            1,
                        )?;

                        // Break out of the loop after encountering a trailing pad.
                        // There should never be another MPPDU after a Trailing Pad MPPDU
                        break;
                    }

                    // Decode the following length value, which indicates the number of octets
                    // remaining in this MPPDU
                    let mppdu_length_range = match mppdu_state.next_tvb.range(0, 2) {
                        Ok(value) => value,
                        // If there is only 1 byte remaining the MPPDU component is invalid;
                        // return immediately
                        // TODO: Consult an analyst on the expected behavior: should we add an
                        // error to an existing tree entry, remove the entry, neither?
                        Err(_) => {
                            tree.add_expert_info(
                                &mut mppdu_type_item,
                                "expert_invalid_component",
                                Some("Invalid MPPDU component"),
                            )?;
                            mppdu_type_item.append_text(" (Invalid)");
                            return Ok(0);
                        }
                    };

                    let length_value = mppdu_length_range.uint16(Encoding::BigEndian)?
                        & MPPDU_FOLLOWING_LENGTH_MASK;

                    let payload_range = mppdu_state
                        .next_tvb
                        .range(mppdu_length_range.length(), i32::from(length_value))
                        .or(mppdu_state.next_tvb.range(mppdu_length_range.length(), -1))?;

                    // Handle decoding of the different MPPDU types
                    let bytes_processed = match mppdu_type_value {
                        0 if length_value == 0 => {
                            /* trailing pad MPPDU */
                            mppdu_state.dissect_trailing_pad(
                                tree,
                                &mut component_tree,
                                &mut mppdu_type_item,
                                mppdu_length_range.length(),
                            )?;

                            // Break out of the loop after encountering a trailing pad.
                            // There should never be another MPPDU component after a Trailing Pad.
                            break;
                        }
                        0 if length_value >= 14
                            && i32::from(length_value) <= payload_range.length() =>
                        {
                            /* encapsulated frame MPPDU */
                            mppdu_state.dissect_encapsulated_frame(
                                tree,
                                &mut component_tree,
                                &mut mppdu_type_item,
                                mppdu_length_range,
                                payload_range,
                            )?
                        }
                        1 => {
                            /* explicit pad MPPDU */
                            mppdu_state.dissect_explicit_pad(
                                tree,
                                &mut component_tree,
                                &mut mppdu_type_item,
                                mppdu_length_range,
                                payload_range,
                            )?
                        }
                        2 if mppdu_state
                            .frame_fragment_flag_clear(payload_range)
                            .unwrap_or_default()
                            && i32::from(length_value) <= payload_range.length() =>
                        {
                            eprintln!("found frame fragment");
                            /* frame fragment MPPDU */
                            mppdu_state.dissect_frame_fragment(
                                tree,
                                &mut component_tree,
                                &mut mppdu_type_item,
                                mppdu_length_range,
                                payload_range,
                            )?
                        }
                        _ => {
                            tree.add_expert_info(
                                &mut mppdu_type_item,
                                "expert_invalid_component",
                                Some("Invalid MPPDU component"),
                            )?;
                            mppdu_type_item.append_text(" (Invalid)");
                            0
                        }
                    };

                    // Update the length of the entire MPPDU after it's been processed
                    component_tree.set_length(mppdu_length_range.length() + bytes_processed);
                    mppdu_state.next_tvb = mppdu_state
                        .next_tvb
                        .range(mppdu_length_range.length() + bytes_processed, -1)?;
                }

                // Only write to the Info column if no other subdissector was called.
                // We don't want to clobber what another dissector wrote.
                if !mppdu_state.subdissector_called {
                    tree.pinfo.set_column_text(
                        Column::Info,
                        &format!("MPPDU Components: [{}]", &mppdu_state.components.join(", ")),
                    );
                }
                Ok(tvb.captured_length())
            },
        ))
        .ett("component", "MPPDU")
        .ett("component.following_length", "Following Length")
        .ett("encapsulated_frame", "Encapsulated Frame")
        .ett("frame_fragment", "Frame Fragment")
        .ett("frame_fragment.flags", "Flags")
        .ett("reassembled_frame", "Reassembled Frame")
        .ett("reassembled_frame.fragment", "Frame Fragment")
        .field(
            FieldBuilder::new("component", "MPPDU component", "macprivacy.component")
                .display(FieldDisplay::None)
                .field_type(FieldType::None)
                .build()?,
        )
        .field(
            FieldBuilder::new("component.type", "Type", "macprivacy.component.type")
                .bitmask(MPPDU_TYPE_MASK.into())
                .display(FieldDisplay::BaseHex)
                .field_type(FieldType::Uint8)
                .build()?,
        )
        .field(
            FieldBuilder::new(
                "component.following_length",
                "Following Length",
                "macprivacy.component.following_length",
            )
            .bitmask(MPPDU_FOLLOWING_LENGTH_MASK.into())
            .display(FieldDisplay::BaseDec)
            .field_type(FieldType::Uint16)
            .build()?,
        )
        .field(
            FieldBuilder::new("trailing_pad", "Trailing Pad", "macprivacy.trailing_pad")
                .display(FieldDisplay::None)
                .field_type(FieldType::Bytes)
                .build()?,
        )
        .field(
            FieldBuilder::new(
                "encapsulated_frame",
                "Encapsulated Frame",
                "macprivacy.encapsulated_frame",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::None)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "encapsulated_frame.destination_address",
                "Destination Address",
                "macprivacy.encapsulated_frame.destination_address",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::Ether)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "encapsulated_frame.source_address",
                "Source Address",
                "macprivacy.encapsulated_frame.source_address",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::Ether)
            .build()?,
        )
        .field(
            FieldBuilder::new("explicit_pad", "Explicit Pad", "macprivacy.explicit_pad")
                .display(FieldDisplay::None)
                .field_type(FieldType::Bytes)
                .build()?,
        )
        .field(
            FieldBuilder::new(
                "frame_fragment",
                "Frame Fragment",
                "macprivacy.frame_fragment",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::None)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "frame_fragment.flags",
                "Flags",
                "macprivacy.frame_fragment.flags",
            )
            .display(FieldDisplay::BaseHex)
            .field_type(FieldType::Uint8)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "frame_fragment.flags.initial_frame",
                "Initial",
                "macprivacy.frame_fragment.flags.initial_frame",
            )
            .bitmask(INITIAL_FRAME.into())
            .display(FieldDisplay::Boolean(8))
            .field_type(FieldType::Boolean)
            .strings(SET_NOT_SET)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "frame_fragment.flags.final_frame",
                "Final",
                "macprivacy.frame_fragment.flags.final_frame",
            )
            .bitmask(FINAL_FRAME.into())
            .display(FieldDisplay::Boolean(8))
            .field_type(FieldType::Boolean)
            .strings(SET_NOT_SET)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "frame_fragment.flags.express_frame",
                "Express",
                "macprivacy.frame_fragment.flags.express_frame",
            )
            .bitmask(EXPRESS_FRAME.into())
            .display(FieldDisplay::Boolean(8))
            .field_type(FieldType::Boolean)
            .strings(SET_NOT_SET)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "frame_fragment.sequence_number",
                "Sequence Number",
                "macprivacy.frame_fragment.sequence_number",
            )
            .display(FieldDisplay::BaseDec)
            .field_type(FieldType::Uint24)
            .build()?,
        )
        // Fields for handling reassembled frames
        .field(
            FieldBuilder::new(
                "reassembled_frame",
                "Reassembled Frame",
                "macprivacy.reassembled_frame",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::None)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.fragments",
                "Frame Fragments",
                "macprivacy.reassembled_frame.fragments",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::None)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.fragment",
                "Frame Fragment",
                "macprivacy.reassembled_frame.fragment",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::Framenum)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.overlap",
                "Frame Overlap",
                "macprivacy.reassembled_frame.overlap",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::Boolean)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.overlap.conflict",
                "Conflicting data in frame fragment overlap",
                "macprivacy.reassembled_frame.overlap.conflict",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::Boolean)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.multipletails",
                "Multiple final fragments found",
                "macprivacy.reassembled_frame.multipletails",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::Boolean)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.toolongfragment",
                "Fragment too long",
                "macprivacy.reassembled_frame.toolongfragment",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::Boolean)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.error",
                "Defragmentation error",
                "macprivacy.reassembled_frame.error",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::Framenum)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.count",
                "Fragment count",
                "macprivacy.reassembled_frame.count",
            )
            .display(FieldDisplay::BaseDec)
            .field_type(FieldType::Uint32)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.reassembled_in",
                "Reassembled MSDU in frame",
                "macprivacy.reassembled_frame.reassembled_in",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::Framenum)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.length",
                "Reassembled MSDU length",
                "macprivacy.reassembled_frame.length",
            )
            .display(FieldDisplay::BaseDec)
            .field_type(FieldType::Uint32)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.destination_address",
                "Destination Address",
                "macprivacy.reassembled_frame.destination_address",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::Ether)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.source_address",
                "Source Address",
                "macprivacy.reassembled_frame.source_address",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::Ether)
            .build()?,
        )
        .field(
            FieldBuilder::new(
                "reassembled_frame.msdu",
                "MAC Service Data Unit",
                "macprivacy.reassembled_frame.msdu",
            )
            .display(FieldDisplay::None)
            .field_type(FieldType::Bytes)
            .build()?,
        )
        .expert_info(
            "expert_explicit_pad_length",
            ExpertGroup::CommentsGroup,
            ExpertSeverity::Comment,
            "'Following length' may exceed the actual number of bytes in the pad if \
            it exceeds the number of octets remaining in the MPPDU",
        )
        .expert_info(
            "expert_invalid_component",
            ExpertGroup::Malformed,
            ExpertSeverity::Warn,
            "Invalid MPPDU component",
        )
        .expert_info(
            "expert_nonzero_pad",
            ExpertGroup::Malformed,
            ExpertSeverity::Warn,
            "Padding bytes must be zero",
        )
        // End of fields for handling fragmented frames
        .fragment_items(FragmentItemsNames {
            ett_fragment: "reassembled_frame".into(),
            ett_fragments: Some("reassembled_frame.fragment".into()),
            hf_fragments: "reassembled_frame.fragments".into(),
            hf_fragment: "reassembled_frame.fragment".into(),
            hf_fragment_overlap: "reassembled_frame.overlap".into(),
            hf_fragment_overlap_conflict: "reassembled_frame.overlap.conflict".into(),
            hf_fragment_multiple_tails: "reassembled_frame.multipletails".into(),
            hf_fragment_too_long_fragment: "reassembled_frame.toolongfragment".into(),
            hf_fragment_error: "reassembled_frame.error".into(),
            hf_fragment_count: Some("reassembled_frame.count".into()),
            hf_reassembled_in: Some("reassembled_frame.reassembled_in".into()),
            hf_reassembled_length: Some("reassembled_frame.length".into()),
            hf_reassembled_data: Some("reassembled_frame".into()),
            tag: "fragments".into(),
        })
        .decode_from(DissectorDecodeFrom::Uint(
            "ethertype".into(),
            vec![MAC_PRIVACY_ETHERTYPE],
        ))
        .build()?;

    Ok(protocol)
}

//-----------------------------------------------------------------------------
/// Reads an ethertype value from the given [`TvbRange`] and calls Wireshark's
/// ethertype dissector.
///
/// Passes MacPrivacy payload data to downstream dissectors.
///
/// Returns an error if the given [`TvbRange`] is not long enough to contain
/// a valid ethertype or if the downstream dissector failed. If successful,
/// returns the number of bytes processed. Returns zero if the ethertype
/// dissector could not be found.
fn call_ethertype_dissector(
    tvb: TvbRange,
    tree: &Tree,
    fh_tree: &Tree,
) -> Result<i32, Box<dyn std::error::Error>> {
    let msdu_tvb = tvb.to_tvb()?;

    let msdu_ethertype_range = tvb.range(0, 2)?;
    let msdu_ethertype_value = msdu_ethertype_range.uint16(Encoding::BigEndian)?;

    if let Some(ethertype_dissector) = EthertypeDissector::new() {
        // Configure parameters for the ethertype dissector
        let ethertype_data = EthertypeData {
            etype: msdu_ethertype_value,
            payload_offset: msdu_ethertype_range.length(),
            fh_tree,
            trailer_id: 0,
            fcs_len: 0,
        };

        Ok(ethertype_dissector.call_with_data(&msdu_tvb, &tree.pinfo, tree, ethertype_data)?)
    } else {
        Ok(0)
    }
}

//-----------------------------------------------------------------------------
/// Uses frame metadata to determine a sequence ID for a frame fragment before
/// it is added to Wireshark's fragment table.
///
/// Wireshark's requirements/assumptions about fragment IDs are stricter than
/// those for MacPrivacy. This function provides bookkeeping and helps the
/// dissector provides sequence IDs which allow Wireshark's fragment
/// reassembly to be successful.
fn sequence_id(is_initial_frame: bool, is_express_frame: bool, frame_sequence_number: u32) -> u32 {
    let sequence = if is_express_frame {
        &EXPRESS_SEQUENCE_FIRST_ID
    } else {
        &PREEMPTABLE_SEQUENCE_FIRST_ID
    };

    if is_initial_frame {
        sequence.store(frame_sequence_number, Ordering::Relaxed);
        frame_sequence_number
    } else {
        sequence.load(Ordering::Relaxed)
    }
}
