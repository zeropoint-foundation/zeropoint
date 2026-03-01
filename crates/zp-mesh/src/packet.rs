//! Mesh packet types — Reticulum-compatible wire format.
//!
//! ## Wire Layout
//!
//! ```text
//! ┌──────────┬──────────┬────────────────────┬─────────┬───────────────┐
//! │ Header 1 │ Header 2 │ Address(es)        │ Context │ Data          │
//! │ (1 byte) │ (1 byte) │ (16 or 32 bytes)   │ (0-1)   │ (0-465 bytes) │
//! └──────────┴──────────┴────────────────────┴─────────┴───────────────┘
//! ```
//!
//! ### Header Byte 1 (flags)
//!
//! ```text
//! Bit 7: IFAC flag (0=open, 1=authenticated)
//! Bit 6: Header type (0=Type1/one address, 1=Type2/two addresses)
//! Bit 5: Context flag (0=no context byte, 1=context byte follows)
//! Bit 4: Propagation type (0=broadcast, 1=transport)
//! Bits 3-2: Destination type (00=single, 01=group, 10=plain, 11=link)
//! Bits 1-0: Packet type (00=data, 01=announce, 10=link_request, 11=proof)
//! ```
//!
//! ### Header Byte 2
//!
//! ```text
//! Bits 7-0: Hop count (0-255, typically max 128)
//! ```

use serde::{Deserialize, Serialize};

use crate::destination::{DestinationHash, DestinationType};
use crate::error::{MeshError, MeshResult};

/// Default maximum packet size (matches Reticulum default MTU).
pub const DEFAULT_MTU: usize = 500;

/// Maximum data payload in a Type 1 packet (one address).
/// MTU - header(2) - address(16) - context(1) = 481, but Reticulum uses 465.
pub const MAX_DATA_TYPE1: usize = 465;

/// Maximum data payload in a Type 2 packet (two addresses).
/// MTU - header(2) - addresses(32) - context(1) = 465
pub const MAX_DATA_TYPE2: usize = 449;

/// Maximum number of hops (Reticulum default).
pub const MAX_HOPS: u8 = 128;

/// Packet type — the purpose of this packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    /// Application data.
    Data = 0b00,
    /// Identity announcement (broadcasts public key).
    Announce = 0b01,
    /// Link establishment request.
    LinkRequest = 0b10,
    /// Cryptographic proof (link proof, delivery confirmation).
    Proof = 0b11,
}

impl PacketType {
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0b11 {
            0b00 => Some(Self::Data),
            0b01 => Some(Self::Announce),
            0b10 => Some(Self::LinkRequest),
            0b11 => Some(Self::Proof),
            _ => None,
        }
    }

    pub fn to_bits(self) -> u8 {
        self as u8
    }
}

/// Propagation type — how the packet traverses the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PropagationType {
    /// Flood to all reachable nodes.
    Broadcast = 0,
    /// Forward via transport nodes toward destination.
    Transport = 1,
}

impl PropagationType {
    pub fn from_bit(bit: u8) -> Self {
        if bit & 1 == 1 {
            Self::Transport
        } else {
            Self::Broadcast
        }
    }

    pub fn to_bit(self) -> u8 {
        self as u8
    }
}

/// Context byte values for signaling packet purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketContext {
    /// No specific context.
    None = 0x00,
    /// Link keepalive.
    Keepalive = 0x01,
    /// Resource advertisement.
    ResourceAdv = 0x02,
    /// Resource request.
    ResourceReq = 0x03,
    /// Resource data.
    ResourceData = 0x04,
    /// Resource proof.
    ResourceProof = 0x05,
    /// Channel request.
    Request = 0x06,
    /// Channel response.
    Response = 0x07,
    /// Link close.
    LinkClose = 0x08,
    /// Receipt (ZeroPoint extension — carries a compact receipt).
    Receipt = 0xF0,
    /// Guard evaluation result (ZeroPoint extension).
    GuardResult = 0xF1,
    /// Agent delegation (ZeroPoint extension).
    Delegation = 0xF2,
}

impl PacketContext {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x00 => Self::None,
            0x01 => Self::Keepalive,
            0x02 => Self::ResourceAdv,
            0x03 => Self::ResourceReq,
            0x04 => Self::ResourceData,
            0x05 => Self::ResourceProof,
            0x06 => Self::Request,
            0x07 => Self::Response,
            0x08 => Self::LinkClose,
            0xF0 => Self::Receipt,
            0xF1 => Self::GuardResult,
            0xF2 => Self::Delegation,
            _ => Self::None,
        }
    }
}

/// Decoded packet header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketHeader {
    /// Interface authentication flag.
    pub ifac: bool,
    /// Header type: false = Type 1 (one address), true = Type 2 (two addresses).
    pub header_type_2: bool,
    /// Whether a context byte is present.
    pub has_context: bool,
    /// Propagation mode.
    pub propagation: PropagationType,
    /// Destination addressing mode.
    pub destination_type: DestinationType,
    /// Purpose of this packet.
    pub packet_type: PacketType,
    /// Remaining hop count.
    pub hops: u8,
}

impl PacketHeader {
    /// Encode header to 2 bytes.
    pub fn encode(&self) -> [u8; 2] {
        let byte1 = (self.ifac as u8) << 7
            | (self.header_type_2 as u8) << 6
            | (self.has_context as u8) << 5
            | self.propagation.to_bit() << 4
            | (self.destination_type.to_bits() & 0b11) << 2
            | (self.packet_type.to_bits() & 0b11);

        [byte1, self.hops]
    }

    /// Decode header from 2 bytes.
    pub fn decode(bytes: &[u8; 2]) -> MeshResult<Self> {
        let byte1 = bytes[0];

        let ifac = (byte1 >> 7) & 1 == 1;
        let header_type_2 = (byte1 >> 6) & 1 == 1;
        let has_context = (byte1 >> 5) & 1 == 1;
        let propagation = PropagationType::from_bit((byte1 >> 4) & 1);
        let destination_type = DestinationType::from_bits((byte1 >> 2) & 0b11)
            .ok_or_else(|| MeshError::InvalidPacket("invalid destination type bits".into()))?;
        let packet_type = PacketType::from_bits(byte1 & 0b11)
            .ok_or_else(|| MeshError::InvalidPacket("invalid packet type bits".into()))?;

        Ok(Self {
            ifac,
            header_type_2,
            has_context,
            propagation,
            destination_type,
            packet_type,
            hops: bytes[1],
        })
    }
}

/// A mesh packet — the fundamental unit of transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    /// Decoded header fields.
    pub header: PacketHeader,
    /// Primary destination hash (always present).
    pub destination: DestinationHash,
    /// Transport destination hash (only in Type 2 headers).
    pub transport_id: Option<DestinationHash>,
    /// Context byte (if present).
    pub context: PacketContext,
    /// Payload data.
    pub data: Vec<u8>,
}

impl Packet {
    /// Create a data packet for an established link.
    pub fn data(
        destination: DestinationHash,
        data: Vec<u8>,
        context: PacketContext,
    ) -> MeshResult<Self> {
        if data.len() > MAX_DATA_TYPE1 {
            return Err(MeshError::PacketTooLarge {
                size: data.len(),
                mtu: MAX_DATA_TYPE1,
            });
        }

        Ok(Self {
            header: PacketHeader {
                ifac: false,
                header_type_2: false,
                has_context: true,
                propagation: PropagationType::Transport,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                hops: MAX_HOPS,
            },
            destination,
            transport_id: None,
            context,
            data,
        })
    }

    /// Create an announce packet.
    pub fn announce(destination: DestinationHash, announce_data: Vec<u8>) -> MeshResult<Self> {
        if announce_data.len() > MAX_DATA_TYPE1 {
            return Err(MeshError::PacketTooLarge {
                size: announce_data.len(),
                mtu: MAX_DATA_TYPE1,
            });
        }

        Ok(Self {
            header: PacketHeader {
                ifac: false,
                header_type_2: false,
                has_context: false,
                propagation: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: MAX_HOPS,
            },
            destination,
            transport_id: None,
            context: PacketContext::None,
            data: announce_data,
        })
    }

    /// Create a link request packet.
    pub fn link_request(destination: DestinationHash, request_data: Vec<u8>) -> MeshResult<Self> {
        Ok(Self {
            header: PacketHeader {
                ifac: false,
                header_type_2: false,
                has_context: false,
                propagation: PropagationType::Transport,
                destination_type: DestinationType::Single,
                packet_type: PacketType::LinkRequest,
                hops: MAX_HOPS,
            },
            destination,
            transport_id: None,
            context: PacketContext::None,
            data: request_data,
        })
    }

    /// Create a proof packet (link proof or delivery confirmation).
    pub fn proof(destination: DestinationHash, proof_data: Vec<u8>) -> MeshResult<Self> {
        Ok(Self {
            header: PacketHeader {
                ifac: false,
                header_type_2: false,
                has_context: false,
                propagation: PropagationType::Transport,
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                hops: MAX_HOPS,
            },
            destination,
            transport_id: None,
            context: PacketContext::None,
            data: proof_data,
        })
    }

    /// Encode to wire format bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.encode();
        let addr_len = if self.header.header_type_2 { 32 } else { 16 };
        let context_len = if self.header.has_context { 1 } else { 0 };
        let total = 2 + addr_len + context_len + self.data.len();

        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&header_bytes);
        buf.extend_from_slice(self.destination.as_bytes());

        if let Some(ref tid) = self.transport_id {
            buf.extend_from_slice(tid.as_bytes());
        }

        if self.header.has_context {
            buf.push(self.context as u8);
        }

        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode from wire format bytes.
    pub fn from_bytes(raw: &[u8]) -> MeshResult<Self> {
        if raw.len() < 2 {
            return Err(MeshError::InvalidPacket("packet too short".into()));
        }

        let header = PacketHeader::decode(&[raw[0], raw[1]])?;
        let mut offset = 2;

        // Primary destination
        if raw.len() < offset + 16 {
            return Err(MeshError::InvalidPacket("missing destination hash".into()));
        }
        let mut dest_bytes = [0u8; 16];
        dest_bytes.copy_from_slice(&raw[offset..offset + 16]);
        let destination = DestinationHash(dest_bytes);
        offset += 16;

        // Transport ID (Type 2 only)
        let transport_id = if header.header_type_2 {
            if raw.len() < offset + 16 {
                return Err(MeshError::InvalidPacket("missing transport ID".into()));
            }
            let mut tid_bytes = [0u8; 16];
            tid_bytes.copy_from_slice(&raw[offset..offset + 16]);
            offset += 16;
            Some(DestinationHash(tid_bytes))
        } else {
            None
        };

        // Context byte
        let context = if header.has_context {
            if raw.len() < offset + 1 {
                return Err(MeshError::InvalidPacket("missing context byte".into()));
            }
            let ctx = PacketContext::from_byte(raw[offset]);
            offset += 1;
            ctx
        } else {
            PacketContext::None
        };

        // Remaining bytes are data
        let data = raw[offset..].to_vec();

        Ok(Self {
            header,
            destination,
            transport_id,
            context,
            data,
        })
    }

    /// Total wire size.
    pub fn wire_size(&self) -> usize {
        let addr_len = if self.header.header_type_2 { 32 } else { 16 };
        let ctx_len = if self.header.has_context { 1 } else { 0 };
        2 + addr_len + ctx_len + self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::MeshIdentity;

    #[test]
    fn test_header_encode_decode_roundtrip() {
        let header = PacketHeader {
            ifac: true,
            header_type_2: false,
            has_context: true,
            propagation: PropagationType::Transport,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Data,
            hops: 42,
        };
        let bytes = header.encode();
        let decoded = PacketHeader::decode(&bytes).unwrap();

        assert_eq!(decoded.ifac, true);
        assert_eq!(decoded.header_type_2, false);
        assert_eq!(decoded.has_context, true);
        assert_eq!(decoded.propagation, PropagationType::Transport);
        assert_eq!(decoded.destination_type, DestinationType::Single);
        assert_eq!(decoded.packet_type, PacketType::Data);
        assert_eq!(decoded.hops, 42);
    }

    #[test]
    fn test_packet_wire_roundtrip() {
        let id = MeshIdentity::generate();
        let dest = DestinationHash::from_public_key(&id.combined_public_key());

        let original =
            Packet::data(dest, b"hello mesh world".to_vec(), PacketContext::Receipt).unwrap();

        let wire = original.to_bytes();
        let decoded = Packet::from_bytes(&wire).unwrap();

        assert_eq!(decoded.destination, dest);
        assert_eq!(decoded.data, b"hello mesh world");
        assert_eq!(decoded.context as u8, PacketContext::Receipt as u8);
        assert_eq!(decoded.header.packet_type, PacketType::Data);
    }

    #[test]
    fn test_announce_packet() {
        let id = MeshIdentity::generate();
        let dest = DestinationHash::from_public_key(&id.combined_public_key());

        let pkt = Packet::announce(dest, id.combined_public_key().to_vec()).unwrap();
        assert_eq!(pkt.header.packet_type, PacketType::Announce);
        assert_eq!(pkt.header.propagation, PropagationType::Broadcast);
        assert!(pkt.wire_size() <= DEFAULT_MTU);
    }

    #[test]
    fn test_packet_too_large() {
        let id = MeshIdentity::generate();
        let dest = DestinationHash::from_public_key(&id.combined_public_key());
        let too_big = vec![0u8; MAX_DATA_TYPE1 + 1];

        let result = Packet::data(dest, too_big, PacketContext::None);
        assert!(result.is_err());
    }

    #[test]
    fn test_data_packet_fits_mtu() {
        let id = MeshIdentity::generate();
        let dest = DestinationHash::from_public_key(&id.combined_public_key());

        // Max payload should fit
        let max_data = vec![0u8; MAX_DATA_TYPE1];
        let pkt = Packet::data(dest, max_data, PacketContext::None).unwrap();
        assert!(pkt.wire_size() <= DEFAULT_MTU);
    }

    #[test]
    fn test_all_header_flag_combinations() {
        // Exhaustive test: encode/decode every flag combination
        for ifac in [false, true] {
            for ht2 in [false, true] {
                for ctx in [false, true] {
                    for prop in [PropagationType::Broadcast, PropagationType::Transport] {
                        for dt in [
                            DestinationType::Single,
                            DestinationType::Group,
                            DestinationType::Plain,
                            DestinationType::Link,
                        ] {
                            for pt in [
                                PacketType::Data,
                                PacketType::Announce,
                                PacketType::LinkRequest,
                                PacketType::Proof,
                            ] {
                                let h = PacketHeader {
                                    ifac,
                                    header_type_2: ht2,
                                    has_context: ctx,
                                    propagation: prop,
                                    destination_type: dt,
                                    packet_type: pt,
                                    hops: 99,
                                };
                                let bytes = h.encode();
                                let d = PacketHeader::decode(&bytes).unwrap();
                                assert_eq!(d.ifac, ifac);
                                assert_eq!(d.header_type_2, ht2);
                                assert_eq!(d.has_context, ctx);
                                assert_eq!(d.propagation, prop);
                                assert_eq!(d.destination_type, dt);
                                assert_eq!(d.packet_type, pt);
                                assert_eq!(d.hops, 99);
                            }
                        }
                    }
                }
            }
        }
    }
}
