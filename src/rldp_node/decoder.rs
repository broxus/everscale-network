use crate::proto::rldp::RaptorQFecType;

pub struct RaptorQDecoder {
    engine: everscale_raptorq::Decoder,
    params: RaptorQFecType,
    seqno: u32,
}

impl RaptorQDecoder {
    pub fn with_params(params: RaptorQFecType) -> Self {
        Self {
            engine: everscale_raptorq::Decoder::new(
                everscale_raptorq::ObjectTransmissionInformation::with_defaults(
                    params.total_len as u64,
                    params.packet_len as u16,
                ),
            ),
            params,
            seqno: 0,
        }
    }

    pub fn decode(&mut self, seqno: u32, data: Vec<u8>) -> Option<Vec<u8>> {
        let packet = everscale_raptorq::EncodingPacket::new(
            everscale_raptorq::PayloadId::new(0, seqno),
            data,
        );
        self.seqno = seqno;
        self.engine.decode(packet)
    }

    pub fn params(&self) -> &RaptorQFecType {
        &self.params
    }

    pub fn seqno(&self) -> u32 {
        self.seqno
    }
}
