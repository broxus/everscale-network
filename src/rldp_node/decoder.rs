use crate::utils::RaptorQFecType;

pub struct RaptorQDecoder {
    engine: raptorq::Decoder,
    params: RaptorQFecType,
    seqno: u32,
}

impl RaptorQDecoder {
    pub fn with_params(params: RaptorQFecType) -> Self {
        Self {
            engine: raptorq::Decoder::new(raptorq::ObjectTransmissionInformation::with_defaults(
                params.data_size as u64,
                params.symbol_size as u16,
            )),
            params,
            seqno: 0,
        }
    }

    pub fn decode(&mut self, seqno: u32, data: Vec<u8>) -> Option<Vec<u8>> {
        let packet = raptorq::EncodingPacket::new(raptorq::PayloadId::new(0, seqno), data);
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
