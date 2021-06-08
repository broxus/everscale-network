use ton_api::ton;

pub struct RaptorQDecoder {
    engine: raptorq::Decoder,
    params: ton::fec::type_::RaptorQ,
    seqno: u32,
}

impl RaptorQDecoder {
    pub fn with_params(params: ton::fec::type_::RaptorQ) -> Self {
        Self {
            engine: raptorq::Decoder::new(raptorq::ObjectTransmissionInformation::with_defaults(
                params.data_size as u64,
                params.symbol_size as u16,
            )),
            params,
            seqno: 0,
        }
    }

    pub fn decode(&mut self, seqno: u32, data: &[u8]) -> Option<Vec<u8>> {
        let packet = raptorq::EncodingPacket::new(raptorq::PayloadId::new(0, seqno), data.to_vec());
        self.seqno = seqno;
        self.engine.decode(packet)
    }

    pub fn params(&self) -> &ton::fec::type_::RaptorQ {
        &self.params
    }

    pub fn seqno(&self) -> u32 {
        self.seqno
    }
}
