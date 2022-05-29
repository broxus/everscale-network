use ton_api::ton;

pub struct RaptorQDecoder {
    engine: everscale_raptorq::Decoder,
    params: ton::fec::type_::RaptorQ,
    seqno: u32,
}

impl RaptorQDecoder {
    pub fn with_params(params: ton::fec::type_::RaptorQ) -> Self {
        Self {
            engine: everscale_raptorq::Decoder::new(
                everscale_raptorq::ObjectTransmissionInformation::with_defaults(
                    params.data_size as u64,
                    params.symbol_size as u16,
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

    pub fn params(&self) -> &ton::fec::type_::RaptorQ {
        &self.params
    }

    pub fn seqno(&self) -> u32 {
        self.seqno
    }
}
