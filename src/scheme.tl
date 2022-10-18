// Generic stuff
////////////////////////////////////////////////////////////////////////////////

---types---

int ? = Int;
long ? = Long;
double ? = Double;
string ? = String;
object ? = Object;
function ? = Function;
bytes data:string = Bytes;
true = True;
boolTrue = Bool;
boolFalse = Bool;

vector {t:Type} # [ t ] = Vector t;

int128 4*[ int ] = Int128;
int256 8*[ int ] = Int256;

fec.raptorQ data_size:int symbol_size:int symbols_count:int = fec.Type;

pub.ed25519 key:int256 = PublicKey;
pub.aes key:int256 = PublicKey;
pub.overlay name:bytes = PublicKey;


// ADNL
////////////////////////////////////////////////////////////////////////////////

---types---

adnl.id.short id:int256 = adnl.id.Short;

adnl.address.udp ip:int port:int = adnl.Address;
adnl.address.udp6 ip:int128 port:int = adnl.Address;

adnl.addressList addrs:(vector adnl.Address) version:int reinit_date:int priority:int expire_at:int = adnl.AddressList;

adnl.node id:PublicKey addr_list:adnl.addressList = adnl.Node;
adnl.nodes nodes:(vector adnl.node) = adnl.Nodes;

adnl.packetContents
  rand1:bytes
  flags:#
  from:flags.0?PublicKey
  from_short:flags.1?adnl.id.short
  message:flags.2?adnl.Message
  messages:flags.3?(vector adnl.Message)
  address:flags.4?adnl.addressList
  priority_address:flags.5?adnl.addressList
  seqno:flags.6?long
  confirm_seqno:flags.7?long
  recv_addr_list_version:flags.8?int
  recv_priority_addr_list_version:flags.9?int
  reinit_date:flags.10?int
  dst_reinit_date:flags.10?int
  signature:flags.11?bytes
  rand2:bytes
        = adnl.PacketContents;

adnl.message.createChannel key:int256 date:int = adnl.Message;
adnl.message.confirmChannel key:int256 peer_key:int256 date:int = adnl.Message;

adnl.message.custom data:bytes = adnl.Message;

adnl.message.nop = adnl.Message;
adnl.message.reinit date:int = adnl.Message;

adnl.message.query query_id:int256 query:bytes = adnl.Message;
adnl.message.answer query_id:int256 answer:bytes = adnl.Message;

adnl.message.part hash:int256 total_size:int offset:int data:bytes = adnl.Message;

adnl.pong value:long = adnl.Pong;

---functions---

adnl.ping value:long = adnl.Pong;


// RLDP
////////////////////////////////////////////////////////////////////////////////

---types---

rldp.messagePart transfer_id:int256 fec_type:fec.Type part:int total_size:long seqno:int data:bytes = rldp.MessagePart;
rldp.confirm transfer_id:int256 part:int seqno:int = rldp.MessagePart;
rldp.complete transfer_id:int256 part:int = rldp.MessagePart;

rldp.message id:int256 data:bytes = rldp.Message;
rldp.query query_id:int256 max_answer_size:long timeout:int data:bytes = rldp.Message;
rldp.answer query_id:int256 data:bytes = rldp.Message;


// DHT
////////////////////////////////////////////////////////////////////////////////

---types---

dht.node id:PublicKey addr_list:adnl.addressList version:int signature:bytes = dht.Node;
dht.nodes nodes:(vector dht.node) = dht.Nodes;

dht.key id:int256 name:bytes idx:int = dht.Key;

dht.updateRule.signature = dht.UpdateRule;
dht.updateRule.anybody = dht.UpdateRule;
dht.updateRule.overlayNodes = dht.UpdateRule;

dht.keyDescription key:dht.key id:PublicKey update_rule:dht.UpdateRule signature:bytes = dht.KeyDescription;

dht.value key:dht.keyDescription value:bytes ttl:int signature:bytes = dht.Value;

dht.pong random_id:long = dht.Pong;

dht.valueNotFound nodes:dht.nodes = dht.ValueResult;
dht.valueFound value:dht.Value = dht.ValueResult;

dht.stored = dht.Stored;
dht.message node:dht.node = dht.Message;

---functions---

dht.ping random_id:long = dht.Pong;
dht.store value:dht.value = dht.Stored;
dht.findNode key:int256 k:int = dht.Nodes;
dht.findValue key:int256 k:int = dht.ValueResult;
dht.getSignedAddressList = dht.Node;

dht.query node:dht.node = True;


// Overlay
////////////////////////////////////////////////////////////////////////////////

---types---

overlay.node.toSign id:adnl.id.short overlay:int256 version:int = overlay.node.ToSign;
overlay.node id:PublicKey overlay:int256 version:int signature:bytes = overlay.Node;
overlay.nodes nodes:(vector overlay.node) = overlay.Nodes;

overlay.message overlay:int256 = overlay.Message;

overlay.fec.received hash:int256 = overlay.Broadcast;
overlay.fec.completed hash:int256 = overlay.Broadcast;

overlay.broadcast.id src:int256 data_hash:int256 flags:int = overlay.broadcast.Id;
overlay.broadcastFec.id src:int256 type:int256 data_hash:int256 size:int flags:int = overlay.broadcastFec.Id;
overlay.broadcastFec.partId broadcast_hash:int256 data_hash:int256 seqno:int = overlay.broadcastFec.PartId;

overlay.broadcast.toSign hash:int256 date:int = overlay.broadcast.ToSign;

overlay.certificate issued_by:PublicKey expire_at:int max_size:int signature:bytes = overlay.Certificate;
overlay.emptyCertificate = overlay.Certificate;

overlay.unicast data:bytes = overlay.Broadcast;
overlay.broadcast src:PublicKey certificate:overlay.Certificate flags:int data:bytes date:int signature:bytes = overlay.Broadcast;
overlay.broadcastFec src:PublicKey certificate:overlay.Certificate data_hash:int256 data_size:int flags:int
          data:bytes seqno:int fec:fec.Type date:int signature:bytes = overlay.Broadcast;
overlay.broadcastFecShort src:PublicKey certificate:overlay.Certificate broadcast_hash:int256 part_data_hash:int256 seqno:int signature:bytes = overlay.Broadcast;
overlay.broadcastNotFound = overlay.Broadcast;

---functions---

overlay.getRandomPeers peers:overlay.nodes = overlay.Nodes;
overlay.query overlay:int256 = True;


// Other
////////////////////////////////////////////////////////////////////////////////

---types---

tonNode.shardPublicOverlayId workchain:int shard:long zero_state_file_hash:int256 = tonNode.ShardPublicOverlayId;
catchain.firstblock unique_hash:int256 nodes:(vector int256) = catchain.FirstBlock;
