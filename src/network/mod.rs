pub use neighbour::Neighbour;
pub use neighbours::Neighbours;

mod neighbour;
mod neighbours;
mod neighbours_cache;

const MAX_NEIGHBOURS: usize = 16;
