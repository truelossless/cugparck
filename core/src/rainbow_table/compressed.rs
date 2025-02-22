use std::iter::{self, Enumerate};

use bitvec::prelude::*;
use itertools::{Itertools, PeekingNext};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{ctx::RainbowTableCtx, CompressedPassword};

use super::{RainbowChain, RainbowTable};

/// An arbitrary block size.
const BLOCK_SIZE: usize = 256;

#[derive(Serialize, Deserialize)]
/// An index to keep track of the different blocks used to store the endpoints.
pub struct Index {
    len: usize,
    entries: BitVec,
    bit_address_size: usize,
    chain_number_size: usize,
}

impl Index {
    /// Creates a new index.
    pub fn new(n: f64, m: f64, k: u8) -> Self {
        let bit_address_size = (CompressedTable::optimal_rice_parameter_rate(n, m, k) * m)
            .log2()
            .ceil() as usize;

        let chain_number_size = m.log2().ceil().max(1.) as usize;

        Self {
            len: 0,
            bit_address_size,
            chain_number_size,
            entries: BitVec::new(),
        }
    }

    /// Adds an entry for a block.
    #[inline]
    pub fn add_entry(&mut self, bit_address: usize, chain_number: usize) {
        self.len += 1;
        self.entries
            .extend_from_bitslice(&bit_address.view_bits::<Lsb0>()[..self.bit_address_size]);
        self.entries
            .extend_from_bitslice(&chain_number.view_bits::<Lsb0>()[..self.chain_number_size]);
    }

    /// Returns the bit address and the chain number of the block at index `i`.
    pub fn get_entry(&self, i: usize) -> Option<(usize, usize)> {
        if i >= self.len {
            return None;
        }

        let entry_size = self.bit_address_size + self.chain_number_size;
        let bit_address =
            self.entries[entry_size * i..entry_size * i + self.bit_address_size].load();
        let chain_number =
            self.entries[entry_size * i + self.bit_address_size..entry_size * (i + 1)].load();

        Some((bit_address, chain_number))
    }
}

#[derive(Serialize, Deserialize)]
/// A rainbow table using compressed delta encoding.
pub struct CompressedTable {
    ctx: RainbowTableCtx,
    pub index: Index,
    startpoints: BitVec,
    endpoints: BitVec,
    l: usize,
    k: u8,
    m: usize,
    password_bits: u8,
}

impl CompressedTable {
    /// Rice decodes a number from a bit slice and returns the rest of the undecoded slice.
    fn rice_decode(k: u8, input: &BitSlice) -> (usize, &BitSlice) {
        let m = 1 << k;
        let s = input.first_zero().unwrap();
        let x = input[s + 1..s + k as usize + 1].load::<usize>();

        (s * m + x, &input[s + k as usize + 1..])
    }

    /// Rice encodes a number.
    /// The k least significant bits are in Lsb0 order.
    fn rice_encode(x: usize, k: u8, output: &mut BitVec) {
        // add q ones
        let m = 1 << k;
        let q = x / m;
        let ones = BitVec::<usize, Lsb0>::repeat(true, q);
        output.extend_from_bitslice(&ones);

        // add the 0 delimiter
        output.push(false);

        // add the k least significant bits
        output.extend_from_bitslice(&x.view_bits::<Lsb0>()[..k as usize]);
    }

    /// Gets the number of blocks required.
    #[inline]
    fn block_count(m: usize) -> usize {
        m.div_ceil(BLOCK_SIZE)
    }

    /// Gets the block number where a password should be in the table.
    #[inline]
    fn password_block(password: CompressedPassword, l: usize, n: usize) -> usize {
        password as usize / (n / l)
    }

    /// Gets the number of bits required to store a password.
    #[inline]
    fn password_bits(m0: usize) -> u8 {
        (m0 as f64).log2().ceil() as u8
    }

    /// Gets k^{opt}, the optimal rice parameter (yes it works, and no don't touch it).
    #[inline]
    fn optimal_rice_parameter(n: f64, m: f64) -> u8 {
        let golden_ratio_log = ((1. + 5f64.sqrt()) / 2. - 1.).log10();
        let space_log = ((n - m) / (n + 1.)).log10();

        let k = 1. + ((golden_ratio_log / space_log).log2());
        (k as u8).max(1)
    }

    /// Gets R_{k^{opt}}, the optimal rice parameter rate.
    #[inline]
    fn optimal_rice_parameter_rate(n: f64, m: f64, k: u8) -> f64 {
        let frac = ((n - m) / (n + 1.)).powi(1 << k);
        k as f64 + 1. / (1. - frac)
    }

    /// Returns the startpoint at the given index.
    #[inline]
    fn startpoint(&self, i: usize) -> CompressedPassword {
        let password_bits = self.password_bits as usize;
        self.startpoints[i * password_bits..(i + 1) * password_bits].load::<usize>()
            as CompressedPassword
    }

    /// Stores a new block of endpoints in the table.
    /// The corresponding startpoints are also stored at the same time.
    /// Returns the number of the first chain to be stored in the next block.
    fn store_block(
        &mut self,
        i: usize,
        chain_start: usize,
        chains_iter: &mut impl PeekingNext<Item = RainbowChain>,
    ) -> usize {
        let block_span = self.ctx.n as usize / self.l;
        let first_value = i * block_span;
        let next_block_start = (i + 1) * block_span;

        let chains_in_block = chains_iter
            .peeking_take_while(|chain| (chain.endpoint as usize) < next_block_start)
            .collect_vec();

        // add the startpoints
        for chain in &chains_in_block {
            self.startpoints.extend_from_bitslice(
                &chain.startpoint.view_bits::<Lsb0>()[..self.password_bits as usize],
            );
        }

        // add the endpoints
        let mut delta_iter = iter::once(first_value)
            .chain(chains_in_block.iter().map(|chain| chain.endpoint as usize))
            .tuple_windows()
            .map(|(last_endpoint, endpoint)| endpoint - last_endpoint);

        // the first difference can't be delta-encoded minus one, in case the first value is equal to the start of the block.
        if let Some(first_diff) = delta_iter.by_ref().next() {
            Self::rice_encode(first_diff, self.k, &mut self.endpoints);
        }

        // encode the endpoints
        for diff in delta_iter {
            Self::rice_encode(diff - 1, self.k, &mut self.endpoints);
        }

        chain_start + chains_in_block.len()
    }
}

impl RainbowTable for CompressedTable {
    type Iter<'a> = CompressedTableIterator<'a>;

    fn len(&self) -> usize {
        self.m
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.into_iter()
    }

    #[inline]
    fn search_endpoints(&self, password: CompressedPassword) -> Option<CompressedPassword> {
        let password_bits = self.password_bits as usize;
        let block_number = CompressedTable::password_block(password, self.l, self.ctx.n as usize);
        let (_, chain_start) = self.index.get_entry(block_number).unwrap();

        let starpoint_index = CompressedTableEndpointIterator::from_block(self, block_number)?
            .position(|endpoint| endpoint == password)
            .map(|pos| chain_start + pos);

        starpoint_index.map(|i| {
            self.startpoints[i * password_bits..(i + 1) * password_bits].load::<usize>() as u64
        })
    }

    fn ctx(&self) -> RainbowTableCtx {
        self.ctx.clone()
    }

    fn from_rainbow_table<T: RainbowTable>(table: T) -> Self {
        let ctx = table.ctx();

        let m = table.len();
        let l = Self::block_count(m);
        let k = Self::optimal_rice_parameter(ctx.n as f64, m as f64);
        let password_bits = Self::password_bits(ctx.m0 as usize);
        let startpoints = BitVec::with_capacity(password_bits as usize * m);
        let index = Index::new(ctx.n as f64, m as f64, k);

        let mut delta_table = Self {
            ctx,
            index,
            l,
            k,
            m,
            password_bits,
            startpoints,
            endpoints: BitVec::new(),
        };

        let mut chains = table.iter().collect_vec();
        chains.par_sort_unstable_by_key(|chain| chain.endpoint);
        let mut chains_iter = chains.into_iter().peekable();

        let mut bit_address = 0;
        let mut chain_start = 0;

        // store the chains
        // we add a last block because of the integer rounding some endpoints exceed (n / l) * l.
        for i in 0..delta_table.l + 1 {
            delta_table.index.add_entry(bit_address, chain_start);

            let next_chain_start = delta_table.store_block(i, chain_start, &mut chains_iter);

            bit_address = delta_table.endpoints.len();
            chain_start = next_chain_start;
        }

        delta_table
    }
}

impl<'a> IntoIterator for &'a CompressedTable {
    type Item = RainbowChain;
    type IntoIter = CompressedTableIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter::new(self)
    }
}
/// An iterator over the chains of a compressed delta encoding table.
pub struct CompressedTableIterator<'a> {
    table: &'a CompressedTable,
    endpoint_iter: Enumerate<CompressedTableEndpointIterator<'a>>,
}

impl<'a> CompressedTableIterator<'a> {
    /// Creates a new iterator over the chains of a compressed delta encoding table.
    pub fn new(table: &'a CompressedTable) -> Self {
        Self {
            table,
            endpoint_iter: CompressedTableEndpointIterator::new(table).enumerate(),
        }
    }
}

impl Iterator for CompressedTableIterator<'_> {
    type Item = RainbowChain;

    fn next(&mut self) -> Option<Self::Item> {
        let (i, endpoint) = self.endpoint_iter.next()?;
        let startpoint = self.table.startpoint(i);

        Some(RainbowChain {
            startpoint,
            endpoint,
        })
    }
}

/// An iterator over the endpoints of a compressed delta encoding table.
pub struct CompressedTableEndpointIterator<'a> {
    table: &'a CompressedTable,
    i: usize,
    block: usize,
    is_first_diff: bool,
    next_switch: Option<usize>,
    last_endpoint: usize,
    endpoint_bit_address: usize,
}

impl<'a> CompressedTableEndpointIterator<'a> {
    /// Creates a new iterator.
    #[inline]
    pub fn new(table: &'a CompressedTable) -> Self {
        Self::from_block(table, 0).unwrap()
    }

    /// Creates a new iterator starting from a specific block.
    pub fn from_block(table: &'a CompressedTable, block: usize) -> Option<Self> {
        let (endpoint_bit_address, i) = table.index.get_entry(block)?;
        let next_switch = table.index.get_entry(block + 1).map(|entry| entry.1);

        Some(Self {
            table,
            next_switch,
            block,
            is_first_diff: true,
            i,
            endpoint_bit_address,
            last_endpoint: table.ctx.n as usize / table.l * block,
        })
    }
}

impl Iterator for CompressedTableEndpointIterator<'_> {
    type Item = CompressedPassword;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.table.m {
            return None;
        }

        let (diff, rest) = CompressedTable::rice_decode(
            self.table.k,
            &self.table.endpoints[self.endpoint_bit_address..],
        );

        let endpoint = if self.is_first_diff {
            self.last_endpoint + diff
        } else {
            self.last_endpoint + diff + 1
        };

        self.endpoint_bit_address = self.table.endpoints.len() - rest.len();

        self.i += 1;

        match self.next_switch {
            Some(switch) if self.i == switch => {
                self.is_first_diff = true;
                self.block += 1;
                self.next_switch = self
                    .table
                    .index
                    .get_entry(self.block + 1)
                    .map(|(_, chain_number)| chain_number);
                self.last_endpoint = self.table.ctx.n as usize / self.table.l * self.block;
            }

            _ => {
                self.is_first_diff = false;
                self.last_endpoint = endpoint;
            }
        }

        Some(endpoint as CompressedPassword)
    }
}

#[cfg(test)]
mod tests {
    use bitvec::prelude::*;
    use cubecl_cuda::CudaRuntime;
    use itertools::Itertools;

    use crate::{
        cpu::counter_to_plaintext,
        ctx::RainbowTableCtxBuilder,
        rainbow_table::{
            compressed::{CompressedTableEndpointIterator, Index},
            RainbowChain, RainbowTable, SimpleTable,
        },
    };

    use super::{CompressedTable, BLOCK_SIZE};

    /// Builds a table for testing purposes with chains like (startpoint, endpoint = startpoint * 7).
    /// We have n = 5461, m0 = m = 513.
    fn build_table() -> (CompressedTable, Vec<RainbowChain>) {
        let ctx = RainbowTableCtxBuilder::new()
            .startpoints(Some(BLOCK_SIZE as u64 * 2 + 1))
            .charset(b"abcd")
            .build()
            .unwrap();
        let chains = (0..BLOCK_SIZE * 2 + 1)
            .map(|i| RainbowChain {
                startpoint: i as u64,
                endpoint: (i * 7) as u64,
            })
            .collect_vec();

        (
            SimpleTable::from_vec(chains.clone(), ctx).into_rainbow_table(),
            chains,
        )
    }

    // Some of the parameters used in the following test cases are from "Optimal Storage for Rainbow Tables" section 5.3.

    #[test]
    fn test_optimal_rice_parameter() {
        assert_eq!(
            3,
            CompressedTable::optimal_rice_parameter(2f64.powi(20), 2f64.powi(16))
        );

        // this one was verified using Wolfram Alpha.
        assert_eq!(
            11,
            CompressedTable::optimal_rice_parameter(2f64.powi(20), 300.)
        );
    }

    #[test]
    fn test_optimal_rice_parameter_rate() {
        let n = 2f64.powi(20);
        let m = 2f64.powi(16);
        let k = 3;

        assert_eq!(
            19,
            (CompressedTable::optimal_rice_parameter_rate(n, m, k) * m)
                .log2()
                .ceil() as usize
        )
    }

    #[test]
    fn test_rice_encode() {
        let mut output = BitVec::new();

        // This should be encoded as 11101.
        CompressedTable::rice_encode(7, 1, &mut output);

        // This should be encoded as 1001.
        CompressedTable::rice_encode(6, 2, &mut output);

        // This should be encoded as 101000.
        CompressedTable::rice_encode(17, 4, &mut output);

        // Therefore the result should be 111011001101000,
        // since the storage type is BitVec<usize, Lsb0> and we're guaranteed that usize == u64.
        assert_eq!(bits![1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0], &output)
    }

    #[test]
    fn test_rice_decode() {
        assert_eq!(7, CompressedTable::rice_decode(1, bits![1, 1, 1, 0, 1]).0);

        assert_eq!(6, CompressedTable::rice_decode(2, bits![1, 0, 0, 1]).0);

        assert_eq!(
            17,
            CompressedTable::rice_decode(4, bits![1, 0, 1, 0, 0, 0]).0
        );
    }

    #[test]
    fn test_index() {
        let n = 2f64.powi(20);
        let m = 2f64.powi(16);
        let k = 3;

        let mut index = Index::new(n, m, k);

        // each entry in the index should be 35 bits long
        index.add_entry(0, 0);
        index.add_entry(1000, 50);
        index.add_entry(2000, 100);

        assert_eq!(35 * 3, index.entries.len());

        // we should be able to get all entries back
        assert_eq!((0, 0), index.get_entry(0).unwrap());
        assert_eq!((1000, 50), index.get_entry(1).unwrap());
        assert_eq!((2000, 100), index.get_entry(2).unwrap());
    }

    #[test]
    fn test_startpoints() {
        let ctx = RainbowTableCtxBuilder::new()
            .charset(b"abc")
            .startpoints(Some(5))
            .build()
            .unwrap();

        let chains = vec![
            RainbowChain::new(b"c".to_vec(), b"aaa".to_vec(), &ctx),
            RainbowChain::new(b"".to_vec(), b"caa".to_vec(), &ctx),
            RainbowChain::new(b"aa".to_vec(), b"aab".to_vec(), &ctx),
            RainbowChain::new(b"b".to_vec(), b"ccb".to_vec(), &ctx),
            RainbowChain::new(b"a".to_vec(), b"ccc".to_vec(), &ctx),
        ];

        let table: CompressedTable = SimpleTable::from_vec(chains, ctx).into_rainbow_table();

        // log2(m) = 3 bits for the address
        // "c" = 110 (Lsb0)
        // "" = 000 (Lsb0)
        // "aa" = 001 (Lsb0)
        // "b" = 010 (Lsb0)
        // "a" = 100 (Lsb0)

        assert_eq!(
            bits![1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0,],
            table.startpoints
        )
    }

    #[test]
    fn test_endpoints() {
        let ctx = RainbowTableCtxBuilder::new()
            .charset(b"abc")
            .build()
            .unwrap();

        let chains = vec![
            RainbowChain::new(b"c".to_vec(), b"".to_vec(), &ctx),
            RainbowChain::new(b"".to_vec(), b"a".to_vec(), &ctx),
            RainbowChain::new(b"aa".to_vec(), b"aa".to_vec(), &ctx),
            RainbowChain::new(b"b".to_vec(), b"cc".to_vec(), &ctx),
            RainbowChain::new(b"a".to_vec(), b"baa".to_vec(), &ctx),
        ];

        let table: CompressedTable = SimpleTable::from_vec(chains, ctx).into_rainbow_table();

        // delta (minus one) between the endpoints:
        // 0, 2, 7, 1
        // since the first index entry start at zero we should get
        // 0, 0, 2, 7, 1 rice-encoded with k = 7
        // k = 7 may not optimal for this table but the formula doesn't work well with small numbers.
        // 0 => 00000000
        // 2 => 00100000 (Lsb0)
        // 7 => 01110000 (Lsb0)
        // 1 => 01000000 (Lsb0)
        // therefore the endpoints should be: 0000000000000000001000000111000001000000
        assert_eq!(
            bits![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1,
                0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0
            ],
            table.endpoints
        );
    }

    #[test]
    fn test_block() {
        let (table, _) = build_table();

        // l = ceil(m / BLOCK_SIZE) = ceil(513 / 256) = 3
        // and we have a last entry for the integer division rounding, so we should get l + 1 = 4.
        assert_eq!(
            4,
            table.index.entries.len()
                / (table.index.bit_address_size + table.index.chain_number_size)
        );

        // one block spans 1820 values (n / l = 5461 / 3).
        // so when the endpoints reach 1820 we should switch to the second block.
        let (bit_address, chain_number) = table.index.get_entry(1).unwrap();

        // the first endpoint to reach 1820 is 1820, so its starpoint should be 1820 / 7 = 260.
        assert_eq!(260, chain_number);

        let (diff, rest) = CompressedTable::rice_decode(table.k, &table.endpoints[bit_address..]);

        // the first delta (not minus one) should be 0, as 1820 - 1820 = 2
        assert_eq!(0, diff);

        let (diff, _) = CompressedTable::rice_decode(table.k, rest);

        // all the following delta (minus one) should be 6 because the difference between two endpoints is always 7
        assert_eq!(6, diff);
    }

    #[test]
    fn test_iterator() {
        let (table, chains) = build_table();

        let chains_found = table.into_iter().collect_vec();
        assert_eq!(chains, chains_found);

        let endpoints_from_second_block = CompressedTableEndpointIterator::from_block(&table, 1)
            .unwrap()
            .collect_vec();
        assert_eq!(
            chains[260..]
                .iter()
                .map(|chain| chain.endpoint)
                .collect_vec(),
            endpoints_from_second_block
        );
    }

    #[test]
    fn test_search_endpoints() {
        let (table, _) = build_table();

        // take an arbitrary endpoint and try to find the chain number again
        const CHAIN_NUMBER: usize = 420;
        let chain = table.into_iter().nth(CHAIN_NUMBER).unwrap();

        let search = table.search_endpoints(chain.endpoint);
        assert_eq!(Some(chain.startpoint), search);
    }

    #[test]
    fn test_search() {
        let ctx = RainbowTableCtxBuilder::new()
            .chain_length(100)
            .max_password_length(4)
            .charset(b"abc")
            .build()
            .unwrap();
        let mut hasher = ctx.hash_function.cpu();
        let mut search_hash = vec![0; hasher.output_size()];

        let table: CompressedTable = SimpleTable::new::<CudaRuntime>(ctx)
            .unwrap()
            .into_rainbow_table();

        let search = b"abca".to_vec();
        hasher.update(&search);
        hasher.finalize_into_reset(&mut search_hash).unwrap();

        let found = table.search(&search_hash);
        assert_eq!(search, found.unwrap());
    }

    #[test]
    fn test_coverage() {
        let ctx = RainbowTableCtxBuilder::new()
            .chain_length(100)
            .max_password_length(4)
            .charset(b"abcdef")
            .build()
            .unwrap();
        let mut hasher = ctx.hash_function.cpu();
        let mut search_hash = vec![0; hasher.output_size()];

        let table: CompressedTable = SimpleTable::new::<CudaRuntime>(ctx.clone())
            .unwrap()
            .into_rainbow_table();

        let mut found = 0;
        for i in 0..ctx.n {
            let password = counter_to_plaintext(i, &ctx);
            hasher.update(&password);
            hasher.finalize_into_reset(&mut search_hash).unwrap();
            if let Some(plaintext) = table.search(&search_hash) {
                assert_eq!(password, plaintext);
                found += 1;
            }
        }

        // the success rate should be around 85% - 87%
        let success_rate = found as f64 / ctx.n as f64 * 100.;
        assert!(
            (80. ..90.).contains(&success_rate),
            "success rate is only {success_rate}"
        );
    }
}
