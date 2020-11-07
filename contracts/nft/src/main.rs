//! Generated by capsule
//!
//! `main.rs` is used to define rust lang items and modules.

#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

// Import from `core` instead of from `std` since we are in no-std mode.
use core::convert::TryInto;
use core::option::Option;
use core::result::Result;

// Import heap related library from `alloc` since we are in no-std mode.
// https://doc.rust-lang.org/alloc/index.html
use alloc::{collections::btree_set::BTreeSet, vec, vec::Vec};

// Import Blake2b functionality.
use blake2b_ref::Blake2bBuilder;

// Import CKB syscalls and structures.
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{debug, default_alloc, entry};
use ckb_std::ckb_constants::Source;
use ckb_std::ckb_types::{bytes::Bytes, packed::Bytes as Args, packed::CellOutput as Cell, packed::Script, packed::OutPoint, prelude::*};
use ckb_std::dynamic_loading::{CKBDLContext, Symbol};
use ckb_std::error::{SysError};
use ckb_std::high_level::{load_cell, load_cell_data, load_cell_lock_hash, load_cell_type_hash, load_input, load_script, load_script_hash, load_tx_hash, QueryIter};

// Constants
const BLAKE2B256_HASH_LEN: usize = 32; // Number of bytes for a Blake2b-256 hash.
const CKBDL_CONTEXT_SIZE: usize = 64 * 1024;
const CODE_HASH_NULL: [u8; 32] = [0u8; 32];
const U128_LEN: usize = 16; // Number of bytes for a 128-bit unsigned integer.
const INSTANCE_ID_LEN: usize = BLAKE2B256_HASH_LEN; // Number of bytes in the Instance ID field.
const LOCK_HASH_LEN: usize = BLAKE2B256_HASH_LEN; // Number of bytes for a lock hash. (Blake2b 32 bytes)
const QUANTITY_LEN: usize = U128_LEN; // Number of bytes in the quantity field.
const TOKEN_LOGIC_FUNCTION: &[u8] = b"token_logic";
const TOKEN_LOGIC_LEN: usize = BLAKE2B256_HASH_LEN; // Number of bytes in a Token Logic field.
const ARGS_LEN: usize = LOCK_HASH_LEN; // Number of bytes required for args. (32 bytes)

entry!(program_entry);
default_alloc!();

/// Program entry point.
fn program_entry() -> i8
{
	// Call main function and return error code.
	match main()
	{
		Ok(_) => 0,
		Err(err) => err as i8,
	}
}

/// Local error values.
/// Low values are reserved for Sys Error codes.
/// Values 100+ are for custom errors.
#[repr(i8)]
enum Error
{
	IndexOutOfBound = 1,
	ItemMissing,
	LengthNotEnough,
	Encoding,
	InvalidArgsLen = 100,
	InvalidInstanceId,
	InvalidInstanceIdLength,
	InvalidQuantity,
	InvalidQuantityLength,
	InvalidStructure,
	InvalidTokenLogicCellDep,
	InvalidTokenLogicLength,
	MissingTokenLogicCellDep,
	MissingTokenLogicFunction,
	UnauthorizedOperation,
	UnexpectedCellMismatch,
}

/// Map Sys Errors to local Error values.
impl From<SysError> for Error
{
	fn from(err: SysError) -> Self
	{
		use SysError::*;
		match err
		{
			IndexOutOfBound => Self::IndexOutOfBound,
			ItemMissing => Self::ItemMissing,
			LengthNotEnough(_) => Self::LengthNotEnough,
			Encoding => Self::Encoding,
			Unknown(err_code) => panic!("Unexpected Sys Error: {}", err_code),
		}
	}
}

/// Determine if owner mode is enabled.
fn check_owner_mode(args: &Args) -> Result<bool, Error>
{
	// Compares the Lock Script Hash from the first 32 bytes of the args with the Lock Scripts
	// of all input Cells to determine if a match exists.
	let args: Bytes = args.unpack();
	let is_owner_mode = QueryIter::new(load_cell_lock_hash, Source::Input)
		.find(|lock_hash| args[0..LOCK_HASH_LEN] == lock_hash[..]).is_some();

	Ok(is_owner_mode)
}

/// Holds the parsed values of an NFT data field. 
#[derive(Debug)]
struct NftData
{
	instance_id: Vec<u8>,
	quantity: Option<u128>,
	token_logic: Option<Vec<u8>>,
	custom: Option<Vec<u8>>,
}

/// Holds the absolute (resolved) values of NFT data regardless on if optional fields were included. 
#[derive(Debug)]
struct NftDataResolved
{
	instance_id: Vec<u8>,
	quantity: u128,
	token_logic: Vec<u8>,
	custom: Vec<u8>,
}

impl From<&NftData> for NftDataResolved
{
	fn from(nft_data: &NftData) -> Self
	{
		NftDataResolved
		{
			instance_id: nft_data.instance_id.clone(),
			quantity: nft_data.quantity.clone().unwrap_or(1),
			token_logic: nft_data.token_logic.clone().unwrap_or(CODE_HASH_NULL.to_vec()),
			custom: nft_data.custom.clone().unwrap_or(vec!()),
		}
	}
}

/// Calculates and Instance ID from an output and output index.
fn calculate_instance_id(seed_cell_outpoint: &OutPoint, output_index: usize) -> [u8; BLAKE2B256_HASH_LEN]
{
	let mut blake2b = Blake2bBuilder::new(BLAKE2B256_HASH_LEN).personal(b"ckb-default-hash").build();

	blake2b.update(&seed_cell_outpoint.tx_hash().raw_data());
	blake2b.update(&seed_cell_outpoint.index().raw_data());
	blake2b.update(&(output_index as u32).to_le_bytes());

	// debug!("calc tx hash: {:?}", seed_cell_outpoint.tx_hash().raw_data());
	// debug!("calc index: {:?}", seed_cell_outpoint.index().raw_data());
	// debug!("calc output index: {:?}", (output_index as u32).to_le_bytes());
	
	let mut hash: [u8; BLAKE2B256_HASH_LEN] = [0; BLAKE2B256_HASH_LEN];
	blake2b.finalize(&mut hash);

	hash
}

/// Collect the indexes of Cells that match a specific script hash from the specified source.
fn collect_nft_indexes(script_hash: [u8; BLAKE2B256_HASH_LEN], source: Source) -> Result<Vec<usize>, Error>
{
	let load_cell_type_hash_ex = |index, source| 
	{
		match load_cell_type_hash(index, source)
		{
			Ok(hash) => Ok((hash, index)),
			Err(SysError::ItemMissing) => Ok((None, index)),
			Err(err) => Err(err),
		}
	};

	let filter_matching_script_hashes = |(current_script_hash, index): (Option<[u8; BLAKE2B256_HASH_LEN]>, usize)|
	{
		if current_script_hash.map(|x|x==script_hash).unwrap_or(false)
		{
			return Some(index);
		}
		else
		{
			return None;
		}
	};

	let output_nft_indexes: Vec<_> = QueryIter::new(load_cell_type_hash_ex, source).filter_map(filter_matching_script_hashes).collect();
	
	Ok(output_nft_indexes)
}

/// Collect all unique Instance IDs.
fn collect_unique_instance_ids(nft_datas: &Vec<NftData>) -> BTreeSet<Vec<u8>>
{
	let mut instance_ids = BTreeSet::new();

	for nft_data in nft_datas.iter()
	{
		// Extract the Instance ID from the NftData instance.
		let instance_id = nft_data.instance_id.clone().into_iter().take(TOKEN_LOGIC_LEN).collect();

		instance_ids.insert(instance_id);
	}

	instance_ids
}

/// Collect all token logic code hashes which should be executed.
fn collect_executable_token_logic_hashes(nft_data_sets: &Vec<&Vec<NftData>>) -> Result<BTreeSet<Vec<u8>>, Error>
{
	let mut token_logic_code_hashes = BTreeSet::new();

	for nft_data_set in nft_data_sets.iter()
	{
		for nft_data in nft_data_set.iter()
		{
			if nft_data.token_logic.is_some()
			{
				// Extract the code hash array from the NftData instance.
				let token_logic_code_hash = nft_data.token_logic.clone().unwrap().into_iter().take(TOKEN_LOGIC_LEN).collect();

				// Do not include zero-filled hashes.
				if token_logic_code_hash != CODE_HASH_NULL
				{
					token_logic_code_hashes.insert(token_logic_code_hash);
				}
			}
		}
	}

	Ok(token_logic_code_hashes)
}

/// Collect and parse all NftData from the specified source.
fn collect_nft_data(source: Source) -> Result<Vec<NftData>, Error>
{
	let parse_and_validate_nft_data = |x: Vec<u8>|
	{
		let nft_data = parse_nft_data(&x)?;
		validate_nft_data(&nft_data)?;

		Ok(nft_data)
	};

	let nft_data: Result<Vec<NftData>, Error> = QueryIter::new(load_cell_data, source).map(|x|parse_and_validate_nft_data(x)).collect();

	Ok(nft_data?)
}

/// Collect the NFT quantity from the matching Instance ID and token logic value only if included.
fn collect_nft_quantity(instance_id: &Vec<u8>, token_logic: &Option<Vec<u8>>, nft_datas: &Vec<NftData>) -> Result<u128, Error>
{
	let mut quantity = 0u128;
	let token_logic_exists = token_logic.is_some();
	let token_logic = token_logic.clone().unwrap_or(vec!());

	for nft_data in nft_datas.iter()
	{
		let nft_data = NftDataResolved::from(nft_data);

		if &nft_data.instance_id == instance_id
		{
			if !token_logic_exists || nft_data.token_logic == token_logic
			{
				quantity += nft_data.quantity;
			}
		}
	}

	Ok(quantity)
}

/// Collect the quantities of the match NFT tokens group input and group output.
fn collect_nft_quantities(nft_data: &NftData, group_input_nft_data: &Vec<NftData>, group_output_nft_data: &Vec<NftData>, consider_token_logic: bool) -> Result<(u128, u128), Error>
{
	let nft_data = NftDataResolved::from(nft_data);
	let instance_id = nft_data.instance_id;
	let token_logic = if consider_token_logic { Some(nft_data.token_logic) } else { None };

	let group_input_quantity = collect_nft_quantity(&instance_id, &token_logic, group_input_nft_data)?;
	let group_output_quantity = collect_nft_quantity(&instance_id, &token_logic, group_output_nft_data)?;

	Ok((group_input_quantity, group_output_quantity))
}

/// Check for data modifications within a Vec<NftData> where the Instance ID and Token Logic match.
fn count_nft_data_modifications(nft_data: &NftData, group_nft_data: &Vec<NftData>) -> Result<usize, Error>
{
	let output_nft_data = NftDataResolved::from(nft_data);
	let mut modifications = 0;

	for input_nft_data in group_nft_data.iter()
	{
		let input_nft_data = NftDataResolved::from(input_nft_data);

		if output_nft_data.instance_id == input_nft_data.instance_id && output_nft_data.token_logic == input_nft_data.token_logic && output_nft_data.custom != input_nft_data.custom
		{
			modifications += 1;
		}
	}

	Ok(modifications)
}

/// Execute the token logic in a Cell with the specified code hash.
fn execute_token_logic(token_logic_code_hash: &Vec<u8>) -> Result<(), Error>
{
	let token_logic_code_hash: [u8; TOKEN_LOGIC_LEN] = token_logic_code_hash.as_slice().try_into().expect("Conversion failed");

	let mut context = CKBDLContext::<[u8; CKBDL_CONTEXT_SIZE]>::new();
	let lib = context.load(&token_logic_code_hash).or(Err(Error::MissingTokenLogicCellDep))?;
	unsafe
	{
		type TokenLogic = unsafe extern "C" fn(token_logic_code_hash: &[u8; TOKEN_LOGIC_LEN]) -> i32;
		let token_logic: Symbol<TokenLogic> = lib.get(TOKEN_LOGIC_FUNCTION).ok_or(Error::MissingTokenLogicFunction)?;
		let token_logic_return_code = token_logic(&token_logic_code_hash);
		if token_logic_return_code != 0
		{
			panic!("Token Logic Script returned code: {}", token_logic_return_code);
		}
	}

	Ok(())
}

/// Validate the token logic in a Cell with the specified code hash without executing.
fn validate_token_logic(token_logic_code_hash: &Vec<u8>) -> Result<(), Error>
{
	let token_logic_code_hash: [u8; TOKEN_LOGIC_LEN] = token_logic_code_hash.as_slice().try_into().expect("Conversion failed");

	// Only process non-zero-filled hashes.
	if token_logic_code_hash != CODE_HASH_NULL
	{
		let mut context = CKBDLContext::<[u8; CKBDL_CONTEXT_SIZE]>::new();
		let lib = context.load(&token_logic_code_hash).or(Err(Error::MissingTokenLogicCellDep))?;
		unsafe
		{
			type TokenLogic = unsafe extern "C" fn(token_logic_code_hash: &[u8; TOKEN_LOGIC_LEN]) -> i32;
			let token_logic: Symbol<TokenLogic> = lib.get(TOKEN_LOGIC_FUNCTION).ok_or(Error::MissingTokenLogicFunction)?;
		}
	}

	Ok(())
}

/// Parse Cell data into an NftData instance.
fn parse_nft_data(cell_data: &Vec<u8>) -> Result<NftData, Error>
{
	let cell_data_len = cell_data.len();

	// Extract Instance ID value or error if there are not enough bytes.
	if cell_data_len < INSTANCE_ID_LEN
	{
		return Err(Error::InvalidInstanceIdLength);
	}
	let instance_id = cell_data[0..INSTANCE_ID_LEN].to_vec();

	// Extract the Quantity field if it exists, or error if there are an unexpected amount of bytes.
	let mut quantity = None;
	if cell_data_len > INSTANCE_ID_LEN
	{
		if cell_data_len < INSTANCE_ID_LEN + QUANTITY_LEN
		{
			return Err(Error::InvalidQuantityLength);
		}

		let mut buf = [0u8; QUANTITY_LEN];
		let start = INSTANCE_ID_LEN;
		let end = INSTANCE_ID_LEN + QUANTITY_LEN;
		buf.copy_from_slice(&cell_data[start..end]);
		quantity = Some(u128::from_le_bytes(buf));
	}

	// Extract Token Logic field if it exists, or error if there are an unexpected amount of bytes.
	let mut token_logic = None;
	if cell_data_len > INSTANCE_ID_LEN + QUANTITY_LEN
	{
		if cell_data_len < INSTANCE_ID_LEN + QUANTITY_LEN + TOKEN_LOGIC_LEN
		{
			return Err(Error::InvalidTokenLogicLength);
		}

		let start = INSTANCE_ID_LEN + QUANTITY_LEN;
		let end = INSTANCE_ID_LEN + QUANTITY_LEN + TOKEN_LOGIC_LEN;
		token_logic = Some(cell_data[start..end].to_vec())
	}

	// Extract the Custom field if it exists.
	let mut custom = None;
	if cell_data_len > INSTANCE_ID_LEN + QUANTITY_LEN + TOKEN_LOGIC_LEN
	{
		let start = INSTANCE_ID_LEN + QUANTITY_LEN + TOKEN_LOGIC_LEN;
		let end = cell_data_len;
		custom = Some(cell_data[start..end].to_vec())
	}

	// Create the NftData instance.
	let nft_data = NftData
	{
		instance_id: instance_id,
		quantity: quantity,
		token_logic: token_logic,
		custom: custom,
	};

	Ok(nft_data)
}

// Validate the data in an NftData instance.
fn validate_nft_data(nft_data: &NftData) -> Result<(), Error>
{
	// Ensure that the Instance ID field is the correct length.
	if nft_data.instance_id.len() != INSTANCE_ID_LEN
	{
		return Err(Error::InvalidInstanceIdLength);
	}

	// Quantity is omitted from checks because u128 has a consistent size.

	// Ensure that the Token Logic field is valid if it exists.
	if nft_data.token_logic.is_some()
	{
		if nft_data.quantity.is_none() || nft_data.token_logic.as_ref().unwrap().len() != TOKEN_LOGIC_LEN
		{
			return Err(Error::InvalidStructure);
		}
	}

	// Ensure that the Custom field is valid if it exists.
	if nft_data.custom.is_some()
	{
		if nft_data.quantity.is_none() || nft_data.token_logic.is_none()
		{
			return Err(Error::InvalidStructure);
		}
	}

	Ok(())
}

fn main() -> Result<(), Error>
{
	// Load arguments from the current script.
	let script = load_script()?;
	let args = script.args();

	// Verify that the minimum length of the arguments was given.
	if args.len() < ARGS_LEN
	{
		return Err(Error::InvalidArgsLen);
	}

	// Detect owner mode.
	let owner_mode = check_owner_mode(&args)?;
	// debug!("Owner Mode: {}", owner_mode);

	// Collect group input and group output Cells.
	// let group_input_cells: Vec<Cell> = QueryIter::new(load_cell, Source::GroupInput).collect();
	// let group_output_cells: Vec<Cell> = QueryIter::new(load_cell, Source::GroupOutput).collect();
	// let group_input_cell_data: Vec<Cell> = QueryIter::new(load_cell_data, Source::GroupInput).collect();
	// let group_output_cell_data: Vec<Cell> = QueryIter::new(load_cell_data, Source::GroupOutput).collect();

	// Parse and collect NftData from the group input and group output.
	let group_input_nft_data = collect_nft_data(Source::GroupInput)?;
	let group_output_nft_data = collect_nft_data(Source::GroupOutput)?;

	// Locate all unique group input Instance IDs.
	let group_input_instance_ids = collect_unique_instance_ids(&group_input_nft_data);

	// Locate the index of all output NFTs.
	let script_hash = load_script_hash()?;
	let output_nft_indexes = collect_nft_indexes(script_hash, Source::Output)?;
	// debug!("Output NFT Indexes: {:?}", output_nft_indexes);

	// Verify that the group output and output indexes have expected counts.
	if group_output_nft_data.len() != output_nft_indexes.len()
	{
		return Err(Error::UnexpectedCellMismatch);
	}

	// Determine the Seed Cell Outpoint.
	let seed_cell_outpoint = load_input(0, Source::Input)?.previous_output();

	// Collect unique Token Logic code hashes which will be executed or validated.
	let mut token_logic_code_hashes_execute = BTreeSet::new();
	let mut token_logic_code_hashes_validate = BTreeSet::new();

	// Loop through all group output NFTData.
	for (index, output_nft_data) in group_output_nft_data.iter().enumerate()
	{
		// If the Instance ID is included it is a transfer/upgrade/burn operation, otherwise it is a generation operation.
		if group_input_instance_ids.contains(&output_nft_data.instance_id)
		{
			// debug!("Operation: Transfer/Update/Burn");

			// Validate quantities taking into account the owner mode.
			let (input_nft_quantity, output_nft_quantity) = collect_nft_quantities(&output_nft_data, &group_input_nft_data, &group_output_nft_data, owner_mode)?;
			if output_nft_quantity > input_nft_quantity
			{
				return Err(Error::InvalidQuantity);
			}

			// Collect token logic code hash for future validation or execution.
			if output_nft_data.token_logic.is_some()
			{
				let token_logic_code_hash = output_nft_data.token_logic.clone().unwrap();
				if token_logic_code_hash != CODE_HASH_NULL
				{
					if owner_mode || count_nft_data_modifications(&output_nft_data, &group_input_nft_data)? == 0
					{
						token_logic_code_hashes_validate.insert(token_logic_code_hash);
					}
					else
					{
						token_logic_code_hashes_execute.insert(token_logic_code_hash);
					}
				}
			}
		}
		else
		{
			// debug!("Operation: Generate");

			if !owner_mode
			{
				return Err(Error::UnauthorizedOperation);
			}

			let instance_id = calculate_instance_id(&seed_cell_outpoint, output_nft_indexes[index]);
			// debug!("Output Instance ID: {:?}", output_nft_data.instance_id);
			// debug!("Calculated Instance ID: {:?}", instance_id);

			if output_nft_data.instance_id != instance_id
			{
				return Err(Error::InvalidInstanceId);
			}

			if output_nft_data.token_logic.is_some()
			{
				validate_token_logic(&output_nft_data.token_logic.as_ref().unwrap())?;
			}
		}
	}

	// Collect all unique executable token logic code hashes from the group input if not owner mode.
	// if !owner_mode
	// {
	// 	token_logic_code_hashes_execute.append(&mut collect_executable_token_logic_hashes(&vec!(&group_input_nft_data))?);
	// }

	// Validate Token Logic.
	for token_logic_code_hash in token_logic_code_hashes_validate.iter()
	{
		validate_token_logic(token_logic_code_hash)?;
	}

	// Execute Token Logic.
	for token_logic_code_hash in token_logic_code_hashes_execute.iter()
	{
		execute_token_logic(token_logic_code_hash)?;
	}

	Ok(())
}
