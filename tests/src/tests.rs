use super::*;
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bBuilder};
use std::collections::HashMap;
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::{ckb_error::assert_error_eq, ckb_script::ScriptError};
use ckb_tool::ckb_types::{bytes::Bytes, packed::*, prelude::*};
use ckb_tool::ckb_types::core::{Capacity, TransactionBuilder};

// Constants
const MAX_CYCLES: u64 = 10_000_000;
const CODE_HASH_NULL: [u8; 32] = [0u8; 32];

// Error Codes (Copied directly from main.rs.)
#[allow(dead_code)]
enum Error
{
	IndexOutOfBound,
	ItemMissing,
	LengthNotEnough,
	Encoding,
	InvalidArgsLen,
	InvalidInstanceId,
	InvalidInstanceIdLength,
	InvalidQuantity,
	InvalidQuantityLength,
	InvalidStructure,
	InvalidTokenLogicLength,
	MissingTokenLogicCellDep,
	MissingTokenLogicFunction,
	UnauthorizedOperation,
	UnexpectedCellMismatch,
	UnexpectedTokenLogicErrorCode,
	TokenLogicError(i8),
}

impl From<Error> for i8
{
	fn from(err: Error) -> Self
	{
		match err
		{
			Error::IndexOutOfBound => 1,
			Error::ItemMissing => 2,
			Error::LengthNotEnough => 3,
			Error::Encoding => 4,
			Error::InvalidArgsLen => 10,
			Error::InvalidInstanceId => 11,
			Error::InvalidInstanceIdLength => 12,
			Error::InvalidQuantity => 13,
			Error::InvalidQuantityLength => 14,
			Error::InvalidStructure => 15,
			Error::InvalidTokenLogicLength => 16,
			Error::MissingTokenLogicCellDep => 17,
			Error::MissingTokenLogicFunction => 18,
			Error::UnauthorizedOperation => 19,
			Error::UnexpectedCellMismatch => 20,
			Error::UnexpectedTokenLogicErrorCode => 21,
			Error::TokenLogicError(e) => e,
		}
	}
}

/// A structure for holding common resources used in multiple tests.
struct LocalResources
{
	binaries: HashMap<String, Bytes>,
	binary_hashes: HashMap<String, String>,
	out_points: HashMap<String, OutPoint>,
	scripts: HashMap<String, Script>,
	deps: HashMap<String, CellDep>,
}

impl LocalResources
{
	pub fn new() -> Self
	{
		Self
		{
			binaries: HashMap::new(),
			binary_hashes: HashMap::new(),
			out_points: HashMap::new(),
			scripts: HashMap::new(),
			deps: HashMap::new(),
		}
	}
}

/// A structure for holding data used to create an NFT cell.
struct NftCellData<'a>
{
	instance_id: &'a str,
	quantity: Option<u128>,
	token_logic: Option<&'a str>,
	custom: Option<&'a str>,
	lock_script: &'a str,
	governance_lock_script: &'a str,
}

/// A structure for holding data used to create an NFT cell using a raw data area.
struct NftCellDataRaw<'a>
{
	data: &'a Vec<u8>,
	lock_script: &'a str,
	governance_lock_script: &'a str,
}

fn build_default_context_and_resources() -> (Context, TransactionBuilder, LocalResources)
{
	// Create the default context.
	let mut context = Context::default();

	// Create a resource holder.
	let mut resources = LocalResources::new();

	// Load binaries.
	resources.binaries.insert("nft".to_owned(), Loader::default().load_binary("nft"));
	resources.binaries.insert("token-logic-custom-quantity".to_owned(), Loader::default().load_binary("token-logic-custom-quantity.so"));
	resources.binaries.insert("token-logic-approve".to_owned(), Loader::default().load_binary("token-logic-approve.so"));
	resources.binaries.insert("token-logic-reject".to_owned(), Loader::default().load_binary("token-logic-reject.so"));

	// Calculate hashes.
	resources.binary_hashes.insert("nft".to_owned(), hex::encode(&generate_hash_for_resource(&resources, "nft").as_bytes()));
	resources.binary_hashes.insert("token-logic-custom-quantity".to_owned(), hex::encode(&generate_hash_for_resource(&resources, "token-logic-custom-quantity").as_bytes()));
	resources.binary_hashes.insert("token-logic-approve".to_owned(), hex::encode(&generate_hash_for_resource(&resources, "token-logic-approve").as_bytes()));
	resources.binary_hashes.insert("token-logic-reject".to_owned(), hex::encode(&generate_hash_for_resource(&resources, "token-logic-reject").as_bytes()));

	// Deploy binaries.
	resources.out_points.insert("nft".to_owned(), context.deploy_cell(resources.binaries.get("nft").unwrap().clone()));
	resources.out_points.insert("token-logic-custom-quantity".to_owned(), context.deploy_cell(resources.binaries.get("token-logic-custom-quantity").unwrap().clone()));
	resources.out_points.insert("token-logic-approve".to_owned(), context.deploy_cell(resources.binaries.get("token-logic-approve").unwrap().clone()));
	resources.out_points.insert("token-logic-reject".to_owned(), context.deploy_cell(resources.binaries.get("token-logic-reject").unwrap().clone()));
	resources.out_points.insert("lock-1".to_owned(), context.deploy_cell(ALWAYS_SUCCESS.clone()));

	// Create Scripts.
	resources.scripts.insert("lock-1".to_owned(), context.build_script(resources.out_points.get("lock-1").unwrap(), [0u8; 20].to_vec().into()).expect("script"));
	resources.scripts.insert("lock-2".to_owned(), context.build_script(resources.out_points.get("lock-1").unwrap(), [1u8; 20].to_vec().into()).expect("script"));
	resources.scripts.insert("lock-3".to_owned(), context.build_script(resources.out_points.get("lock-1").unwrap(), [2u8; 20].to_vec().into()).expect("script"));
	resources.scripts.insert("lock-4".to_owned(), context.build_script(resources.out_points.get("lock-1").unwrap(), [3u8; 20].to_vec().into()).expect("script"));
	resources.scripts.insert("lock-5".to_owned(), context.build_script(resources.out_points.get("lock-1").unwrap(), [4u8; 20].to_vec().into()).expect("script"));
	
	// Create dependencies.
	resources.deps.insert("nft".to_owned(), CellDep::new_builder().out_point(resources.out_points.get("nft").unwrap().clone()).build());
	resources.deps.insert("token-logic-custom-quantity".to_owned(), CellDep::new_builder().out_point(resources.out_points.get("token-logic-custom-quantity").unwrap().clone()).build());
	resources.deps.insert("token-logic-approve".to_owned(), CellDep::new_builder().out_point(resources.out_points.get("token-logic-approve").unwrap().clone()).build());
	resources.deps.insert("token-logic-reject".to_owned(), CellDep::new_builder().out_point(resources.out_points.get("token-logic-reject").unwrap().clone()).build());
	resources.deps.insert("lock-1".to_owned(), CellDep::new_builder().out_point(resources.out_points.get("lock-1").unwrap().clone()).build());

	// Build transaction.
	let tx = TransactionBuilder::default()
		.cell_dep(resources.deps.get(&"nft".to_owned()).unwrap().clone())
		.cell_dep(resources.deps.get(&"token-logic-custom-quantity".to_owned()).unwrap().clone())
		.cell_dep(resources.deps.get(&"token-logic-approve".to_owned()).unwrap().clone())
		.cell_dep(resources.deps.get(&"token-logic-reject".to_owned()).unwrap().clone())
		.cell_dep(resources.deps.get(&"lock-1".to_owned()).unwrap().clone());

	(context, tx, resources)
}

/// Create a input Cell with capacity.
fn create_input_capacity_cell(context: &mut Context, resources: &LocalResources, capacity: u64, lock_script: &str) -> CellInput
{
	let (output, output_data) = create_output_capacity_cell(context, resources, capacity, lock_script);
	let input_out_point = context.create_cell(output, output_data);
	let input = CellInput::new_builder().previous_output(input_out_point).build();

	input
}

/// Create an output Cell with capacity.
fn create_output_capacity_cell(_context: &mut Context, resources: &LocalResources, capacity: u64, lock_script: &str) -> (CellOutput, Bytes)
{
	let lock_script = resources.scripts.get(lock_script).unwrap().clone();

	let output = CellOutput::new_builder()
		.capacity(Capacity::shannons(capacity).as_u64().pack())
		.lock(lock_script.clone())
		.build();
	let output_data: Bytes = Default::default();

	(output, output_data)
}

/// Create an input NFT Cell.
fn create_input_nft_cell(context: &mut Context, resources: &LocalResources, capacity: u64, nft_cell_data: &NftCellData) -> CellInput
{
	let (output, output_data) = create_output_nft_cell(context, resources, capacity, nft_cell_data);
	let input_out_point = context.create_cell(output, output_data);
	let input = CellInput::new_builder().previous_output(input_out_point).build();

	input
}

/// Create an output NFT Cell.
fn create_output_nft_cell(context: &mut Context, resources: &LocalResources, capacity: u64, nft_cell_data: &NftCellData) -> (CellOutput, Bytes)
{
	let lock_script = resources.scripts.get(nft_cell_data.lock_script).unwrap().clone();

	let nft_script_args: [u8; 32] = resources.scripts.get(nft_cell_data.governance_lock_script).unwrap().clone().calc_script_hash().unpack();
	let nft_script = context.build_script(resources.out_points.get("nft").unwrap(), nft_script_args.to_vec().into()).expect("script");

	let output = CellOutput::new_builder()
		.capacity(Capacity::shannons(capacity).as_u64().pack())
		.lock(lock_script)
		.type_(Some(nft_script).pack())
		.build();

	let mut output_data = hex::decode(nft_cell_data.instance_id.to_owned()).unwrap();
	if nft_cell_data.quantity.is_some()
	{
		output_data.append(&mut nft_cell_data.quantity.clone().unwrap().to_le_bytes().to_vec());
	}
	if nft_cell_data.token_logic.is_some()
	{
		output_data.append(&mut hex::decode(nft_cell_data.token_logic.unwrap()).unwrap());
	}
	if nft_cell_data.custom.is_some()
	{
		output_data.append(&mut nft_cell_data.custom.clone().unwrap().to_owned().as_bytes().to_vec());
	}
	let output_data: Bytes = output_data.into();

	(output, output_data)
}

/// Create an input NFT Cell using raw data.
fn create_input_nft_cell_raw(context: &mut Context, resources: &LocalResources, capacity: u64, nft_cell_data_raw: &NftCellDataRaw) -> CellInput
{
	let (output, output_data) = create_output_nft_cell_raw(context, resources, capacity, nft_cell_data_raw);
	let input_out_point = context.create_cell(output, output_data);
	let input = CellInput::new_builder().previous_output(input_out_point).build();

	input
}

/// Create an output NFT Cell using raw data.
fn create_output_nft_cell_raw(context: &mut Context, resources: &LocalResources, capacity: u64, nft_cell_data_raw: &NftCellDataRaw) -> (CellOutput, Bytes)
{
	let lock_script = resources.scripts.get(nft_cell_data_raw.lock_script).unwrap().clone();

	let nft_script_args: [u8; 32] = resources.scripts.get(nft_cell_data_raw.governance_lock_script).unwrap().clone().calc_script_hash().unpack();
	let nft_script = context.build_script(resources.out_points.get("nft").unwrap(), nft_script_args.to_vec().into()).expect("script");

	let output = CellOutput::new_builder()
		.capacity(Capacity::shannons(capacity).as_u64().pack())
		.lock(lock_script)
		.type_(Some(nft_script).pack())
		.build();

	let output_data: Bytes = nft_cell_data_raw.data.clone().into();

	(output, output_data)
}

fn generate_hash_for_resource(resources: &LocalResources, resource_key: &str) -> Blake2bHash
{
	let resource_bytes = resources.binaries.get(resource_key).expect("Unable to read bytes from resource.");
	let blake2b_hash = Blake2bBuilder::new().hash_length(32).personal(b"ckb-default-hash").hash(&resource_bytes);

	blake2b_hash
}

fn instance_id_from_seed_cell(seed_cell: &CellInput, output_index: u32) -> Vec<u8>
{
	let seed_cell_outpoint_tx_hash: [u8; 32] = seed_cell.previous_output().tx_hash().unpack();
	let seed_cell_outpoint_index: u32 = seed_cell.previous_output().index().unpack();

	let mut hash_data: Vec<u8> = vec!();
	hash_data.append(&mut seed_cell_outpoint_tx_hash.to_vec());
	hash_data.append(&mut seed_cell_outpoint_index.to_le_bytes().to_vec());
	hash_data.append(&mut output_index.to_le_bytes().to_vec());

	// println!("test tx hash: {:?}", seed_cell_outpoint_tx_hash.to_vec());
	// println!("test index: {:?}", seed_cell_outpoint_index.to_le_bytes().to_vec());
	// println!("test output index: {:?}", output_index.to_le_bytes().to_vec());

	let instance_id = Blake2bBuilder::new().hash_length(32).personal(b"ckb-default-hash").hash(&hash_data);

	instance_id.as_bytes().to_vec()
}

#[test]
fn generate_bare()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn generate_quantity()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn generate_quantity_zero()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn generate_token_logic()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn generate_token_logic_null()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn generate_custom()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: Some(&token_logic_hash),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn generate_multiple()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash = resources.binary_hashes.get("token-logic-approve").unwrap();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 1)),
		quantity: Some(1_000_000_000),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 2)),
		quantity: Some(0),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 3)),
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("ABC123"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn generate_bare_invalid_instance_id_length()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &hex::decode("deadbeef").unwrap(),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidInstanceIdLength)).output_type_script(0));
}

#[test]
fn generate_bare_invalid_instance_id()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidInstanceId)).output_type_script(0));
}

#[test]
fn generate_quantity_invalid_quantity_length()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let mut data = vec!();
	data.append(&mut instance_id_from_seed_cell(&seed_cell, 3));
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidQuantityLength)).output_type_script(0));
}

#[test]
fn generate_token_logic_invalid_token_logic_length()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let mut data = vec!();
	data.append(&mut instance_id_from_seed_cell(&seed_cell, 3));
	data.append(&mut 0u128.to_le_bytes().to_vec());
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidTokenLogicLength)).output_type_script(0));
}

#[test]
fn generate_token_logic_invalid_cell_dep()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash = hex::encode("1111111111111111111111111111111111111111111111111111111111111111");

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::MissingTokenLogicCellDep)).output_type_script(0));
}

#[test]
fn generate_bare_unauthorized()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::UnauthorizedOperation)).output_type_script(0));
}

#[test]
fn transfer_bare()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_quantity()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: None,
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_quantity_zero()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_token_logic()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(9),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_token_logic_null()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(9),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_custom()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_multiple()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_burn()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(9),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_quantity_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_quantity_zero_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_token_logic_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: None,
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_multiple_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_bare_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_quantity_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: None,
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_quantity_zero_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_token_logic_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(9),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_token_logic_null_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(9),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_custom_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_multiple_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-2",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_burn_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(9),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_quantity_owner_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_quantity_zero_owner_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_token_logic_owner_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: None,
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_multiple_owner_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn transfer_bare_invalid_instance_id_length()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &hex::decode("deadbeef").unwrap(),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &hex::decode("deadbeef").unwrap(),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidInstanceIdLength)).input_type_script(0));
}

#[test]
fn transfer_quantity_invalid_quantity()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(99),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 2_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(50),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(50),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidQuantity)).input_type_script(0));
}

#[test]
fn transfer_quantity_invalid_quantity_length()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let mut data = vec!();
	data.append(&mut hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap());
	data.append(&mut 100u128.to_le_bytes().to_vec());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let mut data = vec!();
	data.append(&mut hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap());
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidQuantityLength)).input_type_script(0));
}

#[test]
fn transfer_token_logic_unauthorized()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 2_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(50),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::UnauthorizedOperation)).input_type_script(0));
}

#[test]
fn transfer_token_logic_invalid_token_logic_length()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);
	let mut data = vec!();
	data.append(&mut instance_id_from_seed_cell(&seed_cell, 3));
	data.append(&mut 0u128.to_le_bytes().to_vec());
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let mut data = vec!();
	data.append(&mut instance_id_from_seed_cell(&seed_cell, 3));
	data.append(&mut 0u128.to_le_bytes().to_vec());
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidTokenLogicLength)).input_type_script(1));
}

#[test]
fn transfer_token_logic_invalid_token_logic_cell_dep()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_invalid = hex::encode("1111111111111111111111111111111111111111111111111111111111111111");

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_invalid),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_invalid),
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::MissingTokenLogicCellDep)).input_type_script(1));
}

#[test]
fn transfer_bare_owner_invalid_instance_id_length()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &hex::decode("deadbeef").unwrap(),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &hex::decode("deadbeef").unwrap(),
		lock_script: "lock-2",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidInstanceIdLength)).input_type_script(0));
}

#[test]
fn transfer_quantity_owner_invalid_quantity()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(9),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidQuantity)).input_type_script(0));
}

#[test]
fn transfer_quantity_owner_invalid_quantity_length()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let mut data = vec!();
	data.append(&mut hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap());
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let mut data = vec!();
	data.append(&mut hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap());
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-2",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidQuantityLength)).input_type_script(0));
}

#[test]
fn transfer_token_logic_owner_invalid_token_logic_length()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);
	let mut data = vec!();
	data.append(&mut instance_id_from_seed_cell(&seed_cell, 3));
	data.append(&mut 0u128.to_le_bytes().to_vec());
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let mut data = vec!();
	data.append(&mut instance_id_from_seed_cell(&seed_cell, 3));
	data.append(&mut 0u128.to_le_bytes().to_vec());
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-2",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidTokenLogicLength)).input_type_script(1));
}

#[test]
fn transfer_token_logic_owner_invalid_token_logic_cell_dep()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash = hex::encode("1111111111111111111111111111111111111111111111111111111111111111");

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::MissingTokenLogicCellDep)).input_type_script(1));
}

#[test]
fn update_custom()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello Nervos!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn update_multiple()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello Nervos!"),
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn update_quantity_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn update_token_logic_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn update_custom_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn update_token_logic_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn update_custom_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn update_multiple_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 5_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(50),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello Nervos!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(25),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(24),
		token_logic: None,
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-4",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-5",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn update_quantity_owner_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(2),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 5_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn update_token_logic_owner_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 5_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn update_custom_owner_shapeshift()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 5_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_approve),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn update_quantity_invalid_quantity()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(99),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 2_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(50),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(50),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidQuantity)).input_type_script(0));
}

#[test]
fn update_quantity_invalid_quantity_length()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let mut data = vec!();
	data.append(&mut hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap());
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let mut data = vec!();
	data.append(&mut hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap());
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidQuantityLength)).input_type_script(0));
}

#[test]
fn update_token_logic_unauthorized()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 2_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(50),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::UnauthorizedOperation)).input_type_script(0));
}

#[test]
fn update_quantity_owner_invalid_quantity()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(99),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 2_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(50),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(50),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidQuantity)).input_type_script(0));
}

#[test]
fn update_quantity_owner_invalid_quantity_length()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let mut data = vec!();
	data.append(&mut hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap());
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let mut data = vec!();
	data.append(&mut hex::decode("0101010101010101010101010101010101010101010101010101010101010101").unwrap());
	data.append(&mut hex::decode("deadbeef").unwrap());
	let nft_cell_data_raw = NftCellDataRaw
	{
		data: &data,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell_raw(&mut context, &resources, 1_000, &nft_cell_data_raw);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::InvalidQuantityLength)).input_type_script(0));
}

#[test]
fn update_token_logic_owner_invalid_token_logic_cell_dep()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();
	let token_logic_hash_invalid = hex::encode("1111111111111111111111111111111111111111111111111111111111111111");

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_invalid),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
	assert_error_eq!(err, ScriptError::ValidationFailure(i8::from(Error::MissingTokenLogicCellDep)).input_type_script(0));
}

#[test]
fn update_token_logic_owner_invalid_token_logic_cell_dep_removal()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_invalid = hex::encode("1111111111111111111111111111111111111111111111111111111111111111");

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_invalid),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_bare()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_quantity()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_quantity_zero()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_token_logic()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_token_logic_null()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_custom()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_multiple()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_bare_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_quantity_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(100),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_quantity_zero_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_token_logic_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_token_logic_null_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_custom_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn burn_multiple_owner()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let outputs: Vec<CellOutput> = vec!();
	let outputs_data: Vec<Bytes> = vec!();

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_approve_generate_quantity_zero()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(0),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_approve_generate_token_logic()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_approve_generate_custom()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_approve),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_approve_generate_multiple()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 1)),
		quantity: Some(1_000_000_000),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 2)),
		quantity: Some(0),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 3)),
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("ABC123"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_reject_generate_quantity_zero()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_reject = resources.binary_hashes.get("token-logic-reject").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(0),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_reject_generate_token_logic()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_reject = resources.binary_hashes.get("token-logic-reject").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_reject_generate_custom()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_reject = resources.binary_hashes.get("token-logic-reject").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: Some(100),
		token_logic: Some(&token_logic_hash_reject),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_reject_generate_multiple()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_reject = resources.binary_hashes.get("token-logic-reject").unwrap();
	let token_logic_hash_null = hex::encode(CODE_HASH_NULL);

	// Prepare inputs.
	let mut inputs = vec!();
	let input = create_input_capacity_cell(&mut context, &resources, 1_000, "lock-1");
	let seed_cell = input.clone();
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 0)),
		quantity: None,
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 1)),
		quantity: Some(1_000_000_000),
		token_logic: None,
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 2)),
		quantity: Some(0),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: &hex::encode(instance_id_from_seed_cell(&seed_cell, 3)),
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_null),
		custom: Some("ABC123"),
		lock_script: "lock-1",
		governance_lock_script: "lock-1",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_approve_transfer_quantity_zero()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 4_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_approve_transfer_token_logic()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 2_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(9),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_approve_transfer_custom()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_approve),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_approve),
		custom: Some("Hello World!"),
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_approve_transfer_multiple()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();
	
	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_approve),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: Some(&token_logic_hash_approve),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_approve),
		custom: Some("Hello World!"),
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_approve),
		custom: Some("Hello World!"),
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_approve_transfer_burn()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_approve = resources.binary_hashes.get("token-logic-approve").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(9),
		token_logic: Some(&token_logic_hash_approve),
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_reject_transfer_quantity_zero()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_reject = resources.binary_hashes.get("token-logic-reject").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 4_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(0),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_reject_transfer_token_logic()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_reject = resources.binary_hashes.get("token-logic-reject").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 2_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(9),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_reject_transfer_custom()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_reject = resources.binary_hashes.get("token-logic-reject").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_reject),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_reject),
		custom: Some("Hello World!"),
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_reject_transfer_multiple()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_reject = resources.binary_hashes.get("token-logic-reject").unwrap();
	
	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_reject),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 3_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(8),
		token_logic: Some(&token_logic_hash_reject),
		custom: Some("Hello World!"),
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_reject),
		custom: Some("Hello World!"),
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(1),
		token_logic: Some(&token_logic_hash_reject),
		custom: Some("Hello World!"),
		lock_script: "lock-3",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}

#[test]
fn token_logic_reject_transfer_burn()
{
	// Get defaults.
	let (mut context, tx, resources) = build_default_context_and_resources();
	let token_logic_hash_reject = resources.binary_hashes.get("token-logic-reject").unwrap();

	// Prepare inputs.
	let mut inputs = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(10),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-1",
		governance_lock_script: "lock-5",
	};
	let input = create_input_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	inputs.push(input);

	// Prepare outputs.
	let mut outputs = vec!();
	let mut outputs_data = vec!();
	let nft_cell_data = NftCellData
	{
		instance_id: "0101010101010101010101010101010101010101010101010101010101010101",
		quantity: Some(9),
		token_logic: Some(&token_logic_hash_reject),
		custom: None,
		lock_script: "lock-2",
		governance_lock_script: "lock-5",
	};
	let (output, output_data) = create_output_nft_cell(&mut context, &resources, 1_000, &nft_cell_data);
	outputs.push(output);
	outputs_data.push(output_data);

	// Populate the transaction, build, and complete.
	let tx = tx.inputs(inputs).outputs(outputs).outputs_data(outputs_data.pack()).build();
	let tx = context.complete_tx(tx);

	// Execute the transaction.
	let _cycles = context.verify_tx(&tx, MAX_CYCLES).expect("pass verification");
	// println!("Cycles: {}", cycles);
}
