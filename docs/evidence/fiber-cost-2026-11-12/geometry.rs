// Audit-only canonical sizing reconstruction; zero bytes are not executable authority.
// No VM benchmark or signing claim is made by this program.
use ckb_types::{core::{Capacity, TransactionBuilder}, packed::{CellDep,CellInput,CellOutput,Script}, prelude::*};
fn script(n:usize)->Script { Script::new_builder().args(vec![0u8;n].pack()).build() }
fn occupied(lock_args:usize, typed:bool, data_len:usize, type_args:usize)->u64 {
    CellOutput::new_builder().lock(script(lock_args)).type_(typed.then(||script(type_args)).pack()).build().occupied_capacity(Capacity::bytes(data_len).unwrap()).unwrap().as_u64()/100_000_000
}
fn size(typed:bool, close:bool, deps:usize)->usize {
 let lock=script(if close {20}else{57});
 let outputs=if close {2}else{1};
 let mut b=TransactionBuilder::default().cell_deps(vec![CellDep::default();deps]).input(CellInput::default()).witness(vec![0u8;112].pack());
 for _ in 0..outputs {
  b=b.output(CellOutput::new_builder().lock(lock.clone()).type_(typed.then(||script(32)).pack()).build()).output_data(vec![0u8;if typed{16}else{0}].pack());
 }
 b.build().data().serialized_size_in_block()
}
fn main(){
 for typed in [false,true] {
  let deps=if typed {3}else{2};
  println!("fiber {} funding_occupied_ckb={} commitment_occupied_ckb={} commitment_bytes={} shutdown_bytes={}",if typed{"udt"}else{"ckb"},occupied(20,typed,if typed{16}else{0},32),occupied(57,typed,if typed{16}else{0},32),size(typed,false,deps),size(typed,true,deps));
 }
 println!("morph root_state={} child_state={} ckb_vault={} udt_vault={} wallet_ckb={} wallet_udt={} factory_udt_vault={}",
  CellOutput::new_builder().lock(script(32)).type_(Some(script(40)).pack()).build().occupied_capacity(Capacity::bytes(318).unwrap()).unwrap().as_u64()/100_000_000,
  CellOutput::new_builder().lock(script(32)).type_(Some(script(72)).pack()).build().occupied_capacity(Capacity::bytes(318).unwrap()).unwrap().as_u64()/100_000_000,
  occupied(116,false,0,0),occupied(116,true,16,32),occupied(20,false,0,0),occupied(20,true,16,32),occupied(64,true,16,32));
}
