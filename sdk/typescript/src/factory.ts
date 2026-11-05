/** Public current Factory codecs. Inspections are stateless evidence views;
 * native Core, canonical source/deployment checks and durable signer journals
 * remain the authority for signing and submission. No private child exit is
 * accepted or returned by these public packet APIs. */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { inspectMultiAssetPublicExitTerms, type MultiAssetPackageSummary } from "./multi-asset.js";
import { MAX_U64, MAX_TRANSACTION_BYTES, utf8, requireValue, bytes, hex, join, hash, domainHash, same, zero,
  unsigned, u16, u32, little, asset, allocation, scriptOccupied, occupied, table, dynamic, byteVector,
  rawTransactionEvidence, validPublicKey, type Vault, type RawTransactionEvidence } from "./protocol-wire.js";

export interface FactoryPoint { tx_hash:string; index:number }
export interface FactoryMember { participant:string; pubkey:string }
export type FactoryRightKind = "Balance"|"ReserveClaim"|"Membership"|"ExitPath"|"SponsorBudgetClaim";
export interface FactoryRight { participant:string; subchannel:string; kind:FactoryRightKind; asset_type:string|null; quantity:string }
export interface FactoryCustody {
  schema:"morph.factory_custody.v1"; header_hex:string; state_out_point:FactoryPoint; manifest_hex:string;
  vault_outpoints:FactoryPoint[]; state_type_hex:string; state_lock_hex:string; vault_lock_hex:string;
  type_scripts:Array<{type_hash:string;script_hex:string}>; state_carrier_capacity:string;
}
export interface FactoryDelivery { child_index:number; pubkey:string; signature:string }
export type FactorySigningRole = "root_funding"|"metadata_update"|"materialisation"|"transition";
export interface FactoryRequest {
  schema:"morph.factory_request.v1"; role:FactorySigningRole; source:FactoryCustody|null; target:FactoryCustody|null;
  raw_transaction_hex:string; witness_hex:string; target_rights:FactoryRight[]; deliveries:FactoryDelivery[];
}
export interface FactorySignatureReceipt {
  schema:"morph.factory_signature.v1"; request_id:string; signing_digest:string; participant:string;pubkey:string;signature:string;
}
export interface FactoryCustodyInspection {
  factory_id:string;chain_id:string;update_number:string;state_out_point:FactoryPoint;content_root:string;outpoint_root:string;
  state_carrier_capacity:string;vault_count:number;assets:Array<{type_hash:string|null;reserve:string;business_ckb:string;amount:string}>;
}
export interface FactoryRequestInspection {
  schema:"morph.factory_request_summary.v1";stage:"offline_review";request_id:string;signing_digest:string;role:FactorySigningRole;
  transaction_hash:string;raw_transaction_bytes:number;witness_bytes:number;source:FactoryCustodyInspection|null;target:FactoryCustodyInspection|null;
  members:FactoryMember[];required_members:FactoryMember[];requires_activation:boolean;target_rights:FactoryRight[];delivery_count:number;
  missing_deliveries:Array<{child_index:number;pubkey:string}>;
  children:Array<{child_index:number;state_output_index:number;initial_exit:MultiAssetPackageSummary}>;
  validation_scope:"public_terms_and_signatures";
  constraints:{canonical_source:"native_check_required";approved_dependencies:"native_check_required";vm_preflight:"native_check_required";
    monotonic_signer_reservation:"required_before_key_use";factory_transition_semantics:"native_core_check_required"};
}
const MAX_U128=(1n<<128n)-1n;
function shape(value:unknown,keys:string):asserts value is Record<string,unknown> {
  requireValue(typeof value === "object" && value !== null && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === keys.split(",").sort().join(","),"unknown or missing Factory packet fields");
}
function decimal(value:string,max=MAX_U64):bigint {
  requireValue(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value) && value.length<=39,"noncanonical Factory quantity");
  const number=BigInt(value);requireValue(number<=max,"Factory quantity overflow");return number;
}
function exact(value:string,count:number):Uint8Array { const raw=bytes(value,count);requireValue(raw.length===count,"incorrect Factory field length");return raw; }
function point(value:FactoryPoint):Uint8Array {
  shape(value,"tx_hash,index");const tx=exact(value.tx_hash,32);
  requireValue(!zero(tx) && Number.isSafeInteger(value.index) && value.index>=0 && value.index<=0xffffffff,"invalid Factory OutPoint");
  return join(tx,little(value.index,4));
}
function header(raw:Uint8Array):void {
  requireValue(raw.length===306 && u16(raw,0)===1 && u16(raw,34)===1 && u16(raw,236)===2 && u16(raw,304)===0
    && u16(raw,302)>=1 && u16(raw,302)<=8,"unsupported Factory State profile");
  for(const offset of [2,36,76,108,204,238])requireValue(!zero(raw.slice(offset,offset+32)),"zero Factory commitment");
}
function identity(a:Uint8Array,b:Uint8Array):boolean { return same(a.slice(0,68),b.slice(0,68)) && same(a.slice(108,140),b.slice(108,140)) && same(a.slice(204,238),b.slice(204,238)); }
function activation(a:Uint8Array,b:Uint8Array):boolean { return zero(a.slice(270,302)) && !zero(b.slice(270,302)) && same(a.slice(0,270),b.slice(0,270)) && same(a.slice(302),b.slice(302)); }
function manifest(raw:Uint8Array):Vault[] {
  const count=raw[2] ?? 0;requireValue(count>=1&&count<=8&&raw.length===4+97*count&&u16(raw,0)===1&&raw[3]===0,"invalid Factory manifest");
  const result:Vault[]=[];let total=0n;
  for(let i=0;i<count;i++) {
    const start=4+i*97,id=asset(raw,start),lock=raw.slice(start+33,start+65),value=allocation(raw,start+65,id,true);
    requireValue(!zero(lock) && (i===0 || (result[i-1]!.asset.key<id.key && same(result[0]!.lock,lock))),"unordered Factory Vaults");
    total+=value.capacity;requireValue(total<=MAX_U64,"Factory capacity overflow");result.push({asset:id,lock,value});
  }
  return result;
}
function content(raw:Uint8Array):Uint8Array { return domainHash("CKB_MORPH_MULTI_ASSET_VAULT_SET_V1",raw); }
function pointsRoot(raw:Uint8Array,count:number,points:Uint8Array):Uint8Array {
  requireValue(points.length===count*36,"incomplete Factory Vault OutPoints");const seen=new Set<string>();
  for(let i=0;i<count;i++){const p=points.slice(i*36,(i+1)*36);requireValue(!zero(p.slice(0,32))&&!seen.has(hex(p)),"duplicate Factory Vault OutPoint");seen.add(hex(p));}
  return domainHash("CKB_MORPH_MULTI_ASSET_OUTPOINT_SET_V1",content(raw),little(count,2),points);
}
interface Custody {value:FactoryCustody;raw:Uint8Array;manifest:Uint8Array;vaults:Vault[];points:Uint8Array;statePoint:Uint8Array;stateType:Uint8Array;stateLock:Uint8Array;vaultLock:Uint8Array;carrier:bigint;types:Map<string,Uint8Array>}
function custody(value:FactoryCustody):Custody {
  shape(value,"schema,header_hex,state_out_point,manifest_hex,vault_outpoints,state_type_hex,state_lock_hex,vault_lock_hex,type_scripts,state_carrier_capacity");
  requireValue(value.schema==="morph.factory_custody.v1","unsupported Factory custody schema");
  const raw=exact(value.header_hex,306);header(raw);const man=bytes(value.manifest_hex,780),vaults=manifest(man);
  requireValue(Array.isArray(value.vault_outpoints)&&value.vault_outpoints.length===vaults.length&&Array.isArray(value.type_scripts)&&value.type_scripts.length<=8,"incomplete Factory custody");
  const points=join(...value.vault_outpoints.map(point)),statePoint=point(value.state_out_point);
  requireValue(!zero(raw.slice(270,302)) && u16(raw,302)===vaults.length && same(content(man),raw.slice(238,270))
    && same(pointsRoot(man,vaults.length,points),raw.slice(270,302)) && value.vault_outpoints.every(p=>!same(point(p),statePoint)),"Factory custody commitment mismatch");
  const stateType=bytes(value.state_type_hex,512),stateLock=bytes(value.state_lock_hex,512),vaultLock=bytes(value.vault_lock_hex,512);
  for(const s of [stateType,stateLock,vaultLock])scriptOccupied(s);
  const args=stateType.slice(53);requireValue(args.length===44&&same(args.slice(0,8),utf8.encode("MORPHFT!"))&&u16(args,8)===1&&u16(args,10)===0
    && same(args.slice(12),raw.slice(36,68))&&same(stateLock.slice(53),hash(stateType))&&vaultLock.length===117
    &&same(vaultLock.slice(53,85),raw.slice(36,68))&&same(vaultLock.slice(85),hash(stateType)),"Factory script identity mismatch");
  const carrier=decimal(value.state_carrier_capacity);
  requireValue(carrier>=(8n+scriptOccupied(stateLock)+scriptOccupied(stateType)+306n)*100_000_000n,"insufficient Factory carrier");
  const typed=vaults.filter(v=>v.asset.kind===1),types=new Map<string,Uint8Array>();
  requireValue(value.type_scripts.length===typed.length,"incomplete Factory Type scripts");
  value.type_scripts.forEach((t,i)=>{shape(t,"type_hash,script_hex");const id=exact(t.type_hash,32),s=bytes(t.script_hex,512);scriptOccupied(s);
    requireValue(same(id,hash(s))&&same(id,typed[i]!.asset.type),"Factory Type script mismatch");types.set(t.type_hash,s);});
  for(const v of vaults)requireValue(same(v.lock,hash(vaultLock))&&v.value.reserve>=occupied(vaultLock,v.asset.kind===0?undefined:types.get(hex(v.asset.type))),"insufficient Factory Vault reserve or wrong lock");
  return {value,raw,manifest:man,vaults,points,statePoint,stateType,stateLock,vaultLock,carrier,types};
}
function custodySummary(v:Custody):FactoryCustodyInspection {
  return {factory_id:hex(v.raw.slice(36,68)),chain_id:hex(v.raw.slice(2,34)),update_number:unsigned(v.raw,68,8).toString(),state_out_point:v.value.state_out_point,
    content_root:hex(v.raw.slice(238,270)),outpoint_root:hex(v.raw.slice(270,302)),state_carrier_capacity:v.carrier.toString(),vault_count:v.vaults.length,
    assets:v.vaults.map(x=>({type_hash:x.asset.kind===0?null:hex(x.asset.type),reserve:x.value.reserve.toString(),business_ckb:x.value.business.toString(),amount:x.value.amount.toString()}))};
}
export function inspectFactoryCustody(value:FactoryCustody):FactoryCustodyInspection {return custodySummary(custody(value));}
function members(raw:Uint8Array,count:number):FactoryMember[] {
  requireValue(count>=2&&count<=16&&raw.length===count*65,"invalid Factory membership");const result:FactoryMember[]=[];const keys=new Set<string>();
  for(let i=0;i<count;i++){const entry=raw.slice(i*65,(i+1)*65),id=hex(entry.slice(0,32)),key=entry.slice(32);
    requireValue(!zero(entry.slice(0,32))&&validPublicKey(key)&&!keys.has(hex(key))&&(i===0||result[i-1]!.participant<id),"invalid Factory member order/key");
    result.push({participant:id,pubkey:hex(key)});keys.add(hex(key));}return result;
}
function membership(list:FactoryMember[]):Uint8Array {return domainHash("CKB_MORPH_FACTORY_PARTICIPANTS",Uint8Array.of(list.length,list.length),...list.map(m=>join(exact(m.participant,32),exact(m.pubkey,33))));}
function factorySignatures(raw:Uint8Array,unsignedOnly:boolean):{members:FactoryMember[];signatures:Uint8Array[]} {
  const count=raw[3] ?? 0;requireValue(u16(raw,0)===1&&raw[2]===count&&count>=2&&count<=16&&raw.length===4+count*129,"invalid Factory signature frame");
  const list=members(join(...Array.from({length:count},(_,i)=>raw.slice(4+i*129,69+i*129))),count);
  const sigs=Array.from({length:count},(_,i)=>raw.slice(69+i*129,133+i*129));
  requireValue(!unsignedOnly||sigs.every(zero),"hidden Factory parent signature");return {members:list,signatures:sigs};
}
const kinds:FactoryRightKind[]=["Balance","ReserveClaim","Membership","ExitPath","SponsorBudgetClaim"];
interface Right {dto:FactoryRight;raw:Uint8Array;id:string;key:Uint8Array;leaf:Uint8Array}
function right(raw:Uint8Array):Right {
  requireValue(raw.length===114&&(raw[64]??9)<=4&&(raw[65]===0||raw[65]===1)&&(raw[65]===1||zero(raw.slice(66,98))),"invalid Factory right");
  const id=raw.slice(0,98),key=domainHash("CKB_MORPH_FACTORY_RIGHT_KEY",id),leaf=domainHash("CKB_MORPH_FACTORY_RIGHT_LEAF",key,raw);
  return {raw,id:hex(id),key,leaf,dto:{participant:hex(raw.slice(0,32)),subchannel:hex(raw.slice(32,64)),kind:kinds[raw[64]!]!,asset_type:raw[65]===0?null:hex(raw.slice(66,98)),quantity:unsigned(raw,98,16).toString()}};
}
function publicRight(value:FactoryRight):Right {
  shape(value,"participant,subchannel,kind,asset_type,quantity");const kind=kinds.indexOf(value.kind);requireValue(kind>=0,"unknown Factory right kind");
  requireValue(value.asset_type===null||typeof value.asset_type==="string","required nullable Factory asset");
  const type=value.asset_type===null?new Uint8Array(32):exact(value.asset_type,32);
  requireValue(value.asset_type===null||!zero(type),"zero Factory Type");
  return right(join(exact(value.participant,32),exact(value.subchannel,32),Uint8Array.of(kind,value.asset_type===null?0:1),type,little(decimal(value.quantity,MAX_U128),16)));
}
function node(depth:number,left:Uint8Array,right:Uint8Array):Uint8Array {return domainHash("CKB_MORPH_FACTORY_RIGHT_NODE",little(depth,2),left,right);}
let emptyHashes:Uint8Array[]|undefined;
function empties():Uint8Array[] {if(emptyHashes===undefined){emptyHashes=[domainHash("CKB_MORPH_FACTORY_RIGHT_EMPTY")];for(let height=1;height<=256;height++)emptyHashes.push(node(256-height,emptyHashes[height-1]!,emptyHashes[height-1]!));}return emptyHashes;}
function bit(key:Uint8Array,depth:number):boolean{return (key[Math.floor(depth/8)]!&(0x80>>(depth%8)))!==0;}
function rightsRoot(rights:Right[]):Uint8Array {
  const sorted=[...rights].sort((a,b)=>hex(a.key).localeCompare(hex(b.key))),empty=empties();
  function subtree(entries:Right[],depth:number):Uint8Array {if(entries.length===0)return empty[256-depth]!;if(depth===256){requireValue(entries.length===1,"duplicate Factory Merkle key");return entries[0]!.leaf;}
    const split=entries.findIndex(e=>bit(e.key,depth));const at=split<0?entries.length:split;return node(depth,subtree(entries.slice(0,at),depth+1),subtree(entries.slice(at),depth+1));}
  return subtree(sorted,0);
}
class Cursor {offset=0;constructor(readonly raw:Uint8Array){} take(n:number):Uint8Array {requireValue(Number.isInteger(n)&&n>=0&&this.offset+n<=this.raw.length,"truncated Factory frame");const out=this.raw.slice(this.offset,this.offset+n);this.offset+=n;return out;} done():void{requireValue(this.offset===this.raw.length,"extra Factory frame bytes");}}
interface Child {index:number;carrier:string;header:Uint8Array;witness:Uint8Array;keys:[string,string];summary?:MultiAssetPackageSummary}
interface Intent {raw:Uint8Array;source:Uint8Array;points:Uint8Array;retained:Uint8Array|undefined;children:Child[];digest:Uint8Array}
function intent(raw:Uint8Array):Intent {
  requireValue(raw.length>=204&&u16(raw,0)===1&&u16(raw,2)>=1&&u16(raw,2)<=4&&u16(raw,202)===0&&u32(raw,168)<=780&&u32(raw,172)<=780
    &&u32(raw,192)<=512&&u32(raw,196)===117&&u16(raw,200)<=8,"invalid Factory child intent");
  const c=new Cursor(raw);c.take(204);const source=c.take(u32(raw,168)),vaults=manifest(source),points=c.take(vaults.length*36);
  pointsRoot(source,vaults.length,points);const retained=u32(raw,172)===0?undefined:c.take(u32(raw,172));if(retained!==undefined)manifest(retained);
  const refund=c.take(u32(raw,192));if(refund.length>0)scriptOccupied(refund);scriptOccupied(c.take(117));
  let previous="";for(let i=0;i<u16(raw,200);i++){const s=c.take(u32(c.take(4),0));scriptOccupied(s);requireValue(hex(hash(s))>previous,"unordered Factory child Type scripts");previous=hex(hash(s));}
  const children:Child[]=[];for(let i=0;i<u16(raw,2);i++){const prefix=c.take(334),witness=c.take(u32(prefix,330));requireValue(witness.length<=32*1024,"Factory child witness bound");children.push({index:u32(prefix,0),carrier:unsigned(prefix,4,8).toString(),header:prefix.slice(12,330),witness,keys:["",""]});}
  c.done();return {raw,source,points,retained,children,digest:domainHash("CKB_MORPH_FACTORY_MULTI_ASSET_MATERIALISATION_V1",raw)};
}
function childKeys(view:Intent,raw:Uint8Array):void {
  requireValue(raw.length===view.children.length*66,"incomplete Factory child keys");view.children.forEach((child,i)=>{
    child.keys=[hex(raw.slice(i*66,i*66+33)),hex(raw.slice(i*66+33,(i+1)*66))];
    child.summary=inspectMultiAssetPublicExitTerms(hex(child.header),hex(child.witness),child.carrier,child.keys);
  });
}
interface Frame {members:FactoryMember[];required:FactoryMember[];signatures:Uint8Array[];digest:Uint8Array;kind:number;intent?:Intent;before?:Uint8Array;after?:Uint8Array;source:Uint8Array;retained?:Uint8Array|undefined;points:Uint8Array;oldPoint?:Uint8Array;txHash?:Uint8Array;payouts:Array<{index:number;lock:Uint8Array;type:string|null;capacity:bigint;amount:bigint}>}
function compact(c:Cursor,r:Right):Map<number,Uint8Array> {
  const count=u16(c.take(2),0);requireValue(count<=64,"Factory proof bound");const proof=new Map<number,Uint8Array>();let previous=256;
  for(let i=0;i<count;i++){const depth=u16(c.take(2),0),sibling=c.take(32);requireValue(depth<previous,"noncanonical Factory proof depth");proof.set(depth,sibling);previous=depth;}
  // Reconstruct the root using the same depth-numbered canonical empty chain.
  let current=r.leaf;const empty=empties();for(let depth=255;depth>=0;depth--){const sibling=proof.get(depth)??empty[255-depth]!;current=bit(r.key,depth)?node(depth,sibling,current):node(depth,current,sibling);}
  proof.set(256,current);return proof;
}
function frame(raw:Uint8Array,unsignedOnly:boolean):Frame {
  requireValue(raw.length>=24&&raw.length<=MAX_TRANSACTION_BYTES,"Factory frame bound");const magic=new TextDecoder().decode(raw.slice(0,8));
  if(magic==="MORPHFS!"){
    requireValue(u16(raw,8)===2&&u16(raw,10)===0&&(u16(raw,12)===1||u16(raw,12)===3)&&u16(raw,14)<=8&&u32(raw,16)<=780&&u32(raw,20)<=2068,"invalid Factory State frame");
    const c=new Cursor(raw);c.take(24);const source=c.take(u32(raw,16)),vaults=manifest(source),points=c.take(u16(raw,14)*36),auth=factorySignatures(c.take(u32(raw,20)),unsignedOnly);c.done();
    requireValue(u16(raw,12)===1?points.length===0:points.length===vaults.length*36,"Factory State point count");
    return {...auth,required:auth.members,digest:new Uint8Array(),kind:u16(raw,12),source,retained:source,points,payouts:[]};
  }
  if(magic==="MORPHFM!"){
    requireValue(u16(raw,8)===1&&u16(raw,10)===0&&u16(raw,22)===0,"invalid Factory materialisation frame");
    const c=new Cursor(raw);c.take(24);const view=intent(c.take(u32(raw,12))),auth=factorySignatures(c.take(u32(raw,16)),unsignedOnly);
    requireValue(u16(raw,20)===view.children.length,"Factory child count mismatch");childKeys(view,c.take(view.children.length*66));c.done();
    return {...auth,required:auth.members,digest:view.digest,kind:10,intent:view,source:view.source,retained:view.retained,points:view.points,oldPoint:view.raw.slice(100,136),txHash:view.raw.slice(136,168),payouts:[]};
  }
  requireValue(magic==="MORPHFR!"&&raw.length>=788&&u16(raw,8)===1&&[0,1,2,4,5].includes(u16(raw,10))&&u16(raw,12)>=2&&u16(raw,12)<=16
    &&u16(raw,14)<u16(raw,12)&&u16(raw,16)<=10&&u16(raw,18)<=8&&u32(raw,20)<=780&&u32(raw,24)<=780&&u32(raw,28)===117&&u16(raw,32)<=16&&u16(raw,34)===0,"invalid Factory transition frame");
  const operation=u16(raw,10),count=u16(raw,12),touched=u16(raw,14),sigCount=operation===4?count:1,before=raw.slice(112,418),after=raw.slice(418,724);header(before);header(after);
  const signatures:Uint8Array[]=[raw.slice(724,788)];const c=new Cursor(raw);c.take(788);for(let i=1;i<sigCount;i++)signatures.push(c.take(64));const sigEnd=c.offset;
  requireValue(!unsignedOnly||signatures.every(zero),"hidden Factory parent signature");
  const list=members(c.take(count*65),count),source=c.take(u32(raw,20)),vaults=manifest(source),points=c.take(vaults.length*36),retained=c.take(u32(raw,24)),next=manifest(retained),lock=c.take(117);scriptOccupied(lock);
  let previous="";for(let i=0;i<u16(raw,32);i++){const s=c.take(u32(c.take(4),0));scriptOccupied(s);requireValue(hex(hash(s))>previous,"unordered Factory transition Type scripts");previous=hex(hash(s));}
  const payouts:Frame["payouts"]=[];previous="";for(let i=0;i<u16(raw,18);i++){const p=c.take(69),id=asset(p,0),value=allocation(p,33,id,false),lock=c.take(u16(p,65));scriptOccupied(lock);
    requireValue(id.key>previous&&value.capacity>0n,"unordered Factory payouts");previous=id.key;payouts.push({index:u16(p,67),lock,type:id.kind===0?null:hex(id.type),capacity:value.capacity,amount:value.amount});}
  const changes:Array<{before:Right;after:Right;a:Map<number,Uint8Array>;b:Map<number,Uint8Array>}>=[];previous="";
  for(let i=0;i<u16(raw,16);i++){const a=right(c.take(114)),b=right(c.take(114));requireValue(a.id===b.id&&a.id>previous&&a.dto.participant===list[touched]!.participant,"unlisted/foreign Factory right change");previous=a.id;
    const pa=compact(c,a),pb=compact(c,b);requireValue(same(pa.get(256)!,before.slice(76,108))&&same(pb.get(256)!,after.slice(76,108)),"Factory sparse proof root mismatch");changes.push({before:a,after:b,a:pa,b:pb});}
  const localityEnd=c.offset;let view:Intent|undefined;if(operation===5){view=intent(c.take(u32(c.take(4),0)));childKeys(view,c.take(view.children.length*66));}c.done();
  const empty=empties();for(const changed of changes)for(let depth=0;depth<256;depth++){
    if(same(changed.a.get(depth)??empty[255-depth]!,changed.b.get(depth)??empty[255-depth]!))continue;
    requireValue(changes.some(other=>other!==changed&&Array.from({length:depth},(_,d)=>bit(other.before.key,d)===bit(changed.before.key,d)).every(Boolean)
      &&bit(other.before.key,depth)!==bit(changed.before.key,depth)),"unlisted Factory sibling change");
  }
  requireValue(identity(before,after)&&unsigned(after,68,8)===unsigned(before,68,8)+1n&&!zero(before.slice(270,302))
    &&same(before.slice(238,270),content(source))&&same(before.slice(270,302),pointsRoot(source,vaults.length,points))&&u16(before,302)===vaults.length
    &&same(after.slice(238,270),content(retained))&&u16(after,302)===next.length&&same(before.slice(108,140),membership(list))
    &&same(after.slice(172,204),domainHash("CKB_MORPH_FACTORY_REDUCED_RELEASE_LOCALITY_V1",raw.slice(0,72),raw.slice(104,590),raw.slice(622,724),raw.slice(sigEnd,localityEnd)))
    &&(operation===4||same(before.slice(140,172),after.slice(140,172)))&&same(hash(lock),vaults[0]!.lock)&&same(vaults[0]!.lock,next[0]!.lock),"Factory transition context mismatch");
  requireValue(operation===1?same(before.slice(238),after.slice(238))&&same(source,retained):zero(after.slice(270,302)),"Factory custody phase mismatch");
  requireValue(operation===4?changes.length===0&&touched===0:changes.length>0,"Factory authority/right count mismatch");
  const result:Frame={members:list,required:operation===4?list:[list[touched]!],signatures,digest:domainHash("CKB_MORPH_FACTORY_REDUCED_RELEASE_V1",raw.slice(0,724),raw.slice(sigEnd)),kind:20+operation,
    before,after,source,retained,points,oldPoint:raw.slice(36,72),txHash:raw.slice(72,104),payouts};if(view!==undefined)result.intent=view;return result;
}
function verifySignature(signature:Uint8Array,digest:Uint8Array,key:Uint8Array):void {
  requireValue(signature.length===64&&validPublicKey(key)&&secp256k1.verify(signature,digest,key,{prehash:false,format:"compact",lowS:true}),"invalid Factory signature");
}
function output(tx:RawTransactionEvidence,index:number,lock:Uint8Array,type:Uint8Array|undefined,capacity:bigint,data:Uint8Array):void {
  const actual=tx.outputs[index];requireValue(actual!==undefined&&same(actual.lock,lock)&&actual.capacity===capacity&&same(actual.data,data)
    &&(type===undefined?actual.type===undefined:actual.type!==undefined&&same(actual.type,type)),"Factory exact output mismatch");
}
function targetVaults(tx:RawTransactionEvidence,target:Custody):void {
  target.vaults.forEach((v,i)=>{
    requireValue(same(target.points.slice(i*36,(i+1)*36),join(hash(tx.raw),little(i+1,4))),"Factory target OutPoint mismatch");
    output(tx,i+1,target.vaultLock,v.asset.kind===0?undefined:target.types.get(hex(v.asset.type)),v.value.capacity,v.asset.kind===0?new Uint8Array():little(v.value.amount,16));
  });
}
function validateRights(value:FactoryRight[],target:Custody|null,list:FactoryMember[]):void {
  requireValue(Array.isArray(value)&&value.length<=512,"Factory rights snapshot bound");
  if(target===null){requireValue(value.length===0,"closed Factory retains rights");return;}
  const rights=value.map(publicRight);let previous="";const claims=new Map<string,bigint>();
  const backing=new Map<string,bigint>([["ckb",target.vaults.reduce((sum,v)=>sum+v.value.capacity,0n)]]);
  for(const v of target.vaults)if(v.asset.kind===1)backing.set(hex(v.asset.type),v.value.amount);
  for(const r of rights){requireValue(r.id>previous&&list.some(m=>m.participant===r.dto.participant),"unordered or foreign Factory target rights");previous=r.id;
    if(["Balance","ReserveClaim","SponsorBudgetClaim"].includes(r.dto.kind)){
      const id=r.dto.asset_type??"ckb",sum=(claims.get(id)??0n)+BigInt(r.dto.quantity);requireValue(sum<=MAX_U128&&sum<=(backing.get(id)??0n),"unbacked Factory value rights");claims.set(id,sum);
    }
  }
  requireValue(same(rightsRoot(rights),target.raw.slice(76,108)),"Factory complete rights root mismatch");
}
interface RequestEvidence {summary:FactoryRequestInspection;frame:Frame;transaction:RawTransactionEvidence;digest:Uint8Array}
function requestEvidence(value:FactoryRequest):RequestEvidence {
  shape(value,"schema,role,source,target,raw_transaction_hex,witness_hex,target_rights,deliveries");
  requireValue(value.schema==="morph.factory_request.v1"&&["root_funding","metadata_update","materialisation","transition"].includes(value.role),"unsupported Factory request schema/role");
  requireValue(value.source===null||typeof value.source==="object","required nullable Factory source");
  requireValue(value.target===null||typeof value.target==="object","required nullable Factory target");
  const source=value.source===null?null:custody(value.source),target=value.target===null?null:custody(value.target);
  const raw=bytes(value.raw_transaction_hex,MAX_TRANSACTION_BYTES),tx=rawTransactionEvidence(raw),txHash=hash(raw),witness=bytes(value.witness_hex,MAX_TRANSACTION_BYTES),view=frame(witness,true),commitment=membership(view.members);
  for(const current of [source,target])if(current!==null)requireValue(same(current.raw.slice(108,140),commitment),"Factory membership commitment mismatch");
  if(target!==null)requireValue(same(target.statePoint,join(txHash,little(0,4))),"Factory target State OutPoint mismatch");
  if(source!==null&&target!==null)requireValue(identity(source.raw,target.raw)&&same(source.stateType,target.stateType)&&same(source.stateLock,target.stateLock)&&same(source.vaultLock,target.vaultLock)
    &&unsigned(target.raw,68,8)>unsigned(source.raw,68,8),"Factory source/target identity or progress mismatch");
  validateRights(value.target_rights,target,view.members);
  let digest:Uint8Array;let requiresActivation:boolean;
  const bodyHeader=tx.outputs[0]!.data;
  if(value.role==="root_funding"||value.role==="metadata_update"){
    requireValue(target!==null&&view.kind===(value.role==="root_funding"?1:3),"Factory role/frame mismatch");header(bodyHeader);
    requireValue(same(view.source,target.manifest)&&same(content(view.source),bodyHeader.slice(238,270))&&same(bodyHeader.slice(108,140),commitment),"Factory State frame context mismatch");
    if(value.role==="root_funding"){
      requireValue(source===null&&unsigned(bodyHeader,68,8)===0n&&activation(bodyHeader,target.raw)
        &&same(hash(tx.inputs[0]!,little(0,8)),bodyHeader.slice(36,68)),"Factory root creation mismatch");
      digest=domainHash("CKB_MORPH_FACTORY_MULTI_ASSET_ROOT_FUNDING_V1",domainHash("CKB_MORPH_FACTORY_MULTI_ASSET_STATE_V1",bodyHeader),txHash);requiresActivation=true;targetVaults(tx,target);
    }else{
      requireValue(source!==null&&same(bodyHeader,target.raw)&&same(source.manifest,target.manifest)&&same(source.points,target.points)&&source.carrier===target.carrier
        &&same(view.points,target.points)&&same(tx.inputs[0]!.slice(8),source.statePoint)&&tx.inputs.every(input=>!source.value.vault_outpoints.some(p=>same(point(p),input.slice(8)))),"Factory metadata custody mismatch");
      digest=domainHash("CKB_MORPH_FACTORY_MULTI_ASSET_UPDATE_V1",domainHash("CKB_MORPH_FACTORY_MULTI_ASSET_STATE_V1",target.raw),txHash);requiresActivation=false;
    }
    output(tx,0,target.stateLock,target.stateType,target.carrier,bodyHeader);
  }else{
    requireValue(source!==null&&(value.role==="materialisation"?view.kind===10:view.kind>=20),"Factory role/frame mismatch");
    requireValue(view.txHash!==undefined&&same(view.txHash,txHash)&&view.oldPoint!==undefined&&same(view.oldPoint,source.statePoint)
      &&same(tx.inputs[0]!.slice(8),source.statePoint)&&same(view.source,source.manifest)&&same(view.points,source.points),"Factory exact source/transaction mismatch");
    if(view.before!==undefined)requireValue(same(view.before,source.raw),"Factory before header mismatch");
    if(target===null)requireValue(view.retained===undefined,"Factory retained custody requires a target");
    else requireValue(view.retained!==undefined&&same(view.retained,target.manifest),"Factory retained manifest mismatch");
    requiresActivation=value.role==="materialisation"?target!==null:view.kind!==21;
    if(target!==null){requireValue(requiresActivation?activation(bodyHeader,target.raw):same(bodyHeader,target.raw),"Factory successor header mismatch");
      if(view.after!==undefined)requireValue(same(bodyHeader,view.after),"Factory transition after header mismatch");
      output(tx,0,target.stateLock,target.stateType,target.carrier,bodyHeader);if(requiresActivation)targetVaults(tx,target);}
    if(requiresActivation||target===null)source.value.vault_outpoints.forEach((p,i)=>requireValue(tx.inputs[i+1]!==undefined&&same(tx.inputs[i+1]!.slice(8),point(p)),"Factory source Vault input mismatch"));
    else requireValue(tx.inputs.every(input=>!source.value.vault_outpoints.some(p=>same(point(p),input.slice(8)))),"rights-only Factory request consumes custody");
    for(const payout of view.payouts)output(tx,payout.index,payout.lock,payout.type===null?undefined:source.types.get(payout.type)??target?.types.get(payout.type),payout.capacity,payout.type===null?new Uint8Array():little(payout.amount,16));
    digest=view.digest;
  }
  const children=view.intent?.children??[];
  for(const child of children){
    const parts=child.witness,c=new Cursor(parts);c.take(28);const man=c.take(u32(parts,12)),vaults=manifest(man),descriptorLen=u32(parts,16);c.take(descriptorLen);const points=c.take(u16(parts,20)*36);
    const scripts:Uint8Array[]=[];while(c.offset<parts.length)scripts.push(c.take(u32(c.take(4),0)));
    const creation=child.header.slice();creation.fill(0,108,116);creation[117]=1;creation.fill(0,282,314);
    output(tx,child.index,scripts[5]!,scripts[4]!,decimal(child.carrier),creation);
    vaults.forEach((v,i)=>{requireValue(same(points.slice(i*36,(i+1)*36),join(txHash,little(child.index+i+1,4))),"Factory child Vault OutPoint mismatch");
      const typed=v.asset.kind===0?undefined:scripts.slice(6).find(s=>same(hash(s),v.asset.type));output(tx,child.index+i+1,scripts[3]!,typed,v.value.capacity,v.asset.kind===0?new Uint8Array():little(v.value.amount,16));});
  }
  requireValue(Array.isArray(value.deliveries)&&value.deliveries.length<=8,"Factory delivery bound");const delivered=new Set<string>();
  for(const receipt of value.deliveries){shape(receipt,"child_index,pubkey,signature");requireValue(Number.isInteger(receipt.child_index)&&receipt.child_index>=0&&receipt.child_index<children.length,"invalid Factory delivery child");
    const child=children[receipt.child_index]!,key=exact(receipt.pubkey,33);requireValue(child.keys.includes(receipt.pubkey),"delivery key does not own child");
    const id=`${receipt.child_index}:${receipt.pubkey}`;requireValue(!delivered.has(id),"duplicate Factory delivery");delivered.add(id);
    const deliveryDigest=domainHash("CKB_MORPH_FACTORY_CHILD_DELIVERY_V1",txHash,view.intent!.digest,little(receipt.child_index,2),domainHash("CKB_MORPH_MULTI_ASSET_STATE_V1",child.header),key);
    verifySignature(exact(receipt.signature,64),deliveryDigest,key);
  }
  const missing=children.flatMap((child,child_index)=>child.keys.filter(key=>!delivered.has(`${child_index}:${key}`)).map(pubkey=>({child_index,pubkey})));
  const roleTag=["root_funding","metadata_update","materialisation","transition"].indexOf(value.role);
  const requestId=domainHash("CKB_MORPH_FACTORY_SIGNING_REQUEST_V1",Uint8Array.of(roleTag),txHash,hash(witness));
  const summary:FactoryRequestInspection={schema:"morph.factory_request_summary.v1",stage:"offline_review",request_id:hex(requestId),signing_digest:hex(digest),role:value.role,
    transaction_hash:hex(txHash),raw_transaction_bytes:raw.length,witness_bytes:witness.length,source:source===null?null:custodySummary(source),target:target===null?null:custodySummary(target),
    members:view.members,required_members:view.required,requires_activation:requiresActivation,target_rights:value.target_rights,delivery_count:value.deliveries.length,missing_deliveries:missing,
    children:children.map((child,child_index)=>({child_index,state_output_index:child.index,initial_exit:child.summary!})),validation_scope:"public_terms_and_signatures",
    constraints:{canonical_source:"native_check_required",approved_dependencies:"native_check_required",vm_preflight:"native_check_required",monotonic_signer_reservation:"required_before_key_use",factory_transition_semantics:"native_core_check_required"}};
  return {summary,frame:view,transaction:tx,digest};
}
export function inspectFactoryRequest(value:FactoryRequest):FactoryRequestInspection {return requestEvidence(value).summary;}
/** A detached parent receipt is accepted only after complete child delivery.
 * This verifies evidence; the SDK does not reserve or invoke a signer. */
export function inspectFactorySignature(value:FactoryRequest,receipt:FactorySignatureReceipt):{participant:string;pubkey:string;request_id:string;signing_digest:string} {
  const evidence=requestEvidence(value);requireValue(evidence.summary.missing_deliveries.length===0,"missing child delivery attestations");
  shape(receipt,"schema,request_id,signing_digest,participant,pubkey,signature");requireValue(receipt.schema==="morph.factory_signature.v1"&&receipt.request_id===evidence.summary.request_id
    &&receipt.signing_digest===evidence.summary.signing_digest&&evidence.frame.required.some(member=>member.participant===receipt.participant&&member.pubkey===receipt.pubkey),"Factory receipt exact request/role/member mismatch");
  verifySignature(exact(receipt.signature,64),evidence.digest,exact(receipt.pubkey,33));
  return {participant:receipt.participant,pubkey:receipt.pubkey,request_id:receipt.request_id,signing_digest:receipt.signing_digest};
}
export interface FactoryTransitionPackage {schema:"morph.factory_transition_package.v1";transaction_hex:string}
export function inspectFactoryTransitionPackage(value:FactoryTransitionPackage):{operation:string;transaction_hash:string;signing_digest:string;members:FactoryMember[];required_members:FactoryMember[];validation_scope:"public_terms_and_signatures"} {
  shape(value,"schema,transaction_hex");requireValue(value.schema==="morph.factory_transition_package.v1","unsupported Factory transition schema");
  const [raw,witnessVector]=table(bytes(value.transaction_hex,MAX_TRANSACTION_BYTES),2),tx=rawTransactionEvidence(raw!),witnesses=dynamic(witnessVector!,64).map(byteVector);
  requireValue(witnesses.length>0,"missing Factory transition witness");const fields=table(witnesses[0]!,3);
  requireValue(fields[0]!.length===0&&fields[1]!.length===0,"unexpected Factory witness authority fields");
  const view=frame(byteVector(fields[2]!),false);requireValue(view.kind>=20&&view.txHash!==undefined&&same(view.txHash,hash(tx.raw))&&same(view.oldPoint!,tx.inputs[0]!.slice(8)),"Factory transition exact body mismatch");
  view.required.forEach((member,i)=>verifySignature(view.signatures[i]!,view.digest,exact(member.pubkey,33)));
  return {operation:({20:"ReducedRelease",21:"ReducedRights",22:"ReducedDeposit",24:"FullCustody",25:"ReducedChild"} as Record<number,string>)[view.kind]!,transaction_hash:hex(hash(tx.raw)),signing_digest:hex(view.digest),members:view.members,required_members:view.required,validation_scope:"public_terms_and_signatures"};
}
