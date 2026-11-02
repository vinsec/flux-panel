import {useEffect, useRef, useState} from 'react';
import {Button} from '@heroui/button';
import {Select, SelectItem} from '@heroui/select';
import Network from '@/api/network';

interface SwitchNode {
 id:number;
 name:string;
 engine?:string;
 forwardingMode?:string;
 connectionStatus?:string;
}

export default function NodeModeSwitch({node,onComplete,onBusyChange}:{node:SwitchNode;onComplete:(mode:string)=>void;onBusyChange?:(busy:boolean)=>void}) {
 const pendingId=useRef<string|null>(null);
 const generation=useRef(0);
 const [current,setCurrent]=useState(node.forwardingMode||'kernel');
 const [target,setTarget]=useState(node.forwardingMode||'kernel');
 const [supported,setSupported]=useState(false);
 const [checking,setChecking]=useState(true);
 const [statusReady,setStatusReady]=useState(false);
 const [reason,setReason]=useState('正在检查切换条件');
 const [job,setJob]=useState<any>(null);
 const [message,setMessage]=useState('');
 const [loading,setLoading]=useState(false);
 const busy=!!job&&['queued','running','pending'].includes(job.status);
 const legacy=node.engine!=='kernel';
 const offline=node.connectionStatus!=='online';
 const names:Record<string,string>={queued:'已排队',pending:'等待节点确认',running:'正在切换',succeeded:'切换完成',failed:'切换失败，原模式保留',blocked:'切换异常，请先恢复节点'};
 function acceptJob(value:any) {
  setJob(value);
  if(['queued','running','pending'].includes(value?.status))pendingId.current=value.id||pendingId.current;
  if(value?.status==='succeeded'&&pendingId.current===value.id){
   pendingId.current=null;
   const mode=value.to||target;
   setCurrent(mode);setTarget(mode);onComplete(mode);
  }
  if(['failed','blocked'].includes(value?.status))pendingId.current=null;
 }
 async function status() {
  const request=generation.current;
  const r=await Network.post('/engine/mode-switch-status',{nodeId:node.id});
  if(request!==generation.current)return;
  setStatusReady(r.code===0);
  if(r.code===0)acceptJob(r.data);else setMessage(r.msg||'无法读取切换状态');
 }
 useEffect(()=>{
  const request=++generation.current;
  pendingId.current=null;setJob(null);setMessage('');setSupported(false);setStatusReady(false);
  const mode=node.engine==='kernel'?(node.forwardingMode||'kernel'):'gost';
  setCurrent(mode);setTarget(mode);
  if(legacy||offline){setChecking(false);setReason(legacy?'旧 GOST 节点需先升级为统一 Agent':'节点离线，暂不能切换');return;}
  setChecking(true);setReason('正在检查切换条件');
  Network.post('/engine/capabilities',{nodeId:node.id}).then(r=>{
   if(request!==generation.current)return;
   const info=r.data;
   const disabled=r.code!==0?(r.msg||'无法获取节点能力')
    :!info?.capabilities?.features?.engineSwitch?'当前 Agent 不支持切换，请先升级节点'
    :info.blocked||info.accountingBlocked?'节点转发或账本受阻，请先恢复'
    :info.maintenancePending?'节点正在维护，暂不能切换':'';
   setSupported(!disabled);setReason(disabled);
   if(info?.forwardingMode){setCurrent(info.forwardingMode);setTarget(info.forwardingMode);}
  }).catch(()=>{if(request===generation.current)setReason('无法获取节点能力，请重新打开编辑窗口');})
    .finally(()=>{if(request===generation.current)setChecking(false);});
  status().catch(()=>{if(request===generation.current)setMessage('无法读取切换状态');});
  return()=>{generation.current++;};
 },[node.id,node.engine,node.connectionStatus]);
 useEffect(()=>{
  onBusyChange?.(busy||loading);
  return()=>onBusyChange?.(false);
 },[busy,loading,onBusyChange]);
 useEffect(()=>{
  if(!busy)return;
  const timer=setInterval(()=>status().catch(()=>setMessage('连接暂不可用，正在确认原任务')),1500);
  return()=>clearInterval(timer);
 },[busy,node.id]);
 async function submit(){
  if(!supported||!statusReady||offline||legacy||busy||loading||job?.status==='blocked'||target===current)return;
  const request=generation.current;
  setLoading(true);setMessage('');
  try{
   const id=crypto.randomUUID();pendingId.current=id;setJob({id,status:'pending'});
   const r=await Network.post('/engine/switch-mode',{nodeId:node.id,id,mode:target});
   if(request!==generation.current)return;
   if(r.code===0)acceptJob(r.data);
   else{pendingId.current=null;setJob(null);setMessage(r.msg||'切换请求失败');}
  }catch{if(request===generation.current)setMessage('请求结果未确认，正在查询；关闭窗口不会取消任务');}
  finally{if(request===generation.current)setLoading(false);}
 }
 const disabledReason=legacy?'旧 GOST 节点需先升级为统一 Agent':offline?'节点离线，暂不能切换':checking?'正在检查切换条件':job?.status==='blocked'?'节点切换异常，请先恢复':busy?'正在切换，请稍候':reason||(!statusReady?'无法确认切换状态，暂不能切换':'');
 const unavailable=legacy||offline||checking||!supported||!statusReady||busy||loading||job?.status==='blocked';
 return <section className="space-y-2">
  <div className="flex items-start gap-2">
   <Select label="转发模式" selectedKeys={[target]} disallowEmptySelection isDisabled={!!unavailable} onSelectionChange={keys=>setTarget(String(Array.from(keys)[0]))}>
    <SelectItem key="kernel">原生 nftables</SelectItem><SelectItem key="gost">{legacy?'独立 GOST':'受管 GOST'}</SelectItem>
   </Select>
   <Button className="mt-2 shrink-0" color="primary" isLoading={loading} isDisabled={!!unavailable||target===current} onPress={submit}>切换</Button>
  </div>
  {disabledReason?<p className="text-xs text-warning">{disabledReason}</p>:target!==current&&<p className="text-xs text-warning">切换会短暂中断连接，客户端需要重连。</p>}
  {job&&job.status!=='idle'&&<p className="text-xs">{names[job.status]||job.status}{job.error?`：${job.error}`:''}</p>}
  {message&&<p className="text-xs text-warning">{message}</p>}
 </section>;
}
