import {useEffect, useRef, useState} from 'react';
import {Button} from '@heroui/button';
import {Modal, ModalContent, ModalHeader, ModalBody, ModalFooter} from '@heroui/modal';
import {Select, SelectItem} from '@heroui/select';
import Network from '@/api/network';

export default function NodeModeSwitch({node,onComplete}:{node:{id:number;name:string;forwardingMode?:string};onComplete:()=>void}) {
 const [open,setOpen]=useState(false);
 const pendingId=useRef<string|null>(null);
 function acceptJob(value:any){
  setJob(value);
  if(['queued','running','pending'].includes(value?.status))pendingId.current=value.id||pendingId.current;
  if(value?.status==='succeeded'&&pendingId.current===value.id){pendingId.current=null;onComplete();}
  if(['failed','blocked'].includes(value?.status))pendingId.current=null;
 }
 const [target,setTarget]=useState('gost');
 const [supported,setSupported]=useState(false);
 const [job,setJob]=useState<any>(null);
 const [message,setMessage]=useState('');
 const [loading,setLoading]=useState(false);
 const busy=job&&['queued','running','pending'].includes(job.status);
 const names:Record<string,string>={idle:'暂无任务',queued:'已排队',pending:'等待节点确认',running:'正在切换',succeeded:'切换完成',failed:'切换失败，原模式保留',blocked:'切换异常，转发保持关闭，需恢复'};
 async function status(){
  const r=await Network.post('/engine/mode-switch-status',{nodeId:node.id});
  if(r.code===0){acceptJob(r.data);}else setMessage(r.msg||'无法读取切换状态');
 }
 useEffect(()=>{if(!open)return;let active=true;
  setMessage('');setTarget((node.forwardingMode||'kernel')==='kernel'?'gost':'kernel');
  Network.post('/engine/capabilities',{nodeId:node.id}).then(r=>{if(!active)return;setSupported(r.code===0&&!!r.data?.capabilities?.features?.engineSwitch);if(r.code!==0||!r.data?.capabilities?.features?.engineSwitch)setMessage('当前节点未启用统一 Agent / 受管 GOST，请先升级节点安装包。');}).catch(()=>{if(active)setMessage('无法获取节点能力');});
  status().catch(()=>setMessage('无法读取切换状态'));return()=>{active=false};
 },[open,node.id]);
 useEffect(()=>{if(!open||!busy)return;const timer=setInterval(()=>status().catch(()=>setMessage('连接暂不可用，继续确认原任务；不要重复创建任务。')),1500);return()=>clearInterval(timer)},[open,busy,node.id]);
 async function submit(){setLoading(true);setMessage('');try{
  const id=crypto.randomUUID();pendingId.current=id;setJob({id,status:'pending'});
  const r=await Network.post('/engine/switch-mode',{nodeId:node.id,id,mode:target});
  if(r.code===0)acceptJob(r.data);else{pendingId.current=null;setJob(null);setMessage(r.msg||'切换请求失败');}
 }catch{setMessage('请求结果未确认，正在查询；关闭窗口不会取消节点上的任务。');}finally{setLoading(false)}}
 return <><Button size="sm" variant="flat" onPress={()=>setOpen(true)}>切换转发模式</Button>
 <Modal isOpen={open} onClose={()=>setOpen(false)}><ModalContent><ModalHeader>{node.name}：切换转发模式</ModalHeader><ModalBody>
  <p>当前配置：{node.forwardingMode==='gost'?'受管 GOST':'原生 nftables'}。节点身份和历史流量保留。</p>
  <p className="text-warning">切换会短暂停流并中断现有 TCP/UDP 连接，客户端需要重连；不做连接排空。不兼容的规则会在切换前拒绝，失败将尝试恢复原模式。</p>
  <Select label="目标模式" selectedKeys={[target]} disallowEmptySelection isDisabled={!!busy||loading} onSelectionChange={keys=>setTarget(String(Array.from(keys)[0]))}>
   <SelectItem key="kernel">原生 nftables</SelectItem><SelectItem key="gost">受管 GOST</SelectItem>
  </Select>
  {job&&<p>{names[job.status]||job.status}{job.error?`：${job.error}`:''}</p>}
  {message&&<p className="text-warning">{message}</p>}
 </ModalBody><ModalFooter><Button variant="flat" onPress={()=>setOpen(false)}>关闭</Button><Button color="primary" isLoading={loading} isDisabled={!supported||!!busy||job?.status==='blocked'||target===(node.forwardingMode||'kernel')} onPress={submit}>暂停并切换</Button></ModalFooter></ModalContent></Modal></>
}
