import {useEffect,useState} from 'react';
import {Modal,ModalContent,ModalHeader,ModalBody,ModalFooter} from '@heroui/modal';
import {Button} from '@heroui/button';
import {Input} from '@heroui/input';
import {Select,SelectItem} from '@heroui/select';
import {Chip} from '@heroui/chip';
import {getBandwidthGroups,setBandwidthGroup} from '@/api';
import Network from '@/api/network';
import toast from 'react-hot-toast';

export default function NodeEngineTools({node,onClose}:{node:{id:number;name:string;version?:string}|null;onClose:()=>void}){
 const [caps,setCaps]=useState<any>(null),[groups,setGroups]=useState<any[]>([]),[scope,setScope]=useState('user'),[owner,setOwner]=useState(''),[up,setUp]=useState('0'),[down,setDown]=useState('0'),[busy,setBusy]=useState(false),[step,setStep]=useState(0);
 const refresh=async()=>{if(!node)return;try{const [cap,group]=await Promise.all([Network.post('/engine/capabilities',{nodeId:node.id}),getBandwidthGroups({nodeId:node.id})]);if(cap.code===0)setCaps(cap.data);else{setCaps(null);toast.error('节点实时状态不可用')}if(group.code===0)setGroups(group.data||[]);}catch{toast.error('节点工具状态不可用')}};
 useEffect(()=>{setStep(0);setCaps(null);setGroups([]);if(node)refresh()},[node?.id]);
 const save=async()=>{if(!node)return;setBusy(true);try{const result=await setBandwidthGroup({nodeId:node.id,scope,ownerId:Number(owner),upBitsPerSecond:Math.round(Number(up)*1000000),downBitsPerSecond:Math.round(Number(down)*1000000)});if(result.code!==0)throw new Error(result.msg);toast.success('共享上限已保存，节点正在对账');await refresh()}catch(error){toast.error(error instanceof Error?error.message:'保存失败')}finally{setBusy(false)}};
 return <Modal isOpen={!!node} onOpenChange={open=>{if(!open)onClose()}} size="3xl" scrollBehavior="inside"><ModalContent><ModalHeader>{node?.name} · 引擎管理</ModalHeader><ModalBody>
  <div className="flex flex-wrap gap-2"><Chip size="sm">{caps?.capabilities?.agentVersion||node?.version||'版本不可用'}</Chip><Chip size="sm" color={caps?.privilegedHelper?'success':'warning'}>{caps?.privilegedHelper?'权限隔离已启用':'未确认权限隔离'}</Chip><Chip size="sm">计量：网络层字节</Chip></div>
  {caps?.capacity&&<p className="text-xs text-default-500">配置 {caps.capacity.configuredForwards}/{caps.capacity.forwardLimit} · 目标路径 {caps.capacity.resolvedPaths}/{caps.capacity.resolvedPathLimit} · 隔离 token {caps.capacity.quarantinedTokens} · 待回收计数 {caps.capacity.retiredCounters}</p>}
  <section className="space-y-3 border rounded-xl border-default-200 p-4"><h3 className="font-semibold">共享带宽组</h3><p className="text-xs text-default-500">用户组覆盖该用户在节点上的转发；授权组覆盖该用户在一个隧道内的转发。单转发上限不能放宽共享上限。</p>
   <div className="grid grid-cols-1 sm:grid-cols-2 gap-3"><Select label="范围" selectedKeys={[scope]} onSelectionChange={keys=>setScope(String(Array.from(keys)[0]))}><SelectItem key="user">用户总带宽</SelectItem><SelectItem key="userTunnel">用户隧道授权</SelectItem></Select><Input label={scope==='user'?'用户 ID':'授权记录 ID'} type="number" value={owner} onValueChange={setOwner}/><Input label="上传 Mbps（0 不另限）" type="number" value={up} onValueChange={setUp}/><Input label="下载 Mbps（0 不另限）" type="number" value={down} onValueChange={setDown}/></div>
   <Button color="primary" size="sm" isLoading={busy} isDisabled={!caps?.capabilities?.features?.shaping||!Number(owner)} onPress={save}>保存共享上限</Button>
   {groups.map(group=><div key={`${group.scope}:${group.ownerId}`} className="text-xs flex justify-between gap-2"><span>{group.scope==='user'?'用户':'授权'} #{group.ownerId}</span><span>↑{group.upBitsPerSecond/1000000} / ↓{group.downBitsPerSecond/1000000} Mbps</span></div>)}
  </section>
  <section className="space-y-3 border rounded-xl border-default-200 p-4"><h3 className="font-semibold">升级与回滚向导</h3><div className="flex flex-wrap gap-2">{['确认能力','备份与停流','校验安装','验证与恢复'].map((label,index)=><Button key={label} size="sm" variant={step===index?'solid':'flat'} onPress={()=>setStep(index)}>{index+1}. {label}</Button>)}</div>
   {step===0&&<div className="text-sm space-y-2"><p>先确认目标节点支持所需地址族、限速与路由能力。节点离线或缺少能力时，不开启对应表单项。</p><p>当前支持：{Object.entries(caps?.capabilities?.features||{}).filter(([,enabled])=>enabled).map(([name])=>({ipv4:'IPv4',ipv6:'IPv6',dns:'域名',shaping:'限速',interfaceRouting:'出口策略',multiTarget:'多目标',dynamicAddresses:'动态地址',runtimeStatus:'生效状态'}[name]||'')).filter(Boolean).join('、')||'未取得能力'}</p><Button size="sm" onPress={refresh}>重新检查</Button></div>}
   {step===1&&<div className="text-sm space-y-2"><p>选择维护窗口，先最终结算并备份。维护会暂停业务，回滚也保持暂停，避免未经确认恢复旧连接。</p><p>保留已验证的旧二进制、配置和账本备份。数据库脚本必须由部署计划显式执行；本向导不会自动修改数据库或远程主机。</p><code className="block whitespace-pre-wrap text-xs break-all">flux-agent --maintenance backup --config /etc/flux-agent/config.json --backup-dir /var/lib/flux-agent/backups/manual</code></div>}
   {step===2&&<div className="text-sm space-y-2"><p>使用固定版本和 SHA-256 的离线包或 HTTPS 发布地址。只有节点、面板和数据库迁移版本相互匹配，才开始安装。</p><p>安装器校验失败或启动未确认时应停止并回滚。节点安装命令入口仍会验证发布 pin，不使用浮动上游下载。</p></div>}
   {step===3&&<div className="text-sm space-y-2"><p>确认控制连接和统计回执均为本次启动产生，再检查期望/生效代次、目标解析和小流量 TCP/UDP。最后由管理员显式恢复暂停的转发。</p><p>指标异常时保留关闭状态；恢复备份时保留最新累计账本，不能用旧账本覆盖新流量。</p><Button size="sm" onPress={refresh}>刷新验收状态</Button><p>最近回执：{caps?.lastAckAt?new Date(caps.lastAckAt).toLocaleString():'未确认'}</p></div>}
  </section>
 </ModalBody><ModalFooter><Button onPress={onClose}>关闭</Button></ModalFooter></ModalContent></Modal>;
}
