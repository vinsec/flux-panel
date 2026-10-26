import { Button } from '@heroui/button';
import { Input } from '@heroui/input';
import { Select, SelectItem } from '@heroui/select';
import { Switch } from '@heroui/switch';

export interface EngineFeatures { [name: string]: boolean }
export interface EngineOptions {
  listeners?: {host:string;port:number;protocol:string}[];
  targets?: {endpoint:{host:string;port:number};weight:number}[];
  selection?: string;
  dnsPolicy?: {failClosed?:boolean;staleMillis?:number;drainMillis?:number};
  health?: {protocol:string;port?:number;intervalMillis?:number;timeoutMillis?:number;rise?:number;fall?:number;payload?:string;expected?:string};
  egress?: {interface:string;sourceIPv4?:string;sourceIPv6?:string;gatewayIPv4?:string;gatewayIPv6?:string};
  bandwidth?: {upBitsPerSecond?:number;downBitsPerSecond?:number};
  traffic?: {localOutput?:boolean;localTargets?:boolean;sourceMode?:"masquerade"|"preserve";returnPathConfirmed?:boolean};
}
export function readEngineOptions(value?:string):EngineOptions {try{return value?JSON.parse(value):{}}catch{return {}}}
export function parseForwardEndpoint(address:string):{host:string;port:number}{
  const value=address.trim();let host:string,portText:string;
  if(value.startsWith('[')){const end=value.indexOf(']:');if(end<0)throw new Error('IPv6 地址必须使用 [地址]:端口');host=value.slice(1,end);portText=value.slice(end+2);const parsed=new URL(`http://[${host}]/`);host=parsed.hostname.replace(/^\[|\]$/g,'');}
  else {const split=value.lastIndexOf(':');if(split<1||value.slice(0,split).includes(':'))throw new Error('目标必须为 域名:端口 或 [IPv6]:端口');host=value.slice(0,split).toLowerCase().replace(/\.$/,'');portText=value.slice(split+1);if(!host||host.length>253||host.split('.').some(label=>!label.match(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/)))throw new Error('目标域名格式无效');if(/^[0-9.]+$/.test(host)&& (host.split('.').length!==4||host.split('.').some(p=>!p.match(/^(0|[1-9][0-9]{0,2})$/)||Number(p)>255)))throw new Error('IPv4 地址格式无效');}
  const port=Number(portText);if(!portText.match(/^[0-9]+$/)||!Number.isInteger(port)||port<1||port>65535)throw new Error('目标端口必须为 1–65535');return {host,port};
}
export function engineOptionsForSubmit(value:string|undefined,remote:string,port:number|null,features:EngineFeatures):string|undefined {
  const options=readEngineOptions(value);const addresses=remote.split(/[\n,]/).map(s=>s.trim()).filter(Boolean);const endpoints=addresses.map(parseForwardEndpoint);
  if(endpoints.some(e=>e.host.includes(':'))&&!features.ipv6)throw new Error('当前节点未提供 IPv6 能力');
  if(endpoints.some(e=>!e.host.includes(':')&&!/^[0-9.]+$/.test(e.host))&&!features.dns)throw new Error('当前节点未提供域名解析能力');
  if(endpoints.length>1&&!features.multiTarget)throw new Error('当前节点未提供多目标能力');
  if(options.listeners){if(!port)throw new Error('自定义监听需要填写入口端口');if(!features.independentProtocols)throw new Error('当前节点不支持独立监听');if(!options.listeners.some(l=>l.port===port))throw new Error('至少一项监听必须使用入口端口');for(const l of options.listeners){parseForwardEndpoint(`${l.host.includes(':')?'['+l.host+']':l.host}:${l.port}`);if(l.host.includes(':')&&!features.ipv6)throw new Error('当前节点未提供 IPv6 能力');}}
  if(options.targets){let total=0;options.targets=endpoints.map((endpoint,i)=>{const weight=options.targets?.[i]?.weight||1;if(!Number.isInteger(weight)||weight<1||weight>32)throw new Error('权重必须为 1–32 的整数');total+=weight;return {endpoint,weight}});if(total>32)throw new Error('目标权重之和不能超过 32');}
  if(options.egress&&!features.interfaceRouting)throw new Error('当前节点不支持出口策略');if(options.bandwidth&&!features.shaping)throw new Error('当前节点不支持平滑限速');if(options.health&&!features.multiTarget)throw new Error('当前节点不支持健康检查');
  if(options.traffic){for(const key of ['localOutput','localTargets'] as const)if(options.traffic[key]&&!features[key])throw new Error('当前节点不支持此本地流量模式');if(options.traffic.sourceMode==='preserve'&&(!features.preserveSource||!options.traffic.returnPathConfirmed))throw new Error('保留源地址需要节点能力及回程路由确认');if((options.traffic.localOutput||options.traffic.localTargets)&&((options.bandwidth?.upBitsPerSecond||0)+(options.bandwidth?.downBitsPerSecond||0)>0))throw new Error('本地流量暂不支持平滑限速组合');}
  return Object.keys(options).length?JSON.stringify(options):undefined;
}

export default function AdvancedForwardFields({value,onChange,features,port,remoteAddr,tcpHost='0.0.0.0',udpHost='0.0.0.0',strategy='fifo'}:{value?:string;onChange:(value:string)=>void;features:EngineFeatures;port:number|null;remoteAddr:string;tcpHost?:string;udpHost?:string;strategy?:string}){
  const options=readEngineOptions(value);const addresses=remoteAddr.split(/[\n,]/).map(s=>s.trim()).filter(Boolean);
  const set=(key:keyof EngineOptions,data:any)=>{const next={...options};if(data===undefined)delete next[key];else (next as any)[key]=data;onChange(JSON.stringify(next));};
  const listener=(index:number,key:string,v:any)=>set('listeners',options.listeners?.map((l,i)=>i===index?{...l,[key]:v}:l));
  return <div className="space-y-4 rounded-xl border border-default-200 p-4">
    <p className="text-sm font-semibold">内核转发选项</p>
    <p className="text-xs text-default-500">仅展示节点已声明的能力。域名由节点解析；IPv4/IPv6 分别转发，统计与配额归入同一业务。</p>
    {features.independentProtocols&&<>
      <Switch size="sm" isSelected={!!options.listeners} onValueChange={enabled=>set('listeners',enabled?[{host:tcpHost,port:port||0,protocol:'tcp'},{host:udpHost,port:port||0,protocol:'udp'}]:undefined)}>自定义 TCP/UDP 监听</Switch>
      {options.listeners&&<div className="space-y-2">
        {options.listeners.map((l,index)=><div key={index} className="grid grid-cols-1 sm:grid-cols-[100px_1fr_110px_60px] gap-2">
          <Select size="sm" label="协议" selectedKeys={[l.protocol]} onSelectionChange={keys=>listener(index,'protocol',String(Array.from(keys)[0]))}><SelectItem key="tcp">TCP</SelectItem><SelectItem key="udp">UDP</SelectItem></Select>
          <Input size="sm" label="监听地址" value={l.host} onValueChange={v=>listener(index,'host',v)} description={features.ipv6?'可使用 0.0.0.0 或 :: 通配地址':undefined}/>
          <Input size="sm" label="端口" type="number" value={l.port?String(l.port):''} onValueChange={v=>listener(index,'port',Number(v))}/>
          <Button size="sm" color="danger" variant="light" onPress={()=>set('listeners',options.listeners?.filter((_,i)=>i!==index))}>移除</Button>
        </div>)}
        <Button size="sm" variant="flat" isDisabled={options.listeners.length>=16} onPress={()=>set('listeners',[...options.listeners!,{protocol:'tcp',host:features.ipv6?'::':'0.0.0.0',port:port||0}])}>添加监听</Button>
      </div>}
    </>}
    {features.multiTarget&&addresses.length>1&&<>
      <Select label="新连接选择" selectedKeys={[options.selection||(strategy==='rand'?'random':strategy)||'fifo']} onSelectionChange={keys=>set('selection',String(Array.from(keys)[0]))}><SelectItem key="fifo">首个可用目标</SelectItem><SelectItem key="hash">源地址哈希</SelectItem><SelectItem key="round">加权轮询</SelectItem><SelectItem key="random">加权随机</SelectItem></Select>
      <div className="space-y-2">{addresses.map((address,index)=><Input key={index} size="sm" label={`权重 · ${address}`} type="number" min={1} max={32} value={String(options.targets?.[index]?.weight||1)} onValueChange={v=>{try{set('targets',addresses.map((addr,i)=>({endpoint:parseForwardEndpoint(addr),weight:i===index?Number(v):options.targets?.[i]?.weight||1})))}catch{}}}/>)}</div>
    </>}
    {features.dns&&<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
      <Switch size="sm" isSelected={!!options.dnsPolicy?.failClosed} onValueChange={v=>set('dnsPolicy',{...options.dnsPolicy,failClosed:v})}>解析失效立即停止新连接</Switch>
      <Input size="sm" label="临时解析错误保留秒数" type="number" min={0} max={300} value={String((options.dnsPolicy?.staleMillis??30000)/1000)} onValueChange={v=>set('dnsPolicy',{...options.dnsPolicy,staleMillis:Number(v)*1000})}/>
    </div>}
    {features.multiTarget&&<>
      <Switch size="sm" isSelected={!!options.health} onValueChange={v=>set('health',v?{protocol:'tcp',intervalMillis:5000,timeoutMillis:500,rise:2,fall:2}:undefined)}>启用有界健康检查</Switch>
      {options.health&&<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Select label="健康协议" selectedKeys={[options.health.protocol]} onSelectionChange={keys=>set('health',{...options.health,protocol:String(Array.from(keys)[0])})}><SelectItem key="tcp">TCP 连接</SelectItem><SelectItem key="udp">UDP 指定请求/响应</SelectItem></Select>
        <Input label="独立健康端口（0 沿用目标）" type="number" value={String(options.health.port||0)} onValueChange={v=>set('health',{...options.health,port:Number(v)})}/>
        <Input label="检查间隔（秒）" type="number" min={1} max={60} value={String((options.health.intervalMillis||5000)/1000)} onValueChange={v=>set('health',{...options.health,intervalMillis:Number(v)*1000})}/>
        <Input label="超时（毫秒）" type="number" min={50} max={3000} value={String(options.health.timeoutMillis||500)} onValueChange={v=>set('health',{...options.health,timeoutMillis:Number(v)})}/>
        {options.health.protocol==='udp'&&<><Input label="请求内容（Base64，最多64字节）" value={options.health.payload||''} onValueChange={v=>set('health',{...options.health,payload:v})}/><Input label="预期响应（Base64）" value={options.health.expected||''} onValueChange={v=>set('health',{...options.health,expected:v})}/></>}
      </div>}
    </>}
    {features.interfaceRouting&&<>
      <Switch size="sm" isSelected={!!options.egress} onValueChange={v=>set('egress',v?{interface:''}:undefined)}>指定出口与源地址</Switch>
      {options.egress&&<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Input label="出口网卡" placeholder="eth1" value={options.egress.interface} onValueChange={v=>set('egress',{...options.egress,interface:v})}/>
        {(['sourceIPv4','gatewayIPv4',...(features.ipv6?['sourceIPv6','gatewayIPv6']:[])] as const).map(key=><Input key={key} label={{sourceIPv4:'IPv4 源地址',gatewayIPv4:'IPv4 网关',sourceIPv6:'IPv6 源地址',gatewayIPv6:'IPv6 网关'}[key]} value={(options.egress as any)?.[key]||''} onValueChange={v=>set('egress',{...options.egress,[key]:v})}/>)}
      </div>}
    </>}
    {(features.localOutput||features.localTargets||features.preserveSource)&&<div className="space-y-2">
      {features.localOutput&&<Switch size="sm" isSelected={!!options.traffic?.localOutput} onValueChange={v=>set('traffic',{...options.traffic,localOutput:v})}>允许本机程序访问转发入口</Switch>}
      {features.localTargets&&<Switch size="sm" isSelected={!!options.traffic?.localTargets} onValueChange={v=>set('traffic',{...options.traffic,localTargets:v})}>允许转发到本机服务</Switch>}
      {features.preserveSource&&<Switch size="sm" isSelected={options.traffic?.sourceMode==='preserve'} onValueChange={v=>set('traffic',{...options.traffic,sourceMode:v?'preserve':'masquerade',returnPathConfirmed:false})}>保留客户端源地址</Switch>}
      {options.traffic?.sourceMode==='preserve'&&<Switch size="sm" isSelected={!!options.traffic.returnPathConfirmed} onValueChange={v=>set('traffic',{...options.traffic,returnPathConfirmed:v})}>已确认目标回程经过本节点</Switch>}
      <p className="text-xs text-default-500">默认保持地址转换，支持同网段回流。本地流量暂不能与用户、隧道或转发平滑限速组合；外部访问 IPv4 回环目标需节点事先配置路由，建议使用本机网卡地址。</p>
    </div>}
    {features.shaping&&<div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
      <Input label="本转发上传上限（Mbps，0 不另限）" type="number" min={0} value={String((options.bandwidth?.upBitsPerSecond||0)/1000000)} onValueChange={v=>set('bandwidth',{...options.bandwidth,upBitsPerSecond:Math.round(Number(v)*1000000)})}/>
      <Input label="本转发下载上限（Mbps，0 不另限）" type="number" min={0} value={String((options.bandwidth?.downBitsPerSecond||0)/1000000)} onValueChange={v=>set('bandwidth',{...options.bandwidth,downBitsPerSecond:Math.round(Number(v)*1000000)})}/>
      <p className="text-xs text-default-500 sm:col-span-2">用户总带宽及该隧道授权的共享上限继续生效；此处不能放宽共享上限。暂停优先于排队和限速。</p>
    </div>}
  </div>;
}
