import { Card, CardBody, CardHeader } from '@heroui/card';
import { Chip } from '@heroui/chip';

interface ProbeMetrics {sent:number;received:number;packetLoss:number;averageTime:number|null;error?:string}
export interface DiagnosisEntry {
  success: boolean;
  description: string;
  nodeName: string;
  nodeId?: string | number;
  targetIp: string;
  targetPort?: number;
  message?: string;
  probeKind?: string;
  averageTime?: number | null;
  packetLoss?: number | null;
  truncated?: boolean;
  icmp?: ProbeMetrics;
  tcp?: ProbeMetrics;
}

export default function DiagnosisCard({result}: {result: DiagnosisEntry}) {
  if (result.probeKind === 'icmpTcp' && result.icmp && result.tcp) {
    const ping=result.icmp,tcp=result.tcp;
    const both=ping.received>0 && tcp.received>0;
    const color=both?'success':result.success?'warning':'danger';
    return <Card className={`shadow-sm border ${both?'border-success':result.success?'border-warning':'border-danger'}`}>
      <CardHeader className="justify-between gap-3 pb-2">
        <div><h3 className="font-semibold">{result.description}</h3><p className="text-small text-default-500">{result.nodeName}</p></div>
        <Chip size="sm" color={color} variant="flat">{both?'连接正常':ping.received>0?'ICMP 可达':tcp.received>0?'TCP 可达':'未响应'}</Chip>
      </CardHeader>
      <CardBody className="space-y-4 pt-0">
        <div className="grid grid-cols-2 gap-4 text-center">
          <div><div className="text-3xl font-bold text-primary">{ping.averageTime!=null?ping.averageTime.toFixed(1):ping.sent>0?'超时':'不可用'}</div><div className="text-small text-default-500">ICMP 延迟(ms)</div></div>
          <div><div className="text-3xl font-bold text-warning">{ping.sent>0?`${ping.packetLoss.toFixed(0)}%`:'—'}</div><div className="text-small text-default-500">ICMP 丢包率</div></div>
        </div>
        <div className="text-small text-default-600">TCP：{tcp.averageTime!=null?`${tcp.averageTime.toFixed(1)} ms`:'未连接'} · {tcp.received}/{tcp.sent} 次成功</div>
        <code className="break-all text-small">{result.targetIp.includes(':')?`[${result.targetIp}]`:result.targetIp}{result.targetPort?`:${result.targetPort}`:''}</code>
      </CardBody>
    </Card>;
  }
  const readOnly = result.probeKind === 'routeOnly' || result.probeKind === 'runtimeState';
  const state = result.probeKind === 'routeOnly'
    ? (result.success ? '路由正常' : '路由异常')
    : result.probeKind === 'runtimeState'
      ? (result.success ? '状态正常' : '状态异常')
      : (result.success ? '连接成功' : '连接失败');
  return <Card className={`shadow-sm border ${result.success ? 'border-success' : 'border-danger'}`}>
    <CardHeader className="justify-between gap-3 pb-2">
      <div><h3 className="font-semibold">{result.description}</h3><p className="text-small text-default-500">{result.nodeName}</p></div>
      <Chip size="sm" color={result.success ? 'success' : 'danger'} variant="flat">{state}</Chip>
    </CardHeader>
    <CardBody className="space-y-2 pt-0 text-small">
      {result.targetIp && <code className="break-all">{result.targetIp}{result.targetPort ? `:${result.targetPort}` : ''}</code>}
      {result.message && <p className={result.success ? 'text-default-600' : 'text-danger'}>{result.message}</p>}
      {!readOnly && typeof result.averageTime === 'number' && result.averageTime >= 0 && <p>TCP 握手：{result.averageTime.toFixed(0)} ms</p>}
      {!readOnly && typeof result.packetLoss === 'number' && <p>连接失败率：{result.packetLoss.toFixed(1)}%</p>}
      {readOnly && <p className="text-xs text-default-500">未建立测试连接</p>}
      {result.truncated && <p className="text-xs text-warning">仅检查前 100 条规则</p>}
    </CardBody>
  </Card>;
}
