import { Card, CardBody, CardHeader } from '@heroui/card';
import { Chip } from '@heroui/chip';

export interface DiagnosisEntry {
  success: boolean;
  description: string;
  nodeName: string;
  targetIp: string;
  targetPort?: number;
  message?: string;
  probeKind?: string;
  averageTime?: number | null;
  packetLoss?: number | null;
  truncated?: boolean;
}

export default function DiagnosisCard({result}: {result: DiagnosisEntry}) {
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
