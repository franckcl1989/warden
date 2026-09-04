/**
 * 终端连接失败/关闭原因的展示文案（M5T4）。
 *
 * 只依赖机器原因键与 WebSocket 关闭码（前端不解析终端正文）；原因键/关闭码
 * 词表对应 app/api/routes/terminal.py + application/terminal_sessions.py
 * 的稳定协议，中文文案可本地化。
 *
 * 拒绝帧契约（M5T4 review）：服务端先 accept，随后对票据/门禁/拨号失败发送
 * 一个机器 JSON 帧 `{"type":"refused","code":..,"reason":..}` 再关闭
 * （post-accept 关闭码 4000-4999 才能被真实 ASGI 服务器送达；accept 前的
 * 关闭只会变成 HTTP 403 握手拒绝）。前端优先按 reason 键展示；关闭码仅在
 * 帧丢失时兜底。
 */

export function closeReasonMessage(reason: string): string {
  switch (reason) {
    case 'user_closed':
      return '会话已由你或管理员关闭。';
    case 'idle_timeout':
      return '会话因空闲超时（15 分钟无操作）自动断开。';
    case 'max_duration':
      return '会话达到最长时限（2 小时），已自动断开。';
    case 'handshake_failed':
      return '设备连接握手失败（认证或网络错误），会话未建立。';
    case 'device_connection_lost':
      return '设备连接中断，会话已断开。';
    case 'client_disconnected':
      return '浏览器连接已断开。';
    case 'server_restart':
      return '平台服务重启，会话已终止。';
    case 'internal_error':
      return '会话异常终止，请重新打开终端。';
    default:
      return `会话已结束（${reason}）。`;
  }
}

/** refused 帧原因键 -> 中文（与服务端 reason 词表一一对应）。 */
const REFUSAL_REASONS: Record<string, string> = {
  ticket_unavailable: '终端票据不可用（已使用、已过期或不属于当前用户），请重新发起连接。',
  capacity_user: '终端会话数量已达上限（每用户 3 个、每设备 1 个），请先关闭其他会话。',
  capacity_device: '终端会话数量已达上限（每用户 3 个、每设备 1 个），请先关闭其他会话。',
  password_change_required: '需要先修改密码才能打开终端，请先完成密码修改。',
  handshake_failed: '设备连接握手失败（认证失败、主机指纹不匹配或设备不可达），会话未建立。',
  internal_error: '会话异常终止，请重新打开终端。',
};

export function refusalReasonMessage(reason: string): string | null {
  return REFUSAL_REASONS[reason] ?? null;
}

export function handshakeCodeMessage(code: number): string {
  switch (code) {
    case 4401:
      return '登录状态已失效，请重新登录后再打开终端。';
    case 4403:
      return '来源校验未通过或需要先修改密码，无法打开终端。';
    case 4404:
      return '终端票据不可用（已使用、已过期或不属于当前用户），请重新发起连接。';
    case 4429:
      return '终端会话数量已达上限（每用户 3 个、每设备 1 个），请先关闭其他会话。';
    case 4101:
      return '设备连接握手失败（认证失败、主机指纹不匹配或设备不可达），会话未建立。';
    case 4500:
      return '会话异常终止，请重新打开终端。';
    default:
      return code === 1000 ? '' : '终端连接被拒绝，请稍后重试。';
  }
}
