/**
 * JWT工具类 - TypeScript版本
 */

interface JWTPayload {
  sub: string;
  role_id: number;
  user: string;
  exp: number;
  iat: number;
}

/**
 * 从JWT Token中获取payload
 * @param token JWT Token
 * @returns payload数据
 */
function getPayloadFromToken(token: string): JWTPayload | null {
  try {
    if (!token) return null;
    
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    // Both Java and Go issue unpadded base64url with UTF-8 JSON payloads.
    const encodedPayload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const paddedPayload = encodedPayload + '='.repeat((4 - encodedPayload.length % 4) % 4);
    const bytes = Uint8Array.from(atob(paddedPayload), char => char.charCodeAt(0));
    const decodedPayload = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return JSON.parse(decodedPayload) as JWTPayload;
  } catch (error) {
    return null;
  }
}

/**
 * 从JWT Token中获取用户ID
 * @param token JWT Token
 * @returns 用户ID
 */
export function getUserIdFromToken(token: string): number | null {
  const payload = getPayloadFromToken(token);
  return payload ? parseInt(payload.sub) : null;
}

/**
 * 从JWT Token中获取用户角色ID
 * @param token JWT Token
 * @returns 角色ID
 */
export function getRoleIdFromToken(token: string): number | null {
  const payload = getPayloadFromToken(token);
  return payload ? payload.role_id : null;
}

/**
 * 从JWT Token中获取用户名
 * @param token JWT Token
 * @returns 用户名
 */
export function getUsernameFromToken(token: string): string | null {
  const payload = getPayloadFromToken(token);
  return payload ? payload.user : null;
}

/**
 * 验证token是否过期
 * @param token JWT Token
 * @returns 是否有效
 */
export function isTokenValid(token: string): boolean {
  const payload = getPayloadFromToken(token);
  if (!payload) return false;
  
  const now = Math.floor(Date.now() / 1000);
  return payload.exp > now;
}

// JwtUtil对象，提供便捷的静态方法调用
export const JwtUtil = {
  /**
   * 从localStorage获取token并解析用户ID
   * @returns 用户ID
   */
  getUserIdFromToken(): number | null {
    const token = localStorage.getItem('token');
    return token ? getUserIdFromToken(token) : null;
  },
  
  /**
   * 从localStorage获取token并解析角色ID
   * @returns 角色ID
   */
  getRoleIdFromToken(): number | null {
    const token = localStorage.getItem('token');
    return token ? getRoleIdFromToken(token) : null;
  },
  
  /**
   * 从localStorage获取token并解析用户名
   * @returns 用户名
   */
  getUsernameFromToken(): string | null {
    const token = localStorage.getItem('token');
    return token ? getUsernameFromToken(token) : null;
  },
  
  /**
   * 验证localStorage中的token是否有效
   * @returns 是否有效
   */
  isTokenValid(): boolean {
    const token = localStorage.getItem('token');
    return token ? isTokenValid(token) : false;
  }
}; 