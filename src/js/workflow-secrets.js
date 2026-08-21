const ENCODED_SECRET_MARKER_PATTERN = /\{\{\s*(secret64|pwd64)\s*:\s*([^\r\n{}]+?)\s*\}\}/gi;
const LEGACY_SECRET_START_PATTERN = /\{\{\s*(secret|pwd)\s*:\s*/gi;

function normalizeSecretValue(value) {
  // Passwords may intentionally contain repeated spaces or tabs. Only trim
  // the optional padding around the marker value; never rewrite its content.
  return String(value || '').trim();
}

function encodeBase64Url(value) {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid secret marker');
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export function encodeWorkflowSecretMarker(value) {
  const raw = String(value || '');
  if (!raw) throw new Error('密码不能为空');
  return `{{secret64:${encodeBase64Url(raw)}}}`;
}

export function replaceWorkflowSecretMarkers(source, replacer) {
  const encodedReplaced = String(source || '').replace(ENCODED_SECRET_MARKER_PATTERN, (marker, type, payload) => {
    try {
      const raw = decodeBase64Url(payload.trim());
      return raw ? replacer(raw, marker) : marker;
    } catch {
      return marker;
    }
  });
  return encodedReplaced.split(/(\r?\n)/).map((line) => {
    if (/^\r?\n$/.test(line)) return line;
    const starts = [];
    LEGACY_SECRET_START_PATTERN.lastIndex = 0;
    let match;
    while ((match = LEGACY_SECRET_START_PATTERN.exec(line))) {
      starts.push({ markerStart: match.index, valueStart: LEGACY_SECRET_START_PATTERN.lastIndex });
    }
    if (!starts.length) return line;
    let cursor = 0;
    let replaced = '';
    for (let index = 0; index < starts.length; index += 1) {
      const start = starts[index];
      const segmentEnd = starts[index + 1]?.markerStart ?? line.length;
      const markerEnd = line.lastIndexOf('}}', segmentEnd - 1);
      if (markerEnd < start.valueStart || markerEnd < cursor) continue;
      const marker = line.slice(start.markerStart, markerEnd + 2);
      const raw = normalizeSecretValue(line.slice(start.valueStart, markerEnd));
      replaced += line.slice(cursor, start.markerStart);
      replaced += raw ? replacer(raw, marker) : marker;
      cursor = markerEnd + 2;
    }
    return replaced + line.slice(cursor);
  }).join('');
}
