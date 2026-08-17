import jsQR from 'jsqr';

export class QrScanner {
  constructor({ video, canvas, onResult, onError, onStatus }) {
    this.video = video;
    this.canvas = canvas;
    this.onResult = onResult;
    this.onError = onError;
    this.onStatus = onStatus;
    this.stream = null;
    this.timer = null;
  }

  async start() {
    if (!navigator.mediaDevices?.getUserMedia) {
      this.onError?.('当前浏览器不支持摄像头访问');
      return;
    }
    this.stop();
    this.onStatus?.('正在请求摄像头权限…');
    try {
      this.stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } },
      });
      this.video.srcObject = this.stream;
      await this.video.play();
      this.canvas.width = this.video.videoWidth || 640;
      this.canvas.height = this.video.videoHeight || 480;
      this.onStatus?.('扫描中…');
      this.timer = setInterval(() => this.scanFrame(), 180);
    } catch (error) {
      this.stop();
      if (error.name === 'NotAllowedError') this.onError?.('摄像头权限被拒绝');
      else if (error.name === 'NotFoundError') this.onError?.('未检测到摄像头');
      else this.onError?.('摄像头启动失败');
    }
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    if (this.stream) this.stream.getTracks().forEach((track) => track.stop());
    this.stream = null;
    if (this.video) this.video.srcObject = null;
    this.onStatus?.('点击按钮启动摄像头');
  }

  scanFrame() {
    if (!this.stream || this.video.readyState < 2) return;
    const context = this.canvas.getContext('2d', { willReadFrequently: true });
    context.drawImage(this.video, 0, 0, this.canvas.width, this.canvas.height);
    const imageData = context.getImageData(0, 0, this.canvas.width, this.canvas.height);
    const result = jsQR(imageData.data, imageData.width, imageData.height);
    if (result?.data) {
      this.stop();
      this.onResult?.(result.data);
    }
  }
}

async function loadImage(file) {
  if ('createImageBitmap' in window) return createImageBitmap(file);
  const url = URL.createObjectURL(file);
  try {
    return await new Promise((resolve, reject) => {
      const image = new Image();
      image.onload = () => resolve(image);
      image.onerror = reject;
      image.src = url;
    });
  } finally {
    URL.revokeObjectURL(url);
  }
}

export async function scanQrImage(file) {
  if (!file?.type?.match(/^image\/(png|jpeg|webp)$/)) throw new Error('仅支持 PNG、JPG 和 WEBP 图片');
  if (file.size > 8 * 1024 * 1024) throw new Error('图片不能超过 8 MB');
  const image = await loadImage(file);
  const maxSide = 2_000;
  const scale = Math.min(1, maxSide / Math.max(image.width, image.height));
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, Math.round(image.width * scale));
  canvas.height = Math.max(1, Math.round(image.height * scale));
  const context = canvas.getContext('2d', { willReadFrequently: true });
  context.drawImage(image, 0, 0, canvas.width, canvas.height);
  image.close?.();
  const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
  const result = jsQR(imageData.data, imageData.width, imageData.height);
  if (!result?.data) throw new Error('图片中未识别到二维码');
  return result.data;
}
