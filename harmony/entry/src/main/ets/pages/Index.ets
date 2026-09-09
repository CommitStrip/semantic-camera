import { common } from '@kit.AbilityKit';
import { webview } from '@kit.ArkWeb';
import { fileIo as fs } from '@kit.CoreFileKit';
import { hilog } from '@kit.PerformanceAnalysisKit';

const DOMAIN: number = 0x0000;
const TAG: string = 'DroneMonitor';

/**
 * 遥测桥：Web 端通过 window.nativeBridge.pushTelemetry(json) 调用的桥接对象。
 * 负责把 Web 端 JS 产生的遥测 JSON(运行时性能 / 检测 / 确认 / 错误等)
 * 追加落盘到应用沙箱 files/telemetry/telemetry_<时间戳>.csv。
 */
class NativeBridge {
  private context: common.UIAbilityContext;
  private teleDir: string = '';
  private teleFile: string = '';
  private seq: number = 0;

  constructor(context: common.UIAbilityContext) {
    this.context = context;
    this.initTelemetry();
  }

  /**
   * 以指定打开模式写入文本（同步）。通过 openSync + writeSync + closeSync 实现。
   * @param path 文件路径
   * @param text 要写入的文本
   * @param mode OpenMode 位或值（如 WRITE_ONLY|CREATE|APPEND）
   */
  private writeText(path: string, text: string, mode: number): void {
    const file = fs.openSync(path, mode);
    try {
      fs.writeSync(file.fd, text);
    } finally {
      fs.closeSync(file);
    }
  }

  private initTelemetry(): void {
    try {
      // context.filesDir 为应用沙箱 files 目录，应用内读写无需额外权限
      const baseDir: string = this.context.filesDir;
      this.teleDir = baseDir + '/telemetry';
      fs.mkdirSync(this.teleDir, true);
      this.teleFile = this.teleDir + '/telemetry_' + this.currentStamp() + '.csv';
      // 写入 CSV 表头（TRUNC 清空重建）
      const wr: number = fs.OpenMode.WRITE_ONLY | fs.OpenMode.CREATE | fs.OpenMode.TRUNC;
      this.writeText(this.teleFile, 'seq,unix_ms,type,telemetry_json\n', wr);
      hilog.info(DOMAIN, TAG, 'telemetry file: %{public}s', this.teleFile);
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'initTelemetry error: %{public}s', JSON.stringify(e));
    }
  }

  private currentStamp(): string {
    const d = new Date();
    const p = (n: number): string => (n < 10 ? '0' + n.toString() : n.toString());
    return d.getFullYear().toString()
      + p(d.getMonth() + 1) + p(d.getDate())
      + '_' + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
  }

  /**
   * 由 Web 端 JS 调用的桥接入口。
   * @param json Web 端遥测对象序列化后的 JSON 字符串
   */
  pushTelemetry(json: string): void {
    try {
      let type = 'unknown';
      try {
        const obj: Record<string, Object> = JSON.parse(json) as Record<string, Object>;
        const ty = obj['ty'];
        if (ty !== undefined && ty !== null) {
          type = String(ty);
        }
      } catch (e) {
        // 非 JSON 时按原生内容记录
      }
      this.seq++;
      // 简单规避 CSV 分隔符/换行干扰
      const safe: string = json.replace(/[\r\n,]/g, ' ');
      const line: string = `${this.seq},${Date.now()},${type},${safe}\n`;
      const ap: number = fs.OpenMode.WRITE_ONLY | fs.OpenMode.CREATE | fs.OpenMode.APPEND;
      this.writeText(this.teleFile, line, ap);
      hilog.info(DOMAIN, TAG, 'pushTelemetry seq=%{public}d type=%{public}s', this.seq, type);
    } catch (e) {
      hilog.error(DOMAIN, TAG, 'pushTelemetry error: %{public}s', JSON.stringify(e));
    }
  }
}

@Entry
@Component
struct Index {
  @State bridgeStatus: string = '遥测桥:初始化中';
  private controller: webview.WebviewController = new webview.WebviewController();
  private bridge: NativeBridge | null = null;

  aboutToAppear(): void {
    const ctx = getContext(this) as common.UIAbilityContext;
    this.bridge = new NativeBridge(ctx);
    this.bridgeStatus = '遥测桥:就绪 · ' + ctx.filesDir + '/telemetry';
  }

  build() {
    Column() {
      // 顶部状态条
      Row() {
        Text('反无人机监控')
          .fontSize(16)
          .fontWeight(FontWeight.Bold)
          .fontColor('#d7e3f4')
        Blank()
        Text(this.bridgeStatus)
          .fontSize(11)
          .fontColor('#7e8ea6')
      }
      .width('100%')
      .padding({ left: 14, right: 14, top: 10, bottom: 10 })
      .backgroundColor('#0d1420')

      // ArkWeb 加载共享 HTML5 检测核心
      Web({ src: 'resource://rawfile/index.html', controller: this.controller })
        .javaScriptProxy({
          object: this.bridge as NativeBridge,
          name: 'nativeBridge',
          methodList: ['pushTelemetry'],
          controller: this.controller
        })
        // ArkWeb 默认拒绝网页 getUserMedia：不显式授权则相机画面黑屏
        // （应用级 CAMERA 权限已在 EntryAbility.requestPermissionsFromUser 请求）
        .onPermissionRequest((event) => {
          const req = event.request;
          req.grant(req.getAccessibleResource());
        })
        .darkMode(WebDarkMode.On)
        .domStorageAccess(true)
        .javaScriptAccess(true)
        .mixedMode(MixedMode.All)
        .horizontalScrollBarAccess(false)
        .verticalScrollBarAccess(false)
        .backgroundColor(Color.Black)
        .width('100%')
        .layoutWeight(1)

      // 底部提示
      Row() {
        Text('共享 web/index.html 核心 · 遥测经 javaScriptProxy 落盘沙箱')
          .fontSize(11)
          .fontColor('#7e8ea6')
      }
      .width('100%')
      .justifyContent(FlexAlign.Center)
      .padding(8)
      .backgroundColor('#0d1420')
    }
    .width('100%')
    .height('100%')
    .backgroundColor('#070b12')
  }
}