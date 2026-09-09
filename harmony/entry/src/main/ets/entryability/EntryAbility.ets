import { AbilityConstant, UIAbility, Want, abilityAccessCtrl } from '@kit.AbilityKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { window } from '@kit.ArkUI';

const DOMAIN: number = 0x0000;
const TAG: string = 'DroneMonitor';

export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, TAG, 'EntryAbility onCreate');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    // 相机是 user_grant 权限：module.json5 声明之外必须运行时请求，
    // 否则 ArkWeb 里 getUserMedia 的 onPermissionRequest 授权也会失败
    const atManager = abilityAccessCtrl.createAtManager();
    atManager.requestPermissionsFromUser(this.context, ['ohos.permission.CAMERA'])
      .then((res) => {
        hilog.info(DOMAIN, TAG, 'camera permission: %{public}d', res.authResults[0]);
      })
      .catch((err: BusinessError) => {
        hilog.error(DOMAIN, TAG, 'requestPermissionsFromUser error: %{public}s', JSON.stringify(err));
      });

    // 加载首页 (pages/Index)，Index.ets 内通过 Web 组件加载共享 web/index.html
    // 并将本 Ability 的 context 传给页面，用于遥测桥写沙箱文件。
    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, TAG, 'loadContent failed: %{public}s', JSON.stringify(err));
        return;
      }
      hilog.info(DOMAIN, TAG, 'loadContent succeeded');
    });
  }

  onWindowStageDestroy(): void {
    hilog.info(DOMAIN, TAG, 'EntryAbility onWindowStageDestroy');
  }

  onForeground(): void {
    hilog.info(DOMAIN, TAG, 'EntryAbility onForeground');
  }

  onBackground(): void {
    hilog.info(DOMAIN, TAG, 'EntryAbility onBackground');
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, 'EntryAbility onDestroy');
  }
}