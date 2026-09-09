// ============================================================
// whep-client.js —— 极简 WHEP(WebRTC HTTP Egress Protocol) 播放器
// ------------------------------------------------------------
// 用于从 MediaMTX 网关拉取海康 RTSP（转成 WebRTC 后）的低延迟画面。
// 无外部依赖，遵循 WHEP 标准信令：
//   1. OPTIONS -> 读取 Link 头里的 ICE 服务器
//   2. createOffer -> POST(SDP) 到 /<path>/whep  -> 得到 Answer
//   3. setRemoteDescription(answer)
//   4. PATCH 本地 ICE candidate（trickle-ice）
//   5. ontrack -> 把媒体流挂到 <video>.srcObject
// 对外暴露全局 window.WhepClient
// ============================================================
(function () {
  'use strict';

  const RETRY_MS = 2000, RETRY_MAX_MS = 30000;

  class WhepClient {
    /**
     * @param {Object} conf
     * @param {string}   conf.url   WHEP 端点，如 http://host:8889/cam1/whep
     * @param {string}   [conf.user] 可选 Basic 认证用户名
     * @param {string}   [conf.pass] 可选 Basic 认证密码
     * @param {HTMLVideoElement} conf.video 目标 <video>
     * @param {Function} [conf.onError]
     * @param {Function} [conf.onTrack]
     */
    constructor(conf) {
      this.conf = conf;
      this.pc = null;
      this.sessionUrl = null;
      this.queued = [];
      this.offerData = null;
      this.closed = false;
      this.retryTimer = null;
      this.retryMs = RETRY_MS;  // 指数退避当前值（连接成功重置）
    }

    start() {
      this.closed = false;
      this.#connect();
    }

    close() {
      this.closed = true;
      if (this.retryTimer) { clearTimeout(this.retryTimer); this.retryTimer = null; }
      if (this.sessionUrl) { try { fetch(this.sessionUrl, { method: 'DELETE' }); } catch (e) {} this.sessionUrl = null; }
      if (this.pc) { this.pc.close(); this.pc = null; }
      this.queued = [];
    }

    #auth() {
      if (this.conf.user) return { Authorization: 'Basic ' + btoa(this.conf.user + ':' + (this.conf.pass || '')) };
      return {};
    }

    #err(msg) {
      if (this.conf.onError) this.conf.onError(msg);
    }

    #connect() {
      if (this.closed) return;
      // 1. 取 ICE 服务器
      fetch(this.conf.url, { method: 'OPTIONS', headers: this.#auth() })
        .then((res) => this.#linkIce(res.headers.get('Link')))
        // 2. 建 PeerConnection + 发 offer
        .then((iceServers) => this.#setup(iceServers))
        .then((offer) => this.#sendOffer(offer))
        .then((answer) => {
          if (this.closed) return;
          return this.pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: answer }));
        })
        .then(() => {
          if (this.closed) return;
          if (this.queued.length) { this.#sendIce(this.queued); this.queued = []; }
        })
        .catch((e) => this.#restart(e));
    }

    #linkIce(link) {
      if (!link) return [];
      return link.split(', ').map((s) => {
        const m = s.match(/^<(.+?)>;\s*rel="ice-server"(?:\s*;\s*username="(.*?)";\s*credential="(.*?)";\s*credential-type="password")?/i);
        if (!m) return null;
        const server = { urls: [m[1]] };
        if (m[2] !== undefined) { server.username = JSON.parse('"' + m[2] + '"'); server.credential = JSON.parse('"' + m[3] + '"'); server.credentialType = 'password'; }
        return server;
      }).filter(Boolean);
    }

    #setup(iceServers) {
      if (this.closed) throw new Error('closed');
      this.pc = new RTCPeerConnection({ iceServers, sdpSemantics: 'unified-plan' });
      this.pc.addTransceiver('video', { direction: 'recvonly' });
      // 音频可选：海康主码流通常无音频，加上不打紧
      this.pc.addTransceiver('audio', { direction: 'recvonly' });
      this.pc.createDataChannel('');
      this.pc.onicecandidate = (evt) => {
        if (this.closed) return;
        if (evt.candidate) {
          if (this.sessionUrl) this.#sendIce([evt.candidate]);
          else this.queued.push(evt.candidate);
        }
      };
      this.pc.onconnectionstatechange = () => {
        if (this.closed) return;
        if (this.pc.connectionState === 'failed' || this.pc.connectionState === 'closed') {
          this.#restart('peer connection closed');
        }
      };
      this.pc.ontrack = (evt) => {
        if (this.closed) return;
        this.retryMs = RETRY_MS;  // 连接成功，退避归位
        const stream = evt.streams && evt.streams[0] ? evt.streams[0] : new MediaStream([evt.track]);
        this.conf.video.srcObject = stream;
        if (this.conf.onTrack) this.conf.onTrack(evt);
      };
      return this.pc.createOffer().then((offer) => {
        this.offerData = this.#parseOffer(offer.sdp);
        return this.pc.setLocalDescription(offer).then(() => offer.sdp);
      });
    }

    #parseOffer(sdp) {
      const ret = { iceUfrag: '', icePwd: '', medias: [] };
      for (const line of sdp.split('\r\n')) {
        if (line.startsWith('m=')) ret.medias.push(line.slice(2));
        else if (!ret.iceUfrag && line.startsWith('a=ice-ufrag:')) ret.iceUfrag = line.slice(12);
        else if (!ret.icePwd && line.startsWith('a=ice-pwd:')) ret.icePwd = line.slice(10);
      }
      return ret;
    }

    #sendOffer(offer) {
      if (this.closed) throw new Error('closed');
      return fetch(this.conf.url, {
        method: 'POST',
        headers: Object.assign({}, this.#auth(), { 'Content-Type': 'application/sdp' }),
        body: offer,
      }).then((res) => {
        if (res.status === 404) throw new Error('stream not found: ' + this.conf.url);
        if (res.status >= 400) return res.text().then((t) => { throw new Error('bad status ' + res.status + ' ' + t.slice(0, 120)); });
        this.sessionUrl = new URL(res.headers.get('location'), this.conf.url).toString();
        return res.text();
      });
    }

    #sendIce(candidates) {
      const byMid = {};
      for (const c of candidates) {
        (byMid[c.sdpMLineIndex] = byMid[c.sdpMLineIndex] || []).push(c);
      }
      let frag = 'a=ice-ufrag:' + this.offerData.iceUfrag + '\r\na=ice-pwd:' + this.offerData.icePwd + '\r\n';
      let mid = 0;
      for (const media of this.offerData.medias) {
        if (byMid[mid]) {
          frag += 'm=' + media + '\r\na=mid:' + mid + '\r\n';
          for (const c of byMid[mid]) frag += 'a=' + c.candidate + '\r\n';
        }
        mid++;
      }
      fetch(this.sessionUrl, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/trickle-ice-sdpfrag', 'If-Match': '*' },
        body: frag,
      }).then((res) => {
        if (res.status === 404) this.#restart('stream not found');
      }).catch((e) => this.#restart(e));
    }

    #restart(e) {
      if (this.closed) return;
      if (this.sessionUrl) { try { fetch(this.sessionUrl, { method: 'DELETE' }); } catch (e2) {} this.sessionUrl = null; }
      if (this.pc) { this.pc.close(); this.pc = null; }
      this.queued = [];
      const wait = this.retryMs;
      this.retryMs = Math.min(RETRY_MAX_MS, this.retryMs * 1.5);  // 指数退避：2s→3s→4.5s…封顶 30s
      this.#err(String(e && e.message ? e.message : e) + '，' + Math.round(wait / 1000) + 's 后重连');
      this.retryTimer = setTimeout(() => this.#connect(), wait);
    }
  }

  window.WhepClient = WhepClient;
})();